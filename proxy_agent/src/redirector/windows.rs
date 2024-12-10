// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

mod bpf_api;
mod bpf_obj;
mod bpf_prog;

use crate::common::error::{Error, WindowsApiErrorType};
use crate::common::{config, constants, helpers, logger, result::Result};
use crate::proxy::authorization_rules::AuthorizationMode;
use crate::redirector::AuditEntry;
use crate::shared_state::agent_status_wrapper::AgentStatusModule;
use crate::shared_state::redirector_wrapper::RedirectorSharedState;
use core::ffi::c_void;
use proxy_agent_shared::proxy_agent_aggregate_status::ModuleState;
use std::mem;
use std::ptr;
use std::sync::{Arc, Mutex};
use windows_sys::Win32::Networking::WinSock;

pub struct BpfObject(pub *mut bpf_obj::bpf_object);
// Safety: bpf_object, which is a reference to an eBPF object, has no dependencies on thread-local storage and can
// safely be sent to another thread. This is not explicitly documented in the Windows eBPF library, but the library does
// document it aims to be source-compatible with libbpf[0]. Note that synchronization is required to share this object
// between threads, and care must be taken when using it as libbpf APIs make use of errno[1], which is thread-local.
//
// [0] https://github.com/microsoft/ebpf-for-windows/tree/Release-v0.17.1#2-does-this-provide-app-compatibility-with-ebpf-programs-written-for-linux
// [1] https://libbpf.readthedocs.io/en/v1.4.5/api.html#error-handling
unsafe impl Send for BpfObject {}

impl Default for BpfObject {
    fn default() -> Self {
        Self::new()
    }
}

// Redirector implementation for Windows platform
impl super::Redirector {
    pub async fn initialized_success(&self) -> bool {
        if !bpf_api::ebpf_api_is_loaded() {
            self.set_error_status("Failed to load eBPF API.".to_string())
                .await;
            return false;
        }
        true
    }

    pub async fn start_internal(&self) -> bool {
        let mut bpf_object = BpfObject::new();

        let result = bpf_object.load_bpf_object(super::get_ebpf_file_path());
        if result != 0 {
            self.set_error_status(format!("Failed to load bpf object with result: {result}"))
                .await;
            return false;
        } else {
            logger::write("Success loaded bpf object.".to_string());
        }

        let result = bpf_object.attach_bpf_prog();
        if result != 0 {
            self.set_error_status(format!("Failed to attach bpf prog with result: {result}"))
                .await;
            return false;
        } else {
            logger::write("Success attached bpf prog.".to_string());
        }

        let pid = std::process::id();
        let result = bpf_object.update_bpf_skip_process_map(pid);
        if result != 0 {
            self.set_error_status(format!(
                "Failed to update bpf skip_process map with result: {result}"
            ))
            .await;
            return false;
        } else {
            logger::write(format!(
                "Success updated bpf skip_process map with pid={pid}."
            ));
        }

        let wireserver_mode =
            if let Ok(Some(rules)) = self.key_keeper_shared_state.get_wireserver_rules().await {
                rules.mode
            } else {
                AuthorizationMode::Audit
            };
        if wireserver_mode != AuthorizationMode::Disabled {
            let result = bpf_object.update_policy_elem_bpf_map(
                self.local_port,
                constants::WIRE_SERVER_IP_NETWORK_BYTE_ORDER, //0x10813FA8 - 168.63.129.16
                constants::WIRE_SERVER_PORT,
            );
            if result != 0 {
                self.set_error_status(format!(
                    "Failed to update bpf map for WireServer support with result: {result}"
                ))
                .await;
                return false;
            } else {
                logger::write("Success updated bpf map for WireServer support.".to_string());
            }
        }
        if config::get_host_gaplugin_support() > 0 {
            let result = bpf_object.update_policy_elem_bpf_map(
                self.local_port,
                constants::GA_PLUGIN_IP_NETWORK_BYTE_ORDER, //0x10813FA8, // 168.63.129.16
                constants::GA_PLUGIN_PORT,
            );
            if result != 0 {
                self.set_error_status(format!(
                    "Failed to update bpf map for Host GAPlugin support with result: {result}"
                ))
                .await;
                return false;
            } else {
                logger::write("Success updated bpf map for Host GAPlugin support.".to_string());
            }
        }

        let imds_mode = if let Ok(Some(rules)) = self.key_keeper_shared_state.get_imds_rules().await
        {
            rules.mode
        } else {
            AuthorizationMode::Audit
        };
        if imds_mode != AuthorizationMode::Disabled {
            let result = bpf_object.update_policy_elem_bpf_map(
                self.local_port,
                constants::IMDS_IP_NETWORK_BYTE_ORDER, //0xFEA9FEA9, // 169.254.169.254
                constants::IMDS_PORT,
            );
            if result != 0 {
                self.set_error_status(format!(
                    "Failed to update bpf map for IMDS support with result: {result}"
                ))
                .await;
                return false;
            } else {
                logger::write("Success updated bpf map for IMDS support.".to_string());
            }
        }

        if let Err(e) = self
            .redirector_shared_state
            .update_bpf_object(Arc::new(Mutex::new(bpf_object)))
            .await
        {
            logger::write_error(format!("Failed to update bpf object in shared state: {e}"));
        }
        if let Err(e) = self
            .redirector_shared_state
            .set_local_port(self.local_port)
            .await
        {
            logger::write_error(format!("Failed to set local port in shared state: {e}"));
        }
        let message = helpers::write_startup_event(
            "Started Redirector with eBPF maps",
            "start",
            "redirector",
            logger::AGENT_LOGGER_KEY,
        );
        if let Err(e) = self
            .agent_status_shared_state
            .set_module_status_message(message.to_string(), AgentStatusModule::Redirector)
            .await
        {
            logger::write_error(format!(
                "Failed to set module status message in shared state: {e}"
            ));
        }
        if let Err(e) = self
            .agent_status_shared_state
            .set_module_state(ModuleState::RUNNING, AgentStatusModule::Redirector)
            .await
        {
            logger::write_error(format!("Failed to set module state in shared state: {e}"));
        }

        true
    }
}

pub async fn close_bpf_object(redirector_shared_state: RedirectorSharedState) {
    if let Ok(Some(bpf_object)) = redirector_shared_state.get_bpf_object().await {
        bpf_object.lock().unwrap().close_bpf_object();
        logger::write("Success closed bpf object.".to_string());
    }
}

pub fn get_audit_from_redirect_context(raw_socket_id: usize) -> Result<AuditEntry> {
    // WSAIoctl - SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT
    let value = AuditEntry::empty();
    let redirect_context_size = mem::size_of::<AuditEntry>() as u32;
    let mut redirect_context_returned: u32 = 0;
    let result = unsafe {
        WinSock::WSAIoctl(
            raw_socket_id,
            WinSock::SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT,
            ptr::null(),
            0,
            &value as *const AuditEntry as *mut c_void,
            redirect_context_size,
            &mut redirect_context_returned,
            ptr::null_mut(),
            None,
        )
    };
    if result != 0 {
        let error = unsafe { WinSock::WSAGetLastError() };
        return Err(Error::WindowsApi(WindowsApiErrorType::WSAIoctl(format!(
            "SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT result: {}, WSAGetLastError: {}",
            result, error,
        ))));
    }

    // Need to check the returned size to ensure it matches the expected size,
    // since the result is 0 even if there is no redirect context in this socket stream.
    if redirect_context_returned != redirect_context_size {
        return Err(Error::WindowsApi(WindowsApiErrorType::WSAIoctl(format!(
            "SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT returned size: {}, expected size: {}",
            redirect_context_returned, redirect_context_size,
        ))));
    }

    Ok(value)
}

pub async fn update_wire_server_redirect_policy(
    redirect: bool,
    redirector_shared_state: RedirectorSharedState,
) {
    if let Ok(Some(bpf_object)) = redirector_shared_state.get_bpf_object().await {
        if redirect {
            if let Ok(local_port) = redirector_shared_state.get_local_port().await {
                let result = bpf_object.lock().unwrap().update_policy_elem_bpf_map(
                    local_port,
                    constants::WIRE_SERVER_IP_NETWORK_BYTE_ORDER,
                    constants::WIRE_SERVER_PORT,
                );
                if result != 0 {
                    logger::write_error(format!(
                    "Failed to update bpf map for wireserver redirect policy with result: {result}"
                ));
                } else {
                    logger::write(
                        "Success updated bpf map for wireserver redirect policy.".to_string(),
                    );
                }
            }
        } else {
            let result = bpf_object.lock().unwrap().remove_policy_elem_bpf_map(
                constants::WIRE_SERVER_IP_NETWORK_BYTE_ORDER,
                constants::WIRE_SERVER_PORT,
            );
            if result != 0 {
                logger::write_error(format!(
                    "Failed to delete bpf map for wireserver redirect policy with result: {result}"
                ));
            } else {
                logger::write(
                    "Success deleted bpf map for wireserver redirect policy.".to_string(),
                );
            }
        }
    }
}

pub async fn update_imds_redirect_policy(
    redirect: bool,
    redirector_shared_state: RedirectorSharedState,
) {
    if let Ok(Some(bpf_object)) = redirector_shared_state.get_bpf_object().await {
        if redirect {
            if let Ok(local_port) = redirector_shared_state.get_local_port().await {
                let result = bpf_object.lock().unwrap().update_policy_elem_bpf_map(
                    local_port,
                    constants::IMDS_IP_NETWORK_BYTE_ORDER,
                    constants::IMDS_PORT,
                );
                if result != 0 {
                    logger::write_error(format!(
                        "Failed to update bpf map for IMDS redirect policy with result: {result}"
                    ));
                } else {
                    logger::write("Success updated bpf map for IMDS redirect policy.".to_string());
                }
            }
        } else {
            let result = bpf_object.lock().unwrap().remove_policy_elem_bpf_map(
                constants::IMDS_IP_NETWORK_BYTE_ORDER,
                constants::IMDS_PORT,
            );
            if result != 0 {
                logger::write_error(format!(
                    "Failed to delete bpf map for IMDS redirect policy with result: {result}"
                ));
            } else {
                logger::write("Success deleted bpf map for IMDS redirect policy.".to_string());
            }
        }
    }
}
