// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

mod bpf_api;
mod bpf_obj;
mod bpf_prog;

use crate::common::error::{BpfErrorType, Error, WindowsApiErrorType};
use crate::common::{constants, logger, result::Result};
use crate::redirector::AuditEntry;
use crate::shared_state::redirector_wrapper::RedirectorSharedState;
use core::ffi::c_void;
use std::mem;
use std::ptr;
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
    pub fn initialized(&self) -> Result<()> {
        // Add retry logic to load the eBPF API
        // This is a workaround for the issue where the eBPF API is not loaded properly
        for _ in 0..Self::MAX_RETRIES {
            if bpf_api::try_load_ebpf_api() {
                return Ok(());
            }
            std::thread::sleep(std::time::Duration::from_millis(Self::RETRY_INTERVAL_MS));
        }

        // If the eBPF API is still not loaded, last retry and return error if it fails
        if !bpf_api::try_load_ebpf_api() {
            return Err(Error::Bpf(BpfErrorType::GetBpfApi));
        }
        Ok(())
    }

    pub fn load_bpf_object(&self) -> Result<BpfObject> {
        let mut bpf_file_path = super::get_ebpf_file_path();

        if let Some(ebpf_api_version) = bpf_api::get_ebpf_api_version() {
            // eBPF program has to work with the same version of eBPF API if windows eBPF had break changes
            // our latest eBPF program may not work with the older version of windows eBPF API
            // in some cases, the windows eBPF may not able, or be allowed to update,
            // so we need to load the eBPF program with the same version of eBPF API
            // the versioned eBPF program is named as <program_name>.<major>.<minor>.<extension>
            let file_ext = bpf_file_path.extension().unwrap_or_default();
            let file_name = bpf_file_path.file_stem().unwrap_or_default();
            let file_name = format!(
                "{}.{}.{}.{}",
                file_name.to_string_lossy(),
                ebpf_api_version.major,
                ebpf_api_version.minor,
                file_ext.to_string_lossy()
            );
            let file_path = bpf_file_path.with_file_name(file_name);
            let file_found: bool;
            if file_path.exists() && file_path.is_file() {
                bpf_file_path = file_path.to_path_buf();
                file_found = true;
            } else {
                file_found = false;
            }

            logger::write(format!(
                "eBPF API version: '{}' found, eBPF program file with api version: '{}'{}found.",
                ebpf_api_version,
                file_path.display(),
                if file_found { " " } else { " not " },
            ));
        }

        let mut bpf_object = BpfObject::new();
        bpf_object.load_bpf_object(&bpf_file_path)?;
        Ok(bpf_object)
    }

    pub fn attach_bpf_prog(&self, bpf_object: &mut BpfObject) -> Result<()> {
        bpf_object.attach_bpf_prog()
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
            "SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT result: {result}, WSAGetLastError: {error}",
        ))));
    }

    // Need to check the returned size to ensure it matches the expected size,
    // since the result is 0 even if there is no redirect context in this socket stream.
    if redirect_context_returned != redirect_context_size {
        return Err(Error::WindowsApi(WindowsApiErrorType::WSAIoctl(format!(
            "SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT returned size: {redirect_context_returned}, expected size: {redirect_context_size}",
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
                if let Err(e) = bpf_object.lock().unwrap().update_policy_elem_bpf_map(
                    "WireServer endpoints",
                    local_port,
                    constants::WIRE_SERVER_IP_NETWORK_BYTE_ORDER,
                    constants::WIRE_SERVER_PORT,
                ) {
                    logger::write_error(format!(
                        "Failed to update bpf map for wireserver redirect policy with result: {e}"
                    ));
                } else {
                    logger::write(
                        "Success updated bpf map for wireserver redirect policy.".to_string(),
                    );
                }
            }
        } else if let Err(e) = bpf_object.lock().unwrap().remove_policy_elem_bpf_map(
            constants::WIRE_SERVER_IP_NETWORK_BYTE_ORDER,
            constants::WIRE_SERVER_PORT,
        ) {
            logger::write_error(format!(
                "Failed to delete bpf map for wireserver redirect policy with result: {e}"
            ));
        } else {
            logger::write("Success deleted bpf map for wireserver redirect policy.".to_string());
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
                if let Err(e) = bpf_object.lock().unwrap().update_policy_elem_bpf_map(
                    "IMDS endpoints",
                    local_port,
                    constants::IMDS_IP_NETWORK_BYTE_ORDER,
                    constants::IMDS_PORT,
                ) {
                    logger::write_error(format!(
                        "Failed to update bpf map for IMDS redirect policy with result: {e}"
                    ));
                } else {
                    logger::write("Success updated bpf map for IMDS redirect policy.".to_string());
                }
            }
        } else if let Err(e) = bpf_object
            .lock()
            .unwrap()
            .remove_policy_elem_bpf_map(constants::IMDS_IP_NETWORK_BYTE_ORDER, constants::IMDS_PORT)
        {
            logger::write_error(format!(
                "Failed to delete bpf map for IMDS redirect policy with result: {e}"
            ));
        } else {
            logger::write("Success deleted bpf map for IMDS redirect policy.".to_string());
        }
    }
}

pub async fn update_hostga_redirect_policy(
    redirect: bool,
    redirector_shared_state: RedirectorSharedState,
) {
    if let Ok(Some(bpf_object)) = redirector_shared_state.get_bpf_object().await {
        if redirect {
            if let Ok(local_port) = redirector_shared_state.get_local_port().await {
                if let Err(e) = bpf_object.lock().unwrap().update_policy_elem_bpf_map(
                    "Host GAPlugin endpoints",
                    local_port,
                    constants::GA_PLUGIN_IP_NETWORK_BYTE_ORDER,
                    constants::GA_PLUGIN_PORT,
                ) {
                    logger::write_error(format!(
                        "Failed to update bpf map for HostGAPlugin redirect policy with result: {e}"
                    ));
                } else {
                    logger::write(
                        "Success updated bpf map for HostGAPlugin redirect policy.".to_string(),
                    );
                }
            }
        } else if let Err(e) = bpf_object.lock().unwrap().remove_policy_elem_bpf_map(
            constants::GA_PLUGIN_IP_NETWORK_BYTE_ORDER,
            constants::GA_PLUGIN_PORT,
        ) {
            logger::write_error(format!(
                "Failed to delete bpf map for HostGAPlugin redirect policy with result: {e}"
            ));
        } else {
            logger::write("Success deleted bpf map for HostGAPlugin redirect policy.".to_string());
        }
    }
}
