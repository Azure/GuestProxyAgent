// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

mod bpf_api;
mod bpf_obj;
mod bpf_prog;

use crate::common::{self, config, constants, helpers, logger};
use crate::key_keeper;
use crate::provision;
use crate::redirector::AuditEntry;
use crate::shared_state::{key_keeper_wrapper, redirector_wrapper, SharedState};
use core::ffi::c_void;
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

pub fn initialized_success(shared_state: Arc<Mutex<SharedState>>) -> bool {
    if !bpf_api::ebpf_api_is_loaded() {
        redirector_wrapper::set_status_message(
            shared_state.clone(),
            "Failed to load eBPF API.".to_string(),
        );
        return false;
    }
    true
}

pub fn start_internal(local_port: u16, shared_state: Arc<Mutex<SharedState>>) -> bool {
    let result = bpf_prog::load_bpf_object(super::get_ebpf_file_path(), shared_state.clone());
    if result != 0 {
        set_error_status(
            format!("Failed to load bpf object with result: {result}"),
            shared_state.clone(),
        );
        return false;
    } else {
        logger::write("Success loaded bpf object.".to_string());
    }

    let result = bpf_prog::attach_bpf_prog(shared_state.clone());
    if result != 0 {
        set_error_status(
            format!("Failed to attach bpf prog with result: {result}"),
            shared_state.clone(),
        );
        return false;
    } else {
        logger::write("Success attached bpf prog.".to_string());
    }

    let pid = std::process::id();
    let result = bpf_prog::update_bpf_skip_process_map(pid, shared_state.clone());
    if result != 0 {
        set_error_status(
            format!("Failed to update bpf skip_process map with result: {result}"),
            shared_state.clone(),
        );
        return false;
    } else {
        logger::write(format!(
            "Success updated bpf skip_process map with pid={pid}."
        ));
    }

    if (key_keeper_wrapper::get_current_secure_channel_state(shared_state.clone())
        != key_keeper::DISABLE_STATE)
        || (config::get_wire_server_support() > 0)
    {
        let result = bpf_prog::update_policy_elem_bpf_map(
            local_port,
            constants::WIRE_SERVER_IP_NETWORK_BYTE_ORDER, //0x10813FA8 - 168.63.129.16
            constants::WIRE_SERVER_PORT,
            shared_state.clone(),
        );
        if result != 0 {
            set_error_status(
                format!("Failed to update bpf map for WireServer support with result: {result}"),
                shared_state.clone(),
            );
            return false;
        } else {
            logger::write("Success updated bpf map for WireServer support.".to_string());
        }
    }
    if config::get_host_gaplugin_support() > 0 {
        let result = bpf_prog::update_policy_elem_bpf_map(
            local_port,
            constants::GA_PLUGIN_IP_NETWORK_BYTE_ORDER, //0x10813FA8, // 168.63.129.16
            constants::GA_PLUGIN_PORT,
            shared_state.clone(),
        );
        if result != 0 {
            set_error_status(
                format!("Failed to update bpf map for Host GAPlugin support with result: {result}"),
                shared_state.clone(),
            );
            return false;
        } else {
            logger::write("Success updated bpf map for Host GAPlugin support.".to_string());
        }
    }
    if (key_keeper_wrapper::get_current_secure_channel_state(shared_state.clone())
        == key_keeper::MUST_SIG_WIRESERVER_IMDS)
        || (config::get_imds_support() > 0)
    {
        let result = bpf_prog::update_policy_elem_bpf_map(
            local_port,
            constants::IMDS_IP_NETWORK_BYTE_ORDER, //0xFEA9FEA9, // 169.254.169.254
            constants::IMDS_PORT,
            shared_state.clone(),
        );
        if result != 0 {
            set_error_status(
                format!("Failed to update bpf map for IMDS support with result: {result}"),
                shared_state.clone(),
            );
            return false;
        } else {
            logger::write("Success updated bpf map for IMDS support.".to_string());
        }
    }

    redirector_wrapper::set_is_started(shared_state.clone(), true);
    redirector_wrapper::set_local_port(shared_state.clone(), local_port);

    let message = helpers::write_startup_event(
        "Started Redirector with eBPF maps",
        "start",
        "redirector",
        logger::AGENT_LOGGER_KEY,
    );
    redirector_wrapper::set_status_message(shared_state.clone(), message.clone());
    provision::redirector_ready(shared_state.clone());

    true
}

fn set_error_status(message: String, shared_state: Arc<Mutex<SharedState>>) {
    redirector_wrapper::set_status_message(shared_state.clone(), message.clone());
    logger::write_error(message);
}

pub fn get_status(shared_state: Arc<Mutex<SharedState>>) -> String {
    redirector_wrapper::get_status_message(shared_state.clone())
}

pub fn close(shared_state: Arc<Mutex<SharedState>>) {
    bpf_prog::close_bpf_object(shared_state.clone());
    logger::write("Success closed bpf object.".to_string());
    redirector_wrapper::set_is_started(shared_state.clone(), false);
}

pub fn is_started(shared_state: Arc<Mutex<SharedState>>) -> bool {
    redirector_wrapper::get_is_started(shared_state.clone())
}

pub fn lookup_audit(
    source_port: u16,
    shared_state: Arc<Mutex<SharedState>>,
) -> std::io::Result<AuditEntry> {
    bpf_prog::lookup_bpf_audit_map(source_port, shared_state)
}

pub fn get_audit_from_redirect_context(raw_socket: usize) -> std::io::Result<AuditEntry> {
    unsafe {
        // WSAIoctl - SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT
        let value = AuditEntry::empty();
        let redirect_context_size = mem::size_of::<AuditEntry>() as u32;
        let mut redirect_context_returned: u32 = 0;
        WinSock::WSAIoctl(
            raw_socket,
            WinSock::SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT,
            ptr::null(),
            0,
            &value as *const AuditEntry as *mut c_void,
            redirect_context_size,
            &mut redirect_context_returned,
            ptr::null_mut(),
            None,
        );
        common::windows::check_winsock_last_error(
            "WinSock::WSAIoctl - SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT",
        )?;

        Ok(value)
    }
}

pub fn update_wire_server_redirect_policy(redirect: bool, shared_state: Arc<Mutex<SharedState>>) {
    if redirect {
        let local_port = redirector_wrapper::get_local_port(shared_state.clone());
        let result = bpf_prog::update_policy_elem_bpf_map(
            local_port,
            constants::WIRE_SERVER_IP_NETWORK_BYTE_ORDER,
            constants::WIRE_SERVER_PORT,
            shared_state.clone(),
        );
        if result != 0 {
            set_error_status(
                format!(
                    "Failed to update bpf map for wireserver redirect policy with result: {result}"
                ),
                shared_state.clone(),
            );
        } else {
            logger::write("Success updated bpf map for wireserver redirect policy.".to_string());
        }
    } else {
        let result = bpf_prog::remove_policy_elem_bpf_map(
            constants::WIRE_SERVER_IP_NETWORK_BYTE_ORDER,
            constants::WIRE_SERVER_PORT,
            shared_state.clone(),
        );
        if result != 0 {
            set_error_status(
                format!(
                    "Failed to delete bpf map for wireserver redirect policy with result: {result}"
                ),
                shared_state.clone(),
            );
        } else {
            logger::write("Success deleted bpf map for wireserver redirect policy.".to_string());
        }
    }
}

pub fn update_imds_redirect_policy(redirect: bool, shared_state: Arc<Mutex<SharedState>>) {
    if redirect {
        let local_port = redirector_wrapper::get_local_port(shared_state.clone());
        let result = bpf_prog::update_policy_elem_bpf_map(
            local_port,
            constants::IMDS_IP_NETWORK_BYTE_ORDER,
            constants::IMDS_PORT,
            shared_state.clone(),
        );
        if result != 0 {
            set_error_status(
                format!("Failed to update bpf map for IMDS redirect policy with result: {result}"),
                shared_state.clone(),
            );
        } else {
            logger::write("Success updated bpf map for IMDS redirect policy.".to_string());
        }
    } else {
        let result = bpf_prog::remove_policy_elem_bpf_map(
            constants::IMDS_IP_NETWORK_BYTE_ORDER,
            constants::IMDS_PORT,
            shared_state.clone(),
        );
        if result != 0 {
            set_error_status(
                format!("Failed to delete bpf map for IMDS redirect policy with result: {result}"),
                shared_state.clone(),
            );
        } else {
            logger::write("Success deleted bpf map for IMDS redirect policy.".to_string());
        }
    }
}
