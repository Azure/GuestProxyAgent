// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#![cfg(windows)]

mod bpf_api;
mod bpf_obj;
mod bpf_prog;

use crate::common::{self, config, constants, helpers, logger};
use crate::key_keeper;
use crate::provision;
use crate::redirector::AuditEntry;
use core::ffi::c_void;
use once_cell::unsync::Lazy;
use proxy_agent_shared::misc_helpers;
use std::mem;
use std::net::TcpStream;
use std::os::windows::io::AsRawSocket;
use std::ptr;
use windows_sys::Win32::Networking::WinSock;

static mut IS_STARTED: bool = false;
static mut STATUS_MESSAGE: Lazy<String> =
    Lazy::new(|| String::from("Redirector has not started yet."));

pub fn start(local_port: u16) -> bool {
    match bpf_prog::init() {
        Ok(_) => (),
        Err(e) => {
            set_error_status(format!("Failed to init bpf_prog with error: {e}"));
            return false;
        }
    }

    // when running as NT service, the working directory is not the current exe dir.,
    // so, we must give the 'redirect.bpf.o' full file path.
    let mut bpf_file_path = misc_helpers::get_current_exe_dir();
    bpf_file_path.push(config::get_ebpf_program_name());

    let result = bpf_prog::load_bpf_object(bpf_file_path);
    if result != 0 {
        set_error_status(format!("Failed to load bpf object with result: {result}"));
        return false;
    } else {
        logger::write("Success loaded bpf object.".to_string());
    }

    let result = bpf_prog::attach_bpf_prog();
    if result != 0 {
        set_error_status(format!("Failed to attach bpf prog with result: {result}"));
        return false;
    } else {
        logger::write("Success attached bpf prog.".to_string());
    }

    let pid = std::process::id();
    let result = bpf_prog::update_bpf_skip_process_map(pid);
    if result != 0 {
        set_error_status(format!(
            "Failed to update bpf skip_process map with result: {result}"
        ));
        return false;
    } else {
        logger::write(format!(
            "Success updated bpf skip_process map with pid={pid}."
        ));
    }

    if (key_keeper::get_secure_channel_state() != key_keeper::DISABLE_STATE)
        || (config::get_wire_server_support() > 0)
    {
        let result = bpf_prog::update_bpf_map(
            local_port,
            constants::WIRE_SERVER_IP_NETWORK_BYTE_ORDER, //0x10813FA8 - 168.63.129.16
            constants::WIRE_SERVER_PORT,
        );
        if result != 0 {
            set_error_status(format!(
                "Failed to update bpf map for WireServer support with result: {result}"
            ));
            return false;
        } else {
            logger::write("Success updated bpf map for WireServer support.".to_string());
        }
    }
    if config::get_host_gaplugin_support() > 0 {
        let result = bpf_prog::update_bpf_map(
            local_port,
            constants::GA_PLUGIN_IP_NETWORK_BYTE_ORDER, //0x10813FA8, // 168.63.129.16
            constants::GA_PLUGIN_PORT,
        );
        if result != 0 {
            set_error_status(format!(
                "Failed to update bpf map for Host GAPlugin support with result: {result}"
            ));
            return false;
        } else {
            logger::write("Success updated bpf map for Host GAPlugin support.".to_string());
        }
    }
    if (key_keeper::get_secure_channel_state() == key_keeper::MUST_SIG_WIRESERVER_IMDS)
        || (config::get_imds_support() > 0)
    {
        let result = bpf_prog::update_bpf_map(
            local_port,
            constants::IMDS_IP_NETWORK_BYTE_ORDER, //0xFEA9FEA9, // 169.254.169.254
            constants::IMDS_PORT,
        );
        if result != 0 {
            set_error_status(format!(
                "Failed to update bpf map for IMDS support with result: {result}"
            ));
            return false;
        } else {
            logger::write("Success updated bpf map for IMDS support.".to_string());
        }
    }

    unsafe {
        IS_STARTED = true;
    }

    let message = helpers::write_startup_event(
        "Started Redirector with eBPF maps",
        "start",
        "redirector",
        logger::AGENT_LOGGER_KEY,
    );
    unsafe {
        *STATUS_MESSAGE = message.to_string();
    }
    provision::redirector_ready();

    return true;
}

fn set_error_status(message: String) {
    unsafe {
        *STATUS_MESSAGE = message.to_string();
        logger::write_error(message);
    }
}

pub fn get_status() -> String {
    unsafe { STATUS_MESSAGE.to_string() }
}

pub fn close(_local_port: u16) {
    unsafe {
        bpf_prog::close_bpf_object();
        logger::write("Success closed bpf object.".to_string());
        IS_STARTED = false;
    }
}

pub fn is_started() -> bool {
    unsafe { IS_STARTED }
}

pub fn lookup_audit(source_port: u16) -> std::io::Result<AuditEntry> {
    bpf_prog::lookup_bpf_audit_map(source_port)
}

pub fn get_audit_from_redirect_context(tcp_stream: &TcpStream) -> std::io::Result<AuditEntry> {
    unsafe {
        // WSAIoctl - SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT
        let value = AuditEntry::empty();
        let redirect_context_size = mem::size_of::<AuditEntry>() as u32;
        let mut redirect_context_returned: u32 = 0;
        WinSock::WSAIoctl(
            tcp_stream.as_raw_socket() as usize,
            WinSock::SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT,
            ptr::null(),
            0,
            &value as *const AuditEntry as *mut c_void,
            redirect_context_size,
            &mut redirect_context_returned,
            ptr::null_mut(),
            Option::None,
        );
        common::windows::check_winsock_last_error(
            "WinSock::WSAIoctl - SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT",
        )?;

        Ok(value)
    }
}
