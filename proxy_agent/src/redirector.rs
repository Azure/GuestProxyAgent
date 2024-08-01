// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#[cfg(windows)]
mod windows;

#[cfg(not(windows))]
mod linux;

use crate::common::{config, logger};
use crate::shared_state::SharedState;
use proxy_agent_shared::misc_helpers;
use proxy_agent_shared::proxy_agent_aggregate_status::{ModuleState, ProxyAgentDetailStatus};
use proxy_agent_shared::telemetry::event_logger;
use serde_derive::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;

#[cfg(not(windows))]
pub use linux::BpfObject;
#[cfg(windows)]
pub use windows::BpfObject;

#[derive(Serialize, Deserialize)]
#[repr(C)]
pub struct AuditEntry {
    pub logon_id: u64,
    pub process_id: u32,
    pub is_admin: i32,
    pub destination_ipv4: u32,
    pub destination_port: u16,
}

impl AuditEntry {
    pub fn empty() -> Self {
        AuditEntry {
            logon_id: 0,
            process_id: 0,
            is_admin: 0,
            destination_ipv4: 0,
            destination_port: 0,
        }
    }
}

const MAX_STATUS_MESSAGE_LENGTH: usize = 1024;

pub fn start_async(local_port: u16, shared_state: Arc<Mutex<SharedState>>) {
    thread::spawn(move || {
        start(local_port, shared_state);
    });
}

fn start(local_port: u16, shared_state: Arc<Mutex<SharedState>>) -> bool {
    let started = start_impl(local_port, shared_state.clone());

    let level = if started {
        event_logger::INFO_LEVEL
    } else {
        event_logger::ERROR_LEVEL
    };
    event_logger::write_event(
        level,
        get_status_message(shared_state.clone()),
        "start",
        "redirector",
        logger::AGENT_LOGGER_KEY,
    );

    started
}

fn start_impl(local_port: u16, shared_state: Arc<Mutex<SharedState>>) -> bool {
    #[cfg(windows)]
    {
        if !windows::initialized_success(shared_state.clone()) {
            return false;
        }
    }
    for _ in 0..5 {
        start_internal(local_port, shared_state.clone());
        if is_started(shared_state.clone()) {
            return true;
        }
        thread::sleep(std::time::Duration::from_millis(10));
    }

    is_started(shared_state.clone())
}

pub fn close(shared_state: Arc<Mutex<SharedState>>) {
    #[cfg(windows)]
    {
        windows::close(shared_state);
    }
    #[cfg(not(windows))]
    {
        linux::close(shared_state);
    }
}

fn get_status_message(shared_state: Arc<Mutex<SharedState>>) -> String {
    #[cfg(windows)]
    {
        windows::get_status(shared_state)
    }
    #[cfg(not(windows))]
    {
        linux::get_status(shared_state)
    }
}

pub fn get_status(shared_state: Arc<Mutex<SharedState>>) -> ProxyAgentDetailStatus {
    let mut message = get_status_message(shared_state.clone());
    if message.len() > MAX_STATUS_MESSAGE_LENGTH {
        event_logger::write_event(
            event_logger::WARN_LEVEL,
            format!(
                "Status message is too long, truncating to {} characters. Message: {}",
                MAX_STATUS_MESSAGE_LENGTH, message
            ),
            "get_status",
            "redirector",
            logger::AGENT_LOGGER_KEY,
        );

        message = format!("{}...", &message[0..MAX_STATUS_MESSAGE_LENGTH]);
    }

    let status = if is_started(shared_state.clone()) {
        ModuleState::RUNNING.to_string()
    } else {
        ModuleState::STOPPED.to_string()
    };

    ProxyAgentDetailStatus {
        status,
        message,
        states: None,
    }
}

pub fn is_started(shared_state: Arc<Mutex<SharedState>>) -> bool {
    #[cfg(windows)]
    {
        windows::is_started(shared_state)
    }
    #[cfg(not(windows))]
    {
        linux::is_started(shared_state)
    }
}

pub fn lookup_audit(
    source_port: u16,
    shared_state: Arc<Mutex<SharedState>>,
) -> std::io::Result<AuditEntry> {
    #[cfg(windows)]
    {
        windows::lookup_audit(source_port, shared_state)
    }
    #[cfg(not(windows))]
    {
        linux::lookup_audit(source_port, shared_state)
    }
}

#[cfg(windows)]
pub fn get_audit_from_stream_socket(_raw_socket: usize) -> std::io::Result<AuditEntry> {
    windows::get_audit_from_redirect_context(_raw_socket)
}

pub fn get_audit_from_stream(_tcp_stream: &std::net::TcpStream) -> std::io::Result<AuditEntry> {
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawSocket;
        get_audit_from_stream_socket(_tcp_stream.as_raw_socket() as usize)
    }
    #[cfg(not(windows))]
    {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "get_audit_from_stream_socket for linux is not supported",
        ))
    }
}

pub fn ip_to_string(ip: u32) -> String {
    let mut ip_str = String::new();

    let seg_number = 16 * 16;
    let seg = ip % seg_number;
    ip_str.push_str(seg.to_string().as_str());
    ip_str.push('.');

    let ip = ip / seg_number;
    let seg = ip % seg_number;
    ip_str.push_str(seg.to_string().as_str());
    ip_str.push('.');

    let ip = ip / seg_number;
    let seg = ip % seg_number;
    ip_str.push_str(seg.to_string().as_str());
    ip_str.push('.');

    let ip = ip / seg_number;
    let seg = ip % seg_number;
    ip_str.push_str(seg.to_string().as_str());

    ip_str
}

pub fn string_to_ip(ip_str: &str) -> u32 {
    let ip_str_seg: Vec<&str> = ip_str.split('.').collect();
    if ip_str_seg.len() != 4 {
        logger::write_warning(format!("string_to_ip:: ip_str {} is invalid", ip_str));
        return 0;
    }

    let mut ip: u32 = 0;
    let mut seg: u32 = 1;
    let seg_number = 16 * 16;
    for str in ip_str_seg {
        match str.parse::<u8>() {
            Ok(n) => {
                ip += (n as u32) * seg;
            }
            Err(e) => {
                logger::write_warning(format!(
                    "string_to_ip:: error parsing ip segment {} with error: {}",
                    ip_str, e
                ));
                return 0;
            }
        }
        if seg < 16777216 {
            seg *= seg_number;
        }
    }

    ip
}

pub fn get_ebpf_file_path() -> PathBuf {
    // get ebpf file full path from environment variable
    let mut bpf_file_path = config::get_ebpf_file_full_path().unwrap_or_default();
    let ebpf_file_name = config::get_ebpf_program_name();
    #[cfg(not(windows))]
    {
        if !bpf_file_path.exists() {
            // linux ebpf file default to /usr/lib/azure-proxy-agent folder
            bpf_file_path = PathBuf::from(format!("/usr/lib/azure-proxy-agent/{ebpf_file_name}"));
        }
    }
    if !bpf_file_path.exists() {
        // default to current exe folder
        bpf_file_path = misc_helpers::get_current_exe_dir();
        bpf_file_path.push(ebpf_file_name);
    }
    bpf_file_path
}

#[cfg(not(windows))]
pub use linux::update_imds_redirect_policy;
#[cfg(windows)]
pub use windows::update_imds_redirect_policy;

#[cfg(not(windows))]
pub use linux::update_wire_server_redirect_policy;
#[cfg(windows)]
pub use windows::update_wire_server_redirect_policy;

#[cfg(not(windows))]
use linux::start_internal;
#[cfg(windows)]
use windows::start_internal;

#[cfg(test)]
mod tests {
    #[test]
    fn ip_to_string_test() {
        let ip = 0x10813FA8u32;
        let ip_str = super::ip_to_string(ip);
        assert_eq!("168.63.129.16", ip_str, "ip_str mismatch.");
        let new_ip = super::string_to_ip(&ip_str);
        assert_eq!(ip, new_ip, "ip mismatch.");

        let ip = 0x100007Fu32;
        let ip_str = super::ip_to_string(ip);
        assert_eq!("127.0.0.1", ip_str, "ip_str mismatch.");

        let new_ip = super::string_to_ip("1270.0.0.1");
        assert_eq!(0, new_ip, "ip must be 0 since the 1270.0.0.1 is invalid.");
        let new_ip = super::string_to_ip("1270.0.1");
        assert_eq!(0, new_ip, "ip must be 0 since the 1270.0.1 is invalid.");
    }
}
