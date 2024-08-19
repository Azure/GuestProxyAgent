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
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

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
    pub destination_ipv4: u32, // in network byte order
    pub destination_port: u16, // in network byte order
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

    pub fn destination_port_in_host_byte_order(&self) -> u16 {
        u16::from_be(self.destination_port)
    }

    pub fn destination_ipv4_addr(&self) -> Ipv4Addr {
        Ipv4Addr::from_bits(self.destination_ipv4.to_be())
    }
}

const MAX_STATUS_MESSAGE_LENGTH: usize = 1024;

pub async fn start(local_port: u16, shared_state: Arc<Mutex<SharedState>>) -> bool {
    let started = start_impl(local_port, shared_state.clone()).await;

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

async fn start_impl(local_port: u16, shared_state: Arc<Mutex<SharedState>>) -> bool {
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
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
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
pub fn get_audit_from_stream_socket(raw_socket_id: usize) -> std::io::Result<AuditEntry> {
    windows::get_audit_from_redirect_context(raw_socket_id)
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
