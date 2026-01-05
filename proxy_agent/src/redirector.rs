// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

//! This module contains the logic to redirect the http traffic to the GPA service proxy listener via eBPF.
//! The eBPF program is loaded by the GPA service and the eBPF program is used to redirect the traffic to the GPA service proxy listener.
//! GPA service update the eBPF map to allow particular http traffics to be redirected to the GPA service proxy listener.
//! When eBPF redirects the http traffic, it writes the audit information to the eBPF map.
//! The GPA service reads the audit information from the eBPF map and authorizes the requests before forwarding to the remote endpoints.
//!
//! Example
//! ```rust
//! use proxy_agent::redirector;
//! use proxy_agent::shared_state::redirector_wrapper::RedirectorSharedState;
//! use proxy_agent::shared_state::key_keeper_wrapper::KeyKeeperSharedState;
//! use proxy_agent::shared_state::agent_status_wrapper::AgentStatusSharedState;
//!
//!
//! // start the redirector with the shared state
//! let redirector_shared_state = RedirectorSharedState::new();
//! let key_keeper_shared_state = KeyKeeperSharedState::new();
//! let agent_status_shared_state = AgentStatusSharedState::new();
//! let local_port = 8080;
//! let redirector = redirector::Redirector::new(
//!    local_port,
//!    redirector_shared_state.clone(),
//!    key_keeper_shared_state.clone(),
//!    agent_status_shared_state.clone(),
//! );
//! tokio::spawn(redirector.start());
//!
//! // Update the redirect policy for the traffics
//! redirector::update_wire_server_redirect_policy(true, redirector_shared_state.clone());
//! redirector::update_imds_redirect_policy(false, redirector_shared_state.clone());
//!
//! // Get the status of the redirector
//! let status = agent_status_shared_state.get_status(AgentStatusModule::Redirector).await;
//!
//! // Close the redirector to offload the eBPF program
//! redirector::close(redirector_shared_state.clone(), agent_status_shared_state.clone()).await;
//! ```

#[cfg(windows)]
mod windows;

#[cfg(not(windows))]
mod linux;

use crate::common::error::BpfErrorType;
use crate::common::error::Error;
use crate::common::helpers;
use crate::common::result::Result;
use crate::common::{config, logger};
use crate::provision;
use crate::shared_state::access_control_wrapper::AccessControlSharedState;
use crate::shared_state::agent_status_wrapper::{AgentStatusModule, AgentStatusSharedState};
use crate::shared_state::connection_summary_wrapper::ConnectionSummarySharedState;
use crate::shared_state::key_keeper_wrapper::KeyKeeperSharedState;
use crate::shared_state::provision_wrapper::ProvisionSharedState;
use crate::shared_state::redirector_wrapper::RedirectorSharedState;
use crate::shared_state::EventThreadsSharedState;
use crate::shared_state::SharedState;
use proxy_agent_shared::common_state::CommonState;
use proxy_agent_shared::logger::LoggerLevel;
use proxy_agent_shared::misc_helpers;
use proxy_agent_shared::proxy_agent_aggregate_status::ModuleState;
use proxy_agent_shared::telemetry::event_logger;
use serde_derive::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio_util::sync::CancellationToken;

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

pub struct Redirector {
    local_port: u16,
    redirector_shared_state: RedirectorSharedState,
    key_keeper_shared_state: KeyKeeperSharedState,
    agent_status_shared_state: AgentStatusSharedState,
    cancellation_token: CancellationToken,
    common_state: CommonState,
    provision_shared_state: ProvisionSharedState,
    access_control_shared_state: AccessControlSharedState,
    connection_summary_shared_state: ConnectionSummarySharedState,
}

impl Redirector {
    pub fn new(local_port: u16, shared_state: &SharedState) -> Self {
        Redirector {
            local_port,
            cancellation_token: shared_state.get_cancellation_token(),
            key_keeper_shared_state: shared_state.get_key_keeper_shared_state(),
            common_state: shared_state.get_common_state(),
            provision_shared_state: shared_state.get_provision_shared_state(),
            agent_status_shared_state: shared_state.get_agent_status_shared_state(),
            redirector_shared_state: shared_state.get_redirector_shared_state(),
            access_control_shared_state: shared_state.get_access_control_shared_state(),
            connection_summary_shared_state: shared_state.get_connection_summary_shared_state(),
        }
    }

    const MAX_RETRIES: usize = 5;
    const RETRY_INTERVAL_MS: u64 = 10;

    pub async fn start(&self) {
        let message = "eBPF redirector is starting";
        if let Err(e) = self
            .agent_status_shared_state
            .set_module_status_message(message.to_string(), AgentStatusModule::Redirector)
            .await
        {
            logger::write_error(format!(
                "Failed to set error status '{message}' for redirector: {e}"
            ));
        }

        let level = match self.start_impl().await {
            Ok(_) => LoggerLevel::Info,
            Err(_) => LoggerLevel::Error,
        };
        event_logger::write_event(
            level,
            self.get_status_message().await,
            "start",
            "redirector",
            logger::AGENT_LOGGER_KEY,
        );
    }

    async fn start_impl(&self) -> Result<()> {
        for _ in 0..Self::MAX_RETRIES {
            match self.start_internal().await {
                Ok(_) => return Ok(()),
                Err(e) => {
                    self.set_error_status(format!("Failed to start redirector: {e}"))
                        .await;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(Self::RETRY_INTERVAL_MS)).await;
        }

        Err(Error::Bpf(BpfErrorType::FailedToStartRedirector))
    }

    async fn start_internal(&self) -> Result<()> {
        #[cfg(windows)]
        {
            self.initialized()?;
        }

        let mut bpf_object = self.load_bpf_object()?;

        logger::write_information("Success loaded bpf object.".to_string());

        // maps
        let pid = std::process::id();
        bpf_object.update_skip_process_map(pid)?;
        logger::write_information(format!(
            "Success updated bpf skip_process map with pid={pid}."
        ));

        // Do not update redirect policy map here, it will be updated by provision module
        // When provision is finished, it will call update_xxx_redirect_policy functions to update the redirect policy maps.

        // programs
        self.attach_bpf_prog(&mut bpf_object)?;
        logger::write_information("Success attached bpf prog.".to_string());

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

        // report redirector ready for provision
        provision::redirector_ready(EventThreadsSharedState {
            cancellation_token: self.cancellation_token.clone(),
            common_state: self.common_state.clone(),
            access_control_shared_state: self.access_control_shared_state.clone(),
            redirector_shared_state: self.redirector_shared_state.clone(),
            key_keeper_shared_state: self.key_keeper_shared_state.clone(),
            provision_shared_state: self.provision_shared_state.clone(),
            agent_status_shared_state: self.agent_status_shared_state.clone(),
            connection_summary_shared_state: self.connection_summary_shared_state.clone(),
        })
        .await;

        Ok(())
    }

    async fn get_status_message(&self) -> String {
        self.agent_status_shared_state
            .get_module_status(AgentStatusModule::Redirector)
            .await
            .message
    }

    async fn set_error_status(&self, message: String) {
        if let Err(e) = self
            .agent_status_shared_state
            .set_module_status_message(message.to_string(), AgentStatusModule::Redirector)
            .await
        {
            logger::write_error(format!(
                "Failed to set error status '{message}' for redirector: {e}"
            ));
        }
    }
}

#[cfg(windows)]
pub fn get_audit_from_stream_socket(raw_socket_id: usize) -> Result<AuditEntry> {
    windows::get_audit_from_redirect_context(raw_socket_id)
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
        logger::write_warning(format!("string_to_ip:: ip_str {ip_str} is invalid"));
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
                    "string_to_ip:: error parsing ip segment {ip_str} with error: {e}"
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

pub async fn lookup_audit(
    source_port: u16,
    redirector_shared_state: &RedirectorSharedState,
) -> Result<AuditEntry> {
    if let Ok(Some(bpf_object)) = redirector_shared_state.get_bpf_object().await {
        bpf_object.lock().unwrap().lookup_audit(source_port)
    } else {
        Err(Error::Bpf(BpfErrorType::NullBpfObject))
    }
}

pub async fn remove_audit(
    source_port: u16,
    redirector_shared_state: &RedirectorSharedState,
) -> Result<()> {
    if let Ok(Some(bpf_object)) = redirector_shared_state.get_bpf_object().await {
        bpf_object
            .lock()
            .unwrap()
            .remove_audit_map_entry(source_port)
    } else {
        Err(Error::Bpf(BpfErrorType::NullBpfObject))
    }
}

pub async fn close(
    redirector_shared_state: RedirectorSharedState,
    agent_status_shared_state: AgentStatusSharedState,
) {
    let _ = agent_status_shared_state
        .set_module_state(ModuleState::STOPPED, AgentStatusModule::Redirector)
        .await;

    // reset ebpf object
    #[cfg(windows)]
    {
        windows::close_bpf_object(redirector_shared_state.clone()).await;
    }
    let _ = redirector_shared_state.clear_bpf_object().await;
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
pub use linux::update_hostga_redirect_policy;
#[cfg(windows)]
pub use windows::update_hostga_redirect_policy;

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn ip_to_string_test() {
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
