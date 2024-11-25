// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

//!
//! This module contains the logic to get the status of the proxy agent.
//! The status includes the status of the key keeper, ebpf program, proxy listener, telemetry logger and proxy connection summaries.
//! The status is written to status.json file in the logs directory.
//!
//! Example
//! ```rust
//! use proxy_agent::proxy_agent_status;
//! use proxy_agent::shared_state::key_keeper_wrapper::KeyKeeperSharedState;
//! use proxy_agent::shared_state::agent_status_wrapper::AgentStatusSharedState;
//! use std::time::Duration;
//! use tokio_util::sync::CancellationToken;
//!
//! let key_keeper_shared_state = KeyKeeperSharedState::start_new();
//! let agent_status_shared_state = AgentStatusSharedState::start_new();
//! let cancellation_token = CancellationToken::new();
//! let interval = Duration::from_secs(60);
//! let proxy_agent_status_task = proxy_agent_status::ProxyAgentStatusTask::new(
//!    interval,
//!    std::path::PathBuf::from("logs_dir"),
//!    cancellation_token,
//!    key_keeper_shared_state,
//!    agent_status_shared_state,
//! );
//! tokio::spawn(proxy_agent_status_task.start());
//! ```

use crate::common::logger;
use crate::key_keeper::UNKNOWN_STATE;
use crate::shared_state::agent_status_wrapper::{AgentStatusModule, AgentStatusSharedState};
use crate::shared_state::key_keeper_wrapper::KeyKeeperSharedState;
use proxy_agent_shared::misc_helpers;
use proxy_agent_shared::proxy_agent_aggregate_status::{
    GuestProxyAgentAggregateStatus, ModuleState, OverallState, ProxyAgentDetailStatus,
    ProxyAgentStatus,
};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

pub struct ProxyAgentStatusTask {
    interval: Duration,
    status_dir: PathBuf,
    cancellation_token: CancellationToken,
    key_keeper_shared_state: KeyKeeperSharedState,
    agent_status_shared_state: AgentStatusSharedState,
}

impl ProxyAgentStatusTask {
    pub fn new(
        interval: Duration,
        status_dir: PathBuf,
        cancellation_token: CancellationToken,
        key_keeper_shared_state: KeyKeeperSharedState,
        agent_status_shared_state: AgentStatusSharedState,
    ) -> ProxyAgentStatusTask {
        ProxyAgentStatusTask {
            interval,
            status_dir,
            cancellation_token,
            key_keeper_shared_state,
            agent_status_shared_state,
        }
    }

    pub async fn start(&self) {
        logger::write("proxy_agent_status task started.".to_string());
        tokio::select! {
            _ = self.loop_status() => {}
            _ = self.cancellation_token.cancelled() => {
                logger::write_warning("cancellation token signal received, stop the guest_proxy_agent_status task.".to_string());
            }
        }
    }

    async fn loop_status(&self) {
        let map_clear_duration = Duration::from_secs(60 * 60 * 24);
        let mut start_time = Instant::now();

        loop {
            let aggregate_status = self.guest_proxy_agent_aggregate_status_new().await;
            self.write_aggregate_status_to_file(aggregate_status);

            let elapsed_time = start_time.elapsed();

            //Clear the connection map and reset start_time after 24 hours
            if elapsed_time >= map_clear_duration {
                logger::write_information(
                    "Clearing the connection summary map and failed authenticate summary map."
                        .to_string(),
                );
                if let Err(e) = self.agent_status_shared_state.clear_all_summary().await {
                    logger::write_error(format!("Error clearing the connection summary map and failed authenticate summary map: {}", e));
                }
                start_time = Instant::now();
            }

            tokio::time::sleep(self.interval).await;
        }
    }

    async fn get_key_keeper_status(&self) -> ProxyAgentDetailStatus {
        let mut key_latch_status = self
            .agent_status_shared_state
            .get_module_status(AgentStatusModule::KeyKeeper)
            .await;
        let mut states = HashMap::new();
        states.insert(
            "secureChannelState".to_string(),
            self.key_keeper_shared_state
                .get_current_secure_channel_state()
                .await
                .unwrap_or(UNKNOWN_STATE.to_string()),
        );
        if let Ok(Some(key_guid)) = self.key_keeper_shared_state.get_current_key_guid().await {
            states.insert("keyGuid".to_string(), key_guid);
        }
        states.insert(
            "wireServerRuleId".to_string(),
            self.key_keeper_shared_state
                .get_wireserver_rule_id()
                .await
                .unwrap_or(UNKNOWN_STATE.to_string()),
        );
        states.insert(
            "imdsRuleId".to_string(),
            self.key_keeper_shared_state
                .get_imds_rule_id()
                .await
                .unwrap_or(UNKNOWN_STATE.to_string()),
        );
        if let Ok(Some(incarnation)) = self
            .key_keeper_shared_state
            .get_current_key_incarnation()
            .await
        {
            states.insert("keyIncarnationId".to_string(), incarnation.to_string());
        }
        key_latch_status.states = Some(states);

        key_latch_status
    }

    async fn proxy_agent_status_new(&self) -> ProxyAgentStatus {
        let key_latch_status = self.get_key_keeper_status().await;
        let ebpf_status = self
            .agent_status_shared_state
            .get_module_status(AgentStatusModule::Redirector)
            .await;
        let proxy_status = self
            .agent_status_shared_state
            .get_module_status(AgentStatusModule::ProxyServer)
            .await;
        let status = if key_latch_status.status != ModuleState::RUNNING
            || ebpf_status.status != ModuleState::RUNNING
            || proxy_status.status != ModuleState::RUNNING
        {
            OverallState::ERROR
        } else {
            OverallState::SUCCESS
        };

        ProxyAgentStatus {
            version: misc_helpers::get_current_version(),
            status,
            // monitorStatus is proxy_agent_status itself status
            monitorStatus: ProxyAgentDetailStatus {
                status: ModuleState::RUNNING,
                message: "proxy_agent_status thread started.".to_string(),
                states: None,
            },
            keyLatchStatus: key_latch_status,
            ebpfProgramStatus: ebpf_status,
            proxyListenerStatus: proxy_status,
            telemetryLoggerStatus: self
                .agent_status_shared_state
                .get_module_status(AgentStatusModule::TelemetryLogger)
                .await,
            proxyConnectionsCount: match self.agent_status_shared_state.get_connection_count().await
            {
                Ok(count) => count,
                Err(e) => {
                    logger::write_error(format!("Error getting connection count: {}", e));
                    0
                }
            },
        }
    }

    async fn guest_proxy_agent_aggregate_status_new(&self) -> GuestProxyAgentAggregateStatus {
        GuestProxyAgentAggregateStatus {
            timestamp: misc_helpers::get_date_time_string_with_milliseconds(),
            proxyAgentStatus: self.proxy_agent_status_new().await,
            proxyConnectionSummary: match self
                .agent_status_shared_state
                .get_all_connection_summary()
                .await
            {
                Ok(summary) => summary,
                Err(e) => {
                    logger::write_error(format!("Error getting connection summary: {}", e));
                    vec![]
                }
            },
            failedAuthenticateSummary: match self
                .agent_status_shared_state
                .get_all_failed_connection_summary()
                .await
            {
                Ok(summary) => summary,
                Err(e) => {
                    logger::write_error(format!("Error getting failed connection summary: {}", e));
                    vec![]
                }
            },
        }
    }

    fn write_aggregate_status_to_file(&self, status: GuestProxyAgentAggregateStatus) {
        let full_file_path = self.status_dir.join("status.json");
        if let Err(e) = misc_helpers::json_write_to_file(&status, &full_file_path) {
            logger::write_error(format!(
                "Error writing aggregate status to status file: {}",
                e
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        proxy_agent_status::ProxyAgentStatusTask,
        shared_state::{
            agent_status_wrapper::AgentStatusSharedState, key_keeper_wrapper::KeyKeeperSharedState,
        },
    };
    use proxy_agent_shared::{
        misc_helpers, proxy_agent_aggregate_status::GuestProxyAgentAggregateStatus,
    };
    use std::time::Duration;
    use std::{env, fs};
    use tokio_util::sync::CancellationToken;

    #[tokio::test]
    async fn write_aggregate_status_test() {
        let mut temp_test_path = env::temp_dir();
        temp_test_path.push("write_aggregate_status_test");
        _ = fs::remove_dir_all(&temp_test_path);
        misc_helpers::try_create_folder(&temp_test_path).unwrap();
        let task = ProxyAgentStatusTask::new(
            Duration::from_secs(1),
            temp_test_path.clone(),
            CancellationToken::new(),
            KeyKeeperSharedState::start_new(),
            AgentStatusSharedState::start_new(),
        );
        let aggregate_status = task.guest_proxy_agent_aggregate_status_new().await;
        task.write_aggregate_status_to_file(aggregate_status);

        let file_path = temp_test_path.join("status.json");
        assert!(file_path.exists(), "File does not exist in the directory");

        let file_content =
            misc_helpers::json_read_from_file::<GuestProxyAgentAggregateStatus>(&file_path);
        assert!(file_content.is_ok(), "Failed to read file content");

        //Check if field were written
        let gpa_aggregate_status = file_content.unwrap();
        assert!(
            !gpa_aggregate_status.timestamp.is_empty(),
            "Failed to get Timestamp field"
        );
        assert!(
            !gpa_aggregate_status.proxyAgentStatus.version.is_empty(),
            "Failed to get proxy_agent_status field"
        );
        assert!(
            gpa_aggregate_status.proxyConnectionSummary.is_empty()
                || !gpa_aggregate_status.proxyConnectionSummary.is_empty(),
            "proxyConnectionSummary does not exist"
        );
    }
}
