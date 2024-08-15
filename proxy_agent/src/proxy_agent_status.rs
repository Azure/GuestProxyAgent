// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use crate::common::{config, logger};
use crate::monitor;
use crate::proxy::proxy_server;
use crate::shared_state::{
    agent_status_wrapper, proxy_listener_wrapper, telemetry_wrapper, SharedState,
};
use crate::{key_keeper, redirector};
use proxy_agent_shared::misc_helpers;
use proxy_agent_shared::proxy_agent_aggregate_status::{
    GuestProxyAgentAggregateStatus, ModuleState, OverallState, ProxyAgentDetailStatus,
    ProxyAgentStatus,
};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub async fn start(mut interval: Duration, shared_state: Arc<Mutex<SharedState>>) {
    if interval == Duration::default() {
        interval = Duration::from_secs(60); // update status every 1 minute
    }

    logger::write("proxy_agent_status task started.".to_string());

    let map_clear_duration = Duration::from_secs(60 * 60 * 24);
    let mut start_time = Instant::now();
    let dir_path = config::get_logs_dir();

    loop {
        if proxy_listener_wrapper::get_shutdown(shared_state.clone()) {
            logger::write_warning(
                "Stop signal received, exiting the guest_proxy_agent_status task.".to_string(),
            );
            break;
        }

        let aggregate_status = guest_proxy_agent_aggregate_status_new(shared_state.clone());

        if let Err(e) = write_aggregate_status_to_file(dir_path.clone(), aggregate_status) {
            logger::write_error(format!("Error writing aggregate status to file: {}", e));
        }

        let elapsed_time = start_time.elapsed();

        //Clear the connection map and reset start_time after 24 hours
        if elapsed_time >= map_clear_duration {
            logger::write_information(
                "Clearing the connection summary map and failed authenticate summary map."
                    .to_string(),
            );
            agent_status_wrapper::clear_all_summary(shared_state.clone());
            start_time = Instant::now();
        }

        tokio::time::sleep(interval).await;
    }
}

fn get_telemetry_log_status(shared_state: Arc<Mutex<SharedState>>) -> ProxyAgentDetailStatus {
    let status = if telemetry_wrapper::get_logger_shutdown(shared_state.clone()) {
        ModuleState::STOPPED.to_string()
    } else {
        ModuleState::RUNNING.to_string()
    };

    ProxyAgentDetailStatus {
        status,
        message: telemetry_wrapper::get_logger_status_message(shared_state),
        states: None,
    }
}

fn proxy_agent_status_new(shared_state: Arc<Mutex<SharedState>>) -> ProxyAgentStatus {
    let key_latch_status = key_keeper::get_status(shared_state.clone());
    let ebpf_status = redirector::get_status(shared_state.clone());
    let proxy_status = proxy_server::get_status(shared_state.clone());
    let mut status = OverallState::SUCCESS.to_string();
    if key_latch_status.status != ModuleState::RUNNING
        || ebpf_status.status != ModuleState::RUNNING
        || proxy_status.status != ModuleState::RUNNING
    {
        status = OverallState::ERROR.to_string();
    }

    ProxyAgentStatus {
        version: misc_helpers::get_current_version(),
        status,
        monitorStatus: monitor::get_status(shared_state.clone()),
        keyLatchStatus: key_latch_status,
        ebpfProgramStatus: ebpf_status,
        proxyListenerStatus: proxy_status,
        telemetryLoggerStatus: get_telemetry_log_status(shared_state.clone()),
        proxyConnectionsCount: proxy_listener_wrapper::get_connection_count(shared_state),
    }
}

fn guest_proxy_agent_aggregate_status_new(
    shared_state: Arc<Mutex<SharedState>>,
) -> GuestProxyAgentAggregateStatus {
    GuestProxyAgentAggregateStatus {
        timestamp: misc_helpers::get_date_time_string_with_milliseconds(),
        proxyAgentStatus: proxy_agent_status_new(shared_state.clone()),
        proxyConnectionSummary: agent_status_wrapper::get_all_connection_summary(
            shared_state.clone(),
            false,
        ),
        failedAuthenticateSummary: agent_status_wrapper::get_all_connection_summary(
            shared_state.clone(),
            true,
        ),
    }
}

fn write_aggregate_status_to_file(
    dir_path: PathBuf,
    status: GuestProxyAgentAggregateStatus,
) -> std::io::Result<()> {
    let full_file_path = dir_path.clone();
    let full_file_path = full_file_path.join("status.json");

    if let Err(e) = misc_helpers::json_write_to_file(&status, full_file_path.clone()) {
        logger::write_error(format!("Error writing status to status file: {}", e));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{
        proxy_agent_status::{
            guest_proxy_agent_aggregate_status_new, write_aggregate_status_to_file,
        },
        shared_state::SharedState,
    };
    use proxy_agent_shared::{
        misc_helpers, proxy_agent_aggregate_status::GuestProxyAgentAggregateStatus,
    };
    use std::{env, fs};

    #[test]
    fn write_aggregate_status_test() {
        let mut temp_test_path = env::temp_dir();
        temp_test_path.push("write_aggregate_status_test");
        _ = fs::remove_dir_all(&temp_test_path);
        misc_helpers::try_create_folder(temp_test_path.clone()).unwrap();
        let shared_state = SharedState::new();
        let aggregate_status = guest_proxy_agent_aggregate_status_new(shared_state.clone());

        _ = write_aggregate_status_to_file(temp_test_path.clone(), aggregate_status);

        let file_path = temp_test_path.join("status.json");
        assert!(file_path.exists(), "File does not exist in the directory");

        let file_content = misc_helpers::json_read_from_file::<GuestProxyAgentAggregateStatus>(
            file_path.clone().to_path_buf(),
        );
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
