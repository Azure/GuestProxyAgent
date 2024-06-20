// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use crate::common::{config, logger};
use crate::monitor;
use crate::proxy::proxy_listener;
use crate::proxy::proxy_summary::ProxySummary;
use crate::shared_state::{proxy_listener_wrapper, SharedState};
use crate::{key_keeper, redirector};
use once_cell::sync::Lazy;
use proxy_agent_shared::misc_helpers;
use proxy_agent_shared::proxy_agent_aggregate_status::{
    GuestProxyAgentAggregateStatus, ModuleState, OveralState, ProxyAgentStatus,
    ProxyConnectionSummary,
};
use proxy_agent_shared::telemetry::event_logger;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

static SHUT_DOWN: Lazy<Arc<AtomicBool>> = Lazy::new(|| Arc::new(AtomicBool::new(false)));
static mut SUMMARY_MAP: Lazy<Mutex<HashMap<String, ProxyConnectionSummary>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
static mut FAILED_AUTHENTICATE_SUMMARY_MAP: Lazy<Mutex<HashMap<String, ProxyConnectionSummary>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

pub fn start_async(interval: Duration, shared_state: Arc<Mutex<SharedState>>) {
    _ = thread::Builder::new()
        .name("guest_proxy_agent_status".to_string())
        .spawn(move || {
            start(interval, shared_state);
        });
}

fn start(mut interval: Duration, shared_state: Arc<Mutex<SharedState>>) {
    let shutdown = SHUT_DOWN.clone();
    if interval == Duration::default() {
        interval = Duration::from_secs(60); // update status every 1 minute
    }

    logger::write("proxy_agent_status thread started.".to_string());

    let map_clear_duration = Duration::from_secs(60 * 60 * 24);
    let mut start_time = Instant::now();
    let dir_path = config::get_logs_dir();

    loop {
        if shutdown.load(Ordering::Relaxed) {
            logger::write_warning(
                "Stop signal received, exiting the guest_proxy_agent_status thread.".to_string(),
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
            unsafe {
                let mut summary_map_guard = SUMMARY_MAP.lock().unwrap();
                summary_map_guard.clear();
                let mut summary_map_guard = FAILED_AUTHENTICATE_SUMMARY_MAP.lock().unwrap();
                summary_map_guard.clear();
                start_time = Instant::now();
            }
        }

        thread::sleep(interval);
    }
}

pub fn proxy_agent_status_new(shared_state: Arc<Mutex<SharedState>>) -> ProxyAgentStatus {
    let key_latch_status = key_keeper::get_status(shared_state.clone());
    let ebpf_status = redirector::get_status();
    let proxy_status = proxy_listener::get_status(shared_state.clone());
    let mut status = OveralState::SUCCESS.to_string();
    if key_latch_status.status != ModuleState::RUNNING
        || ebpf_status.status != ModuleState::RUNNING
        || proxy_status.status != ModuleState::RUNNING
    {
        status = OveralState::ERROR.to_string();
    }
    ProxyAgentStatus {
        version: misc_helpers::get_current_version(),
        status,
        monitorStatus: monitor::get_status(),
        keyLatchStatus: key_latch_status,
        ebpfProgramStatus: ebpf_status,
        proxyListenerStatus: proxy_status,
        telemetryLoggerStatus: event_logger::get_status(),
        proxyConnectionsCount: proxy_listener_wrapper::get_connection_count(shared_state),
    }
}

pub fn proxy_connection_summary_new(summary: ProxySummary) -> ProxyConnectionSummary {
    ProxyConnectionSummary {
        userName: summary.userName.to_string(),
        userGroups: summary.userGroups.clone(),
        ip: summary.ip.to_string(),
        port: summary.port,
        processFullPath: summary.processFullPath.to_string(),
        processCmdLine: summary.processCmdLine.to_string(),
        responseStatus: summary.responseStatus.to_string(),
        count: 1,
    }
}
pub fn increase_count(connection_summary: &mut ProxyConnectionSummary) {
    connection_summary.count += 1;
}

pub fn guest_proxy_agent_aggregate_status_new(
    shared_state: Arc<Mutex<SharedState>>,
) -> GuestProxyAgentAggregateStatus {
    GuestProxyAgentAggregateStatus {
        timestamp: misc_helpers::get_date_time_string_with_miliseconds(),
        proxyAgentStatus: proxy_agent_status_new(shared_state.clone()),
        proxyConnectionSummary: get_all_connection_summary(false),
        failedAuthenticateSummary: get_all_connection_summary(true),
    }
}

pub fn add_connection_summary(summary: ProxySummary, is_failed_authenticate: bool) {
    let mut summary_map = if is_failed_authenticate {
        unsafe { FAILED_AUTHENTICATE_SUMMARY_MAP.lock().unwrap() }
    } else {
        unsafe { SUMMARY_MAP.lock().unwrap() }
    };

    let summary_key = summary.to_key_string();
    if let std::collections::hash_map::Entry::Vacant(e) = summary_map.entry(summary_key.clone()) {
        e.insert(proxy_connection_summary_new(summary));
    } else if let Some(connection_summary) = summary_map.get_mut(&summary_key) {
        increase_count(connection_summary);
    }
}

fn get_all_connection_summary(is_failed_authenticate: bool) -> Vec<ProxyConnectionSummary> {
    let summary_map_lock = if is_failed_authenticate {
        unsafe { FAILED_AUTHENTICATE_SUMMARY_MAP.lock().unwrap() }
    } else {
        unsafe { SUMMARY_MAP.lock().unwrap() }
    };
    let mut copy_summary: Vec<ProxyConnectionSummary> = Vec::new();
    for (_, connection_summary) in summary_map_lock.iter() {
        copy_summary.push(connection_summary.clone());
    }
    copy_summary
}

pub fn write_aggregate_status_to_file(
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
    use crate::proxy_agent_status::{
        guest_proxy_agent_aggregate_status_new, write_aggregate_status_to_file,
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
        let shared_state = crate::shared_state::new_shared_state();
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
