// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use crate::common::{config, logger};
use crate::monitor;
use crate::proxy::proxy_listener;
use crate::proxy::proxy_summary::ProxySummary;
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

pub fn start_async(interval: Duration) {
    _ = thread::Builder::new()
        .name("guest_proxy_agent_status".to_string())
        .spawn(move || {
            _ = start(interval);
        });
}

fn start(mut interval: Duration) {
    let shutdown = SHUT_DOWN.clone();
    if interval == Duration::default() {
        interval = Duration::from_secs(60 * 1); // update status every 1 minute
    }

    _ = logger::write("proxy_agent_status thread started.".to_string());

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

        let aggregate_status = guest_proxy_agent_aggregate_status_new();

        if let Err(e) = write_aggregate_status_to_file(dir_path.clone(), aggregate_status) {
            logger::write_error(format!("Error writing aggregate status to file: {}", e));
        }

        let elapsed_time = start_time.elapsed();

        //Clear the connection map and reset start_time after 24 hours
        if elapsed_time >= map_clear_duration {
            unsafe {
                let mut summary_map_guard = SUMMARY_MAP.lock().unwrap();
                summary_map_guard.clear();
                start_time = Instant::now();
            }
        }

        thread::sleep(interval);
    }
}

pub fn proxy_agent_status_new() -> ProxyAgentStatus {
    let keyLatchStatus = key_keeper::get_status();
    let ebpfProgramStatus = redirector::get_status();
    let proxyListenerStatus = proxy_listener::get_status();
    let mut status = OveralState::SUCCESS.to_string();
    if keyLatchStatus.status != ModuleState::RUNNING
        || ebpfProgramStatus.status != ModuleState::RUNNING
        || proxyListenerStatus.status != ModuleState::RUNNING
    {
        status = OveralState::ERROR.to_string();
    }
    ProxyAgentStatus {
        version: misc_helpers::get_current_version(),
        status: status,
        monitorStatus: monitor::get_status(),
        keyLatchStatus: keyLatchStatus,
        ebpfProgramStatus: ebpfProgramStatus,
        proxyListenerStatus: proxyListenerStatus,
        telemetryLoggerStatus: event_logger::get_status(),
        proxyConnectionsCount: proxy_listener::get_proxy_connection_count(),
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

pub fn guest_proxy_agent_aggregate_status_new() -> GuestProxyAgentAggregateStatus {
    GuestProxyAgentAggregateStatus {
        timestamp: misc_helpers::get_date_time_string_with_miliseconds(),
        proxyAgentStatus: proxy_agent_status_new(),
        proxyConnectionSummary: get_all_connection_summary(),
    }
}

pub fn add_connection_summary(summary: ProxySummary) {
    let summary_key = summary.to_key_string();
    let mut summary_map = unsafe { SUMMARY_MAP.lock().unwrap() };
    if !summary_map.contains_key(&summary_key) {
        summary_map.insert(summary_key, proxy_connection_summary_new(summary));
    } else {
        if let Some(connection_summary) = summary_map.get_mut(&summary_key) {
            increase_count(connection_summary);
        }
    }
}

fn get_all_connection_summary() -> Vec<ProxyConnectionSummary> {
    let mut copy_summary: Vec<ProxyConnectionSummary> = Vec::new();
    let summary_map_lock = unsafe { SUMMARY_MAP.lock().unwrap() };
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
    use std::{env, fs};

    use proxy_agent_shared::{
        misc_helpers, proxy_agent_aggregate_status::GuestProxyAgentAggregateStatus,
    };

    use crate::proxy_agent_status::{
        guest_proxy_agent_aggregate_status_new, write_aggregate_status_to_file,
    };

    #[test]
    fn write_aggregate_status_test() {
        let mut temp_test_path = env::temp_dir();
        temp_test_path.push("write_aggregate_status_test");
        _ = fs::remove_dir_all(&temp_test_path);
        misc_helpers::try_create_folder(temp_test_path.clone()).unwrap();

        let aggregate_status = guest_proxy_agent_aggregate_status_new();

        _ = write_aggregate_status_to_file(temp_test_path.clone(), aggregate_status);

        let file_path = temp_test_path.join("status.json".to_string());
        assert_eq!(
            file_path.exists(),
            true,
            "File does not exist in the directory"
        );

        let file_content = misc_helpers::json_read_from_file::<GuestProxyAgentAggregateStatus>(
            file_path.clone().to_path_buf(),
        );
        assert!(file_content.is_ok(), "Failed to read file content");

        //Check if field were written
        let Gpa_aggregate_status = file_content.unwrap();
        assert!(
            !Gpa_aggregate_status.timestamp.is_empty(),
            "Failed to get Timestamp field"
        );
        assert!(
            !Gpa_aggregate_status.proxyAgentStatus.version.is_empty(),
            "Failed to get proxy_agent_status field"
        );
        assert!(
            Gpa_aggregate_status.proxyConnectionSummary.is_empty()
                || Gpa_aggregate_status.proxyConnectionSummary.len() >= 1,
            "proxyConnectionSummary does not exist"
        );
    }
}
