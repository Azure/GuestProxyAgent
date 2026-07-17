// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#[cfg(windows)]
pub mod windows_main;

use crate::common::{config, constants, helpers, logger};
use crate::key_keeper::KeyKeeper;
use crate::proxy::proxy_connection::ConnectionLogger;
use crate::proxy::proxy_server::ProxyServer;
use crate::redirector::{self, Redirector};
use crate::shared_state::SharedState;
use proxy_agent_shared::current_info;
use proxy_agent_shared::hyper_client::HostEndpoint;
use proxy_agent_shared::logger::logger_manager;
use proxy_agent_shared::proxy_agent_aggregate_status;
use proxy_agent_shared::telemetry::event_logger;

#[cfg(not(windows))]
use std::time::Duration;

/// Start the service with the shared state.
/// Example:
/// ```rust
/// use proxy_agent::service;
/// use proxy_agent::shared_state::SharedState;
///
/// let shared_state = SharedState::start_all();
/// service::start_service(shared_state).await;
/// ```
pub async fn start_service(shared_state: SharedState) {
    if let Some(max_log_level) = config::get_file_log_level_for_system_events() {
        logger_manager::set_system_logger(
            max_log_level,
            constants::WINDOWS_AZURE,
            constants::PROXY_AGENT_SERVICE_NAME,
        );
    }

    let log_folder = config::get_logs_dir();
    if log_folder == proxy_agent_shared::misc_helpers::empty_path() {
        println!("The log folder is not set, skip write to GPA managed file log.");
    } else {
        proxy_agent_shared::logger::init_loggers(
            log_folder,
            &[
                (logger::AGENT_LOGGER_KEY, "ProxyAgent.log"),
                (
                    ConnectionLogger::CONNECTION_LOGGER_KEY,
                    "ProxyAgent.Connection.log",
                ),
            ],
            logger::AGENT_LOGGER_KEY,
            constants::MAX_LOG_FILE_SIZE,
            constants::MAX_LOG_FILE_COUNT as u16,
            config::get_file_log_level(),
        );
    }

    let start_message = format!(
        "============== GuestProxyAgent ({}) is starting on {}({}), elapsed: {}",
        current_info::get_current_exe_version(),
        current_info::get_long_os_version(),
        current_info::get_cpu_arch(),
        helpers::get_elapsed_time_in_millisec()
    );
    logger::write_information(start_message.clone());
    #[cfg(not(windows))]
    logger::write_serial_console_log(start_message);
    #[cfg(windows)]
    start_etw_listener();

    tokio::spawn({
        let key_keeper = KeyKeeper::new(
            constants::WIRE_SERVER_IP.to_string(),
            HostEndpoint::DEFAULT_HTTP_PORT,
            config::get_keys_dir(),
            proxy_agent_aggregate_status::get_proxy_agent_aggregate_status_folder(),
            config::get_poll_key_status_duration(),
            &shared_state,
        );
        async move {
            key_keeper.poll_secure_channel_status().await;
        }
    });

    tokio::spawn({
        let redirector: Redirector = Redirector::new(constants::PROXY_AGENT_PORT, &shared_state);
        async move {
            redirector.start().await;
        }
    });

    tokio::spawn({
        let proxy_server = ProxyServer::new(constants::PROXY_AGENT_PORT, &shared_state);
        async move {
            proxy_server.start().await;
        }
    });
}

#[cfg(windows)]
fn start_etw_listener() {
    const WINDOWS_ETW_TRACE_SESSION_NAME: &str = "WindowsEtwTraceSession";
    const EBPF_FOR_WINDOWS_PROVIDER_ID: &str = "394f321c-5cf4-404c-aa34-4df1428a7f9c";
    const NET_EBPF_EXT_PROVIDER_ID: &str = "f2f2ca01-ad02-4a07-9e90-95a2334f3692";

    // The maximum level for ETW provider, 3 - Warning, 4 - Informational
    // The level is used to filter events from the provider, only events with level less than or equal to the specified level will be captured.
    // We choose 3 (Warning) as the maximum level to reduce the amount of events captured and avoid overwhelming the system with too many events.
    const MAX_LEVEL: u8 = 3;

    use proxy_agent_shared::windows_events::{
        etw_listener::EtwListener, evt_listener::EvtListener, evt_listener::SourceFilter,
    };

    let mut etw_listener = EtwListener::new(WINDOWS_ETW_TRACE_SESSION_NAME);
    // start with the default providers, which includes the kernel provider and the Microsoft-Windows-Kernel-Network provider
    //
    if let Err(e) = etw_listener.add_provider(EBPF_FOR_WINDOWS_PROVIDER_ID, MAX_LEVEL) {
        logger::write_error(format!(
            "Failed to add ETW provider '{EBPF_FOR_WINDOWS_PROVIDER_ID}' with error: {:?}",
            e
        ));
    }
    if let Err(e) = etw_listener.add_provider(NET_EBPF_EXT_PROVIDER_ID, MAX_LEVEL) {
        logger::write_error(format!(
            "Failed to add ETW provider '{NET_EBPF_EXT_PROVIDER_ID}' with error: {:?}",
            e
        ));
    }
    if let Err(e) = etw_listener.run() {
        logger::write_error(format!("Failed to run ETW listener with error: {:?}", e));
    }

    if let Err(e) = EvtListener::subscribe_by_sources(
        "Application",
        &[
            SourceFilter {
                name: "MsiInstaller".to_string(),
                event_ids: vec![1035, 1040],
            },
            SourceFilter {
                name: ".NET Runtime".to_string(),
                event_ids: vec![1026],
            },
            SourceFilter {
                name: "Application Error".to_string(),
                event_ids: vec![1000],
            },
        ],
    ) {
        logger::write_error(format!(
            "Failed to subscribe to Event Log channel 'Applications' with error: {:?}",
            e
        ));
    }
    if let Err(e) = EvtListener::subscribe_by_sources(
        "System",
        &[SourceFilter {
            name: "User32".to_string(),
            event_ids: vec![1074],
        }],
    ) {
        logger::write_error(format!(
            "Failed to subscribe to Event Log channel 'System' with error: {:?}",
            e
        ));
    }
}

/// Start the service and wait until the service is stopped.
/// Example:
/// ```rust
/// use proxy_agent::service;
/// service::start_service_wait();
/// ```
#[cfg(not(windows))]
pub async fn start_service_wait() {
    let shared_state = SharedState::start_all();
    start_service(shared_state).await;

    loop {
        // continue to sleep until the service is stopped
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

/// Stop the service with the shared state.
/// Example:
/// ```rust
/// use proxy_agent::service;
/// use proxy_agent::shared_state::SharedState;
/// use std::sync::{Arc, Mutex};
///
/// let shared_state = SharedState::new();
/// service::stop_service(shared_state);
/// ```
pub fn stop_service(shared_state: SharedState) {
    logger::write_information(format!(
        "============== GuestProxyAgent is stopping, elapsed: {}",
        helpers::get_elapsed_time_in_millisec()
    ));
    shared_state.cancel_cancellation_token();

    tokio::spawn({
        let shared_state = shared_state.clone();
        async move {
            redirector::close(
                shared_state.get_redirector_shared_state(),
                shared_state.get_agent_status_shared_state(),
            )
            .await;
        }
    });

    #[cfg(windows)]
    proxy_agent_shared::windows_events::etw_listener::stop();

    event_logger::stop();
}
