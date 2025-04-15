// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#[cfg(windows)]
pub mod windows;

use crate::common::{config, constants, helpers, logger};
use crate::key_keeper::KeyKeeper;
use crate::proxy::proxy_connection::ConnectionLogger;
use crate::proxy::proxy_server::ProxyServer;
use crate::redirector::{self, Redirector};
use crate::shared_state::SharedState;
use proxy_agent_shared::logger::rolling_logger::RollingLogger;
use proxy_agent_shared::logger::{logger_manager, LoggerLevel};
use proxy_agent_shared::telemetry::event_logger;

use std::path::PathBuf;
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
    let log_folder = config::get_logs_dir();
    if log_folder == PathBuf::from("") {
        logger::write_console_log(
            "The log folder is not set, skip write to GPA managed file log.".to_string(),
        );
    } else {
        setup_loggers(log_folder, config::get_file_log_level());
    }

    let start_message = format!(
        "============== GuestProxyAgent ({}) is starting on {}({}), elapsed: {}",
        proxy_agent_shared::misc_helpers::get_current_version(),
        helpers::get_long_os_version(),
        helpers::get_cpu_arch(),
        helpers::get_elapsed_time_in_millisec()
    );
    logger::write_information(start_message.clone());
    #[cfg(not(windows))]
    logger::write_serial_console_log(start_message);

    tokio::spawn({
        let key_keeper = KeyKeeper::new(
            (format!("http://{}/", constants::WIRE_SERVER_IP))
                .parse()
                .unwrap(),
            config::get_keys_dir(),
            config::get_logs_dir(),
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

fn setup_loggers(log_folder: PathBuf, max_logger_level: LoggerLevel) {
    logger_manager::set_logger_level(max_logger_level);

    let agent_logger = RollingLogger::create_new(
        log_folder.clone(),
        "ProxyAgent.log".to_string(),
        constants::MAX_LOG_FILE_SIZE,
        constants::MAX_LOG_FILE_COUNT as u16,
    );
    let connection_logger = RollingLogger::create_new(
        log_folder.clone(),
        "ProxyAgent.Connection.log".to_string(),
        constants::MAX_LOG_FILE_SIZE,
        constants::MAX_LOG_FILE_COUNT as u16,
    );
    let mut loggers = std::collections::HashMap::new();
    loggers.insert(logger::AGENT_LOGGER_KEY.to_string(), agent_logger);
    loggers.insert(
        ConnectionLogger::CONNECTION_LOGGER_KEY.to_string(),
        connection_logger,
    );
    logger_manager::set_loggers(loggers, logger::AGENT_LOGGER_KEY.to_string());
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

    event_logger::stop();
}

#[cfg(test)]
mod tests {
    use ctor::{ctor, dtor};
    use proxy_agent_shared::logger::LoggerLevel;
    use std::env;
    use std::fs;

    const TEST_LOGGER_KEY: &str = "proxy_agent_test";

    fn get_temp_test_dir() -> std::path::PathBuf {
        let mut temp_test_path = env::temp_dir();
        temp_test_path.push(TEST_LOGGER_KEY);
        temp_test_path
    }

    #[ctor]
    fn setup() {
        // Setup logger_manager for unit tests
        super::setup_loggers(get_temp_test_dir(), LoggerLevel::Trace);
    }

    #[dtor]
    fn cleanup() {
        // clean up and ignore the clean up errors
        _ = fs::remove_dir_all(&get_temp_test_dir());
    }
}
