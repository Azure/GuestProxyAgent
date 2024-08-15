// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#[cfg(windows)]
pub mod windows;

use crate::common::{config, constants, helpers, logger};
use crate::proxy::proxy_server;
use crate::shared_state::{shared_state_wrapper, telemetry_wrapper, SharedState};
use crate::telemetry::event_reader;
use proxy_agent_shared::logger_manager;
use proxy_agent_shared::telemetry::event_logger;
use std::sync::{Arc, Mutex};
use url::Url;

#[cfg(not(windows))]
use std::time::Duration;

pub async fn start_service(shared_state: Arc<Mutex<SharedState>>) {
    logger_manager::init_logger(
        logger::AGENT_LOGGER_KEY.to_string(),
        config::get_logs_dir(),
        "ProxyAgent.log".to_string(),
        20 * 1024 * 1024,
        20,
    );
    logger::write_information(format!(
        "============== GuestProxyAgent ({}) is starting on {}, elapsed: {}",
        proxy_agent_shared::misc_helpers::get_current_version(),
        helpers::get_long_os_version(),
        helpers::get_elapsed_time_in_millisec()
    ));

    let config_start_redirector = config::get_start_redirector();
    tokio::spawn(crate::key_keeper::poll_secure_channel_status(
        Url::parse(&format!("http://{}/", constants::WIRE_SERVER_IP)).unwrap(),
        config::get_keys_dir(),
        config::get_poll_key_status_duration(),
        config_start_redirector,
        shared_state.clone(),
    ));

    tokio::spawn(proxy_server::start(
        constants::PROXY_AGENT_PORT,
        shared_state.clone(),
    ));
}

#[cfg(not(windows))]
pub async fn start_service_wait() {
    let shared_state = SharedState::new();
    start_service(shared_state).await;

    loop {
        // continue to sleep until the service is stopped
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

pub fn stop_service(shared_state: Arc<Mutex<SharedState>>) {
    logger::write_information(format!(
        "============== GuestProxyAgent is stopping, elapsed: {}",
        helpers::get_elapsed_time_in_millisec()
    ));
    shared_state_wrapper::cancel_cancellation_token(shared_state.clone());

    crate::monitor::stop(shared_state.clone());
    crate::redirector::close(shared_state.clone());
    crate::key_keeper::stop(shared_state.clone());
    proxy_server::stop(constants::PROXY_AGENT_PORT, shared_state.clone());
    event_logger::stop();
    telemetry_wrapper::set_logger_shutdown(shared_state.clone(), true);
    event_reader::stop(shared_state.clone());

    logger::write_information("async runtime dropped.".to_string());
}
