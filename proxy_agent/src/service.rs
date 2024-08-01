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
use std::thread;
#[cfg(not(windows))]
use std::time::Duration;

pub fn start_service(shared_state: Arc<Mutex<SharedState>>) {
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

    start_service_async(shared_state.clone());

    // TODO:: need start the monitor thread and write proxy agent status to the file
    // monitor::start_async(config::get_monitor_duration());
}

fn start_service_async(shared_state: Arc<Mutex<SharedState>>) {
    _ = std::thread::Builder::new().spawn(move || {
        let runtime = shared_state_wrapper::get_runtime(shared_state.clone());
        match runtime {
            Some(rt) => {
                rt.lock().unwrap().block_on(async move {
                    let config_start_redirector = config::get_start_redirector();

                    crate::key_keeper::poll_status_async(
                        Url::parse(&format!("http://{}/", constants::WIRE_SERVER_IP)).unwrap(),
                        config::get_keys_dir(),
                        config::get_poll_key_status_duration(),
                        config_start_redirector,
                        shared_state.clone(),
                    )
                    .await;

                    proxy_server::start_async(constants::PROXY_AGENT_PORT, shared_state.clone())
                        .await;
                });
            }
            None => {
                logger::write_error("Failed to get tokio runtime.".to_string());
            }
        }
    });
}

#[cfg(not(windows))]
pub fn start_service_wait() {
    let shared_state = SharedState::new();
    start_service(shared_state);

    loop {
        // continue to sleep until the service is stopped
        thread::sleep(Duration::from_secs(1));
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

    shared_state_wrapper::shutdown_runtime(shared_state.clone());
    logger::write_information("Async runtime dropped.".to_string());
}
