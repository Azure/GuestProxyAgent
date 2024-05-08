// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#[cfg(windows)]
pub mod windows;

use crate::common::{config, constants, helpers, logger};
use crate::proxy::proxy_listener;
use crate::telemetry::event_reader;
use proxy_agent_shared::logger_manager;
use proxy_agent_shared::telemetry::event_logger;
use url::Url;

#[cfg(not(windows))]
use std::thread;
#[cfg(not(windows))]
use std::time::Duration;

pub fn start_service() {
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

    crate::key_keeper::poll_status_async(
        Url::parse(&format!("http://{}/", constants::WIRE_SERVER_IP)).unwrap(),
        config::get_keys_dir(),
        config::get_poll_key_status_duration(),
        config_start_redirector,
    );

    proxy_listener::start_async(constants::PROXY_AGENT_PORT, 20);

    // TODO:: need start the monitor thread and write proxy agent status to the file
    // monitor::start_async(config::get_monitor_duration());
}

#[cfg(not(windows))]
pub fn start_service_wait(){
    start_service();

    loop {
        // continue to sleep until the service is stopped
        thread::sleep(Duration::from_secs(1));
    }
}

pub fn stop_service() {
    crate::monitor::stop();
    crate::redirector::close(constants::PROXY_AGENT_PORT);
    crate::key_keeper::stop();
    proxy_listener::stop(constants::PROXY_AGENT_PORT);
    event_logger::stop();
    event_reader::stop();
}
