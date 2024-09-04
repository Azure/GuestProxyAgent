// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#[cfg(not(windows))]
use std::thread;
#[cfg(not(windows))]
use std::time::Duration;

use crate::logger;
use crate::service_main;
use proxy_agent_shared::{misc_helpers, telemetry};

#[cfg(not(windows))]
pub fn start_service_wait() {
    // start service
    let service_state = service_main::service_state::ServiceState::new();
    service_main::run(service_state);
    let message = format!(
        "==============  GuestProxyAgentExtension Start Service, Version: {}, OS Arch: {}, OS Version: {}",
        misc_helpers::get_current_version(),
        misc_helpers::get_processor_arch(),
        misc_helpers::get_long_os_version()
    );
    telemetry::event_logger::write_event(
        telemetry::event_logger::INFO_LEVEL,
        message,
        "run",
        "service_main",
        &logger::get_logger_key(),
    );
    loop {
        // continue to sleep until the service is stopped
        thread::sleep(Duration::from_secs(1));
    }
}
