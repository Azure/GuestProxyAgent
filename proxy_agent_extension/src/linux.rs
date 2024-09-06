// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#[cfg(not(windows))]
use std::thread;
#[cfg(not(windows))]
use std::time::Duration;

use crate::service_main;

#[cfg(not(windows))]
pub fn start_service_wait() {
    // start service
    let service_state = service_main::service_state::ServiceState::new();
    service_main::run(service_state);

    loop {
        // continue to sleep until the service is stopped
        thread::sleep(Duration::from_secs(1));
    }
}
