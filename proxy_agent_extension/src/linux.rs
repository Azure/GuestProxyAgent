// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#[cfg(not(windows))]
use std::time::Duration;
#[cfg(not(windows))]
use std::thread;

use crate::service_main;

#[cfg(not(windows))]
pub fn start_service_wait(){
    // start service
    service_main::enable_agent();

    loop {
        // continue to sleep until the service is stopped
        thread::sleep(Duration::from_secs(1));
    }
}