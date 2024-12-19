// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use crate::service_main;
use std::time::Duration;

#[cfg(not(windows))]
pub async fn start_service_wait() {
    // start service
    service_main::run();

    loop {
        // continue to sleep until the service is stopped
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}
