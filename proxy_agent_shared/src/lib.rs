// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#![deny(warnings)]

pub mod logger_manager;
pub mod misc_helpers;
pub mod proxy_agent_aggregate_status;
pub mod rolling_logger;
pub mod service;
pub mod telemetry;
pub mod version;
#[cfg(windows)]
pub mod windows;

#[cfg(not(windows))]
pub mod linux;
