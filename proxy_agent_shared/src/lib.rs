// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

pub mod error;
#[cfg(windows)]
pub mod etw;
pub mod logger;
pub mod misc_helpers;
pub mod proxy_agent_aggregate_status;
pub mod result;
pub mod service;
pub mod telemetry;
pub mod version;
#[cfg(windows)]
pub mod windows;
pub mod client;
pub mod certificates_helper;

#[cfg(not(windows))]
pub mod linux;
