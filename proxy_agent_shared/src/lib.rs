// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

pub mod certificate;
pub mod error;
#[cfg(windows)]
pub mod etw;
pub mod formatted_error_message;
pub mod host_clients;
pub mod hyper_client;
pub mod logger;
pub mod misc_helpers;
pub mod proxy_agent_aggregate_status;
pub mod result;
pub mod secrets_redactor;
pub mod service;
pub mod telemetry;
pub mod version;
#[cfg(windows)]
pub mod windows;

#[cfg(not(windows))]
pub mod linux;

/// Mock server for unit tests and local development
pub mod server_mock;
