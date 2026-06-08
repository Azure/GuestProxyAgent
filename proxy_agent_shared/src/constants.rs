// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

//! Workspace-wide constants shared across the agent, extension, and setup crates.
//!
//! This module consolidates values that previously lived in three
//! separate `constants` modules and had silently drifted apart.

/// The OS service name under which the proxy agent runs.
///
/// - Windows: registered Service Control Manager name.
/// - Linux: `systemd` unit name (matches the binary installed at
///   `/usr/sbin/azure-proxy-agent` and packaged in the .deb / .rpm).
#[cfg(windows)]
pub const PROXY_AGENT_SERVICE_NAME: &str = "GuestProxyAgent";
#[cfg(not(windows))]
pub const PROXY_AGENT_SERVICE_NAME: &str = "azure-proxy-agent";

/// Human-readable display name for the proxy agent service.
pub const PROXY_AGENT_SERVICE_DISPLAY_NAME: &str = "Microsoft Azure Guest Proxy Agent";
