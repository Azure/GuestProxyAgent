// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
pub use proxy_agent_shared::constants::GA_PLUGIN_IP;
pub use proxy_agent_shared::constants::GA_PLUGIN_PORT;
pub use proxy_agent_shared::constants::IMDS_IP;
pub use proxy_agent_shared::constants::IMDS_PORT;
pub use proxy_agent_shared::constants::PROXY_AGENT_IP;
pub use proxy_agent_shared::constants::PROXY_AGENT_PORT;
pub use proxy_agent_shared::constants::PROXY_AGENT_SERVICE_NAME;
pub use proxy_agent_shared::constants::WIRE_SERVER_IP;
pub use proxy_agent_shared::constants::WIRE_SERVER_PORT;

pub const WINDOWS_AZURE: &str = "Windows Azure";

pub const WIRE_SERVER_IP_NETWORK_BYTE_ORDER: u32 = 0x10813FA8; // 168.63.129.16
pub const GA_PLUGIN_IP_NETWORK_BYTE_ORDER: u32 = 0x10813FA8; // 168.63.129.16
pub const IMDS_IP_NETWORK_BYTE_ORDER: u32 = 0xFEA9FEA9; //"169.254.169.254";
pub const PROXY_AGENT_IP_NETWORK_BYTE_ORDER: u32 = 0x100007F; //"127.0.0.1";

pub const KEY_DELIVERY_METHOD_HTTP: &str = "http";
pub const KEY_DELIVERY_METHOD_VTPM: &str = "vtpm";

pub const CONNECTION_HEADER: &str = "connection";
pub const TIME_TICK_HEADER: &str = "x-ms-azure-time-tick";
pub const NOTIFY_HEADER: &str = "x-ms-azure-notify";

// Default Config Settings
pub const DEFAULT_MAX_EVENT_FILE_COUNT: usize = 30;

pub const CGROUP_ROOT: &str = "/sys/fs/cgroup";

pub const MAX_LOG_FILE_COUNT: usize = 5;
pub const MAX_LOG_FILE_SIZE: u64 = 10 * 1024 * 1024; // 10MB
