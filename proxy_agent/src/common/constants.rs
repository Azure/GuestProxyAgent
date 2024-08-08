// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
pub const WIRE_SERVER_IP: &str = "168.63.129.16";
pub const WIRE_SERVER_PORT: u16 = 80u16;
pub const GA_PLUGIN_IP: &str = "168.63.129.16";
pub const GA_PLUGIN_PORT: u16 = 32526u16;
pub const IMDS_IP: &str = "169.254.169.254";
pub const IMDS_PORT: u16 = 80u16;

pub const PROXY_AGENT_SERVICE_NAME: &str = "GuestProxyAgent";
pub const PROXY_AGENT_IP: &str = "127.0.0.1";
pub const PROXY_AGENT_PORT: u16 = 3080;

pub const WIRE_SERVER_IP_NETWORK_BYTE_ORDER: u32 = 0x10813FA8; // 168.63.129.16
pub const GA_PLUGIN_IP_NETWORK_BYTE_ORDER: u32 = 0x10813FA8; // 168.63.129.16
pub const IMDS_IP_NETWORK_BYTE_ORDER: u32 = 0xFEA9FEA9; //"169.254.169.254";
pub const PROXY_AGENT_IP_NETWORK_BYTE_ORDER: u32 = 0x100007F; //"127.0.0.1";

pub const EMPTY_GUID: &str = "00000000-0000-0000-0000-000000000000";

pub const AUTHORIZATION_SCHEME: &str = "Azure-HMAC-SHA256";
pub const KEY_DELIVERY_METHOD_HTTP: &str = "http";
pub const KEY_DELIVERY_METHOD_VTPM: &str = "vtpm";
pub const CLAIMS_IS_ROOT: &str = "isRoot";

pub const CLAIMS_HEADER: &str = "x-ms-azure-host-claims";
pub const AUTHORIZATION_HEADER: &str = "x-ms-azure-host-authorization";
pub const DATE_HEADER: &str = "x-ms-azure-host-date";
pub const METADATA_HEADER: &str = "Metadata";
pub const CONNECTION_HEADER: &str = "connection";

// Default Config Settings
pub const DEFAULT_START_REDIRECTOR: bool = true;
pub const DEFAULT_MAX_EVENT_FILE_COUNT: usize = 30;

pub const CGROUP_ROOT: &str = "/sys/fs/cgroup";
pub const EGID: u32 = 3080;

pub const LF: &str = "\n";
