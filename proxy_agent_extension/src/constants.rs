// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
pub const PLUGIN_NAME: &str = "ProxyAgentVMExtension";
pub const PLUGIN_CONNECTION_NAME: &str = "ProxyAgentConnectionSummary";
pub const PLUGIN_STATUS_NAME: &str = "ProxyAgentStatus";
pub const PLUGIN_FAILED_AUTH_NAME: &str = "ProxyAgentFailedAuthenticationSummary";
pub const HANDLER_ENVIRONMENT_FILE: &str = "HandlerEnvironment.json";
pub const HANDLER_LOG_FILE: &str = "ProxyAgentExtension.log";
pub const SERVICE_LOG_FILE: &str = "ProxyAgentExtensionService.log";
pub const EXTENSION_SERVICE_NAME: &str = "GuestProxyAgentVMExtension";
#[cfg(not(windows))]
pub const EXTENSION_PROCESS_NAME: &str = "ProxyAgentExt";
#[cfg(windows)]
pub const EXTENSION_PROCESS_NAME: &str = "ProxyAgentExt.exe";
pub const EXTENSION_SERVICE_DISPLAY_NAME: &str = "Microsoft Azure GuestProxyAgent VMExtension";
pub const PROXY_AGENT_SERVICE_NAME: &str = "GuestProxyAgent";
pub const UPDATE_TAG_FILE: &str = "update.tag";
pub const ENABLE_OPERATION: &str = "Enable";
pub const LANG_EN_US: &str = "en-US";
pub const STATUS_FILE_SUFFIX: &str = "status";
pub const CONFIG_FILE_SUFFIX: &str = "settings";
pub const HEARTBEAT_FILE_SUFFIX: &str = "json";
#[cfg(windows)]
pub const TRANSITIONING_STATUS: &str = "Transitioning";
#[cfg(not(windows))]
pub const TRANSITIONING_STATUS: &str = "transitioning";
#[cfg(windows)]
pub const ERROR_STATUS: &str = "Error";
#[cfg(not(windows))]
pub const ERROR_STATUS: &str = "error";
#[cfg(windows)]
pub const SUCCESS_STATUS: &str = "Success";
#[cfg(not(windows))]
pub const SUCCESS_STATUS: &str = "success";
#[cfg(windows)]
pub const WARNING_STATUS: &str = "Warning";
#[cfg(not(windows))]
pub const WARNING_STATUS: &str = "warning";
#[cfg(windows)]
pub const HEARTBEAT_READY_STATUS: &str = "Ready";
#[cfg(not(windows))]
pub const HEARTBEAT_READY_STATUS: &str = "ready";

pub const CURRENT_SEQ_NO_FILE: &str = "current_seq_no.txt";
pub const VERSION: &str = "1.0";
pub const WINDOWS_SUPPORTED_VERSIONS: &str = "10.0.17763";
pub const INVALID_FILE_VERSION: &str = "0.0.0.0";
pub const SERVICE_START_RETRY_COUNT: u32 = 5;
pub const STATUS_CODE_OK: i32 = 0;
pub const STATUS_CODE_NOT_OK: i32 = 4;

// Non zero exit codes
pub const EXIT_CODE_HANDLER_ENV_ERR: i32 = 1;
pub const EXIT_CODE_SERVICE_UPDATE_ERR: i32 = 2;
pub const EXIT_CODE_SERVICE_INSTALL_ERR: i32 = 3;
pub const EXIT_CODE_SERVICE_UNINSTALL_ERR: i32 = 5;
pub const EXIT_CODE_NOT_SUPPORTED_OS_VERSION: i32 = 6;
pub const EXIT_CODE_SERVICE_START_ERR: i32 = 7;
pub const EXIT_CODE_SERVICE_STOP_ERR: i32 = 8;
pub const EXIT_CODE_UPDATE_TO_VERSION_ENV_VAR_NOTFOUND: i32 = 9;
pub const EXIT_CODE_WRITE_CURRENT_SEQ_NO_ERROR: i32 = 10;

pub const MIN_SUPPORTED_OS_BUILD: u32 = 17763;

pub const STATE_KEY_READ_PROXY_AGENT_STATUS_FILE: &str = "ReadProxyAgentStatusFile";
pub const STATE_KEY_FILE_VERSION: &str = "FileVersion";

pub const EBPF_CORE: &str = "EbpfCore";
pub const EBPF_EXT: &str = "NetEbpfExt";
pub const EBPF_SUBSTATUS_NAME: &str = "EbpfStatus";

pub const MAX_CONNECTION_SUMMARY_LEN: usize = 100;
pub const MAX_FAILED_AUTH_SUMMARY_LEN: usize = 50;
// Max KB of substatus string for connection summary and failed authentication summary
pub const MAX_PROXYAGENT_CONNECTION_DATA_SIZE_IN_KB: usize = 80;

#[cfg(not(windows))]
pub mod linux {
    pub const MIN_SUPPORTED_MARINER_OS_VERSION_MAJOR: u32 = 2;
    pub const MIN_SUPPORTED_UBUNTU_OS_VERSION_MAJOR: u32 = 20;
    pub const MIN_SUPPORTED_AZURE_LINUX_OS_VERSION_MAJOR: u32 = 3;

    pub const RED_HAT_OS_NAME: &str = "red hat enterprise linux";
    pub const MIN_RED_HAT_OS_VERSION_MAJOR: u32 = 9;
    pub const ROCKY_OS_NAME: &str = "rocky linux";
    pub const MIN_ROCKY_OS_VERSION_MAJOR: u32 = 9;
    pub const SUSE_OS_NAME: &str = "suse linux enterprise server";
    pub const MIN_SUSE_OS_VERSION_MAJOR: u32 = 15;
    pub const MIN_SUSE_OS_VERSION_MINOR: u32 = 4;
}
