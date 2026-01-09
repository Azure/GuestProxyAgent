// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

//! This module contains the logic to read the configuration from the config file.
//! The configuration file is a json file that contains the configuration for the GPA service.
//!
//! Example
//! ```rust
//! use proxy_agent::config;
//!
//! // Get the logs directory
//! let logs_dir = config::get_logs_dir();
//!
//! // Get the keys directory
//! let keys_dir = config::get_keys_dir();
//!
//! ```

use crate::common::constants;
use once_cell::sync::Lazy;
use proxy_agent_shared::{logger::LoggerLevel, misc_helpers};
use serde_derive::{Deserialize, Serialize};
use std::str::FromStr;
use std::{path::PathBuf, time::Duration};

#[cfg(not(windows))]
const CONFIG_FILE_NAME: &str = "proxy-agent.json";
#[cfg(windows)]
const CONFIG_FILE_NAME: &str = "GuestProxyAgent.json";

static SYSTEM_CONFIG: Lazy<Config> = Lazy::new(Config::default);

#[cfg(not(windows))]
pub fn get_cgroup_root() -> PathBuf {
    SYSTEM_CONFIG.get_cgroup_root()
}
pub fn get_logs_dir() -> PathBuf {
    PathBuf::from(SYSTEM_CONFIG.get_log_folder())
}
pub fn get_keys_dir() -> PathBuf {
    PathBuf::from(SYSTEM_CONFIG.get_latch_key_folder())
}
pub fn get_events_dir() -> PathBuf {
    PathBuf::from(SYSTEM_CONFIG.get_event_folder())
}
pub fn get_monitor_duration() -> Duration {
    Duration::from_secs(SYSTEM_CONFIG.get_monitor_interval())
}
pub fn get_poll_key_status_duration() -> Duration {
    Duration::from_secs(SYSTEM_CONFIG.get_poll_key_status_interval())
}

pub fn get_max_event_file_count() -> usize {
    SYSTEM_CONFIG.get_max_event_file_count()
}

pub fn get_ebpf_file_full_path() -> Option<PathBuf> {
    SYSTEM_CONFIG.get_ebpf_file_full_path()
}

pub fn get_ebpf_program_name() -> String {
    SYSTEM_CONFIG.get_ebpf_program_name().to_string()
}

pub fn get_file_log_level() -> LoggerLevel {
    SYSTEM_CONFIG.get_file_log_level()
}

pub fn get_file_log_level_for_events() -> Option<LoggerLevel> {
    SYSTEM_CONFIG.get_file_log_level_for_events()
}

pub fn get_file_log_level_for_system_events() -> Option<LoggerLevel> {
    SYSTEM_CONFIG.get_file_log_level_for_system_events()
}

pub fn get_enable_http_proxy_trace() -> bool {
    SYSTEM_CONFIG.enableHttpProxyTrace.unwrap_or(false)
}

#[derive(Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct Config {
    logFolder: String,
    eventFolder: String,
    latchKeyFolder: String,
    monitorIntervalInSeconds: u64,
    pollKeyStatusIntervalInSeconds: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    maxEventFileCount: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ebpfFileFullPath: Option<String>,
    ebpfProgramName: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    fileLogLevel: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg(not(windows))]
    cgroupRoot: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fileLogLevelForEvents: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fileLogLevelForSystemEvents: Option<String>,
    /// Enable HTTP proxy trace logging, default to false if not set
    /// This is an optional config, mainly for manual debugging purpose
    #[serde(skip_serializing_if = "Option::is_none")]
    enableHttpProxyTrace: Option<bool>,
}

impl Default for Config {
    fn default() -> Self {
        let mut config_file_full_path = PathBuf::new();
        #[cfg(not(windows))]
        {
            if !config_file_full_path.exists() {
                // linux config file default to /etc/azure folder
                config_file_full_path = PathBuf::from(format!("/etc/azure/{CONFIG_FILE_NAME}"));
            }
        }

        if !config_file_full_path.exists() {
            // default to current exe folder
            config_file_full_path = misc_helpers::get_current_exe_dir();
            config_file_full_path.push(CONFIG_FILE_NAME);
        }
        Config::from_json_file(config_file_full_path)
    }
}

impl Config {
    pub fn from_json_file(file_path: PathBuf) -> Self {
        misc_helpers::json_read_from_file::<Config>(&file_path).unwrap_or_else(|_| {
            panic!(
                "Error in reading Config from Json file: {}",
                misc_helpers::path_to_string(&file_path)
            )
        })
    }

    pub fn get_log_folder(&self) -> String {
        match misc_helpers::resolve_env_variables(&self.logFolder) {
            Ok(val) => val,
            Err(_) => self.logFolder.clone(),
        }
    }

    pub fn get_event_folder(&self) -> String {
        match misc_helpers::resolve_env_variables(&self.eventFolder) {
            Ok(val) => val,
            Err(_) => self.eventFolder.clone(),
        }
    }

    pub fn get_latch_key_folder(&self) -> String {
        match misc_helpers::resolve_env_variables(&self.latchKeyFolder) {
            Ok(val) => val,
            Err(_) => self.latchKeyFolder.clone(),
        }
    }

    pub fn get_monitor_interval(&self) -> u64 {
        self.monitorIntervalInSeconds
    }

    pub fn get_poll_key_status_interval(&self) -> u64 {
        self.pollKeyStatusIntervalInSeconds
    }

    pub fn get_max_event_file_count(&self) -> usize {
        self.maxEventFileCount
            .unwrap_or(constants::DEFAULT_MAX_EVENT_FILE_COUNT)
    }

    pub fn get_ebpf_program_name(&self) -> &str {
        &self.ebpfProgramName
    }

    pub fn get_ebpf_file_full_path(&self) -> Option<PathBuf> {
        self.ebpfFileFullPath.as_ref().map(PathBuf::from)
    }

    pub fn get_file_log_level(&self) -> LoggerLevel {
        let file_log_level = self.fileLogLevel.clone().unwrap_or("Info".to_string());
        LoggerLevel::from_str(&file_log_level).unwrap_or(LoggerLevel::Info)
    }

    #[cfg(not(windows))]
    pub fn get_cgroup_root(&self) -> PathBuf {
        match &self.cgroupRoot {
            Some(cgroup) => PathBuf::from(cgroup),
            None => PathBuf::from(constants::CGROUP_ROOT),
        }
    }

    pub fn get_file_log_level_for_events(&self) -> Option<LoggerLevel> {
        if let Some(file_log_level) = &self.fileLogLevelForEvents {
            let log_level = LoggerLevel::from_str(file_log_level).unwrap_or(LoggerLevel::Info);
            return Some(log_level);
        }
        None
    }

    pub fn get_file_log_level_for_system_events(&self) -> Option<LoggerLevel> {
        if let Some(file_log_level) = &self.fileLogLevelForSystemEvents {
            let log_level = LoggerLevel::from_str(file_log_level).unwrap_or(LoggerLevel::Info);
            return Some(log_level);
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use crate::common::config::Config;
    use crate::common::constants;
    use proxy_agent_shared::misc_helpers;
    use std::fs::File;
    use std::io::Write;
    use std::path::PathBuf;
    use std::{env, fs};

    #[test]
    fn config_struct_test() {
        let mut temp_test_path: PathBuf = env::temp_dir();
        temp_test_path.push("config_struct_test");
        _ = fs::remove_dir_all(&temp_test_path);
        match misc_helpers::try_create_folder(&temp_test_path) {
            Ok(_) => {}
            Err(err) => panic!("Failed to create folder: {}", err),
        }
        let config_file_path = temp_test_path.join("test_config.json");
        let config = create_config_file(config_file_path);

        assert_eq!(
            r#"C:\logFolderName"#.to_string(),
            config.get_log_folder(),
            "Log Folder mismatch"
        );

        assert_eq!(
            r#"C:\eventFolderName"#.to_string(),
            config.get_event_folder(),
            "Event Folder mismatch"
        );

        assert_eq!(
            r#"C:\latchKeyFolderName"#.to_string(),
            config.get_latch_key_folder(),
            "Latch Key Folder mismatch"
        );

        assert_eq!(
            60u64,
            config.get_monitor_interval(),
            "get_monitor_interval mismatch"
        );

        assert_eq!(
            15u64,
            config.get_poll_key_status_interval(),
            "get_poll_key_status_interval mismatch"
        );

        assert_eq!(
            constants::DEFAULT_MAX_EVENT_FILE_COUNT,
            config.get_max_event_file_count(),
            "get_max_event_file_count mismatch"
        );

        assert_eq!(
            "ebpfProgramName".to_string(),
            config.get_ebpf_program_name(),
            "get_ebpf_program_name mismatch"
        );

        #[cfg(not(windows))]
        {
            assert_eq!(
                PathBuf::from(constants::CGROUP_ROOT),
                config.get_cgroup_root(),
                "get_cgroup_root mismatch"
            );
        }

        assert_eq!(
            proxy_agent_shared::logger::LoggerLevel::Info,
            config.get_file_log_level_for_events().unwrap(),
            "get_file_log_level_for_events mismatch"
        );

        assert_eq!(
            proxy_agent_shared::logger::LoggerLevel::Info,
            config.get_file_log_level_for_system_events().unwrap(),
            "get_file_log_level_for_system_events mismatch"
        );

        assert_eq!(
            None, config.enableHttpProxyTrace,
            "enableHttpProxyTrace mismatch"
        );

        // clean up
        _ = fs::remove_dir_all(&temp_test_path);
    }

    fn create_config_file(file_path: PathBuf) -> Config {
        let data = if cfg!(not(windows)) {
            r#"{
            "logFolder": "C:\\logFolderName",
            "eventFolder": "C:\\eventFolderName",
            "latchKeyFolder": "C:\\latchKeyFolderName",
            "monitorIntervalInSeconds": 60,
            "pollKeyStatusIntervalInSeconds": 15,
            "wireServerSupport": 2,
            "hostGAPluginSupport": 1,
            "imdsSupport": 1,
            "ebpfProgramName": "ebpfProgramName",
            "fileLogLevelForEvents": "Info",
            "fileLogLevelForSystemEvents": "Info"
        }"#
        } else {
            r#"{
            "logFolder": "%SYSTEMDRIVE%\\logFolderName",
            "eventFolder": "%SYSTEMDRIVE%\\eventFolderName",
            "latchKeyFolder": "%SYSTEMDRIVE%\\latchKeyFolderName",
            "monitorIntervalInSeconds": 60,
            "pollKeyStatusIntervalInSeconds": 15,
            "wireServerSupport": 2,
            "hostGAPluginSupport": 1,
            "imdsSupport": 1,
            "ebpfProgramName": "ebpfProgramName",
            "fileLogLevelForEvents": "Info",
            "fileLogLevelForSystemEvents": "Info"
        }"#
        };

        File::create(&file_path)
            .unwrap()
            .write_all(data.as_bytes())
            .unwrap();
        Config::from_json_file(file_path)
    }
}
