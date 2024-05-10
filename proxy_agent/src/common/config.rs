// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use crate::common::constants;
use once_cell::sync::Lazy;
use proxy_agent_shared::misc_helpers;
use serde_derive::{Deserialize, Serialize};
use std::{env, path::PathBuf, time::Duration};

const CONFIG_FILE_NAME: &str = "GuestProxyAgent.json";
static SYSTEM_CONFIG: Lazy<Config> = Lazy::new(|| Config::default());

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
pub fn get_start_redirector() -> bool {
    SYSTEM_CONFIG.get_start_redirector()
}
pub fn get_monitor_duration() -> Duration {
    Duration::from_secs(SYSTEM_CONFIG.get_monitor_interval())
}
pub fn get_poll_key_status_duration() -> Duration {
    Duration::from_secs(SYSTEM_CONFIG.get_poll_key_status_interval())
}
pub fn get_wire_server_support() -> u8 {
    SYSTEM_CONFIG.wireServerSupport
}
pub fn get_host_gaplugin_support() -> u8 {
    SYSTEM_CONFIG.hostGAPluginSupport
}
pub fn get_imds_support() -> u8 {
    SYSTEM_CONFIG.imdsSupport
}

pub fn get_max_event_file_count() -> usize {
    SYSTEM_CONFIG.get_max_event_file_count()
}

pub fn get_ebpf_program_name() -> String {
    SYSTEM_CONFIG.get_ebpf_program_name().to_string()
}

#[cfg(not(windows))]
pub fn get_fallback_with_iptable_redirect() -> bool {
    SYSTEM_CONFIG.get_fallback_with_iptable_redirect()
}

#[derive(Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct Config {
    logFolder: String,
    eventFolder: String,
    latchKeyFolder: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    startRedirector: Option<bool>, // true start the redirector/eBPF even secure channel is in disabled state
    monitorIntervalInSeconds: u64,
    pollKeyStatusIntervalInSeconds: u64,
    wireServerSupport: u8, // 0 not support; 1 proxy only; 2 proxy + authentication check
    hostGAPluginSupport: u8, // 0 not support; 1 proxy only; 2 proxy + authentication check
    imdsSupport: u8,       // 0 not support; 1 proxy only; 2 proxy + authentication check
    #[serde(skip_serializing_if = "Option::is_none")]
    maxEventFileCount: Option<usize>,
    ebpfProgramName: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg(not(windows))]
    cgroupRoot: Option<String>,
    #[cfg(not(windows))]
    fallBackWithIpTableRedirect: Option<bool>, // fallback to iptable redirect if cgroup redirect is not supported, it should only be use for old kernel, some scenario like docker container may not work
}

impl Config {
    pub fn from_json_file(file_path: PathBuf) -> Self {
        misc_helpers::json_read_from_file::<Config>(file_path.to_path_buf()).expect(&format!(
            "Error in reading Config from Json file: {}",
            misc_helpers::path_to_string(file_path.to_path_buf())
        ))
    }

    pub fn default() -> Self {
        // get config file full path from environment variable
        let mut config_file_full_path =
            match env::var(super::constants::AZURE_PROXY_AGENT_ENV_CONFIG_FULL_PATH) {
                Ok(file_path) => PathBuf::from(file_path),
                Err(_) => PathBuf::new(),
            };
        if !config_file_full_path.exists() {
            // default to current exe folder
            config_file_full_path = misc_helpers::get_current_exe_dir();
            config_file_full_path.push(CONFIG_FILE_NAME);
        }
        Config::from_json_file(config_file_full_path)
    }

    pub fn get_log_folder(&self) -> &str {
        &self.logFolder
    }

    pub fn get_event_folder(&self) -> &str {
        &self.eventFolder
    }

    pub fn get_latch_key_folder(&self) -> &str {
        &self.latchKeyFolder
    }

    pub fn get_start_redirector(&self) -> bool {
        self.startRedirector
            .unwrap_or(constants::DEFAULT_START_REDIRECTOR)
    }

    pub fn get_monitor_interval(&self) -> u64 {
        self.monitorIntervalInSeconds
    }

    pub fn get_poll_key_status_interval(&self) -> u64 {
        self.pollKeyStatusIntervalInSeconds
    }

    pub fn get_wire_server_support(&self) -> u8 {
        self.wireServerSupport
    }

    pub fn get_host_gaplugin_support(&self) -> u8 {
        self.hostGAPluginSupport
    }

    pub fn get_imds_support(&self) -> u8 {
        self.imdsSupport
    }

    pub fn get_max_event_file_count(&self) -> usize {
        self.maxEventFileCount
            .unwrap_or(constants::DEFAULT_MAX_EVENT_FILE_COUNT)
    }

    pub fn get_ebpf_program_name(&self) -> &str {
        &self.ebpfProgramName
    }

    #[cfg(not(windows))]
    pub fn get_cgroup_root(&self) -> PathBuf {
        match &self.cgroupRoot {
            Some(cgroup) => PathBuf::from(cgroup),
            None => PathBuf::from(constants::CGROUP_ROOT),
        }
    }

    #[cfg(not(windows))]
    pub fn get_fallback_with_iptable_redirect(&self) -> bool {
        self.fallBackWithIpTableRedirect
            .unwrap_or(constants::DEFAULT_FALLBACK_WITH_IPTABLE_REDIRECT)
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
        match misc_helpers::try_create_folder(temp_test_path.to_path_buf()) {
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
            constants::DEFAULT_START_REDIRECTOR,
            config.get_start_redirector(),
            "startRedirector should use the default value true"
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
            2u8,
            config.get_wire_server_support(),
            "get_wire_server_support mismatch"
        );

        assert_eq!(
            1u8,
            config.get_host_gaplugin_support(),
            "get_host_gaplugin_support mismatch"
        );

        assert_eq!(1u8, config.get_imds_support(), "get_imds_support mismatch");

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

        #[cfg(not(windows))]
        {
            assert_eq!(
                constants::DEFAULT_FALLBACK_WITH_IPTABLE_REDIRECT,
                config.get_fallback_with_iptable_redirect(),
                "get_fallback_with_iptable_redirect mismatch"
            );
        }

        // clean up
        _ = fs::remove_dir_all(&temp_test_path);
    }

    #[test]
    fn default_config_test() {
        let mut temp_test_path: PathBuf = env::temp_dir();
        temp_test_path.push("default_config_test");
        _ = fs::remove_dir_all(&temp_test_path);
        match misc_helpers::try_create_folder(temp_test_path.to_path_buf()) {
            Ok(_) => {}
            Err(err) => panic!("Failed to create folder: {}", err),
        }
        let config_file_path = temp_test_path.join("test_config.json");
        let test_config = create_config_file(config_file_path.to_path_buf());

        // no env variable set, use the default config copied over to current exe folder
        env::remove_var(constants::AZURE_PROXY_AGENT_ENV_CONFIG_FULL_PATH);
        let config = Config::default();
        assert_ne!(
            test_config.get_log_folder(),
            config.get_log_folder(),
            "default config should not be the same as the test config when no env variable set"
        );

        // set env variable to the invalid test config file
        let invalid_config_file_path = temp_test_path.join("invalid_test_config.json");
        env::set_var(
            constants::AZURE_PROXY_AGENT_ENV_CONFIG_FULL_PATH,
            misc_helpers::path_to_string(invalid_config_file_path),
        );
        let config = Config::default();
        assert_ne!(
            test_config.get_log_folder(),
            config.get_log_folder(),
            "default config should not be the same as the test config when env variable set to invalid file"
        );

        // set env variable to the valid test config file
        env::set_var(
            constants::AZURE_PROXY_AGENT_ENV_CONFIG_FULL_PATH,
            misc_helpers::path_to_string(config_file_path.to_path_buf()),
        );
        let config = Config::default();
        assert_eq!(
            test_config.get_log_folder(),
            config.get_log_folder(),
            "default config should be the same as the test config when env variable set to valid file"
        );

        // clean up
        env::remove_var(constants::AZURE_PROXY_AGENT_ENV_CONFIG_FULL_PATH);
        _ = fs::remove_dir_all(&temp_test_path);
    }

    fn create_config_file(file_path: PathBuf) -> Config {
        let data = r#"{
            "logFolder": "C:\\logFolderName",
            "eventFolder": "C:\\eventFolderName",
            "latchKeyFolder": "C:\\latchKeyFolderName",
            "monitorIntervalInSeconds": 60,
            "pollKeyStatusIntervalInSeconds": 15,
            "wireServerSupport": 2,
            "hostGAPluginSupport": 1,
            "imdsSupport": 1,
            "ebpfProgramName": "ebpfProgramName"
        }"#;
        File::create(&file_path)
            .unwrap()
            .write_all(data.as_bytes())
            .unwrap();
        Config::from_json_file(file_path)
    }
}
