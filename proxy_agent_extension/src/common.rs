// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use crate::constants;
use crate::error::Error;
use crate::logger;
use crate::result::Result;
use crate::structs;
use crate::structs::FormattedMessage;
use crate::structs::HandlerEnvironment;
use crate::structs::TopLevelStatus;
use proxy_agent_shared::{misc_helpers, telemetry};
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::process;

#[cfg(windows)]
use proxy_agent_shared::service;

pub fn get_handler_environment(exe_path: &Path) -> HandlerEnvironment {
    let mut handler_env_path: PathBuf = exe_path.to_path_buf();
    handler_env_path.push(constants::HANDLER_ENVIRONMENT_FILE);

    let handler_env_file: Vec<structs::Handler> =
        match misc_helpers::json_read_from_file(&handler_env_path) {
            Ok(temp) => temp,
            Err(e) => {
                eprintln!("Error in reading handler env file: {e}");
                process::exit(constants::EXIT_CODE_HANDLER_ENV_ERR);
            }
        };
    if handler_env_file.is_empty() {
        eprintln!("Handler environment file is empty");
        process::exit(constants::EXIT_CODE_HANDLER_ENV_ERR);
    }

    handler_env_file[0].handlerEnvironment.clone()
}

pub fn report_heartbeat(heartbeat_file_path: PathBuf, heartbeat_obj: structs::HeartbeatObj) {
    //Heartbeat Instance
    let root_heartbeat_obj = structs::TopLevelHeartbeat {
        version: constants::VERSION.to_string(),
        heartbeat: heartbeat_obj,
    };

    let root_obj: Vec<structs::TopLevelHeartbeat> = vec![root_heartbeat_obj];

    let root_heartbeat = match serde_json::to_string(&root_obj) {
        Ok(temp) => temp,
        Err(e) => {
            logger::write(format!("Error in serializing heartbeat object: {e}"));
            return;
        }
    };
    match fs::write(&heartbeat_file_path, root_heartbeat) {
        Ok(_) => {
            logger::write(format!(
                "HeartBeat file created: {:?}",
                heartbeat_file_path.to_path_buf()
            ));
        }
        Err(e) => {
            logger::write(format!("Error in creating HeartBeat file: {e:?}"));
        }
    }
}

pub fn get_file_path(status_folder: PathBuf, config_seq_no: &str, file_extension: &str) -> PathBuf {
    let mut file: PathBuf = status_folder;
    if let Err(e) = misc_helpers::try_create_folder(&file) {
        logger::write(format!("Error in creating folder: {e:?}"));
    }
    file.push(config_seq_no);
    file.set_extension(file_extension);
    file
}

pub fn report_status(
    status_folder_path: PathBuf,
    config_seq_no: &str,
    status_obj: &structs::StatusObj,
) {
    //Status Instance
    let status_file: PathBuf = get_file_path(
        status_folder_path,
        config_seq_no,
        constants::STATUS_FILE_SUFFIX,
    );

    let current_datetime: String = misc_helpers::get_date_time_string_with_milliseconds();
    let root_status_obj = TopLevelStatus {
        version: constants::VERSION.to_string(),
        timestampUTC: current_datetime,
        status: status_obj.clone(),
    };

    let root_vec: Vec<TopLevelStatus> = vec![root_status_obj];

    let root_status = match serde_json::to_string(&root_vec) {
        Ok(temp) => temp,
        Err(e) => {
            logger::write(format!("Error in serializing status object: {e}"));
            return;
        }
    };
    // TODO: retry if write failed
    match fs::write(&status_file, root_status) {
        Ok(_) => {
            logger::write(format!("Status file created: {status_file:?}"));
        }
        Err(e) => {
            logger::write(format!("Error in creating status file: {e:?}"));
        }
    }
}

/// Update the current seq no in the CURRENT_SEQ_NO_FILE
/// If the seq no is different from the current seq no, update the seq no in the file
/// If the seq no is same as the current seq no, do not update the seq no in the file
/// Returns true if the seq no is updated in the file, false otherwise
/// Returns error if there is an error in writing the seq no to the file
pub fn update_current_seq_no(config_seq_no: &str, exe_path: &Path) -> Result<bool> {
    let mut should_report_status = true;

    logger::write(format!("enable command with new seq no: {config_seq_no}"));
    let current_seq_no_stored_file: PathBuf = exe_path.join(constants::CURRENT_SEQ_NO_FILE);
    match fs::read_to_string(&current_seq_no_stored_file) {
        Ok(seq_no) => {
            if seq_no != *config_seq_no {
                logger::write(format!("updating seq no from {seq_no} to {config_seq_no}"));
                if let Err(e) = fs::write(&current_seq_no_stored_file, config_seq_no) {
                    logger::write(format!("Error in writing seq no to file: {e:?}"));
                    return Err(Error::Io(e));
                }
            } else {
                logger::write("no update on seq no".to_string());
                should_report_status = false;
            }
        }
        Err(_e) => {
            logger::write(format!(
                "no seq no found, writing seq no {} to file '{}'",
                config_seq_no,
                current_seq_no_stored_file.display()
            ));
            if let Err(e) = fs::write(&current_seq_no_stored_file, config_seq_no) {
                logger::write(format!("Error in writing seq no to file: {e:?}"));
                return Err(Error::Io(e));
            }
        }
    }

    Ok(should_report_status)
}

pub fn get_current_seq_no(exe_path: &Path) -> String {
    let current_seq_no_stored_file: PathBuf = exe_path.join(constants::CURRENT_SEQ_NO_FILE);
    match fs::read_to_string(current_seq_no_stored_file) {
        Ok(seq_no) => {
            logger::write(format!("Current seq no: {seq_no}"));
            seq_no
        }
        Err(e) => {
            logger::write(format!("Error reading current seq no file: {e:?}"));
            "".to_string()
        }
    }
}

pub fn get_proxy_agent_service_path() -> PathBuf {
    #[cfg(windows)]
    {
        service::query_service_executable_path(constants::PROXY_AGENT_SERVICE_NAME)
    }
    #[cfg(not(windows))]
    {
        // linux service hard-coded to this location
        PathBuf::from(proxy_agent_shared::linux::EXE_FOLDER_PATH).join("azure-proxy-agent")
    }
}

pub fn get_proxy_agent_exe_path() -> PathBuf {
    let exe_path = misc_helpers::get_current_exe_dir();
    logger::write(
        "Current proxy agent exe path: ".to_string() + &misc_helpers::path_to_string(&exe_path),
    );

    #[cfg(windows)]
    {
        exe_path.join("ProxyAgent/ProxyAgent/GuestProxyAgent.exe")
    }
    #[cfg(not(windows))]
    {
        exe_path.join("ProxyAgent/ProxyAgent/azure-proxy-agent")
    }
}

pub fn report_status_enable_command(
    status_folder: PathBuf,
    config_seq_no: &str,
    status: Option<String>,
) {
    let message: &str = "Enabling the ProxyAgent Extension...";
    //Report Status
    let handler_status = structs::StatusObj {
        name: constants::PLUGIN_NAME.to_string(),
        operation: constants::ENABLE_OPERATION.to_string(),
        configurationAppliedTime: misc_helpers::get_date_time_string(),
        code: constants::STATUS_CODE_OK,
        status: status.unwrap_or_else(|| constants::TRANSITIONING_STATUS.to_string()),
        formattedMessage: FormattedMessage {
            lang: constants::LANG_EN_US.to_string(),
            message: message.to_string(),
        },
        substatus: Default::default(),
    };
    report_status(status_folder, config_seq_no, &handler_status);
}

pub async fn start_event_logger() {
    logger::write("starting event logger".to_string());
    tokio::spawn({
        async move {
            let interval = std::time::Duration::from_secs(60);
            let max_event_file_count: usize = 50;
            let exe_path = misc_helpers::get_current_exe_dir();
            // Get the events folder from the handler environment
            let events_folder_str = match get_handler_environment(&exe_path).eventsFolder {
                Some(folder) => folder,
                None => {
                    logger::write(
                        "No events folder specified, skipping event logger start.".to_string(),
                    );
                    return;
                }
            };
            let event_folder = PathBuf::from(events_folder_str.clone());
            // Check if the events folder exists
            if !event_folder.exists() {
                logger::write(format!(
                    "Events folder does not exist: {event_folder:?}. Skipping event logger start."
                ));
                return;
            }

            telemetry::event_logger::start(event_folder, interval, max_event_file_count, |_| {
                async {
                    // do nothing
                }
            })
            .await;
        }
    });
}

pub fn stop_event_logger() {
    logger::write("stopping event logger".to_string());
    telemetry::event_logger::stop();
}

pub struct StatusState {
    current_state: String,
    consecutive_fail_count: u32,
    consecutive_success_count: u32,
    transition_to_error_threshold: u32,
}

pub fn setup_tool_exe_path() -> PathBuf {
    #[cfg(windows)]
    {
        misc_helpers::get_current_exe_dir().join("ProxyAgent/proxy_agent_setup.exe")
    }
    #[cfg(not(windows))]
    {
        misc_helpers::get_current_exe_dir().join("ProxyAgent/proxy_agent_setup")
    }
}

impl Default for StatusState {
    fn default() -> Self {
        Self::new()
    }
}

impl StatusState {
    const MAX_CONSECUTIVE_COUNT: u32 = 10000;

    pub fn new() -> StatusState {
        StatusState {
            current_state: constants::TRANSITIONING_STATUS.to_string(),
            consecutive_fail_count: 0,
            consecutive_success_count: 0,
            transition_to_error_threshold: 20,
        }
    }

    pub fn update_state(&mut self, operation_success: bool) -> String {
        if operation_success {
            self.consecutive_fail_count = 0;
            if self.consecutive_success_count < StatusState::MAX_CONSECUTIVE_COUNT {
                self.consecutive_success_count += 1;
            }
        } else {
            self.consecutive_success_count = 0;
            if self.consecutive_fail_count < StatusState::MAX_CONSECUTIVE_COUNT {
                self.consecutive_fail_count += 1;
            }
        }
        match self.current_state.as_str() {
            constants::SUCCESS_STATUS => {
                if self.consecutive_fail_count >= 1 {
                    self.current_state = constants::TRANSITIONING_STATUS.to_string();
                }
            }
            constants::TRANSITIONING_STATUS => {
                if self.consecutive_success_count >= 1 {
                    self.current_state = constants::SUCCESS_STATUS.to_string();
                } else if self.consecutive_fail_count >= self.transition_to_error_threshold {
                    self.current_state = constants::ERROR_STATUS.to_string();
                }
            }
            constants::ERROR_STATUS => {
                if self.consecutive_success_count >= 1 {
                    self.current_state = constants::TRANSITIONING_STATUS.to_string();
                }
            }
            _ => {
                self.current_state = constants::TRANSITIONING_STATUS.to_string();
            }
        }
        self.current_state.clone()
    }
}

#[cfg(test)]
mod tests {
    use crate::{common, constants, structs::*};
    use proxy_agent_shared::misc_helpers;
    use std::env;
    use std::fs::{self};
    use std::path::PathBuf;

    #[test]
    fn test_handler_env_file() {
        //Set the temp directory for handler environment json file
        let mut temp_test_path = env::temp_dir();
        temp_test_path.push("test_handler_env_file");

        //Clean up and ignore the clean up errors
        _ = fs::remove_dir_all(&temp_test_path);
        _ = misc_helpers::try_create_folder(&temp_test_path);

        let handler_env_file = temp_test_path.to_path_buf().join("HandlerEnvironment.json");

        // Case 1: eventsFolder exists
        let json_handler_linux: &str = r#"[{
            "version": 1.0,
            "handlerEnvironment": {
                "logFolder": "log", 
                "configFolder": "config", 
                "statusFolder": "status", 
                "heartbeatFile": "heartbeat.json", 
                "eventsFolder": "test_kusto" 
            }
        }]"#;

        let handler_env_obj: Vec<Handler> = serde_json::from_str(json_handler_linux).unwrap();
        _ = misc_helpers::json_write_to_file(&handler_env_obj, &handler_env_file);

        let events_folder = temp_test_path.join("test_kusto");
        _ = misc_helpers::try_create_folder(&events_folder);
        assert!(events_folder.exists(), "Events folder should exist");

        let handler_env = super::get_handler_environment(&temp_test_path);
        assert_eq!(handler_env.eventsFolder, Some("test_kusto".to_string()));

        // Case 2: eventsFolder does NOT exist
        _ = fs::remove_dir_all(&events_folder);
        assert!(!events_folder.exists(), "Events folder should NOT exist");
        let handler_env = super::get_handler_environment(&temp_test_path);
        assert_eq!(handler_env.eventsFolder, Some("test_kusto".to_string()));

        // Case 3: eventsFolder is not specified (None)
        let json_handler_no_events: &str = r#"[{
            "version": 1.0,
            "handlerEnvironment": {
                "logFolder": "log",
                "configFolder": "config",
                "statusFolder": "status",
                "heartbeatFile": "heartbeat.json"
            }
        }]"#;
        let handler_env_obj: Vec<Handler> = serde_json::from_str(json_handler_no_events).unwrap();
        _ = misc_helpers::json_write_to_file(&handler_env_obj, &handler_env_file);
        let handler_env = super::get_handler_environment(&temp_test_path);
        assert_eq!(handler_env.eventsFolder, None);

        // Case 4: eventsFolder is an empty string
        let json_handler_empty_events: &str = r#"[{
            "version": 1.0,
            "handlerEnvironment": {
                "logFolder": "log",
                "configFolder": "config",
                "statusFolder": "status",
                "heartbeatFile": "heartbeat.json",
                "eventsFolder": ""
            }
        }]"#;
        let handler_env_obj: Vec<Handler> =
            serde_json::from_str(json_handler_empty_events).unwrap();
        _ = misc_helpers::json_write_to_file(&handler_env_obj, &handler_env_file);
        let handler_env = super::get_handler_environment(&temp_test_path);
        assert_eq!(handler_env.eventsFolder, Some("".to_string()));

        _ = fs::remove_dir_all(&temp_test_path);
    }

    #[tokio::test]
    async fn test_status_file() {
        // Create temp directory for status folder
        let mut temp_test_path = env::temp_dir();
        temp_test_path.push("test_status_file");

        //Clean up and ignore the clean up errors
        _ = fs::remove_dir_all(&temp_test_path);
        _ = misc_helpers::try_create_folder(&temp_test_path);

        let status_folder: PathBuf = temp_test_path.join("status");

        //Set the config_seq_no value
        let seq_no = "0";
        let expected_status_file: &PathBuf = &temp_test_path.join("status").join("0.status");
        let handler_status = StatusObj {
            name: "test".to_string(),
            operation: "test".to_string(),
            configurationAppliedTime: "1-2-3".to_string(),
            code: 0,
            status: "test success".to_string(),
            formattedMessage: FormattedMessage {
                lang: "en-US".to_string(),
                message: "test status".to_string(),
            },
            substatus: Default::default(),
        };
        common::report_status(status_folder, &seq_no.to_string(), &handler_status);
        let status_obj =
            misc_helpers::json_read_from_file::<Vec<TopLevelStatus>>(&expected_status_file)
                .unwrap();
        assert_eq!(status_obj.len(), 1);
        assert_eq!(status_obj[0].status.name, "test".to_string());

        _ = fs::remove_dir_all(&temp_test_path);
    }

    #[test]
    fn test_get_file_path() {
        // Create temp directory for status folder
        let mut temp_test_path = env::temp_dir();
        temp_test_path.push("test_get_file_path");

        //Clean up and ignore the clean up errors
        _ = fs::remove_dir_all(&temp_test_path);
        _ = misc_helpers::try_create_folder(&temp_test_path);

        let status_folder: PathBuf = temp_test_path.join("status");
        let config_seq_no = "0";
        let expected_status_file: &PathBuf = &temp_test_path.join("status").join("0.status");
        let status_file = common::get_file_path(status_folder, config_seq_no, "status");
        assert_eq!(status_file, *expected_status_file);

        _ = fs::remove_dir_all(&temp_test_path);
    }

    #[tokio::test]
    async fn test_update_current_seq_no() {
        // Create temp directory for status folder
        let mut temp_test_path = env::temp_dir();
        temp_test_path.push("test_update_current_seq_no");

        //Clean up and ignore the clean up errors
        _ = fs::remove_dir_all(&temp_test_path);
        _ = misc_helpers::try_create_folder(&temp_test_path);

        // test invalid dir_path
        let exe_path = PathBuf::from("invalid_path");
        let config_seq_no = "0";
        let should_report_status = common::update_current_seq_no(config_seq_no, &exe_path);
        assert!(
            should_report_status.is_err(),
            "Error expected when update current seq no to an invalid_path"
        );

        // test valid dir_path
        let exe_path = &temp_test_path;

        // test seq no file not found, first write
        let config_seq_no = "0";
        let should_report_status = common::update_current_seq_no(config_seq_no, &exe_path).unwrap();
        assert!(should_report_status);
        let seq_no = common::get_current_seq_no(&exe_path);
        assert_eq!(seq_no, "0".to_string());

        // test seq no file found, write different seq no
        let config_seq_no = "1";
        let should_report_status = common::update_current_seq_no(config_seq_no, &exe_path).unwrap();
        assert!(should_report_status);
        let seq_no = common::get_current_seq_no(&exe_path);
        assert_eq!(seq_no, "1".to_string());

        // test seq no file found, write same seq no
        let config_seq_no = "1";
        let should_report_status = common::update_current_seq_no(config_seq_no, &exe_path).unwrap();
        assert!(!should_report_status);
        let seq_no = common::get_current_seq_no(&exe_path);
        assert_eq!(seq_no, "1".to_string());

        _ = fs::remove_dir_all(&temp_test_path);
    }

    #[tokio::test]
    async fn test_report_status_enable_command() {
        // Create temp directory for status folder
        let mut temp_test_path = env::temp_dir();
        temp_test_path.push("test_report_status_enable_command");

        //Clean up and ignore the clean up errors
        _ = fs::remove_dir_all(&temp_test_path);
        _ = misc_helpers::try_create_folder(&temp_test_path);
        let status_folder: PathBuf = temp_test_path.join("status");

        let config_seq_no = "0";
        let expected_status_file: &PathBuf = &temp_test_path.join("status").join("0.status");

        super::report_status_enable_command(status_folder, config_seq_no, None);
        let status_obj =
            misc_helpers::json_read_from_file::<Vec<TopLevelStatus>>(&expected_status_file)
                .unwrap();
        assert_eq!(status_obj.len(), 1);
        assert_eq!(status_obj[0].status.operation, "Enable");
        _ = fs::remove_dir_all(&temp_test_path);
    }

    #[tokio::test]
    async fn test_heartbeat_file() {
        // Create temp directory for status folder
        let mut temp_test_path = env::temp_dir();
        temp_test_path.push("test_heartbeat_file");

        //Clean up and ignore the clean up errors
        _ = fs::remove_dir_all(&temp_test_path);
        _ = misc_helpers::try_create_folder(&temp_test_path);

        let expected_heartbeat_file: PathBuf = temp_test_path.join("heartbeat.json");
        let heartbeat_obj = HeartbeatObj {
            status: "test".to_string(),
            code: "0".to_string(),
            formattedMessage: FormattedMessage {
                lang: constants::LANG_EN_US.to_string(),
                message: "test".to_string(),
            },
        };
        common::report_heartbeat(expected_heartbeat_file.to_path_buf(), heartbeat_obj);
        let heartbeat_obj =
            misc_helpers::json_read_from_file::<Vec<TopLevelHeartbeat>>(&expected_heartbeat_file)
                .unwrap();
        assert_eq!(heartbeat_obj.len(), 1);
        assert_eq!(heartbeat_obj[0].heartbeat.status, "test".to_string());

        _ = fs::remove_dir_all(&temp_test_path);
    }

    #[test]
    fn test_StatusState() {
        let mut status_state_obj = super::StatusState::new();

        // Case 1: Testing Success to Transitioning
        status_state_obj.current_state = constants::SUCCESS_STATUS.to_string();
        status_state_obj.consecutive_success_count = 2;
        let updated_state = status_state_obj.update_state(false);
        assert_eq!(updated_state, constants::TRANSITIONING_STATUS.to_string());

        // Case 2: Testing Transitioning to Success
        status_state_obj.current_state = constants::TRANSITIONING_STATUS.to_string();
        status_state_obj.consecutive_fail_count = 2;
        let updated_state = status_state_obj.update_state(true);
        assert_eq!(updated_state, constants::SUCCESS_STATUS.to_string());

        // Case 3: Testing Transitioning to Error
        status_state_obj.current_state = constants::TRANSITIONING_STATUS.to_string();
        status_state_obj.consecutive_fail_count = 19;
        let updated_state = status_state_obj.update_state(false);
        assert_eq!(updated_state, constants::ERROR_STATUS.to_string());

        // Case 4: Testing Error to Transitioning
        status_state_obj.current_state = constants::ERROR_STATUS.to_string();
        status_state_obj.consecutive_fail_count = 2;
        let updated_state = status_state_obj.update_state(true);
        assert_eq!(updated_state, constants::TRANSITIONING_STATUS.to_string());

        // Case 5: Testing report transitioning for the first time
        status_state_obj.current_state = "".to_string();
        let updated_state = status_state_obj.update_state(false);
        assert_eq!(updated_state, constants::TRANSITIONING_STATUS.to_string());

        // Case 6: Testing max consecutive count
        status_state_obj.consecutive_success_count = super::StatusState::MAX_CONSECUTIVE_COUNT;
        status_state_obj.current_state = status_state_obj.update_state(true);
        assert_eq!(
            status_state_obj.consecutive_success_count,
            super::StatusState::MAX_CONSECUTIVE_COUNT
        );
    }
}
