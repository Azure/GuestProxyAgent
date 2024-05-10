// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use crate::common;
use crate::constants;
use crate::logger;
use crate::structs;
use crate::structs::FormattedMessage;
use crate::structs::HandlerEnvironment;
use crate::structs::TopLevelStatus;
use proxy_agent_shared::{misc_helpers, telemetry};
use std::fs;
use std::io::{Error, ErrorKind};
use std::path::PathBuf;
use std::process;

#[cfg(windows)]
use proxy_agent_shared::service;

pub fn get_handler_environment(exe_path: PathBuf) -> HandlerEnvironment {
    let mut handler_env_path: PathBuf = exe_path.to_path_buf();
    handler_env_path.push(constants::HANDLER_ENVIRONMENT_FILE);
    let handler_env_file: Vec<structs::Handler>;
    match misc_helpers::json_read_from_file(handler_env_path) {
        Ok(temp) => {
            handler_env_file = temp;
        }
        Err(e) => {
            eprintln!("Error in reading handler env file: {e}");
            process::exit(constants::EXIT_CODE_HANDLERENV_ERR);
        }
    }
    if handler_env_file.len() == 0 {
        eprintln!("Handler environment file is empty");
        process::exit(constants::EXIT_CODE_HANDLERENV_ERR);
    }
    let root_handler_environment = handler_env_file[0].handlerEnvironment.clone();
    root_handler_environment
}

pub fn report_heartbeat(heartbeat_file_path: PathBuf, heartbeat_obj: structs::HeartbeatObj) {
    //Heartbeat Instance
    let root_heartbeat_obj = structs::TopLevelHeartbeat {
        version: constants::VERSION.to_string(),
        heartbeat: heartbeat_obj,
    };

    let root_obj: Vec<structs::TopLevelHeartbeat> = vec![root_heartbeat_obj];
    let root_heartbeat;
    match serde_json::to_string(&root_obj) {
        Ok(temp) => {
            root_heartbeat = temp;
        }
        Err(e) => {
            logger::write(format!("Error in serializing heartbeat object: {e}"));
            return;
        }
    }
    match fs::write(heartbeat_file_path.to_path_buf(), &root_heartbeat) {
        Ok(_) => {
            logger::write(format!(
                "HeartBeat file created: {:?}",
                heartbeat_file_path.to_path_buf()
            ));
        }
        Err(e) => {
            logger::write(format!("Error in creating HeartBeat file: {:?}", e));
        }
    }
}

pub fn get_file_path(
    status_folder: PathBuf,
    config_seq_no: &Option<String>,
    file_extension: &str,
) -> PathBuf {
    let mut file: PathBuf = status_folder;
    _ = misc_helpers::try_create_folder(file.clone());
    match config_seq_no {
        Some(config_seq_no) => {
            file.push(config_seq_no);
        }
        None => {
            file.push("");
        }
    }
    file.set_extension(file_extension);
    file
}

pub fn report_status(
    status_folder_path: PathBuf,
    config_seq_no: &Option<String>,
    status_obj: &structs::StatusObj,
) {
    //Status Instance
    let status_file: PathBuf = get_file_path(
        status_folder_path,
        &config_seq_no,
        constants::STATUS_FILE_SUFFIX,
    );

    let current_datetime: String = misc_helpers::get_date_time_string_with_miliseconds();
    let root_status_obj = structs::TopLevelStatus {
        version: constants::VERSION.to_string(),
        timestampUTC: current_datetime,
        status: status_obj.clone(),
    };

    let root_vec: Vec<TopLevelStatus> = vec![root_status_obj];
    let root_status;

    match serde_json::to_string(&root_vec) {
        Ok(temp) => {
            root_status = temp;
        }
        Err(e) => {
            logger::write(format!("Error in serializing status object: {e}"));
            return;
        }
    }
    // TODO: retry if write failed
    match fs::write(status_file.to_path_buf(), root_status) {
        Ok(_) => {
            logger::write(format!("Status file created: {:?}", status_file));
        }
        Err(e) => {
            logger::write(format!("Error in creating status file: {:?}", e));
        }
    }
}

pub fn update_current_seq_no(
    config_seq_no: &Option<String>,
    exe_path: PathBuf,
) -> std::io::Result<bool> {
    let mut should_report_status = true;
    match config_seq_no {
        Some(new_seq_no) => {
            logger::write(format!("enable command with new seq no: {new_seq_no}"));
            let current_seq_no_stored_file: PathBuf = exe_path.join(constants::CURRENT_SEQ_NO_FILE);
            match fs::read_to_string(current_seq_no_stored_file.to_path_buf()) {
                Ok(seq_no) => {
                    if seq_no != *new_seq_no {
                        logger::write(format!("updating seq no from {} to {}", seq_no, new_seq_no));
                        _ = fs::write(current_seq_no_stored_file.to_path_buf(), new_seq_no);
                    } else {
                        logger::write("no update on seq no".to_string());
                        should_report_status = false;
                    }
                }
                Err(_e) => {
                    logger::write(format!(
                        "no seq no found, writing seq no {} to file",
                        new_seq_no
                    ));
                    _ = fs::write(current_seq_no_stored_file.to_path_buf(), new_seq_no);
                }
            }
        }
        None => {
            logger::write("No config seq no found for enable command".to_string());
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "No config seq no found for enable command",
            ));
        }
    }
    Ok(should_report_status)
}

pub fn get_current_seq_no(exe_path: PathBuf) -> String {
    let current_seq_no_stored_file: PathBuf = exe_path.join(constants::CURRENT_SEQ_NO_FILE);
    match fs::read_to_string(current_seq_no_stored_file) {
        Ok(seq_no) => {
            logger::write(format!("Current seq no: {}", seq_no));
            return seq_no;
        }
        Err(e) => {
            logger::write(format!("Error reading current seq no file: {:?}", e));
            return "".to_string();
        }
    }
}

pub fn get_proxy_agent_service_path() -> PathBuf {
    #[cfg(windows)]
    {
        return service::query_service_executable_path(constants::PROXY_AGENT_SERVICE_NAME);
    }
    #[cfg(not(windows))]
    {
        // linux service harded to this soft link
        return PathBuf::from(proxy_agent_shared::linux::SERVICE_PACKAGE_LINK_NAME)
            .join("GuestProxyAgent");
    }
}

pub fn get_proxy_agent_exe_path() -> PathBuf {
    let exe_path = misc_helpers::get_current_exe_dir();
    logger::write(
        "Current proxy agent exe path: ".to_string()
            + &misc_helpers::path_to_string(exe_path.clone()),
    );

    #[cfg(windows)]
    {
        exe_path.join("ProxyAgent/ProxyAgent/GuestProxyAgent.exe")
    }
    #[cfg(not(windows))]
    {
        exe_path.join("ProxyAgent/ProxyAgent/GuestProxyAgent")
    }    
}

pub fn report_status_enable_command(
    status_folder: PathBuf,
    config_seq_no: &Option<String>,
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

pub fn start_event_logger(logger_key: &str) {
    logger::write("starting event logger".to_string());
    let interval: std::time::Duration = std::time::Duration::from_secs(60);
    let max_event_file_count: usize = 50;
    let exe_path = misc_helpers::get_current_exe_dir();
    let event_folder = PathBuf::from(
        common::get_handler_environment(exe_path.to_path_buf())
            .eventsFolder
            .to_string(),
    );
    telemetry::event_logger::start_async(event_folder, interval, max_event_file_count, logger_key);
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
        return self.current_state.clone();
    }
}

#[cfg(test)]
mod tests {
    use crate::{common, constants, structs::*};
    use proxy_agent_shared::misc_helpers;
    use std::env;
    use std::fs::{self};
    use std::io::Error;
    use std::io::ErrorKind;
    use std::path::PathBuf;

    #[test]
    fn test_handler_env_file() {
        //Set the temp directory for handler environment json file
        let mut temp_test_path = env::temp_dir();
        temp_test_path.push("test_handler_env_file");

        //Clean up and ignore the clean up errors
        _ = fs::remove_dir_all(&temp_test_path);
        _ = misc_helpers::try_create_folder(temp_test_path.to_path_buf());

        //Add HandlerEnvironment.json in the temp directory
        let handler_env_file = temp_test_path.to_path_buf().join("HandlerEnvironment.json");

        //Create raw handler environment json string
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

        //Deserialize handler environment json string
        let handler_env_obj: Vec<Handler> = serde_json::from_str(json_handler_linux).unwrap();

        //Write the deserialized json object to HandlerEnvironment.json file
        _ = misc_helpers::json_write_to_file(&handler_env_obj, handler_env_file);

        let handler_env = super::get_handler_environment(temp_test_path.to_path_buf());
        assert_eq!(handler_env.logFolder, "log".to_string());
        assert_eq!(handler_env.configFolder, "config".to_string());
        assert_eq!(handler_env.statusFolder, "status".to_string());
        assert_eq!(handler_env.heartbeatFile, "heartbeat.json".to_string());
        assert_eq!(handler_env.eventsFolder, "test_kusto".to_string());
        assert_eq!(handler_env.deploymentid, None);
        assert_eq!(handler_env.rolename, None);
        assert_eq!(handler_env.instance, None);
        assert_eq!(handler_env.hostResolverAddress, None);

        _ = fs::remove_dir_all(&temp_test_path);
    }

    #[test]
    fn test_status_file() {
        // Create temp directory for status folder
        let mut temp_test_path = env::temp_dir();
        temp_test_path.push("test_status_file");

        //Clean up and ignore the clean up errors
        _ = fs::remove_dir_all(&temp_test_path);
        _ = misc_helpers::try_create_folder(temp_test_path.to_path_buf());

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
        common::report_status(status_folder, &Some(seq_no.to_string()), &handler_status);
        let status_obj = misc_helpers::json_read_from_file::<Vec<TopLevelStatus>>(
            expected_status_file.to_path_buf(),
        )
        .unwrap();
        assert!(status_obj.len() == 1);
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
        _ = misc_helpers::try_create_folder(temp_test_path.to_path_buf());

        let status_folder: PathBuf = temp_test_path.join("status");
        let config_seq_no = "0";
        let expected_status_file: &PathBuf = &temp_test_path.join("status").join("0.status");
        let status_file =
            common::get_file_path(status_folder, &Some(config_seq_no.to_string()), "status");
        assert_eq!(status_file, *expected_status_file);

        _ = fs::remove_dir_all(&temp_test_path);
    }

    #[test]
    fn test_update_current_seq_no() {
        // Create temp directory for status folder
        let mut temp_test_path = env::temp_dir();
        temp_test_path.push("test_update_current_seq_no");

        //Clean up and ignore the clean up errors
        _ = fs::remove_dir_all(&temp_test_path);
        let log_folder: String = temp_test_path.to_str().unwrap().to_string();
        super::logger::init_logger(log_folder, "log.txt");
        _ = misc_helpers::try_create_folder(temp_test_path.to_path_buf());

        let config_seq_no = None;
        let exe_path = &temp_test_path;

        let should_report_status: Error =
            common::update_current_seq_no(&config_seq_no, exe_path.to_path_buf()).unwrap_err();
        assert!(should_report_status.kind() == ErrorKind::InvalidInput);
        let seq_no = common::get_current_seq_no(exe_path.to_path_buf());
        assert_eq!(seq_no, "".to_string());

        let config_seq_no = "0";
        let should_report_status =
            common::update_current_seq_no(&Some(config_seq_no.to_string()), exe_path.to_path_buf())
                .unwrap();
        assert_eq!(should_report_status, true);
        let seq_no = common::get_current_seq_no(exe_path.to_path_buf());
        assert_eq!(seq_no, "0".to_string());

        let config_seq_no = "1";
        let should_report_status =
            common::update_current_seq_no(&Some(config_seq_no.to_string()), exe_path.to_path_buf())
                .unwrap();
        assert_eq!(should_report_status, true);
        let seq_no = common::get_current_seq_no(exe_path.to_path_buf());
        assert_eq!(seq_no, "1".to_string());

        let config_seq_no = "1";
        let should_report_status =
            common::update_current_seq_no(&Some(config_seq_no.to_string()), exe_path.to_path_buf())
                .unwrap();
        assert_eq!(should_report_status, false);
        let seq_no = common::get_current_seq_no(exe_path.to_path_buf());
        assert_eq!(seq_no, "1".to_string());

        _ = fs::remove_dir_all(&temp_test_path);
    }

    #[test]
    fn test_report_status_enable_command() {
        // Create temp directory for status folder
        let mut temp_test_path = env::temp_dir();
        temp_test_path.push("test_report_status_enable_command");

        //Clean up and ignore the clean up errors
        _ = fs::remove_dir_all(&temp_test_path);
        _ = misc_helpers::try_create_folder(temp_test_path.to_path_buf());

        let status_folder: PathBuf = temp_test_path.join("status");
        let config_seq_no = "0";
        let expected_status_file: &PathBuf = &temp_test_path.join("status").join("0.status");

        super::report_status_enable_command(status_folder, &Some(config_seq_no.to_string()), None);
        let status_obj = misc_helpers::json_read_from_file::<Vec<TopLevelStatus>>(
            expected_status_file.to_path_buf(),
        )
        .unwrap();
        assert!(status_obj.len() == 1);
        assert_eq!(status_obj[0].status.operation, "Enable");
        _ = fs::remove_dir_all(&temp_test_path);
    }

    #[test]
    fn test_heartbeat_file() {
        // Create temp directory for status folder
        let mut temp_test_path = env::temp_dir();
        temp_test_path.push("test_heartbeat_file");

        //Clean up and ignore the clean up errors
        _ = fs::remove_dir_all(&temp_test_path);
        let log_folder: String = temp_test_path.to_str().unwrap().to_string();
        super::logger::init_logger(log_folder, "log.txt");
        _ = misc_helpers::try_create_folder(temp_test_path.to_path_buf());

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
        let heartbeat_obj = misc_helpers::json_read_from_file::<Vec<TopLevelHeartbeat>>(
            expected_heartbeat_file.to_path_buf(),
        )
        .unwrap();
        assert!(heartbeat_obj.len() == 1);
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
