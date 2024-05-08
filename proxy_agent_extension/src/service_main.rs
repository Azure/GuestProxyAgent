// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use crate::common;
use crate::constants;
use crate::logger;
use crate::structs::*;
use proxy_agent_shared::proxy_agent_aggregate_status::GuestProxyAgentAggregateStatus;
use proxy_agent_shared::{misc_helpers, telemetry};
use std::io::Error;
use std::path::PathBuf;
use std::process::Command;
use std::process::Output;
use std::thread;
use std::time::Duration;

#[cfg(windows)]
pub mod windows_main;
#[cfg(windows)]
use proxy_agent_shared::service;

pub fn enable_agent() {
    let message = format!(
        "GuestProxyAgentExtension Enabling Agent, Version: {}, OS Arch: {}, OS Version: {}",
        misc_helpers::get_current_version(),
        misc_helpers::get_processor_arch(),
        misc_helpers::get_long_os_version()
    );
    telemetry::event_logger::write_event(
        telemetry::event_logger::INFO_LEVEL,
        message,
        "enable_agent",
        "service_main",
        &logger::get_logger_key(),
    );
    thread::spawn(|| {
        monitor_thread();
    });

    thread::spawn(|| {
        heartbeat_thread();
    });
}

fn heartbeat_thread() {
    let exe_path = misc_helpers::get_current_exe_dir();
    let handler_environment = common::get_handler_environment(exe_path);
    let heartbeat_file_path: PathBuf = handler_environment.heartbeatFile.to_string().into();
    let duration = std::time::Duration::from_secs(5 * 60);
    loop {
        let heartbeat_obj = HeartbeatObj {
            status: constants::HEARTBEAT_READY_STATUS.to_string(),
            code: constants::STATUS_CODE_OK.to_string(),
            formattedMessage: FormattedMessage {
                lang: constants::LANG_EN_US.to_string(),
                message: "Extension is running".to_string(),
            },
        };
        common::report_heartbeat(heartbeat_file_path.to_path_buf(), heartbeat_obj);
        thread::sleep(duration);
    }
}

fn monitor_thread() {
    let exe_path = misc_helpers::get_current_exe_dir();
    let handler_environment = common::get_handler_environment(exe_path.to_path_buf());
    let status_folder_path: PathBuf = handler_environment.statusFolder.to_string().into();
    let mut cache_seq_no = String::new();
    let proxyagent_file_version_in_extension = get_proxy_agent_file_version_in_extension();
    let mut status = StatusObj {
        name: constants::PLUGIN_NAME.to_string(),
        operation: constants::ENABLE_OPERATION.to_string(),
        configurationAppliedTime: misc_helpers::get_date_time_string(),
        code: constants::STATUS_CODE_OK,
        status: constants::SUCCESS_STATUS.to_string(),
        formattedMessage: FormattedMessage {
            lang: constants::LANG_EN_US.to_string(),
            message: "Update Proxy Agent command output successfully".to_string(),
        },
        substatus: Default::default(),
    };
    let mut status_state_obj = common::StatusState::new();
    let logger_key: &String = &logger::get_logger_key();
    let mut restored_in_error = false;
    let mut proxy_agent_update_reported: Option<telemetry::span::SimpleSpan> = None;
    loop {
        let current_seq_no = common::get_current_seq_no(exe_path.to_path_buf());
        if cache_seq_no != current_seq_no {
            telemetry::event_logger::write_event(
                telemetry::event_logger::INFO_LEVEL,
                format!(
                    "Current seq_no: {} does not match cached seq no {}",
                    current_seq_no.to_string(),
                    cache_seq_no.to_string()
                ),
                "monitor_thread",
                "service_main",
                logger_key,
            );
            cache_seq_no = current_seq_no.to_string();
            let proxyagent_service_file_version =
                misc_helpers::get_proxy_agent_version(common::get_proxy_agent_service_path());
            if proxyagent_file_version_in_extension != proxyagent_service_file_version {
                // Call setup tool to install or update proxy agent service
                telemetry::event_logger::write_event(
                    telemetry::event_logger::INFO_LEVEL,
                    format!("Version mismatch between file versions. ProxyAgentService File Version: {}, ProxyAgent in Extension File Version: {}", 
                        proxyagent_service_file_version, 
                        proxyagent_file_version_in_extension),
                    "monitor_thread",
                    "service_main",
                    logger_key,
                );
                let setup_tool = misc_helpers::path_to_string(common::setup_tool_exe_path());
                backup_proxyagent(&setup_tool);
                let mut install_command = Command::new(&setup_tool);
                // Set the current directory to the directory of the current executable for the setup tool to work properly
                install_command.current_dir(misc_helpers::get_current_exe_dir());
                let proxy_agent_update_command = telemetry::span::SimpleSpan::new();
                proxy_agent_update_reported = Some(telemetry::span::SimpleSpan::new()); 
                install_command.arg("install");
                let output = install_command.output();
                report_proxy_agent_service_status(
                    output,
                    exe_path.join("status"),
                    &Some(cache_seq_no.to_string()),
                    &mut status,
                    &mut status_state_obj,
                );
                // Time taken to update proxy agent service
                proxy_agent_update_command.write_event(
                    "Update Proxy Agent command completed",
                    "monitor_thread",
                    "service_main",
                    logger_key,
                );
            }
        }
        // Read proxy agent aggregate status file and get ProxyAgentAggregateStatus object
        report_proxy_agent_aggregate_status(
            &proxyagent_file_version_in_extension,
            &mut status,
            &mut status_state_obj,
            &mut restored_in_error,
        );

        // Time taken to report success for proxy agent service after update
        if status.status == constants::SUCCESS_STATUS.to_string() {
            match proxy_agent_update_reported.as_ref() {
                Some(proxy_agent_update_reported) => {
                    proxy_agent_update_reported.write_event(
                        "Proxy Agent Service is updated and reporting successful status",
                        "monitor_thread",
                        "service_main",
                        logger_key
                    );
                }
                None => {}
            }
            proxy_agent_update_reported = None;           
        } 
        #[cfg(windows)] 
        {
            report_ebpf_status(&mut status);
        }

        common::report_status(status_folder_path.to_path_buf(), &Some(cache_seq_no.to_string()), &status);

        thread::sleep(Duration::from_secs(15));
    }
}

#[cfg(windows)] 
fn report_ebpf_status(status_obj: &mut StatusObj) {
    match service::check_service_installed(constants::EBPF_CORE) {
        (true, message) => {
            logger::write(message.to_string());
            match service::check_service_installed(constants::EBPF_EXT) {
                (true, message) => {
                    logger::write(message.to_string());
                    status_obj.substatus = {
                        let mut substatus = status_obj.substatus.clone();
                        substatus.push(SubStatus {
                            name: constants::EBPF_SUBSTATUS_NAME.to_string(),
                            status: constants::SUCCESS_STATUS.to_string(),
                            code: constants::STATUS_CODE_OK,
                            formattedMessage: FormattedMessage {
                                lang: constants::LANG_EN_US.to_string(),
                                message: format!(
                                    "Ebpf Drivers successfully queried."
                                ),
                            },
                        });
                        substatus
                    };
                }
                (false, message) => {
                    logger::write(message.to_string());
                    status_obj.substatus = {
                        let mut substatus = status_obj.substatus.clone();
                        substatus.push(SubStatus {
                            name: constants::EBPF_SUBSTATUS_NAME.to_string(),
                            status: constants::ERROR_STATUS.to_string(),
                            code: constants::STATUS_CODE_NOT_OK,
                            formattedMessage: FormattedMessage {
                                lang: constants::LANG_EN_US.to_string(),
                                message: format!(
                                    "Ebpf Driver: {} unsuccessfully queried.", constants::EBPF_EXT
                                ),
                            },
                        });
                        substatus
                    };
                }
            }
        }
        (false, message) => {
            logger::write(message.to_string());
            status_obj.substatus = {
                let mut substatus = status_obj.substatus.clone();
                substatus.push(SubStatus {
                    name: constants::EBPF_SUBSTATUS_NAME.to_string(),
                    status: constants::ERROR_STATUS.to_string(),
                    code: constants::STATUS_CODE_NOT_OK,
                    formattedMessage: FormattedMessage {
                        lang: constants::LANG_EN_US.to_string(),
                        message: format!(
                            "Ebpf Driver: {} unsuccessfully queried.", constants::EBPF_CORE
                        ),
                    },
                });
                substatus
            };
        }
    }
   
}

fn backup_proxyagent(setup_tool: &String) {
    match Command::new(setup_tool).arg("backup").output() {
        Ok(output) => {
            let event_level = if output.status.success() {
                telemetry::event_logger::INFO_LEVEL
            } else {
                telemetry::event_logger::WARN_LEVEL
            };
            telemetry::event_logger::write_event(
                event_level,
                format!(
                    "Backup Proxy Agent command finished with stdoutput: {}, stderr: {}",
                    String::from_utf8_lossy(&output.stdout), 
                    String::from_utf8_lossy(&output.stderr)
                ),
                "backup_proxyagent",
                "service_main",
                &logger::get_logger_key(),
            );
        }
        Err(e) => {
            telemetry::event_logger::write_event(
                telemetry::event_logger::INFO_LEVEL,
                format!(
                    "Error in running Backup Proxy Agent command: {}",
                    e
                ),
                "backup_proxyagent",
                "service_main",
                &logger::get_logger_key(),
            );
        }
    }
}

fn report_proxy_agent_aggregate_status(
    proxyagent_file_version_in_extension: &String,
    status: &mut StatusObj,
    status_state_obj: &mut common::StatusState,
    restored_in_error: &mut bool,
) {
    let aggregate_status_file_path =
        PathBuf::from(constants::PROXY_AGENT_AGGREGATE_STATUS_FILE.to_string());

    let proxy_agent_aggregate_status_top_level: GuestProxyAgentAggregateStatus;
    match misc_helpers::json_read_from_file::<GuestProxyAgentAggregateStatus>(
        aggregate_status_file_path,
    ) {
        Ok(ok) => {
            telemetry::event_logger::write_state_event(
                constants::STATE_KEY_READ_PROXY_AGENT_STATUS_FILE,
                constants::SUCCESS_STATUS,
                telemetry::event_logger::INFO_LEVEL,
                "Successfully read proxy agent aggregate status file".to_string(),
                "report_proxy_agent_aggregate_status",
                "service_main",
                &logger::get_logger_key(),
            );
            proxy_agent_aggregate_status_top_level = ok;
            extension_substatus(
                proxy_agent_aggregate_status_top_level,
                proxyagent_file_version_in_extension,
                status,
                status_state_obj,
            );
        }
        Err(e) => {
            let error_message =
                        format!("Error in reading proxy agent aggregate status file: {}", e);
            telemetry::event_logger::write_state_event(
                constants::STATE_KEY_READ_PROXY_AGENT_STATUS_FILE,
                constants::ERROR_STATUS,
                telemetry::event_logger::INFO_LEVEL,
                error_message.to_string(),
                "report_proxy_agent_aggregate_status",
                "service_main",
                &logger::get_logger_key(),
            );
            status.status = status_state_obj.update_state(false);
            status.configurationAppliedTime = misc_helpers::get_date_time_string();
            status.substatus = {
                let mut substatus = Vec::new();
                substatus.push(SubStatus {
                    name: constants::PLUGIN_CONNECTION_NAME.to_string(),
                    status: constants::TRANSITIONING_STATUS.to_string(),
                    code: constants::STATUS_CODE_NOT_OK,
                    formattedMessage: FormattedMessage {
                        lang: constants::LANG_EN_US.to_string(),
                        message: error_message.to_string(),
                    },
                });
                substatus.push(SubStatus {
                    name: constants::PLUGIN_STATUS_NAME.to_string(),
                    status: constants::TRANSITIONING_STATUS.to_string(),
                    code: constants::STATUS_CODE_NOT_OK,
                    formattedMessage: FormattedMessage {
                        lang: constants::LANG_EN_US.to_string(),
                        message: error_message.to_string(),
                    },
                });
                substatus
            };
        }
    }
    if *restored_in_error == false {
        *restored_in_error = restore_purge_proxyagent(status);
    }
}

fn extension_substatus(
    proxy_agent_aggregate_status_top_level: GuestProxyAgentAggregateStatus,
    proxyagent_file_version_in_extension: &String,
    status: &mut StatusObj,
    status_state_obj: &mut common::StatusState,
) {
    let proxy_agent_aggregate_status_obj =
        proxy_agent_aggregate_status_top_level.proxyAgentStatus;

    let proxy_agent_aggregate_status_file_version =
        proxy_agent_aggregate_status_obj.version.to_string();
    if proxy_agent_aggregate_status_file_version != *proxyagent_file_version_in_extension {
        status.status = status_state_obj.update_state(false);
        let version_mismatch_message = format!("Proxy agent aggregate status file version {} does not match proxy agent file version in extension {}", proxy_agent_aggregate_status_file_version, proxyagent_file_version_in_extension);
        telemetry::event_logger::write_state_event(
            constants::STATE_KEY_FILE_VERSION,
            constants::ERROR_STATUS,
            telemetry::event_logger::INFO_LEVEL,
            version_mismatch_message.to_string(),
            "extension_substatus",
            "service_main",
            &logger::get_logger_key(),
        );
        status.configurationAppliedTime = misc_helpers::get_date_time_string();
        status.substatus = {
            let mut substatus = Vec::new();
            substatus.push(SubStatus {
                name: constants::PLUGIN_CONNECTION_NAME.to_string(),
                status: constants::TRANSITIONING_STATUS.to_string(),
                code: constants::STATUS_CODE_NOT_OK,
                formattedMessage: FormattedMessage {
                    lang: constants::LANG_EN_US.to_string(),
                    message: version_mismatch_message.to_string(),
                },
            });
            substatus.push(SubStatus {
                name: constants::PLUGIN_STATUS_NAME.to_string(),
                status: constants::TRANSITIONING_STATUS.to_string(),
                code: constants::STATUS_CODE_NOT_OK,
                formattedMessage: FormattedMessage {
                    lang: constants::LANG_EN_US.to_string(),
                    message: version_mismatch_message.to_string(),
                },
            });
            substatus
        };
    }
    // Success Status and report to status file for CRP to read from
    else {
        let substatus_proxy_agent_message;
        match serde_json::to_string(&proxy_agent_aggregate_status_obj) {
            Ok(proxy_agent_aggregate_status) => {
                substatus_proxy_agent_message = proxy_agent_aggregate_status;
            }
            Err(e) => {
                let error_message =
                    format!("Error in serializing proxy agent aggregate status: {}", e);
                logger::write(error_message.to_string());
                substatus_proxy_agent_message = error_message;
            }
        }
        let substatus_proxy_agent_connection_message: String;
        if !proxy_agent_aggregate_status_top_level
            .proxyConnectionSummary
            .is_empty()
        {
            let proxy_agent_aggregate_connection_status_obj =
                proxy_agent_aggregate_status_top_level.proxyConnectionSummary;
            match serde_json::to_string(&proxy_agent_aggregate_connection_status_obj) {
                // TODO: only select Top X connection summary if the connection status is too big
                Ok(proxy_agent_aggregate_connection_status) => {
                    substatus_proxy_agent_connection_message =
                        proxy_agent_aggregate_connection_status;
                }
                Err(e) => {
                    let error_message = format!(
                        "Error in serializing proxy agent aggregate connection status: {}",
                        e
                    );
                    logger::write(error_message.to_string());
                    substatus_proxy_agent_connection_message = error_message;
                }
            }
        } else {
            logger::write(("proxy connection summary is empty").to_string());
            substatus_proxy_agent_connection_message =
                "proxy connection summary is empty".to_string();
        }

        status.substatus = {
            let mut substatus = Vec::new();
            substatus.push(SubStatus {
                name: constants::PLUGIN_CONNECTION_NAME.to_string(),
                status: constants::SUCCESS_STATUS.to_string(),
                code: constants::STATUS_CODE_OK,
                formattedMessage: FormattedMessage {
                    lang: constants::LANG_EN_US.to_string(),
                    message: substatus_proxy_agent_connection_message.to_string(),
                },
            });
            substatus.push(SubStatus {
                name: constants::PLUGIN_STATUS_NAME.to_string(),
                status: constants::SUCCESS_STATUS.to_string(),
                code: constants::STATUS_CODE_OK,
                formattedMessage: FormattedMessage {
                    lang: constants::LANG_EN_US.to_string(),
                    message: substatus_proxy_agent_message.to_string(),
                },
            });
            substatus
        };
        status.status = status_state_obj.update_state(true);
        status.configurationAppliedTime = misc_helpers::get_date_time_string();
        telemetry::event_logger::write_state_event(
            constants::STATE_KEY_FILE_VERSION,
            constants::SUCCESS_STATUS,
            telemetry::event_logger::INFO_LEVEL,
            substatus_proxy_agent_connection_message.to_string(),
            "extension_substatus",
            "service_main",
            &logger::get_logger_key(),
        );

    }
}

fn restore_purge_proxyagent(status: &mut StatusObj) -> bool {
    let setup_tool = misc_helpers::path_to_string(common::setup_tool_exe_path());
    if status.status == constants::ERROR_STATUS.to_string() {
        let output = Command::new(&setup_tool).arg("restore").output();
        match output {
            Ok(output) => {
                let event_level = if output.status.success() {
                    telemetry::event_logger::INFO_LEVEL
                } else {
                    telemetry::event_logger::WARN_LEVEL
                };
                telemetry::event_logger::write_event(
                    event_level,
                    format!(
                        "Restore Proxy Agent command finished with stdoutput: {}, stderr: {}",
                        String::from_utf8_lossy(&output.stdout), 
                        String::from_utf8_lossy(&output.stderr)
                    ),
                    "restore_purge_proxyagent",
                    "service_main",
                    &logger::get_logger_key(),
                );
            }
            Err(e) => {
                telemetry::event_logger::write_event(
                    telemetry::event_logger::INFO_LEVEL,
                    format!(
                        "Error in running Restore Proxy Agent command: {}",
                        e
                    ),
                    "restore_purge_proxyagent",
                    "service_main",
                    &logger::get_logger_key(),
                );
            }
        } 
        return true;
    }
    else if status.status == constants::SUCCESS_STATUS.to_string() {
        let output =  Command::new(setup_tool).arg("purge").output();
        match output {
            Ok(output) => {
                let event_level = if output.status.success() {
                    telemetry::event_logger::INFO_LEVEL
                } else {
                    telemetry::event_logger::WARN_LEVEL
                };
                telemetry::event_logger::write_event(
                    event_level,
                    format!(
                        "Purge Proxy Agent command finished with stdoutput: {}, stderr: {}",
                        String::from_utf8_lossy(&output.stdout), 
                        String::from_utf8_lossy(&output.stderr)
                    ),
                    "restore_purge_proxyagent",
                    "service_main",
                    &logger::get_logger_key(),
                );
            }
            Err(e) => {
                telemetry::event_logger::write_event(
                    telemetry::event_logger::INFO_LEVEL,
                    format!(
                        "Error in running Purge Proxy Agent command: {}",
                        e
                    ),
                    "restore_purge_proxyagent",
                    "service_main",
                    &logger::get_logger_key(),
                );
            }
        }
        return true;
    } else {
        return false;
    }
}

fn report_proxy_agent_service_status(
    output: Result<Output, Error>,
    status_folder: PathBuf,
    seq_no: &Option<String>,
    status: &mut StatusObj,
    status_state_obj: &mut common::StatusState,
) {
    match output {
        Ok(output) => {
            logger::write(format!(
                "Update Proxy Agent command output: {}",
                String::from_utf8_lossy(&output.stdout)
            ));
            if output.status.success() {
                logger::write("Update Proxy Agent command output successfully".to_string());
                status.configurationAppliedTime = misc_helpers::get_date_time_string();
                status.code = constants::STATUS_CODE_OK;
                status.status = status_state_obj.update_state(false);
                status.formattedMessage.message =
                    "Update Proxy Agent command output successfully".to_string();
                status.substatus = Default::default();
                common::report_status(status_folder, seq_no, &status);
            } else {
                telemetry::event_logger::write_event(
                    telemetry::event_logger::INFO_LEVEL,
                    format!(
                        "Update Proxy Agent command failed with error: {}",
                        String::from_utf8_lossy(&output.stderr)
                    ),
                    "report_proxy_agent_service_status",
                    "service_main",
                    &logger::get_logger_key(),
                );
                status.configurationAppliedTime = misc_helpers::get_date_time_string();
                status.code = output
                    .status
                    .code()
                    .unwrap_or_else(|| constants::STATUS_CODE_NOT_OK);
                status.status = status_state_obj.update_state(false);
                status.formattedMessage.message =
                    "Update Proxy Agent command failed with error".to_string();
                status.substatus = Default::default();
                common::report_status(status_folder, seq_no, &status);
            }
        }
        Err(e) => {
            telemetry::event_logger::write_event(
                telemetry::event_logger::INFO_LEVEL,
                format!(
                    "Error in running Update Proxy Agent command: {}",
                    e
                ),
                "report_proxy_agent_service_status",
                "service_main",
                &logger::get_logger_key(),
            );
            // report proxyagent service update failed state
            status.configurationAppliedTime = misc_helpers::get_date_time_string();
            status.code = constants::STATUS_CODE_NOT_OK;
            status.status = status_state_obj.update_state(false);
            status.formattedMessage.message =
                format!("Update Proxy Agent command failed with error: {}", e);
            status.substatus = Default::default();
            common::report_status(status_folder, seq_no, &status);
        }
    }
}

fn get_proxy_agent_file_version_in_extension() -> String {
    // File version of proxy agent service already downloaded by VM Agent
    let path = common::get_proxy_agent_exe_path();
    let version = misc_helpers::get_proxy_agent_version(path.to_path_buf());
    logger::write(format!("get_proxy_agent_file_version_in_extension: get GuestProxyAgent version {} from file {}", version.to_string(), misc_helpers::path_to_string(path.to_path_buf())));
    version
}

// test report status
#[cfg(test)]
mod tests {
    use crate::constants;
    use crate::logger;
    use crate::structs::*;
    use proxy_agent_shared::misc_helpers;
    use proxy_agent_shared::proxy_agent_aggregate_status::*;
    use std::env;
    use std::fs;
   
    #[cfg(windows)]
    use std::io::Write;
    #[cfg(windows)]
    use std::path::PathBuf;
    #[cfg(windows)]
    use std::process::Command;

    #[test]
    fn report_proxy_agent_service_status() {
        #[cfg(windows)]
        {
            // Create temp directory for status folder
            let mut temp_test_path = env::temp_dir();
            temp_test_path.push("test_status_file");

            //Clean up and ignore the clean up errors
            _ = fs::remove_dir_all(&temp_test_path);
            _ = misc_helpers::try_create_folder(temp_test_path.to_path_buf());
            let status_folder: PathBuf = temp_test_path.join("status");
            let log_folder: String = temp_test_path.to_str().unwrap().to_string();
            logger::init_logger(log_folder, constants::SERVICE_LOG_FILE);
    
    
            let mut test_good = temp_test_path.clone();
            test_good.push("test.ps1");
            let mut file = fs::File::create(&test_good).unwrap();
            file.write(b"\"Hello World\"").unwrap();

            let output = Command::new("powershell.exe").args(&test_good).output();

            //Set the config_seq_no value
            let seq_no = "0";
            let expected_status_file: &PathBuf = &temp_test_path.join("status").join("0.status");

            let mut status = StatusObj {
                name: constants::PLUGIN_NAME.to_string(),
                operation: constants::ENABLE_OPERATION.to_string(),
                configurationAppliedTime: misc_helpers::get_date_time_string(),
                code: constants::STATUS_CODE_OK,
                status: constants::SUCCESS_STATUS.to_string(),
                formattedMessage: FormattedMessage {
                    lang: constants::LANG_EN_US.to_string(),
                    message: "Update Proxy Agent command output successfully".to_string(),
                },
                substatus: Default::default(),
            };
            let mut status_state_obj = super::common::StatusState::new();

            super::report_proxy_agent_service_status(
                output,
                status_folder,
                &Some(seq_no.to_string()),
                &mut status,
                &mut status_state_obj,
            );

            let handler_status = misc_helpers::json_read_from_file::<Vec<TopLevelStatus>>(
                expected_status_file.to_path_buf(),
            )
            .unwrap();
            assert!(handler_status.len() == 1);
            assert_eq!(handler_status[0].status.code, 0);

            let status_folder_bad = temp_test_path.join("status_bad");
            let mut test_bad = temp_test_path.clone();
            test_bad.push("&?@(random)?.ps1");

            let output = Command::new("powershell.exe").args(&test_bad).output();

            let expected_status_file_bad: &PathBuf =
                &temp_test_path.join("status_bad").join("0.status");

            super::report_proxy_agent_service_status(
                output,
                status_folder_bad,
                &Some(seq_no.to_string()),
                &mut status,
                &mut status_state_obj,
            );
            let handler_status_bad = misc_helpers::json_read_from_file::<Vec<TopLevelStatus>>(
                expected_status_file_bad.to_path_buf(),
            )
            .unwrap();
            assert!(handler_status_bad.len() == 1);
            assert_eq!(handler_status_bad[0].status.code, 1);

            //Clean up and ignore the clean up errors
            _ = fs::remove_dir_all(&temp_test_path);
        }
    }

    #[test]
    fn test_proxyagent_service_success_status() {
        // Create temp directory for status folder
        let mut temp_test_path = env::temp_dir();
        temp_test_path.push("test_status_file");

        //Clean up and ignore the clean up errors
        _ = fs::remove_dir_all(&temp_test_path);
        _ = misc_helpers::try_create_folder(temp_test_path.to_path_buf());
        let log_folder: String = temp_test_path.to_str().unwrap().to_string();
        logger::init_logger(log_folder, constants::SERVICE_LOG_FILE);

        let proxy_agent_status_obj = ProxyAgentStatus {
            version: "1.0.0".to_string(),
            status: OveralState::SUCCESS.to_string(),
            monitorStatus: ProxyAgentDetailStatus{
                status: ModuleState::RUNNING.to_string(),
                message: "test".to_string(),
                states: None,
            },
            keyLatchStatus: ProxyAgentDetailStatus{
                status: ModuleState::RUNNING.to_string(),
                message: "test".to_string(),
                states: None,
            },
            ebpfProgramStatus: ProxyAgentDetailStatus{
                status: ModuleState::RUNNING.to_string(),
                message: "test".to_string(),
                states: None,
            },
            proxyListenerStatus: ProxyAgentDetailStatus{
                status: ModuleState::RUNNING.to_string(),
                message: "test".to_string(),
                states: None,
            },
            telemetryLoggerStatus: ProxyAgentDetailStatus{
                status: ModuleState::RUNNING.to_string(),
                message: "test".to_string(),
                states: None,
            },
            proxyConnectionsCount: 1,
        };

        let proxy_connection_summary_obj = ProxyConnectionSummary {
            userName: "test".to_string(),
            userGroups: vec!["test".to_string()],
            ip: "test".to_string(),
            port: 1,
            processFullPath: "test".to_string(),
            processCmdLine: "test".to_string(),
            responseStatus: "test".to_string(),
            count: 1,
        };

        let toplevel_status = GuestProxyAgentAggregateStatus {
            timestamp: misc_helpers::get_date_time_string(),
            proxyAgentStatus: proxy_agent_status_obj,
            proxyConnectionSummary: vec![proxy_connection_summary_obj],
        };

        let mut status = StatusObj {
            name: constants::PLUGIN_NAME.to_string(),
            operation: constants::ENABLE_OPERATION.to_string(),
            configurationAppliedTime: misc_helpers::get_date_time_string(),
            code: constants::STATUS_CODE_OK,
            status: constants::SUCCESS_STATUS.to_string(),
            formattedMessage: FormattedMessage {
                lang: constants::LANG_EN_US.to_string(),
                message: "Update Proxy Agent command output successfully".to_string(),
            },
            substatus: Default::default(),
        };

        let mut status_state_obj = super::common::StatusState::new();

        let proxyagent_file_version_in_extension: &String = &"1.0.0".to_string();

        super::extension_substatus(
            toplevel_status,
            proxyagent_file_version_in_extension,
            &mut status,
            &mut status_state_obj,
        );  
        assert_eq!(status.status, constants::SUCCESS_STATUS.to_string());

        //Clean up and ignore the clean up errors
        _ = fs::remove_dir_all(&temp_test_path);
    }

    #[test]
    fn test_report_ebpf_status() {
        #[cfg(windows)] {
            // Create temp directory for status folder
            let mut temp_test_path = env::temp_dir();
            temp_test_path.push("test_status_file");

            //Clean up and ignore the clean up errors
            _ = fs::remove_dir_all(&temp_test_path);
            _ = misc_helpers::try_create_folder(temp_test_path.to_path_buf());
            let log_folder: String = temp_test_path.to_str().unwrap().to_string();
            logger::init_logger(log_folder, constants::SERVICE_LOG_FILE);

            let mut status = StatusObj {
                name: constants::PLUGIN_NAME.to_string(),
                operation: constants::ENABLE_OPERATION.to_string(),
                configurationAppliedTime: misc_helpers::get_date_time_string(),
                code: constants::STATUS_CODE_OK,
                status: constants::SUCCESS_STATUS.to_string(),
                formattedMessage: FormattedMessage {
                    lang: constants::LANG_EN_US.to_string(),
                    message: "Update Proxy Agent command output successfully".to_string(),
                },
                substatus: {
                    let mut substatus = Vec::new();
                    substatus.push(SubStatus {
                        name: constants::PLUGIN_CONNECTION_NAME.to_string(),
                        status: constants::SUCCESS_STATUS.to_string(),
                        code: constants::STATUS_CODE_OK,
                        formattedMessage: FormattedMessage {
                            lang: constants::LANG_EN_US.to_string(),
                            message: "test".to_string(),
                        },
                    });
                    substatus.push(SubStatus {
                        name: constants::PLUGIN_STATUS_NAME.to_string(),
                        status: constants::SUCCESS_STATUS.to_string(),
                        code: constants::STATUS_CODE_OK,
                        formattedMessage: FormattedMessage {
                            lang: constants::LANG_EN_US.to_string(),
                            message: "test".to_string(),
                        },
                    });
                    substatus
                }
            };

            super::report_ebpf_status(&mut status);
            assert_eq!(status.substatus[0].name, constants::PLUGIN_CONNECTION_NAME.to_string());
            assert_eq!(status.substatus[1].name, constants::PLUGIN_STATUS_NAME.to_string());
            assert_eq!(status.substatus[2].name, constants::EBPF_SUBSTATUS_NAME.to_string());

            //Clean up and ignore the clean up errors
            _ = fs::remove_dir_all(&temp_test_path);
        }
    }
}
