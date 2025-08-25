// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use crate::common;
use crate::constants;
use crate::logger;
use crate::structs::*;
use proxy_agent_shared::logger::LoggerLevel;
use proxy_agent_shared::proxy_agent_aggregate_status::{
    self, GuestProxyAgentAggregateStatus, ProxyConnectionSummary,
};
use proxy_agent_shared::telemetry::event_logger;
use proxy_agent_shared::{misc_helpers, telemetry};
use service_state::ServiceState;
use std::io::Error;
use std::path::PathBuf;
use std::process::Command;
use std::process::Output;
use std::time::Duration;

pub mod service_state;
#[cfg(windows)]
pub mod windows_main;
#[cfg(windows)]
use proxy_agent_shared::service;

const MAX_STATE_COUNT: u32 = 120;

pub fn run() {
    let message = format!(
        "==============  GuestProxyAgentExtension Enabling Agent, Version: {}, OS Arch: {}, OS Version: {}",
        misc_helpers::get_current_version(),
        misc_helpers::get_processor_arch(),
        misc_helpers::get_long_os_version()
    );
    telemetry::event_logger::write_event(
        LoggerLevel::Info,
        message,
        "run",
        "service_main",
        &logger::get_logger_key(),
    );
    tokio::spawn({
        async {
            monitor_thread().await;
        }
    });
    tokio::spawn({
        async {
            heartbeat_thread().await;
        }
    });
}

async fn heartbeat_thread() {
    let exe_path = misc_helpers::get_current_exe_dir();
    let handler_environment = common::get_handler_environment(&exe_path);
    let heartbeat_file_path: PathBuf = handler_environment.heartbeatFile.to_string().into();
    let duration = Duration::from_secs(5 * 60);
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
        tokio::time::sleep(duration).await;
    }
}

async fn monitor_thread() {
    let exe_path = misc_helpers::get_current_exe_dir();
    let handler_environment = common::get_handler_environment(&exe_path);
    let status_folder_path: PathBuf = handler_environment.statusFolder.to_string().into();
    let mut cache_seq_no = String::new();
    let mut proxyagent_file_version_in_extension = String::new();
    let mut service_state = ServiceState::default();
    let mut status = StatusObj {
        name: constants::PLUGIN_NAME.to_string(),
        operation: constants::ENABLE_OPERATION.to_string(),
        configurationAppliedTime: misc_helpers::get_date_time_string(),
        code: constants::STATUS_CODE_OK,
        status: constants::SUCCESS_STATUS.to_string(),
        formattedMessage: FormattedMessage {
            lang: constants::LANG_EN_US.to_string(),
            message: "Started ProxyAgent Extension Monitoring thread.".to_string(),
        },
        substatus: Default::default(),
    };
    let mut status_state_obj = common::StatusState::new();
    let logger_key: &String = &logger::get_logger_key();
    let mut restored_in_error = false;
    let mut proxy_agent_update_reported: Option<telemetry::span::SimpleSpan> = None;
    loop {
        let current_seq_no: String = common::get_current_seq_no(&exe_path);
        if proxyagent_file_version_in_extension.is_empty() {
            // File version of proxy agent service already downloaded by VM Agent
            let path = common::get_proxy_agent_exe_path();
            proxyagent_file_version_in_extension =
                match misc_helpers::get_proxy_agent_version(&path) {
                    Ok(version) => version,
                    Err(e) => {
                        let error_message = format!(
                            "Failed to get GuestProxyAgent version from file {} with error: {}",
                            misc_helpers::path_to_string(&path),
                            e
                        );
                        logger::write(error_message.clone());
                        status.formattedMessage.message = error_message;
                        status.code = constants::STATUS_CODE_NOT_OK;
                        status.status = status_state_obj.update_state(false);
                        common::report_status(
                            status_folder_path.to_path_buf(),
                            &current_seq_no,
                            &status,
                        );
                        tokio::time::sleep(Duration::from_secs(15)).await;
                        continue;
                    }
                };
        }
        if cache_seq_no != current_seq_no {
            telemetry::event_logger::write_event(
                LoggerLevel::Info,
                format!(
                    "Current seq_no: {current_seq_no} does not match cached seq no {cache_seq_no}"
                ),
                "monitor_thread",
                "service_main",
                logger_key,
            );
            cache_seq_no = current_seq_no.to_string();
            let proxy_service_exe_file_path = common::get_proxy_agent_service_path();
            let proxyagent_service_file_version =
                match misc_helpers::get_proxy_agent_version(&proxy_service_exe_file_path) {
                    Ok(version) => version,
                    Err(e) => {
                        logger::write(format!(
                            "Failed to get GuestProxyAgent version from file {} with error: {}",
                            misc_helpers::path_to_string(&proxy_service_exe_file_path),
                            e
                        ));
                        // return empty string if failed to get version
                        "".to_string()
                    }
                };
            if proxyagent_file_version_in_extension != proxyagent_service_file_version {
                // Call setup tool to install or update proxy agent service
                telemetry::event_logger::write_event(
                    LoggerLevel::Info,
                    format!("Version mismatch between file versions. ProxyAgentService File Version: {proxyagent_service_file_version}, ProxyAgent in Extension File Version: {proxyagent_file_version_in_extension}"
                        ),
                    "monitor_thread",
                    "service_main",
                    logger_key,
                );
                let setup_tool = misc_helpers::path_to_string(&common::setup_tool_exe_path());
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
                    &cache_seq_no,
                    &mut status,
                    &mut status_state_obj,
                );
            }
        }
        // Read proxy agent aggregate status file and get ProxyAgentAggregateStatus object
        report_proxy_agent_aggregate_status(
            &proxyagent_file_version_in_extension,
            &mut status,
            &mut status_state_obj,
            &mut restored_in_error,
            &mut service_state,
        );

        // Time taken to report success for proxy agent service after update
        if status.status == *constants::SUCCESS_STATUS {
            if let Some(proxy_agent_update_reported) = proxy_agent_update_reported.as_ref() {
                proxy_agent_update_reported.write_event(
                    "Proxy Agent Service is updated and reporting successful status",
                    "monitor_thread",
                    "service_main",
                    logger_key,
                );
            }
            proxy_agent_update_reported = None;
        }
        #[cfg(windows)]
        {
            report_ebpf_status(&mut status);
        }

        common::report_status(
            status_folder_path.to_path_buf(),
            &cache_seq_no.to_string(),
            &status,
        );

        tokio::time::sleep(Duration::from_secs(15)).await;
    }
}

fn write_state_event(
    state_key: &str,
    state_value: &str,
    message: String,
    method_name: &str,
    module_name: &str,
    logger_key: &str,
    service_state: &mut ServiceState,
) {
    if service_state.update_service_state_entry(state_key, state_value, MAX_STATE_COUNT) {
        event_logger::write_event(
            LoggerLevel::Info,
            message,
            method_name,
            module_name,
            logger_key,
        );
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
                                message: "Ebpf Drivers successfully queried.".to_string(),
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
                                    "Ebpf Driver: {} unsuccessfully queried.",
                                    constants::EBPF_EXT
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
                            "Ebpf Driver: {} unsuccessfully queried.",
                            constants::EBPF_CORE
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
                LoggerLevel::Info
            } else {
                LoggerLevel::Warn
            };
            let message = format!(
                "Backup Proxy Agent command finished with stdoutput: {}, stderr: {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            telemetry::event_logger::write_event(
                event_level,
                message.clone(),
                "backup_proxyagent",
                "service_main",
                &logger::get_logger_key(),
            );
        }
        Err(e) => {
            let message = format!("Error in running Backup Proxy Agent command: {e}");
            telemetry::event_logger::write_event(
                LoggerLevel::Warn,
                message.clone(),
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
    service_state: &mut ServiceState,
) {
    let aggregate_status_file_path =
        proxy_agent_aggregate_status::get_proxy_agent_aggregate_status_folder()
            .join(proxy_agent_aggregate_status::PROXY_AGENT_AGGREGATE_STATUS_FILE_NAME);

    let proxy_agent_aggregate_status_top_level: GuestProxyAgentAggregateStatus;
    match misc_helpers::json_read_from_file::<GuestProxyAgentAggregateStatus>(
        &aggregate_status_file_path,
    ) {
        Ok(ok) => {
            write_state_event(
                constants::STATE_KEY_READ_PROXY_AGENT_STATUS_FILE,
                constants::SUCCESS_STATUS,
                "Successfully read proxy agent aggregate status file".to_string(),
                "report_proxy_agent_aggregate_status",
                "service_main",
                &logger::get_logger_key(),
                service_state,
            );
            proxy_agent_aggregate_status_top_level = ok;
            extension_substatus(
                proxy_agent_aggregate_status_top_level,
                proxyagent_file_version_in_extension,
                status,
                status_state_obj,
                service_state,
            );
        }
        Err(e) => {
            let error_message = format!("Error in reading proxy agent aggregate status file: {e}");
            write_state_event(
                constants::STATE_KEY_READ_PROXY_AGENT_STATUS_FILE,
                constants::ERROR_STATUS,
                error_message.to_string(),
                "report_proxy_agent_aggregate_status",
                "service_main",
                &logger::get_logger_key(),
                service_state,
            );
            status.status = status_state_obj.update_state(false);
            status.configurationAppliedTime = misc_helpers::get_date_time_string();
            status.substatus = {
                vec![
                    SubStatus {
                        name: constants::PLUGIN_CONNECTION_NAME.to_string(),
                        status: constants::TRANSITIONING_STATUS.to_string(),
                        code: constants::STATUS_CODE_NOT_OK,
                        formattedMessage: FormattedMessage {
                            lang: constants::LANG_EN_US.to_string(),
                            message: error_message.to_string(),
                        },
                    },
                    SubStatus {
                        name: constants::PLUGIN_STATUS_NAME.to_string(),
                        status: constants::TRANSITIONING_STATUS.to_string(),
                        code: constants::STATUS_CODE_NOT_OK,
                        formattedMessage: FormattedMessage {
                            lang: constants::LANG_EN_US.to_string(),
                            message: error_message.to_string(),
                        },
                    },
                    SubStatus {
                        name: constants::PLUGIN_FAILED_AUTH_NAME.to_string(),
                        status: constants::TRANSITIONING_STATUS.to_string(),
                        code: constants::STATUS_CODE_NOT_OK,
                        formattedMessage: FormattedMessage {
                            lang: constants::LANG_EN_US.to_string(),
                            message: error_message.to_string(),
                        },
                    },
                ]
            };
        }
    }
    if !(*restored_in_error) {
        *restored_in_error = restore_purge_proxyagent(status);
    }
}

fn extension_substatus(
    proxy_agent_aggregate_status_top_level: GuestProxyAgentAggregateStatus,
    proxyagent_file_version_in_extension: &String,
    status: &mut StatusObj,
    status_state_obj: &mut common::StatusState,
    service_state: &mut ServiceState,
) {
    let proxy_agent_aggregate_status_obj = proxy_agent_aggregate_status_top_level.proxyAgentStatus;

    let proxy_agent_aggregate_status_file_version =
        proxy_agent_aggregate_status_obj.version.to_string();
    if proxy_agent_aggregate_status_file_version != *proxyagent_file_version_in_extension {
        status.status = status_state_obj.update_state(false);
        let version_mismatch_message = format!("Proxy agent aggregate status file version {proxy_agent_aggregate_status_file_version} does not match proxy agent file version in extension {proxyagent_file_version_in_extension}");
        write_state_event(
            constants::STATE_KEY_FILE_VERSION,
            constants::ERROR_STATUS,
            version_mismatch_message.to_string(),
            "extension_substatus",
            "service_main",
            &logger::get_logger_key(),
            service_state,
        );
        status.configurationAppliedTime = misc_helpers::get_date_time_string();
        status.substatus = {
            vec![
                SubStatus {
                    name: constants::PLUGIN_CONNECTION_NAME.to_string(),
                    status: constants::TRANSITIONING_STATUS.to_string(),
                    code: constants::STATUS_CODE_NOT_OK,
                    formattedMessage: FormattedMessage {
                        lang: constants::LANG_EN_US.to_string(),
                        message: version_mismatch_message.to_string(),
                    },
                },
                SubStatus {
                    name: constants::PLUGIN_STATUS_NAME.to_string(),
                    status: constants::TRANSITIONING_STATUS.to_string(),
                    code: constants::STATUS_CODE_NOT_OK,
                    formattedMessage: FormattedMessage {
                        lang: constants::LANG_EN_US.to_string(),
                        message: version_mismatch_message.to_string(),
                    },
                },
                SubStatus {
                    name: constants::PLUGIN_FAILED_AUTH_NAME.to_string(),
                    status: constants::TRANSITIONING_STATUS.to_string(),
                    code: constants::STATUS_CODE_NOT_OK,
                    formattedMessage: FormattedMessage {
                        lang: constants::LANG_EN_US.to_string(),
                        message: version_mismatch_message.to_string(),
                    },
                },
            ]
        };
    }
    // Success Status and report to status file for CRP to read from
    else {
        let substatus_proxy_agent_message =
            match serde_json::to_string(&proxy_agent_aggregate_status_obj) {
                Ok(proxy_agent_aggregate_status) => proxy_agent_aggregate_status,
                Err(e) => {
                    let error_message =
                        format!("Error in serializing proxy agent aggregate status: {e}");
                    logger::write(error_message.to_string());
                    error_message
                }
            };
        let mut substatus_proxy_agent_connection_message: String;
        if !proxy_agent_aggregate_status_top_level
            .proxyConnectionSummary
            .is_empty()
        {
            let proxy_agent_aggregate_connection_status_obj = get_top_proxy_connection_summary(
                proxy_agent_aggregate_status_top_level
                    .proxyConnectionSummary
                    .clone(),
                constants::MAX_CONNECTION_SUMMARY_LEN,
            );
            match serde_json::to_string(&proxy_agent_aggregate_connection_status_obj) {
                Ok(proxy_agent_aggregate_connection_status) => {
                    substatus_proxy_agent_connection_message =
                        proxy_agent_aggregate_connection_status;
                }
                Err(e) => {
                    let error_message = format!(
                        "Error in serializing proxy agent aggregate connection status: {e}"
                    );
                    logger::write(error_message.to_string());
                    substatus_proxy_agent_connection_message = error_message;
                }
            }
        } else {
            logger::write("proxy connection summary is empty".to_string());
            substatus_proxy_agent_connection_message =
                "proxy connection summary is empty".to_string();
        }
        let mut substatus_failed_auth_message: String;
        if !proxy_agent_aggregate_status_top_level
            .failedAuthenticateSummary
            .is_empty()
        {
            let proxy_agent_aggregate_failed_auth_status_obj = get_top_proxy_connection_summary(
                proxy_agent_aggregate_status_top_level
                    .failedAuthenticateSummary
                    .clone(),
                constants::MAX_FAILED_AUTH_SUMMARY_LEN,
            );
            match serde_json::to_string(&proxy_agent_aggregate_failed_auth_status_obj) {
                Ok(proxy_agent_aggregate_failed_auth_status) => {
                    substatus_failed_auth_message = proxy_agent_aggregate_failed_auth_status;
                }
                Err(e) => {
                    let error_message = format!(
                        "Error in serializing proxy agent aggregate failed auth status: {e}"
                    );
                    logger::write(error_message.to_string());
                    substatus_failed_auth_message = error_message;
                }
            }
        } else {
            logger::write("proxy failed auth summary is empty".to_string());
            substatus_failed_auth_message = "proxy failed auth summary is empty".to_string();
        }

        trim_proxy_agent_status_file(
            &mut substatus_failed_auth_message,
            &mut substatus_proxy_agent_connection_message,
            constants::MAX_PROXYAGENT_CONNECTION_DATA_SIZE_IN_KB,
        );

        status.substatus = {
            vec![
                SubStatus {
                    name: constants::PLUGIN_CONNECTION_NAME.to_string(),
                    status: constants::SUCCESS_STATUS.to_string(),
                    code: constants::STATUS_CODE_OK,
                    formattedMessage: FormattedMessage {
                        lang: constants::LANG_EN_US.to_string(),
                        message: substatus_proxy_agent_connection_message.to_string(),
                    },
                },
                SubStatus {
                    name: constants::PLUGIN_STATUS_NAME.to_string(),
                    status: constants::SUCCESS_STATUS.to_string(),
                    code: constants::STATUS_CODE_OK,
                    formattedMessage: FormattedMessage {
                        lang: constants::LANG_EN_US.to_string(),
                        message: substatus_proxy_agent_message.to_string(),
                    },
                },
                SubStatus {
                    name: constants::PLUGIN_FAILED_AUTH_NAME.to_string(),
                    status: constants::SUCCESS_STATUS.to_string(),
                    code: constants::STATUS_CODE_OK,
                    formattedMessage: FormattedMessage {
                        lang: constants::LANG_EN_US.to_string(),
                        message: substatus_failed_auth_message.to_string(),
                    },
                },
            ]
        };
        status.status = status_state_obj.update_state(true);
        status.configurationAppliedTime = misc_helpers::get_date_time_string();
        write_state_event(
            constants::STATE_KEY_FILE_VERSION,
            constants::SUCCESS_STATUS,
            substatus_proxy_agent_connection_message.to_string(),
            "extension_substatus",
            "service_main",
            &logger::get_logger_key(),
            service_state,
        );
    }
}

fn trim_proxy_agent_status_file(
    substatus_failed_auth_message: &mut String,
    substatus_connection_summary_message: &mut String,
    max_size_in_kb: usize,
) {
    let allowed_bytes = max_size_in_kb * 1024;
    if substatus_connection_summary_message.len() + substatus_failed_auth_message.len()
        > allowed_bytes
    {
        let connection_message = "Substatus of proxy agent connection message and failed auth message size exceeds max size, dropping connection summary".to_string();
        logger::write(connection_message.clone());
        *substatus_connection_summary_message = connection_message;
        if substatus_failed_auth_message.len() > allowed_bytes {
            substatus_failed_auth_message.truncate(allowed_bytes);
        }
    }
}

fn get_top_proxy_connection_summary(
    mut summary: Vec<ProxyConnectionSummary>,
    max_count: usize,
) -> Vec<ProxyConnectionSummary> {
    summary.sort_by(|a, b| a.count.cmp(&b.count));
    let len = summary.len();
    if len > max_count {
        summary = summary.split_off(len - max_count);
    }

    summary
}

fn restore_purge_proxyagent(status: &mut StatusObj) -> bool {
    let setup_tool = misc_helpers::path_to_string(&common::setup_tool_exe_path());
    if status.status == *constants::ERROR_STATUS {
        let output = Command::new(&setup_tool).arg("restore").output();
        match output {
            Ok(output) => {
                let event_level = if output.status.success() {
                    LoggerLevel::Info
                } else {
                    LoggerLevel::Warn
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
                    LoggerLevel::Info,
                    format!("Error in running Restore Proxy Agent command: {e}"),
                    "restore_purge_proxyagent",
                    "service_main",
                    &logger::get_logger_key(),
                );
            }
        }
        true
    } else if status.status == *constants::SUCCESS_STATUS {
        let output = Command::new(setup_tool).arg("purge").output();
        match output {
            Ok(output) => {
                let event_level = if output.status.success() {
                    LoggerLevel::Info
                } else {
                    LoggerLevel::Warn
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
                    LoggerLevel::Info,
                    format!("Error in running Purge Proxy Agent command: {e}"),
                    "restore_purge_proxyagent",
                    "service_main",
                    &logger::get_logger_key(),
                );
            }
        }
        true
    } else {
        false
    }
}

fn report_proxy_agent_service_status(
    output: Result<Output, Error>,
    status_folder: PathBuf,
    seq_no: &str,
    status: &mut StatusObj,
    status_state_obj: &mut common::StatusState,
) {
    match output {
        Ok(output) => {
            let message =
                "Successfully Executed Setup Tool Install Command for Proxy Agent Version Upgrade"
                    .to_string();
            logger::write(format!(
                "{} with stdoutput: {}, stderr: {}",
                message.clone(),
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ));
            if output.status.success() {
                status.configurationAppliedTime = misc_helpers::get_date_time_string();
                status.code = constants::STATUS_CODE_OK;
                status.status = status_state_obj.update_state(false);
                status.formattedMessage.message = message;
                status.substatus = Default::default();
                common::report_status(status_folder, seq_no, status);
            } else {
                let err_message = format!(
                    "Execute Install Command in Proxy Agent Setup Tool Output Status Not Success: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
                telemetry::event_logger::write_event(
                    LoggerLevel::Warn,
                    err_message.clone(),
                    "report_proxy_agent_service_status",
                    "service_main",
                    &logger::get_logger_key(),
                );
                status.configurationAppliedTime = misc_helpers::get_date_time_string();
                status.code = output
                    .status
                    .code()
                    .unwrap_or(constants::STATUS_CODE_NOT_OK);
                status.status = status_state_obj.update_state(false);
                status.formattedMessage.message = err_message.clone();
                status.substatus = Default::default();
                common::report_status(status_folder, seq_no, status);
            }
        }
        Err(e) => {
            let err_message = format!(
                "Failed to execute Install Proxy Agent Command Through Setup Tool with error: {e}"
            );
            telemetry::event_logger::write_event(
                LoggerLevel::Warn,
                err_message.clone(),
                "report_proxy_agent_service_status",
                "service_main",
                &logger::get_logger_key(),
            );
            // report proxyagent service update failed state
            status.configurationAppliedTime = misc_helpers::get_date_time_string();
            status.code = constants::STATUS_CODE_NOT_OK;
            status.status = status_state_obj.update_state(false);
            status.formattedMessage.message = err_message.clone();
            status.substatus = Default::default();
            common::report_status(status_folder, seq_no, status);
        }
    }
}

// test report status
#[cfg(test)]
mod tests {
    use crate::constants;
    use crate::structs::*;
    use proxy_agent_shared::misc_helpers;
    use proxy_agent_shared::proxy_agent_aggregate_status::*;

    #[test]
    #[cfg(windows)]
    fn report_proxy_agent_service_status() {
        use std::env;
        use std::fs;
        use std::io::Write;
        use std::path::PathBuf;
        use std::process::Command;

        // Create temp directory for status folder
        let mut temp_test_path = env::temp_dir();
        temp_test_path.push("test_status_file");

        //Clean up and ignore the clean up errors
        _ = fs::remove_dir_all(&temp_test_path);
        _ = misc_helpers::try_create_folder(&temp_test_path);
        let status_folder: PathBuf = temp_test_path.join("status");

        let mut test_good = temp_test_path.clone();
        test_good.push("test.ps1");
        let mut file = fs::File::create(&test_good).unwrap();
        file.write_all(b"\"Hello World\"").unwrap();

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
            &seq_no,
            &mut status,
            &mut status_state_obj,
        );

        let handler_status =
            misc_helpers::json_read_from_file::<Vec<TopLevelStatus>>(&expected_status_file)
                .unwrap();
        assert_eq!(handler_status.len(), 1);
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
            &seq_no,
            &mut status,
            &mut status_state_obj,
        );
        let handler_status_bad =
            misc_helpers::json_read_from_file::<Vec<TopLevelStatus>>(expected_status_file_bad)
                .unwrap();
        assert_eq!(handler_status_bad.len(), 1);
        assert_eq!(handler_status_bad[0].status.code, 1);

        //Clean up and ignore the clean up errors
        _ = fs::remove_dir_all(&temp_test_path);
    }

    #[test]
    fn test_proxyagent_service_success_status() {
        let proxy_agent_status_obj = ProxyAgentStatus {
            version: "1.0.0".to_string(),
            status: OverallState::SUCCESS,
            monitorStatus: ProxyAgentDetailStatus {
                status: ModuleState::RUNNING,
                message: "test".to_string(),
                states: None,
            },
            keyLatchStatus: ProxyAgentDetailStatus {
                status: ModuleState::RUNNING,
                message: "test".to_string(),
                states: None,
            },
            ebpfProgramStatus: ProxyAgentDetailStatus {
                status: ModuleState::RUNNING,
                message: "test".to_string(),
                states: None,
            },
            proxyListenerStatus: ProxyAgentDetailStatus {
                status: ModuleState::RUNNING,
                message: "test".to_string(),
                states: None,
            },
            telemetryLoggerStatus: ProxyAgentDetailStatus {
                status: ModuleState::RUNNING,
                message: "test".to_string(),
                states: None,
            },
            proxyConnectionsCount: 1,
        };

        let proxy_connection_summary_obj = ProxyConnectionSummary {
            userName: "test".to_string(),
            ip: "test".to_string(),
            port: 1,
            processCmdLine: "test".to_string(),
            responseStatus: "test".to_string(),
            count: 1,
            processFullPath: Some("test".to_string()),
            userGroups: Some(vec!["test".to_string()]),
        };

        let proxy_failedAuthenticateSummary_obj = ProxyConnectionSummary {
            userName: "test".to_string(),
            ip: "test".to_string(),
            port: 1,
            processCmdLine: "test".to_string(),
            responseStatus: "test".to_string(),
            count: 1,
            processFullPath: Some("test".to_string()),
            userGroups: Some(vec!["test".to_string()]),
        };

        let toplevel_status = GuestProxyAgentAggregateStatus {
            timestamp: misc_helpers::get_date_time_string(),
            proxyAgentStatus: proxy_agent_status_obj,
            proxyConnectionSummary: vec![proxy_connection_summary_obj],
            failedAuthenticateSummary: vec![proxy_failedAuthenticateSummary_obj],
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
        let mut service_state = super::service_state::ServiceState::default();

        super::extension_substatus(
            toplevel_status,
            proxyagent_file_version_in_extension,
            &mut status,
            &mut status_state_obj,
            &mut service_state,
        );
        assert_eq!(status.status, constants::SUCCESS_STATUS.to_string());
    }

    #[tokio::test]
    #[cfg(windows)]
    async fn test_report_ebpf_status() {
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
                vec![
                    SubStatus {
                        name: constants::PLUGIN_CONNECTION_NAME.to_string(),
                        status: constants::SUCCESS_STATUS.to_string(),
                        code: constants::STATUS_CODE_OK,
                        formattedMessage: FormattedMessage {
                            lang: constants::LANG_EN_US.to_string(),
                            message: "test".to_string(),
                        },
                    },
                    SubStatus {
                        name: constants::PLUGIN_STATUS_NAME.to_string(),
                        status: constants::SUCCESS_STATUS.to_string(),
                        code: constants::STATUS_CODE_OK,
                        formattedMessage: FormattedMessage {
                            lang: constants::LANG_EN_US.to_string(),
                            message: "test".to_string(),
                        },
                    },
                    SubStatus {
                        name: constants::PLUGIN_FAILED_AUTH_NAME.to_string(),
                        status: constants::SUCCESS_STATUS.to_string(),
                        code: constants::STATUS_CODE_OK,
                        formattedMessage: FormattedMessage {
                            lang: constants::LANG_EN_US.to_string(),
                            message: "test".to_string(),
                        },
                    },
                ]
            },
        };

        super::report_ebpf_status(&mut status);
        assert_eq!(
            status.substatus[0].name,
            constants::PLUGIN_CONNECTION_NAME.to_string()
        );
        assert_eq!(
            status.substatus[1].name,
            constants::PLUGIN_STATUS_NAME.to_string()
        );
        assert_eq!(
            status.substatus[2].name,
            constants::PLUGIN_FAILED_AUTH_NAME.to_string()
        );
        assert_eq!(
            status.substatus[3].name,
            constants::EBPF_SUBSTATUS_NAME.to_string()
        );
    }

    #[tokio::test]
    async fn get_top_proxy_connection_summary_tests() {
        let mut summary = Vec::new();
        let mut proxy_connection_summary_obj = ProxyConnectionSummary {
            userName: "test".to_string(),
            ip: "test".to_string(),
            port: 1,
            processCmdLine: "test".to_string(),
            responseStatus: "test".to_string(),
            count: 1,
            processFullPath: Some("test".to_string()),
            userGroups: Some(vec!["test".to_string()]),
        };
        summary.push(proxy_connection_summary_obj.clone());
        proxy_connection_summary_obj.count = 5;
        summary.push(proxy_connection_summary_obj.clone());
        proxy_connection_summary_obj.count = 2;
        summary.push(proxy_connection_summary_obj.clone());
        proxy_connection_summary_obj.count = 4;
        summary.push(proxy_connection_summary_obj.clone());
        proxy_connection_summary_obj.count = 2;
        summary.push(proxy_connection_summary_obj.clone());
        let max_len = 3;
        let result = super::get_top_proxy_connection_summary(summary, max_len);
        assert_eq!(result.len(), max_len);
        assert_eq!(result[0].count, 2); // lowest count
        assert_eq!(result[1].count, 4); // 2nd highest count
        assert_eq!(result[2].count, 5); // 3rd highest count
    }

    #[test]
    fn test_trim_proxy_agent_status_file_cases() {
        // Case 1: total size is under max_size, should not modify the strings
        let mut connection_summary = "b".repeat(1024 * 2); // 2 KB
        let mut failed_auth_summary = "a".repeat(1024); // 1 KB
        let max_size = 4; // 4 KB
        let orig_conn = connection_summary.clone();
        let orig_auth = failed_auth_summary.clone();
        super::trim_proxy_agent_status_file(
            &mut failed_auth_summary,
            &mut connection_summary,
            max_size,
        );
        assert_eq!(connection_summary, orig_conn);
        assert_eq!(failed_auth_summary, orig_auth);

        // Case 2: total size exceeds max_size, should drop connection summary and keep failed_auth_summary the same
        let mut connection_summary = "b".repeat(1024 * 3); // 3 KB
        let mut failed_auth_summary = "a".repeat(1024 * 3); // 3 KB
        let max_size = 5; // 5 KB
        super::trim_proxy_agent_status_file(
            &mut failed_auth_summary,
            &mut connection_summary,
            max_size,
        );
        assert!(connection_summary.contains("Substatus of proxy agent connection message and failed auth message size exceeds max size"));
        assert_eq!(failed_auth_summary, "a".repeat(1024 * 3));

        // Case 3: failed_auth_summary alone exceeds max_size, should drop connection summary and trim failed_auth_summary
        let mut connection_summary = "b".repeat(1024 * 1); // 1 KB
        let mut failed_auth_summary = "a".repeat(1024 * 10); // 10 KB
        let max_size = 2; // 2 KB
        super::trim_proxy_agent_status_file(
            &mut failed_auth_summary,
            &mut connection_summary,
            max_size,
        );
        assert!(connection_summary.contains("Substatus of proxy agent connection message and failed auth message size exceeds max size"));
        assert_eq!(failed_auth_summary, "a".repeat(2048));

        // Case 4: total size exactly equals max_size, should not modify the strings
        let mut connection_summary = "b".repeat(1024 * 2); // 2 KB
        let mut failed_auth_summary = "a".repeat(1024 * 2); // 2 KB
        let max_size = 4; // 4 KB
        let orig_conn = connection_summary.clone();
        let orig_auth = failed_auth_summary.clone();
        super::trim_proxy_agent_status_file(
            &mut failed_auth_summary,
            &mut connection_summary,
            max_size,
        );
        assert_eq!(connection_summary, orig_conn);
        assert_eq!(failed_auth_summary, orig_auth);
    }
}
