// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use crate::error::CommandErrorType;
use crate::error::Error;
use crate::linux;
use crate::logger::logger_manager;
use crate::misc_helpers;
use crate::result::Result;
use std::fs;
use std::path::PathBuf;

pub fn stop_service(service_name: &str) -> Result<()> {
    let output = misc_helpers::execute_command("systemctl", vec!["stop", service_name], -1)?;
    logger_manager::write_info(format!(
        "stop_service: {}  result: {}",
        service_name,
        output.message()
    ));
    Ok(())
}

/// Starts the specified service with `systemctl start` command.
/// If the command fails, an Error is returned.
pub fn start_service(service_name: &str) -> Result<()> {
    let output = misc_helpers::execute_command("systemctl", vec!["start", service_name], -1)?;
    if output.is_success() {
        logger_manager::write_info(format!("Service {service_name} started successfully"));
        Ok(())
    } else {
        let error_message = format!(
            "start_service: {service_name} failed with error: {}",
            output.message()
        );
        Err(Error::Command(
            CommandErrorType::CommandName("systemctl start".to_string()),
            error_message,
        ))
    }
}

pub fn install_or_update_service(service_name: &str) -> Result<()> {
    unmask_service(service_name)?;
    reload_systemd_daemon()?;
    enable_service(service_name)
}

fn unmask_service(service_name: &str) -> Result<()> {
    let output = misc_helpers::execute_command("systemctl", vec!["unmask", service_name], -1)?;
    logger_manager::write_info(format!(
        "unmask_service: {}  result: {}",
        service_name,
        output.message()
    ));
    Ok(())
}

pub fn uninstall_service(service_name: &str) -> Result<()> {
    disable_service(service_name)?;
    delete_service_config_file(service_name)
}

fn disable_service(service_name: &str) -> Result<()> {
    let output = misc_helpers::execute_command("systemctl", vec!["disable", service_name], -1)?;
    logger_manager::write_info(format!(
        "disable_service: {}  result: {}",
        service_name,
        output.message()
    ));
    Ok(())
}

fn reload_systemd_daemon() -> Result<()> {
    let output = misc_helpers::execute_command("systemctl", vec!["daemon-reload"], -1)?;
    logger_manager::write_info(format!(
        "reload_systemd_daemon result: {}",
        output.message()
    ));
    Ok(())
}

fn enable_service(service_name: &str) -> Result<()> {
    let output = misc_helpers::execute_command("systemctl", vec!["enable", service_name], -1)?;
    logger_manager::write_info(format!(
        "enable_service: {}  result: {}",
        service_name,
        output.message()
    ));
    Ok(())
}

fn delete_service_config_file(service_name: &str) -> Result<()> {
    let config_file_path =
        PathBuf::from(linux::SERVICE_CONFIG_FOLDER_PATH).join(format!("{service_name}.service"));
    match fs::remove_file(&config_file_path) {
        Ok(_) => {
            reload_systemd_daemon()?;
        }
        Err(e) => {
            let message = format!(
                "delete_service_config_file: {}  failed to delete service config file '{}': {}",
                service_name,
                misc_helpers::path_to_string(&config_file_path),
                e
            );
            logger_manager::write_info(message);
        }
    }
    Ok(())
}

/// Queries the executable path of the specified service.
/// It uses systemctl show command to get the ExecStart property.
/// If the command fails or the output cannot be parsed, an Error is returned.
pub fn query_service_executable_path(service_name: &str) -> Result<PathBuf> {
    let output = misc_helpers::execute_command(
        "systemctl",
        vec!["show", "--property=ExecStart", service_name],
        -1,
    )?;

    if !output.is_success() {
        let error_message = format!(
            "query_service_executable_path: {service_name} failed with error: {}",
            output.message()
        );
        return Err(Error::Command(
            CommandErrorType::CommandName("systemctl show --property=ExecStart".to_string()),
            error_message,
        ));
    }

    let stdout = output.stdout();
    logger_manager::write_info(format!(
        "query_service_executable_path: {service_name} result: {stdout}",
    ));

    // Parse ExecStart output
    // Format: ExecStart={ path=/path/to/executable ; argv[]=/path/to/executable [args] ; ... }
    if let Some(path_start) = stdout.find("path=") {
        let path_str = &stdout[path_start + 5..];
        if let Some(semicolon_pos) = path_str.find(" ;") {
            let executable_path = path_str[..semicolon_pos].trim();
            return Ok(PathBuf::from(executable_path));
        }
    }

    let error_message = format!(
        "query_service_executable_path: {service_name} failed to parse ExecStart output: {stdout}"
    );
    Err(Error::Command(
        CommandErrorType::CommandName("systemctl show --property=ExecStart".to_string()),
        error_message,
    ))
}

/// Check if the service is installed by verifying the existence of its unit file.
pub fn check_service_installed(service_name: &str) -> (bool, String) {
    let config_file_path =
        PathBuf::from(linux::SERVICE_CONFIG_FOLDER_PATH).join(format!("{service_name}.service"));

    if config_file_path.exists() && config_file_path.is_file() {
        let message =
            format!("check_service_installed: service: {service_name} successfully queried.");
        logger_manager::write_info(message.clone());
        (true, message)
    } else {
        let message = format!(
            "check_service_installed: service: {service_name} unit file not found at '{}'",
            misc_helpers::path_to_string(&config_file_path)
        );
        logger_manager::write_info(message.clone());
        (false, message)
    }
}
