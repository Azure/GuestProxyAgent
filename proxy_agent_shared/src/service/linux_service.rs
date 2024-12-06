// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use crate::linux;
use crate::logger_manager;
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

pub fn start_service(service_name: &str) -> Result<()> {
    let output = misc_helpers::execute_command("systemctl", vec!["start", service_name], -1)?;
    logger_manager::write_info(format!(
        "start_service: {}  result: {}",
        service_name,
        output.message()
    ));
    Ok(())
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
        PathBuf::from(linux::SERVICE_CONFIG_FOLDER_PATH).join(format!("{}.service", service_name));
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
