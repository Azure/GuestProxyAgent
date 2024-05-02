use crate::linux;
use crate::logger_manager;
use crate::misc_helpers;

use std::path::PathBuf;
use std::fs;

pub fn stop_service(service_name: &str) {
    let output = misc_helpers::execute_command("systemctl", vec!["stop", service_name], -1);
    let message = format!(
        "stop_service: {}  result: '{}'-'{}'-'{}'.",
        service_name, output.0, output.1, output.2
    );
    logger_manager::write_info(message);
}

pub fn start_service(service_name: &str) {
    let output = misc_helpers::execute_command("systemctl", vec!["start", service_name], -1);
    let message = format!(
        "start_service: {}  result: '{}'-'{}'-'{}'.",
        service_name, output.0, output.1, output.2
    );
    logger_manager::write_info(message);
}

pub fn install_or_update_service(service_name: &str) {
    unmask_service(service_name);
    reload_systemd_daemon();
    enable_service(service_name);
}

fn unmask_service(service_name: &str){
    let output = misc_helpers::execute_command("systemctl", vec!["unmask", service_name], -1);
    let message = format!(
        "unmask_service: {}  result: '{}'-'{}'-'{}'.",
        service_name, output.0, output.1, output.2
    );
    logger_manager::write_info(message);
}

pub fn uninstall_service(service_name: &str) {
    disable_service(service_name);
    delete_service_config_file(service_name);
}

fn disable_service(service_name: &str) {
    let output = misc_helpers::execute_command("systemctl", vec!["disable", service_name], -1);
    let message = format!(
        "disable_service: {}  result: '{}'-'{}'-'{}'.",
        service_name, output.0, output.1, output.2
    );
    logger_manager::write_info(message);
}

fn reload_systemd_daemon() {
    let output = misc_helpers::execute_command("systemctl", vec!["daemon-reload"], -1);
    let message = format!(
        "reload_systemd_daemon: result: '{}'-'{}'-'{}'.",
        output.0, output.1, output.2
    );
    logger_manager::write_info(message);
}

fn enable_service(service_name: &str) {
    let output = misc_helpers::execute_command("systemctl", vec!["enable", service_name], -1);
    let message = format!(
        "enable_service: {}  result: '{}'-'{}'-'{}'.",
        service_name, output.0, output.1, output.2
    );
    logger_manager::write_info(message);
}

fn delete_service_config_file(service_name: &str) {
    let config_file_path =
        PathBuf::from(linux::SERVICE_CONFIG_FOLDER_PATH).join(format!("{}.service", service_name));
    match fs::remove_file(config_file_path.to_path_buf()) {
        Ok(_) => {
            reload_systemd_daemon();
        }
        Err(e) => {
            let message = format!(
                "delete_service_config_file: {}  failed to delete service config file '{}': {}",
                service_name,
                misc_helpers::path_to_string(config_file_path),
                e
            );
            logger_manager::write_info(message);
        }
    }
}
