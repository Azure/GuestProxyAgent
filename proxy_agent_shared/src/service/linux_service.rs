// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use crate::linux;
use crate::misc_helpers;

use std::fs;
use std::path::PathBuf;

pub fn stop_service(service_name: &str) {
    let output = misc_helpers::execute_command("systemctl", vec!["stop", service_name], -1);
    tracing::info!(
        "stop_service: {}  result: '{}'-'{}'-'{}'.",
        service_name,
        output.0,
        output.1,
        output.2
    );
}

pub fn start_service(service_name: &str) {
    let output = misc_helpers::execute_command("systemctl", vec!["start", service_name], -1);
    tracing::info!(
        "start_service: {}  result: '{}'-'{}'-'{}'.",
        service_name,
        output.0,
        output.1,
        output.2
    );
}

pub fn install_or_update_service(service_name: &str) {
    unmask_service(service_name);
    reload_systemd_daemon();
    enable_service(service_name);
}

fn unmask_service(service_name: &str) {
    let output = misc_helpers::execute_command("systemctl", vec!["unmask", service_name], -1);
    tracing::info!(
        "unmask_service: {}  result: '{}'-'{}'-'{}'.",
        service_name,
        output.0,
        output.1,
        output.2
    );
}

pub fn uninstall_service(service_name: &str) {
    disable_service(service_name);
    delete_service_config_file(service_name);
}

fn disable_service(service_name: &str) {
    let output = misc_helpers::execute_command("systemctl", vec!["disable", service_name], -1);
    tracing::info!(
        "disable_service: {}  result: '{}'-'{}'-'{}'.",
        service_name,
        output.0,
        output.1,
        output.2
    );
}

fn reload_systemd_daemon() {
    let output = misc_helpers::execute_command("systemctl", vec!["daemon-reload"], -1);
    tracing::info!(
        "reload_systemd_daemon: result: '{}'-'{}'-'{}'.",
        output.0,
        output.1,
        output.2
    );
}

fn enable_service(service_name: &str) {
    let output = misc_helpers::execute_command("systemctl", vec!["enable", service_name], -1);
    tracing::info!(
        "enable_service: {}  result: '{}'-'{}'-'{}'.",
        service_name,
        output.0,
        output.1,
        output.2
    );
}

fn delete_service_config_file(service_name: &str) {
    let config_file_path =
        PathBuf::from(linux::SERVICE_CONFIG_FOLDER_PATH).join(format!("{}.service", service_name));
    match fs::remove_file(&config_file_path) {
        Ok(_) => {
            reload_systemd_daemon();
        }
        Err(e) => {
            tracing::info!(
                "delete_service_config_file: {}  failed to delete service config file '{}': {}",
                service_name,
                misc_helpers::path_to_string(config_file_path),
                e
            );
        }
    }
}
