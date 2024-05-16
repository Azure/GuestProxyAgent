// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#![cfg(not(windows))]

use crate::logger;
use std::{fs, path::PathBuf};

const SERVICE_CONFIG_FILE_NAME: &str = "azure-proxy-agent.service";
pub const EXE_PATH: &str = "/usr/sbin";
pub const CONFIG_PATH: &str = "/etc/azure/proxy-agent.json";
pub const EBPF_PATH: &str = "/usr/lib/azure-proxy-agent/ebpf_cgroup.o";

pub fn setup_service(service_name: &str, service_file_dir: PathBuf) -> std::io::Result<u64> {
    copy_service_config_file(service_name, service_file_dir)
}

fn copy_service_config_file(service_name: &str, service_file_dir: PathBuf) -> std::io::Result<u64> {
    let service_config_name = format!("{}.service", service_name);
    let src_config_file_path = service_file_dir.join(service_config_name.to_string());
    let dst_config_file_path = PathBuf::from(proxy_agent_shared::linux::SERVICE_CONFIG_FOLDER_PATH)
        .join(service_config_name.to_string());
    fs::copy(src_config_file_path, dst_config_file_path)
}

pub fn backup_service_config_file(backup_folder: PathBuf) {
    let backup_service_file = backup_folder.join(SERVICE_CONFIG_FILE_NAME);
    match fs::copy(
        PathBuf::from(proxy_agent_shared::linux::SERVICE_CONFIG_FOLDER_PATH)
            .join(SERVICE_CONFIG_FILE_NAME),
        backup_service_file.to_path_buf(),
    ) {
        Ok(_) => {
            logger::write(format!(
                "Copied service config file to {:?}",
                backup_service_file
            ));
        }
        Err(e) => {
            logger::write(format!(
                "Failed to copy service config file to {:?}, error: {:?}",
                backup_service_file, e
            ));
        }
    }
}
