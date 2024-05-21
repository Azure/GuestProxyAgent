// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#![cfg(not(windows))]

use crate::{backup, logger, running};
use proxy_agent_shared::misc_helpers;
use std::{fs, path::PathBuf};

const SERVICE_CONFIG_FILE_NAME: &str = "azure-proxy-agent.service";
const CONFIG_FILE: &str = "proxy-agent.json";
const EBPF_FILE: &str = "ebpf_cgroup.o";
const CONFIG_PATH: &str = "/etc/azure/proxy-agent.json";
const EBPF_PATH: &str = "/usr/lib/azure-proxy-agent/ebpf_cgroup.o";

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

fn backup_service_config_file(backup_folder: PathBuf) {
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

fn copy_file(src_file: PathBuf, dst_file: PathBuf) {
    match dst_file.parent() {
        Some(p) => match misc_helpers::try_create_folder(p.to_path_buf()) {
            Ok(_) => {}
            Err(e) => {
                logger::write(format!("Failed to create folder {:?}, error: {:?}", p, e));
            }
        },
        None => {}
    }
    match fs::copy(src_file.to_path_buf(), dst_file.to_path_buf()) {
        Ok(_) => {
            logger::write(format!("Copied file {:?} to {:?}", src_file, dst_file));
        }
        Err(e) => {
            logger::write(format!(
                "Failed to copy file {:?} to {:?}, error: {:?}",
                src_file, dst_file, e
            ));
        }
    }
}

fn delete_file(file_to_be_delete: PathBuf) {
    match fs::remove_file(file_to_be_delete.to_path_buf()) {
        Ok(_) => {
            logger::write(format!("Deleted file {:?}", file_to_be_delete));
        }
        Err(e) => {
            logger::write(format!(
                "Failed to delete file {:?}, error: {:?}",
                file_to_be_delete, e
            ));
        }
    }
}

// copy azure-proxy-agent, proxy-agent.json, ebpf_cgroup.o, service config files to backup folder
pub fn backup_files() {
    let backup_folder = backup::proxy_agent_backup_package_folder();
    copy_file(PathBuf::from(CONFIG_PATH), backup_folder.join(CONFIG_FILE));
    copy_file(PathBuf::from(EBPF_PATH), backup_folder.join(EBPF_FILE));
    copy_file(
        running::proxy_agent_running_folder("").join("azure-proxy-agent"),
        backup_folder.join("azure-proxy-agent"),
    );
    backup_service_config_file(backup::proxy_agent_backup_folder());
}

// copy azure-proxy-agent, proxy-agent.json, ebpf_cgroup.o to different destination folders
pub fn copy_files(src_folder: PathBuf) {
    let dst_folder = crate::running::proxy_agent_running_folder("");
    copy_file(
        src_folder.join("azure-proxy-agent"),
        dst_folder.join("azure-proxy-agent"),
    );
    copy_file(src_folder.join(CONFIG_FILE), PathBuf::from(CONFIG_PATH));
    copy_file(src_folder.join(EBPF_FILE), PathBuf::from(EBPF_PATH));
}

pub fn delete_files() {
    let proxy_agent_running_folder =
        crate::running::proxy_agent_running_folder("azure-proxy-agent");
    delete_file(proxy_agent_running_folder.join("azure-proxy-agent"));
    delete_file(PathBuf::from(crate::linux::CONFIG_PATH));
    delete_file(PathBuf::from(crate::linux::EBPF_PATH));
}
