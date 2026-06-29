// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#![cfg(not(windows))]

use crate::{backup, logger, result::Result, running};
use proxy_agent_shared::misc_helpers;
use std::{fs, path::PathBuf};

const SERVICE_CONFIG_FILE_NAME: &str = "azure-proxy-agent.service";
const CONFIG_FILE: &str = "proxy-agent.json";
const EBPF_FILE: &str = "ebpf_cgroup.o";
const MAN_FILE: &str = "azure-proxy-agent.8";
const CONFIG_PATH: &str = "/etc/azure/proxy-agent.json";
const EBPF_PATH: &str = "/usr/lib/azure-proxy-agent/ebpf_cgroup.o";
const MAN_PATH: &str = "/usr/share/man/man8/azure-proxy-agent.8";

pub fn setup_service(service_name: &str, service_file_dir: PathBuf) -> Result<()> {
    copy_service_config_file(service_name, service_file_dir.clone())?;
    copy_man_page(service_file_dir);
    Ok(())
}

// Install the man page (staged next to the service config file) so that
// `man azure-proxy-agent` works on extension-based installs, matching the
// distro (.deb/.rpm) packages. Older packages may not ship the man page, in
// which case this is a no-op.
fn copy_man_page(src_folder: PathBuf) {
    let man_src = src_folder.join(MAN_FILE);
    if !man_src.exists() {
        return;
    }
    copy_file(man_src, PathBuf::from(MAN_PATH));
    if let Err(e) = proxy_agent_shared::linux::set_file_permissions(&PathBuf::from(MAN_PATH), 0o644)
    {
        logger::write_error(format!(
            "Failed to set man page file permission to 644 with error: {e}"
        ));
    }
}

fn copy_service_config_file(service_name: &str, service_file_dir: PathBuf) -> Result<()> {
    let service_config_name = format!("{service_name}.service");
    let src_config_file_path = service_file_dir.join(&service_config_name);
    let dst_config_file_path = PathBuf::from(proxy_agent_shared::linux::SERVICE_CONFIG_FOLDER_PATH)
        .join(&service_config_name);
    fs::copy(src_config_file_path, &dst_config_file_path).map_err(|e| {
        std::io::Error::other(format!(
            "Failed to copy service config file to {dst_config_file_path:?} with error: {e}"
        ))
    })?;
    // set the file permissions to 644 for the service config unit file
    proxy_agent_shared::linux::set_file_permissions(&dst_config_file_path, 0o644).map_err(|e| {
        std::io::Error::other(format!(
            "Failed to set file permissions for {dst_config_file_path:?} with error: {e}"
        ))
    })?;

    logger::write(format!(
        "Copied service config file to {dst_config_file_path:?}"
    ));
    Ok(())
}

fn backup_service_config_file(backup_folder: PathBuf) {
    let backup_service_file = backup_folder.join(SERVICE_CONFIG_FILE_NAME);
    match fs::copy(
        PathBuf::from(proxy_agent_shared::linux::SERVICE_CONFIG_FOLDER_PATH)
            .join(SERVICE_CONFIG_FILE_NAME),
        &backup_service_file,
    ) {
        Ok(_) => {
            logger::write(format!(
                "Copied service config file to {backup_service_file:?}"
            ));
        }
        Err(e) => {
            logger::write(format!(
                "Failed to copy service config file to {backup_service_file:?}, error: {e:?}"
            ));
        }
    }
}

fn copy_file(src_file: PathBuf, dst_file: PathBuf) {
    if let Some(p) = dst_file.parent() {
        if let Err(e) = misc_helpers::try_create_folder(p) {
            logger::write(format!("Failed to create folder {p:?}, error: {e:?}"));
        }
    }
    match fs::copy(&src_file, &dst_file) {
        Ok(_) => {
            logger::write(format!("Copied file {src_file:?} to {dst_file:?}"));
        }
        Err(e) => {
            logger::write(format!(
                "Failed to copy file {src_file:?} to {dst_file:?}, error: {e:?}"
            ));
        }
    }
}

fn delete_file(file_to_be_delete: PathBuf) {
    match fs::remove_file(&file_to_be_delete) {
        Ok(_) => {
            logger::write(format!("Deleted file {file_to_be_delete:?}"));
        }
        Err(e) => {
            logger::write(format!(
                "Failed to delete file {file_to_be_delete:?}, error: {e:?}"
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
    // back up the man page next to the service config file so restore can
    // reinstall it from the same folder.
    copy_file(
        PathBuf::from(MAN_PATH),
        backup::proxy_agent_backup_folder().join(MAN_FILE),
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
    // set the file permissions to 755 for the azure-proxy-agent binary
    proxy_agent_shared::linux::set_file_permissions(&dst_folder.join("azure-proxy-agent"), 0o755)
        .unwrap_or_else(|e| {
            logger::write_error(format!(
                "Failed to set azure-proxy-agent file permission to 755 with error: {e}"
            ));
        });

    copy_file(src_folder.join(CONFIG_FILE), PathBuf::from(CONFIG_PATH));
    proxy_agent_shared::linux::set_file_permissions(&PathBuf::from(CONFIG_PATH), 0o644)
        .unwrap_or_else(|e| {
            logger::write_error(format!(
                "Failed to set config file permission to 644 with error: {e}"
            ));
        });

    copy_file(src_folder.join(EBPF_FILE), PathBuf::from(EBPF_PATH));
}

pub fn delete_files() {
    let proxy_agent_running_folder =
        crate::running::proxy_agent_running_folder("azure-proxy-agent");
    delete_file(proxy_agent_running_folder.join("azure-proxy-agent"));
    delete_file(PathBuf::from(crate::linux::CONFIG_PATH));
    delete_file(PathBuf::from(crate::linux::EBPF_PATH));
    delete_file(PathBuf::from(crate::linux::MAN_PATH));
}
