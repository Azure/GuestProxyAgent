// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#![cfg(not(windows))]

use crate::logger;
use proxy_agent_shared::misc_helpers;
use std::{fs, path::PathBuf};

const SERVICE_CONFIG_FILE_NAME: &str = "GuestProxyAgent.service";
// setup the soft link to the service executable
pub const SERVICE_EXEC_LINK_NAME: &str = "/usr/sbin/azure-proxy-agent";

pub fn setup_service(
    service_name: &str,
    exe_dir: PathBuf,
    service_file_dir: PathBuf,
) -> std::io::Result<u64> {
    setup_soft_link(
        exe_dir,
        proxy_agent_shared::linux::SERVICE_PACKAGE_LINK_NAME,
    );
    let proxy_agent_exe =
        PathBuf::from(proxy_agent_shared::linux::SERVICE_PACKAGE_LINK_NAME).join("GuestProxyAgent");
    setup_soft_link(proxy_agent_exe.to_path_buf(), SERVICE_EXEC_LINK_NAME);
    set_bin_t_security_context(proxy_agent_exe.to_path_buf());

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

fn setup_soft_link(target_path: PathBuf, soft_link_name: &str) {
    match read_link(soft_link_name) {
        Some(path) => {
            if path == target_path {
                logger::write(format!(
                    "setup_soft_link: soft link already exists and set to correct path: {:?}.",
                    target_path
                ));
                return;
            }
            // remove the old soft link
            let output = misc_helpers::execute_command("rm", vec!["-r", soft_link_name], -1);
            let message = format!(
                "setup_soft_link: removed the existing soft link {}  result: '{}'-'{}'-'{}'.",
                soft_link_name, output.0, output.1, output.2
            );
            logger::write(message);

            // delete the path if it is a folder
            if path.is_dir() {
                _ = fs::remove_dir_all(path.to_path_buf());
                let message = format!(
                    "setup_soft_link: removed the existing folder {} .",
                    misc_helpers::path_to_string(path.to_path_buf())
                );
                logger::write(message);
            }
        }
        None => {
            logger::write(format!(
                "setup_soft_link: soft link '{}' does not exist, creating one.",
                soft_link_name
            ));
        }
    }
    let target = misc_helpers::path_to_string(target_path.to_path_buf());
    let output = misc_helpers::execute_command("ln", vec!["-sf", &target, soft_link_name], -1);
    let message = format!(
        "setup_soft_link: {} -> {} result: '{}'-'{}'-'{}'.",
        soft_link_name, target, output.0, output.1, output.2
    );
    logger::write(message);
}

pub fn read_link(link_name: &str) -> Option<PathBuf> {
    match fs::read_link(link_name) {
        Ok(path) => Some(path),
        Err(e) => {
            let message = format!("read_link: failed to read link '{}': {}", link_name, e,);
            logger::write(message);
            None
        }
    }
}

fn set_bin_t_security_context(proxy_agent_exe: PathBuf) {
    let proxy_agent = misc_helpers::path_to_string(proxy_agent_exe);

    // redhat 9.0 set the security context to /usr/lib with lib_t instead of bin_t
    // ls -Z /usr/lib/azure-proxy-agent/package/GuestProxyAgent
    // unconfined_u:object_r:lib_t:s0 /usr/lib/azure-proxy-agent/package/GuestProxyAgent
    let output = misc_helpers::execute_command("ls", vec!["-Z", &proxy_agent], -1);
    logger::write(format!(
        "set_bin_t_security_context: ls -Z {} with result: '{}'-'{}'-'{}'",
        &proxy_agent, output.0, output.1, output.2
    ));
    let security_context = output.1.trim();
    if security_context == format!("? {}", &proxy_agent) {
        logger::write(format!(
            "set_bin_t_security_context: {} does not support bin_t, skip set it.",
            misc_helpers::get_long_os_version()
        ));
        return;
    }
    if security_context.contains("bin_t") {
        logger::write(format!("set_bin_t_security_context: {} already has bin_t, skip set it.", &proxy_agent));
        return;
    }

    // chcon -t bin_t /usr/lib/azure-proxy-agent/package/GuestProxyAgent
    let output = misc_helpers::execute_command("chcon", vec!["-t", "bin_t", &proxy_agent], -1);
    let message = format!(
        "set_bin_t_security_context: chcon -t bin_t {} with result: '{}'-'{}'-'{}'.",
        &proxy_agent, output.0, output.1, output.2
    );
    logger::write(message);
}
