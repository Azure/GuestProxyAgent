// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

mod args;
pub mod backup;
pub mod error;
pub mod logger;
pub mod result;
pub mod running;
pub mod setup;

#[cfg(not(windows))]
mod linux;

use clap::Parser;
use proxy_agent_shared::misc_helpers;
use proxy_agent_shared::service;
use std::process;
use std::time::Duration;
use std::{fs, path::PathBuf};

#[cfg(windows)]
const SERVICE_NAME: &str = "GuestProxyAgent";
const SERVICE_DISPLAY_NAME: &str = "Microsoft Azure Guest Proxy Agent";

#[cfg(not(windows))]
const SERVICE_NAME: &str = "azure-proxy-agent";

fn main() {
    logger::init_logger();
    let cli = args::Cli::parse();
    logger::write(format!(
        "\r\n\r\n============== ProxyAgent Setup Tool ({}) is starting with args: {} ==============",
        misc_helpers::get_current_version(),
        cli
    ));

    match cli.command {
        args::Command::Backup => {
            backup_proxy_agent();
        }
        args::Command::Restore { delete_backup } => {
            if !check_backup_exists() {
                logger::write("Backup check failed, skip the restore operation.".to_string());
                return;
            }
            stop_service();
            let proxy_agent_target_folder = restore_proxy_agent();
            setup_service(
                proxy_agent_target_folder,
                backup::proxy_agent_backup_folder(),
            );

            if delete_backup {
                delete_backup_folder();
            }
        }
        args::Command::Uninstall { uninstall_mode } => {
            let proxy_agent_running_folder = uninstall_service();
            if uninstall_mode == args::UninstallMode::Package {
                delete_package(proxy_agent_running_folder);
            }
        }
        args::Command::Purge => {
            delete_backup_folder();
        }
        args::Command::Install => {
            stop_service();
            let proxy_agent_target_folder = copy_proxy_agent();
            setup_service(
                proxy_agent_target_folder,
                misc_helpers::get_current_exe_dir(),
            );
        }
    }
}

fn copy_proxy_agent() -> PathBuf {
    let src_folder = setup::proxy_agent_folder_in_setup();
    let dst_folder = running::proxy_agent_version_target_folder(&setup::proxy_agent_exe_in_setup());
    #[cfg(windows)]
    {
        copy_proxy_agent_files(src_folder, dst_folder.to_path_buf());
    }
    #[cfg(not(windows))]
    {
        linux::copy_files(src_folder);
    }
    dst_folder
}

fn backup_proxy_agent() {
    #[cfg(windows)]
    {
        copy_proxy_agent_files(
            running::proxy_agent_running_folder(SERVICE_NAME),
            backup::proxy_agent_backup_package_folder(),
        );
    }
    #[cfg(not(windows))]
    {
        linux::backup_files();
    }
}

fn restore_proxy_agent() -> PathBuf {
    let src_folder = backup::proxy_agent_backup_package_folder();
    let dst_folder =
        running::proxy_agent_version_target_folder(&setup::proxy_agent_exe_path(&src_folder));
    #[cfg(windows)]
    {
        copy_proxy_agent_files(src_folder, dst_folder.to_path_buf());
    }
    #[cfg(not(windows))]
    {
        linux::copy_files(src_folder);
    }
    dst_folder
}

#[cfg(windows)]
fn copy_proxy_agent_files(src_folder: PathBuf, dst_folder: PathBuf) {
    match misc_helpers::try_create_folder(&dst_folder) {
        Ok(_) => {}
        Err(e) => {
            logger::write(format!(
                "Failed to create folder {:?}, error: {:?}",
                dst_folder, e
            ));
        }
    }
    match misc_helpers::get_files(&src_folder) {
        Ok(files) => {
            for file in files {
                let file_name = misc_helpers::get_file_name(&file);
                let dst_file = dst_folder.join(&file_name);
                match fs::copy(&file, &dst_file) {
                    Ok(_) => {
                        logger::write(format!("Copied {:?} to {:?}", file, dst_file));
                    }
                    Err(e) => {
                        logger::write(format!(
                            "Failed to copy {:?} to {:?}, error: {:?}",
                            file, dst_file, e
                        ));
                    }
                }
            }
        }
        Err(e) => {
            logger::write(format!(
                "Failed to get files from {:?}, error: {:?}",
                src_folder, e
            ));
        }
    }
}

fn stop_service() {
    match service::stop_service(SERVICE_NAME) {
        Ok(_) => {
            logger::write(format!("Stopped service {} successfully", SERVICE_NAME));
        }
        Err(e) => {
            logger::write(format!(
                "Stopped service {} failed, error: {:?}",
                SERVICE_NAME, e
            ));
        }
    }
}

fn setup_service(proxy_agent_target_folder: PathBuf, _service_config_folder_path: PathBuf) {
    #[cfg(windows)]
    {
        // delete the existing proxy agent service folder
        let proxy_agent_running_folder = running::proxy_agent_running_folder(SERVICE_NAME);
        if proxy_agent_running_folder.exists()
            && proxy_agent_running_folder != proxy_agent_target_folder
        {
            delete_folder(proxy_agent_running_folder);
        }
    }
    #[cfg(not(windows))]
    {
        match linux::setup_service(SERVICE_NAME, _service_config_folder_path) {
            Ok(_) => {
                logger::write(format!("Setup service {} successfully", SERVICE_NAME));
            }
            Err(e) => {
                logger::write(format!(
                    "Setup service {} failed, error: {:?}",
                    SERVICE_NAME, e
                ));
                process::exit(1);
            }
        }
    }

    match service::install_service(
        SERVICE_NAME,
        SERVICE_DISPLAY_NAME,
        vec!["EbpfCore", "NetEbpfExt"],
        setup::proxy_agent_exe_path(&proxy_agent_target_folder),
    ) {
        Ok(_) => {
            logger::write(format!("Install service {} successfully", SERVICE_NAME));
        }
        Err(e) => {
            logger::write(format!(
                "Install service {} failed, error: {:?}",
                SERVICE_NAME, e
            ));
            process::exit(1);
        }
    }

    #[cfg(windows)]
    {
        // check if eBPF setup script exists, if exist then try launch the eBPF setup scripts
        let ebpf_setup_script_file = setup::ebpf_setup_script_file();
        if ebpf_setup_script_file.exists() && ebpf_setup_script_file.is_file() {
            let setup_script_file_str = misc_helpers::path_to_string(&ebpf_setup_script_file);
            let output = misc_helpers::execute_command(
                "powershell.exe",
                vec![
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    &setup_script_file_str,
                ],
                1,
            );
            logger::write(format!(
                "ebpf_setup: invoked script file '{}' with result: '{}'-'{}'-'{}'.",
                setup_script_file_str, output.0, output.1, output.2
            ));
        }
    }

    service::start_service(SERVICE_NAME, 5, Duration::from_secs(15));
    logger::write(format!("Service {} start successfully", SERVICE_NAME));
}

fn check_backup_exists() -> bool {
    let proxy_agent_exe = setup::proxy_agent_exe_path(&backup::proxy_agent_backup_package_folder());
    if !proxy_agent_exe.exists() {
        logger::write(format!(
            "GuestProxyAgent ({:?}) does not exists.",
            proxy_agent_exe
        ));
        return false;
    }

    true
}

fn uninstall_service() -> PathBuf {
    let proxy_agent_running_folder = running::proxy_agent_running_folder(SERVICE_NAME);

    match service::stop_and_delete_service(SERVICE_NAME) {
        Ok(_) => {
            logger::write(format!("Uninstall service {} successfully", SERVICE_NAME));
        }
        Err(e) => {
            logger::write(format!(
                "Uninstall service {} failed, error: {:?}",
                SERVICE_NAME, e
            ));
            process::exit(1);
        }
    }

    proxy_agent_running_folder
}

fn delete_package(_proxy_agent_running_folder: PathBuf) {
    #[cfg(windows)]
    {
        delete_folder(_proxy_agent_running_folder);
    }
    #[cfg(not(windows))]
    {
        linux::delete_files();
    }
}

fn delete_folder(folder_to_be_delete: PathBuf) {
    match fs::remove_dir_all(&folder_to_be_delete) {
        Ok(_) => {
            logger::write(format!("Deleted folder {:?}", folder_to_be_delete));
        }
        Err(e) => {
            logger::write(format!(
                "Failed to delete folder {:?}, error: {:?}",
                folder_to_be_delete, e
            ));
        }
    }
}

fn delete_backup_folder() {
    let backup_folder = backup::proxy_agent_backup_folder();
    delete_folder(backup_folder);
}
