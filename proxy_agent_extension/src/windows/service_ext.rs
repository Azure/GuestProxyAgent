// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use crate::constants;
use crate::logger;
use proxy_agent_shared::{misc_helpers, service};
use std::path::PathBuf;
use std::process;

pub fn install_extension_service() {
    //Get executable file path
    let exe_root_path: PathBuf = misc_helpers::get_current_exe_dir();
    let service_exe_path = exe_root_path.join(constants::EXTENSION_PROCESS_NAME);
    match service::install_service(
        constants::EXTENSION_SERVICE_NAME,
        constants::EXTENSION_SERVICE_DISPLAY_NAME,
        vec![],
        service_exe_path,
    ) {
        Ok(_service) => {
            logger::write(format!(
                "Service {} successfully installed",
                constants::EXTENSION_SERVICE_NAME
            ));
        }
        Err(e) => {
            logger::write(format!(
                "Service {} install failed: {}",
                constants::EXTENSION_SERVICE_NAME,
                e
            ));
            eprintln!(
                "Service {} install failed: {}",
                constants::EXTENSION_SERVICE_NAME,
                e
            );
            process::exit(constants::EXIT_CODE_SERVICE_INSTALL_ERR);
        }
    }
}

pub fn uninstall_extension_service() {
    // Stop and Delete the service given
    match service::stop_and_delete_service(constants::EXTENSION_SERVICE_NAME) {
        Ok(_service) => {
            logger::write(format!(
                "Service {} successfully uninstalled",
                constants::EXTENSION_SERVICE_NAME
            ));
        }
        Err(e) => {
            logger::write(format!(
                "Service {} uninstall failed: {}",
                constants::EXTENSION_SERVICE_NAME,
                e
            ));
            eprintln!(
                "Service {} update failed: {}",
                constants::EXTENSION_SERVICE_NAME,
                e
            );
            process::exit(constants::EXIT_CODE_SERVICE_UNINSTALL_ERR);
        }
    }
}

pub fn start_extension_service() {
    service::start_service(
        constants::EXTENSION_SERVICE_NAME,
        constants::SERVICE_START_RETRY_COUNT,
        std::time::Duration::from_secs(15),
    );
}

pub fn stop_extension_service() {
    match service::stop_service(constants::EXTENSION_SERVICE_NAME) {
        Ok(_service) => {
            logger::write(format!(
                "Service {} successfully stopped",
                constants::EXTENSION_SERVICE_NAME
            ));
        }
        Err(e) => {
            logger::write(format!(
                "Service {} stop failed: {}",
                constants::EXTENSION_SERVICE_NAME,
                e
            ));
            eprintln!(
                "Service {} stop failed: {}",
                constants::EXTENSION_SERVICE_NAME,
                e
            );
            process::exit(constants::EXIT_CODE_SERVICE_STOP_ERR);
        }
    }
}

pub fn update_extension_service(exe_root_path: PathBuf) {
    let service_exe_path = exe_root_path.join(constants::EXTENSION_PROCESS_NAME);
    logger::write(format!(
        "Updating service {} with exe_path {}",
        constants::EXTENSION_SERVICE_NAME,
        misc_helpers::path_to_string(service_exe_path.to_path_buf())
    ));
    match service::update_service(
        constants::EXTENSION_SERVICE_NAME,
        constants::EXTENSION_SERVICE_DISPLAY_NAME,
        vec![],
        service_exe_path,
    ) {
        Ok(_service) => {
            logger::write(format!(
                "Service {} successfully updated",
                constants::EXTENSION_SERVICE_NAME
            ));
        }
        Err(e) => {
            logger::write(format!(
                "Service {} update failed: {}",
                constants::EXTENSION_SERVICE_NAME,
                e
            ));
            eprintln!(
                "Service {} update failed: {}",
                constants::EXTENSION_SERVICE_NAME,
                e
            );
            process::exit(constants::EXIT_CODE_SERVICE_UPDATE_ERR);
        }
    }
}
