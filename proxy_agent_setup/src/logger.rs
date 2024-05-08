// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use proxy_agent_shared::{logger_manager, misc_helpers};
use std::path::PathBuf;

const LOGGER_KEY: &str = "setup.log";
pub fn init_logger() {
    force_init_logger(misc_helpers::get_current_exe_dir(), LOGGER_KEY);
}

fn force_init_logger(log_folder: PathBuf, log_name: &str) {
    logger_manager::init_logger(
        log_name.to_string(),
        log_folder,
        log_name.to_string(),
        20 * 1024 * 1024,
        30,
    );
}

pub fn write(message: String) {
    println!("{}", message.to_string());
    logger_manager::write(LOGGER_KEY, message);
}
