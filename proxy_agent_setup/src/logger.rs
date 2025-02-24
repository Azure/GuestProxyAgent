// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use proxy_agent_shared::{logger::logger_manager, logger::LoggerLevel, misc_helpers};
use std::path::PathBuf;

const LOGGER_KEY: &str = "setup.log";
pub async fn init_logger() {
    force_init_logger(misc_helpers::get_current_exe_dir(), LOGGER_KEY).await;
}

async fn force_init_logger(log_folder: PathBuf, log_name: &str) {
    logger_manager::init_logger(
        log_name.to_string(),
        log_folder,
        log_name.to_string(),
        20 * 1024 * 1024,
        30,
    )
    .await;
}

pub fn write(message: String) {
    println!("{}", message);
    logger_manager::log(LOGGER_KEY.to_string(), LoggerLevel::Information, message);
}
