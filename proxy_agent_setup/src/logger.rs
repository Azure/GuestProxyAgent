// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use proxy_agent_shared::{
    logger::{logger_manager, rolling_logger::RollingLogger, LoggerLevel},
    misc_helpers,
};
use std::path::PathBuf;

const LOGGER_KEY: &str = "setup.log";
pub fn init_logger() {
    force_init_logger(misc_helpers::get_current_exe_dir(), LOGGER_KEY);
}

fn force_init_logger(log_folder: PathBuf, log_name: &str) {
    let logger = RollingLogger::create_new(log_folder, log_name.to_string(), 20 * 1024 * 1024, 30);
    let mut loggers = std::collections::HashMap::new();
    loggers.insert(log_name.to_string(), logger);
    logger_manager::set_loggers(loggers, log_name.to_string());
}

pub fn write(message: String) {
    println!("{}", message);
    logger_manager::log(LOGGER_KEY.to_string(), LoggerLevel::Info, message);
}
