// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use proxy_agent_shared::{
    logger::{self, logger_manager, LoggerLevel},
    misc_helpers,
};
use std::path::PathBuf;

const LOGGER_KEY: &str = "setup.log";
pub fn init_logger() {
    force_init_logger(misc_helpers::get_current_exe_dir(), LOGGER_KEY);
}

fn force_init_logger(log_folder: PathBuf, log_name: &str) {
    logger::init_loggers(
        log_folder,
        &[(log_name, log_name)],
        log_name,
        20 * 1024 * 1024,
        30,
        LoggerLevel::Trace,
    );
}

pub fn write(message: String) {
    println!("{message}");
    logger_manager::log(LOGGER_KEY.to_string(), LoggerLevel::Info, message);
}

pub fn write_error(message: String) {
    eprintln!("{message}");
    logger_manager::log(LOGGER_KEY.to_string(), LoggerLevel::Error, message);
}
