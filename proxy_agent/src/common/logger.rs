// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use proxy_agent_shared::{
    logger_manager::{self, LoggerLevel},
    misc_helpers,
};

pub const AGENT_LOGGER_KEY: &str = "Agent_Logger";

pub fn write(message: String) {
    log(LoggerLevel::Verbeose, message);
}

pub fn write_information(message: String) {
    log(LoggerLevel::Information, message);
}

pub fn write_warning(message: String) {
    log(LoggerLevel::Warning, message);
}

pub fn write_error(message: String) {
    log(LoggerLevel::Error, message);
}

fn log(log_level: LoggerLevel, message: String) {
    if log_level != LoggerLevel::Verbeose {
        write_console_log(message.to_string());
    };
    logger_manager::log(AGENT_LOGGER_KEY.to_string(), log_level, message);
}

pub fn write_console_log(message: String) {
    println!(
        "{} {}",
        misc_helpers::get_date_time_string_with_milliseconds(),
        message
    );
}

#[cfg(not(windows))]
pub fn write_serial_console_log(message: String) {
    use proxy_agent_shared::misc_helpers;
    use std::io::Write;

    let message = format!(
        "{} {}_{}({}) - {}\n",
        misc_helpers::get_date_time_string_with_milliseconds(),
        env!("CARGO_PKG_NAME"),
        misc_helpers::get_current_version(),
        std::process::id(),
        message
    );

    const SERIAL_CONSOLE_PATH: &str = "/dev/console";
    match std::fs::OpenOptions::new()
        .write(true)
        .open(SERIAL_CONSOLE_PATH)
    {
        Ok(mut serial_console) => {
            if serial_console.write_all(message.as_bytes()).is_err() {
                eprintln!("Failed to write to serial console: {}", message);
            }
        }
        Err(e) => {
            eprintln!("Failed to open serial console: {}", e);
        }
    }
}
