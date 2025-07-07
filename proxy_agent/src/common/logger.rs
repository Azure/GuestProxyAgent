// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use proxy_agent_shared::{
    logger::{logger_manager, LoggerLevel},
    telemetry::event_logger,
};

use super::config;

pub const AGENT_LOGGER_KEY: &str = "Agent_Logger";

pub fn write(message: String) {
    log(LoggerLevel::Trace, message);
}

pub fn write_information(message: String) {
    log(LoggerLevel::Info, message);
}

pub fn write_warning(message: String) {
    log(LoggerLevel::Warn, message);
}

pub fn write_error(message: String) {
    log(LoggerLevel::Error, message);
}

fn log(log_level: LoggerLevel, message: String) {
    if let Some(log_for_event) = config::get_file_log_level_for_events() {
        if log_for_event >= log_level {
            // write to event
            let (module_name, caller_name) =
                proxy_agent_shared::logger::get_caller_info("proxy_agent::common::logger");
            event_logger::write_event_only(
                log_level,
                message.to_string(),
                &caller_name,
                &module_name,
            );
        }
    }

    logger_manager::log(AGENT_LOGGER_KEY.to_string(), log_level, message);
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
                eprintln!("Failed to write to serial console: {message}");
            }
        }
        Err(e) => {
            eprintln!("Failed to open serial console: {e}");
        }
    }
}
