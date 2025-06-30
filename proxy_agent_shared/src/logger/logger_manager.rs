// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
//! This module manages the loggers for the application.
//! It provides functionality to set up loggers, write logs, and manage log levels.
//! It uses a static `OnceCell` to ensure that the loggers are initialized only once.

use super::rolling_logger::RollingLogger;
#[cfg(windows)]
use crate::etw::application::ApplicationEventWritter;
use crate::logger::LoggerLevel;
use std::collections::HashMap;

// The loggers are stored in a static `OnceCell` to ensure they are initialized only once.
static LOGGERS: tokio::sync::OnceCell<HashMap<String, RollingLogger>> =
    tokio::sync::OnceCell::const_new();
// The `DEFAULT_LOGGER_KEY` is used to specify which rolling logger should be used by default when no key is provided.
static DEFAULT_LOGGER_KEY: tokio::sync::OnceCell<String> = tokio::sync::OnceCell::const_new();
// The `MAX_LOG_LEVEL` is used to set the maximum log level for the loggers.
static MAX_LOG_LEVEL: tokio::sync::OnceCell<LoggerLevel> = tokio::sync::OnceCell::const_new();
// The `MAX_SYSTEM_LOG_LEVEL` is used to set the maximum log level for system logs.
static MAX_SYSTEM_LOG_LEVEL: tokio::sync::OnceCell<LoggerLevel> =
    tokio::sync::OnceCell::const_new();
#[cfg(windows)]
static WINDOWS_ETW_APPLICATION_LOGGER: tokio::sync::OnceCell<ApplicationEventWritter> =
    tokio::sync::OnceCell::const_new();

/// Setup the loggers and set the default logger key
/// # Arguments
/// * `loggers` - A hashmap of loggers
/// * `default_logger_key` - The default logger key
/// * `max_log_level` - The maximum log level for file logging
/// # Panics
/// * If the default logger key is not found in the loggers hashmap
pub fn set_loggers(
    loggers: HashMap<String, RollingLogger>,
    default_logger_key: String,
    max_log_level: LoggerLevel,
) {
    if !MAX_LOG_LEVEL.initialized() {
        if let Err(e) = MAX_LOG_LEVEL.set(max_log_level) {
            write_system_log(
                LoggerLevel::Error,
                format!("Failed to set logger level: {e}"),
            );
        }
    }

    if LOGGERS.initialized() {
        return;
    }

    if !loggers.contains_key(&default_logger_key) {
        panic!("Default logger key not found in the loggers hashmap");
    }

    // set the loggers once
    if let Err(e) = LOGGERS.set(loggers) {
        write_system_log(LoggerLevel::Error, format!("Failed to set loggers: {e}"));
    };
    if let Err(e) = DEFAULT_LOGGER_KEY.set(default_logger_key) {
        write_system_log(
            LoggerLevel::Error,
            format!("Failed to set default logger key: {e}"),
        );
    }
}

pub fn set_system_logger(max_log_level: LoggerLevel, _service_name: &str) {
    #[cfg(windows)]
    {
        if !WINDOWS_ETW_APPLICATION_LOGGER.initialized() {
            match ApplicationEventWritter::new(_service_name) {
                Ok(logger) => {
                    if let Err(e) = WINDOWS_ETW_APPLICATION_LOGGER.set(logger) {
                        write_system_log(
                            LoggerLevel::Error,
                            format!("Failed to set Windows Application ETW logger: {e}"),
                        );
                    }
                }
                Err(e) => {
                    write_system_log(
                        LoggerLevel::Error,
                        format!("Failed to create Windows Application ETW logger: {e}"),
                    );
                }
            }
        }
    }

    if !MAX_SYSTEM_LOG_LEVEL.initialized() {
        if let Err(e) = MAX_SYSTEM_LOG_LEVEL.set(max_log_level) {
            write_system_log(
                LoggerLevel::Error,
                format!("Failed to set system logger level: {e}"),
            );
        }
    }
}

pub fn get_max_logger_level() -> LoggerLevel {
    let level = match MAX_LOG_LEVEL.get() {
        Some(l) => *l, // No need to use `clone` on type `Level` which implements the `Copy` trait
        None => LoggerLevel::Trace,
    };
    level
}

fn get_logger(logger_key: Option<String>) -> Option<&'static RollingLogger> {
    if let Some(loggers) = LOGGERS.get() {
        let key = match logger_key {
            Some(k) => k,
            None => DEFAULT_LOGGER_KEY.get().unwrap().clone(),
        };
        return loggers.get(&key);
    }
    None
}

fn internal_log(logger_key: Option<String>, log_level: LoggerLevel, message: String) {
    // By default, we write the log to the system log
    // This is useful for debugging and monitoring purposes.
    write_system_log(log_level, message.clone());

    if log_level > get_max_logger_level() {
        return;
    }

    if let Some(logger) = get_logger(logger_key) {
        if let Err(e) = logger.write(log_level, message) {
            eprintln!("Error writing to log: {e}");
        }
    }
}

pub fn log(logger_key: String, log_level: LoggerLevel, message: String) {
    internal_log(Some(logger_key), log_level, message);
}

pub fn write_log(log_level: LoggerLevel, message: String) {
    internal_log(None, log_level, message);
}

pub fn write_info(message: String) {
    write_log(LoggerLevel::Info, message);
}

pub fn write_warn(message: String) {
    write_log(LoggerLevel::Warn, message);
}

pub fn write_err(message: String) {
    write_log(LoggerLevel::Error, message);
}

pub fn write_many(logger_key: Option<String>, messages: Vec<String>) {
    if let Some(logger) = get_logger(logger_key) {
        if let Err(e) = logger.write_many(messages) {
            eprintln!("Error writing to log: {e}");
        }
    }
}

fn write_system_log(log_level: LoggerLevel, message: String) {
    if log_level > get_max_system_logger_level() {
        return;
    }

    // Linux automatically captures console logs to syslog.
    if log_level == LoggerLevel::Error {
        eprintln!("{message}",);
    } else {
        println!("{message}",);
    }

    #[cfg(windows)]
    {
        if let Some(logger) = WINDOWS_ETW_APPLICATION_LOGGER.get() {
            logger.write(log_level, message);
        } else {
            eprintln!("Windows ETW Application logger is not initialized.");
        }
    }
}

fn get_max_system_logger_level() -> LoggerLevel {
    let level = match MAX_SYSTEM_LOG_LEVEL.get() {
        Some(l) => *l, // No need to use `clone` on type `Level` which implements the `Copy` trait
        None => LoggerLevel::Error,
    };
    level
}

#[cfg(test)]
mod tests {
    use crate::logger::LoggerLevel;
    use crate::misc_helpers;
    use ctor::{ctor, dtor};
    use std::env;
    use std::fs;

    const TEST_LOGGER_KEY: &str = "logger_manager_test";

    fn get_temp_test_dir() -> std::path::PathBuf {
        let mut temp_test_path = env::temp_dir();
        temp_test_path.push(TEST_LOGGER_KEY);
        temp_test_path
    }

    #[ctor]
    fn setup() {
        // Setup logger_manager for unit tests
        let logger = crate::logger::rolling_logger::RollingLogger::create_new(
            get_temp_test_dir(),
            "test.log".to_string(),
            200,
            6,
        );
        let mut loggers = std::collections::HashMap::new();
        loggers.insert(TEST_LOGGER_KEY.to_string(), logger);
        crate::logger::logger_manager::set_loggers(
            loggers,
            TEST_LOGGER_KEY.to_string(),
            LoggerLevel::Trace,
        );
    }

    #[dtor]
    fn cleanup() {
        // clean up and ignore the clean up errors
        _ = fs::remove_dir_all(&get_temp_test_dir());
    }

    #[test]
    fn logger_manager_test() {
        for _ in [0; 20] {
            super::write_log(
                LoggerLevel::Trace,
                String::from("This is a test message This is a test message"),
            );
            super::write_log(
                LoggerLevel::Debug,
                String::from("This is a test message This is a test message"),
            );
            super::write_log(LoggerLevel::Info, "message from write_info".to_string());
            super::write_log(LoggerLevel::Warn, "message from write_warn".to_string());
            super::write_log(LoggerLevel::Error, "message from write_err".to_string());
        }

        let file_count = misc_helpers::get_files(&get_temp_test_dir()).unwrap();
        assert_eq!(6, file_count.len(), "log file count mismatch");
    }
}
