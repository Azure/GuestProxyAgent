// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

use super::rolling_logger::RollingLogger;
use log::Level;
use std::collections::HashMap;

static LOGGERS: tokio::sync::OnceCell<HashMap<String, RollingLogger>> =
    tokio::sync::OnceCell::const_new();
static DEFAULT_LOGGER_KEY: tokio::sync::OnceCell<String> = tokio::sync::OnceCell::const_new();
static MAX_LOG_LEVEL: tokio::sync::OnceCell<Level> = tokio::sync::OnceCell::const_new();

/// Setup the loggers and set the default logger key
/// # Arguments
/// * `loggers` - A hashmap of loggers
/// * `default_logger_key` - The default logger key
/// # Panics
/// * If the default logger key is not found in the loggers hashmap
pub fn set_loggers(loggers: HashMap<String, RollingLogger>, default_logger_key: String) {
    if LOGGERS.initialized() {
        return;
    }

    if !loggers.contains_key(&default_logger_key) {
        panic!("Default logger key not found in the loggers hashmap");
    }

    // set the loggers once
    LOGGERS.set(loggers).unwrap();
    DEFAULT_LOGGER_KEY.set(default_logger_key).unwrap();
}

pub fn set_logger_level(log_level: Level) {
    if MAX_LOG_LEVEL.initialized() {
        return;
    }
    MAX_LOG_LEVEL.set(log_level).unwrap();
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

pub fn log(logger_key: String, log_level: Level, message: String) {
    let level = match MAX_LOG_LEVEL.get() {
        Some(l) => *l, // No need to use `clone` on type `Level` which implements the `Copy` trait
        None => Level::Trace,
    };
    if log_level > level {
        return;
    }

    if let Some(logger) = get_logger(Some(logger_key)) {
        if let Err(e) = logger.write(log_level, message) {
            eprintln!("Error writing to log: {}", e);
        }
    }
}

pub fn write_log(log_level: Level, message: String) {
    let level = match MAX_LOG_LEVEL.get() {
        Some(l) => *l, // No need to use `clone` on type `Level` which implements the `Copy` trait
        None => Level::Trace,
    };
    if log_level > level {
        return;
    }

    if let Some(logger) = get_logger(None) {
        if let Err(e) = logger.write(log_level, message) {
            eprintln!("Error writing to log: {}", e);
        }
    }
}

pub fn write_info(message: String) {
    write_log(Level::Info, message);
}

pub fn write_warn(message: String) {
    write_log(Level::Warn, message);
}

pub fn write_err(message: String) {
    write_log(Level::Error, message);
}

#[cfg(test)]
mod tests {
    use crate::misc_helpers;
    use ctor::{ctor, dtor};
    use log::Level;
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
        crate::logger::logger_manager::set_loggers(loggers, TEST_LOGGER_KEY.to_string());
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
                Level::Trace,
                String::from("This is a test message This is a test message"),
            );
            super::write_log(
                Level::Debug,
                String::from("This is a test message This is a test message"),
            );
            super::write_log(Level::Info, "message from write_info".to_string());
            super::write_log(Level::Warn, "message from write_warn".to_string());
            super::write_log(Level::Error, "message from write_err".to_string());
        }

        let file_count = misc_helpers::get_files(&get_temp_test_dir()).unwrap();
        assert_eq!(6, file_count.len(), "log file count mismatch");
    }
}
