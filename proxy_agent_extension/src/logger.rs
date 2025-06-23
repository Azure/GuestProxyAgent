// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use proxy_agent_shared::logger::{logger_manager, rolling_logger::RollingLogger, LoggerLevel};
use std::path::PathBuf;
static LOGGER_KEY: tokio::sync::OnceCell<String> = tokio::sync::OnceCell::const_new();
pub fn get_logger_key() -> String {
    LOGGER_KEY
        .get()
        .expect("You must set the LOGGER_KEY before this function is called")
        .to_string()
}

pub fn init_logger(log_folder: String, log_name: &str) {
    let logger = RollingLogger::create_new(
        PathBuf::from(log_folder),
        log_name.to_string(),
        20 * 1024 * 1024,
        30,
    );
    let mut loggers = std::collections::HashMap::new();
    loggers.insert(log_name.to_string(), logger);
    logger_manager::set_loggers(loggers, log_name.to_string(), LoggerLevel::Trace);

    if !LOGGER_KEY.initialized() {
        if let Err(e) = LOGGER_KEY.set(log_name.to_string()) {
            eprintln!("Failed to set logger key: {}", e);
        };
    }
}

pub fn write(message: String) {
    logger_manager::write_log(LoggerLevel::Info, message);
}

#[cfg(test)]
mod tests {
    use ctor::{ctor, dtor};
    use std::env;
    use std::fs;

    const TEST_LOGGER_KEY: &str = "proxy_agent_extension_test";

    fn get_temp_test_dir() -> std::path::PathBuf {
        let mut temp_test_path = env::temp_dir();
        temp_test_path.push(TEST_LOGGER_KEY);
        temp_test_path
    }

    #[ctor]
    fn setup() {
        // Setup logger_manager for unit tests
        super::init_logger(
            get_temp_test_dir().to_string_lossy().to_string(),
            "test.log",
        );
    }

    #[dtor]
    fn cleanup() {
        // clean up and ignore the clean up errors
        _ = fs::remove_dir_all(&get_temp_test_dir());
    }
}
