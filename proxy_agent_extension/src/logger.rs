// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use proxy_agent_shared::logger::{logger_manager, LoggerLevel};
use std::path::PathBuf;

static LOGGER_KEY: tokio::sync::OnceCell<String> = tokio::sync::OnceCell::const_new();
pub fn get_logger_key() -> String {
    LOGGER_KEY
        .get()
        .expect("You must set the LOGGER_KEY before this function is called")
        .to_string()
}

pub async fn init_logger(log_folder: String, log_name: &str) {
    logger_manager::init_logger(
        log_name.to_string(),
        PathBuf::from(log_folder),
        log_name.to_string(),
        20 * 1024 * 1024,
        30,
    )
    .await;

    if !LOGGER_KEY.initialized() {
        if let Err(e) = LOGGER_KEY.set(log_name.to_string()) {
            eprintln!("Failed to set logger key: {}", e);
        };
    }
}

pub fn write(message: String) {
    logger_manager::log(get_logger_key(), LoggerLevel::Information, message);
}
