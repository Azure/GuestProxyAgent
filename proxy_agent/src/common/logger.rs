// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use proxy_agent_shared::logger_manager::{self, LoggerLevel};

pub const AGENT_LOGGER_KEY: &str = "Agent_Logger";

pub fn write(message: String) {
    logger_manager::log(AGENT_LOGGER_KEY.to_string(), LoggerLevel::Verbeose, message);
}

pub fn write_information(message: String) {
    logger_manager::log(
        AGENT_LOGGER_KEY.to_string(),
        LoggerLevel::Information,
        message,
    );
}

pub fn write_warning(message: String) {
    logger_manager::log(AGENT_LOGGER_KEY.to_string(), LoggerLevel::Warning, message);
}

pub fn write_error(message: String) {
    logger_manager::log(AGENT_LOGGER_KEY.to_string(), LoggerLevel::Error, message);
}
