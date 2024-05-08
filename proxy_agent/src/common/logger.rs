// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use proxy_agent_shared::logger_manager;

pub const AGENT_LOGGER_KEY: &str = "Agent_Logger";

pub fn write(message: String) {
    logger_manager::write(AGENT_LOGGER_KEY, message);
}

pub fn write_information(message: String) {
    logger_manager::write_information(AGENT_LOGGER_KEY, message);
}

pub fn write_warning(message: String) {
    logger_manager::write_warning(AGENT_LOGGER_KEY, message);
}

pub fn write_error(message: String) {
    logger_manager::write_error(AGENT_LOGGER_KEY, message);
}
