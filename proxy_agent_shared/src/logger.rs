// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

pub mod logger_manager;
pub mod rolling_logger;

#[derive(PartialEq, PartialOrd, Debug)]
pub enum LoggerLevel {
    Verbose,
    Information,
    Warning,
    Error,
}

impl LoggerLevel {
    pub fn from_string(level: &str) -> Self {
        match level {
            "Verb" => LoggerLevel::Verbose,
            "Info" => LoggerLevel::Information,
            "Warn" => LoggerLevel::Warning,
            "Err" => LoggerLevel::Error,
            _ => LoggerLevel::Information,
        }
    }
}
