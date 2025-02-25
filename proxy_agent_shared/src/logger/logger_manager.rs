// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

use super::rolling_logger::RollingLogger;
use super::LoggerLevel;
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::path::PathBuf;
use tokio::sync::mpsc;

enum LoggerAction {
    InitLogger {
        logger_key: String,
        log_folder: PathBuf,
        log_name: String,
        log_size: u64,
        log_count: u16,
    },
    SetLoggerLevel {
        log_level: LoggerLevel,
    },
    WriteLog {
        logger_key: Option<String>,
        log_level: LoggerLevel,
        message: String,
    },
}

#[derive(Clone, Debug)]
struct Logger(mpsc::Sender<LoggerAction>);

impl Logger {
    pub fn start_new() -> Self {
        let (tx, mut rx) = mpsc::channel(100);
        tokio::spawn(async move {
            let mut loggers: HashMap<String, RollingLogger> = HashMap::new();
            let mut first_logger_key: Option<String> = None;
            let mut file_logger_level = LoggerLevel::Verbose;
            while let Some(action) = rx.recv().await {
                match action {
                    LoggerAction::InitLogger {
                        logger_key,
                        log_folder,
                        log_name,
                        log_size,
                        log_count,
                    } => {
                        if loggers.contains_key(&logger_key) {
                            eprintln!("logger '{logger_key}' already exists.");
                            continue;
                        }

                        let logger =
                            RollingLogger::create_new(log_folder, log_name, log_size, log_count);
                        loggers.insert(logger_key.to_string(), logger);
                        println!("logger '{logger_key}' created.");

                        if first_logger_key.is_none() {
                            first_logger_key = Some(logger_key);
                        }
                    }
                    LoggerAction::SetLoggerLevel { log_level } => {
                        file_logger_level = log_level;
                    }
                    LoggerAction::WriteLog {
                        logger_key,
                        log_level,
                        message,
                    } => {
                        if log_level < file_logger_level {
                            // skip write to file
                            continue;
                        }
                        // get the logger key
                        let logger_key = match logger_key {
                            Some(logger_key) => logger_key,
                            None => match first_logger_key.as_ref() {
                                Some(logger_key) => logger_key.clone(),
                                None => {
                                    eprintln!("No logger has been created.");
                                    continue;
                                }
                            },
                        };
                        match loggers.get_mut(&logger_key) {
                            Some(logger) => {
                                if let Err(e) = logger.write(log_level, message) {
                                    // TODO write to application event log if windows
                                    // TODO write to syslog if linux
                                    eprintln!(
                                        "Writing to logger '{}' with error: {}",
                                        logger_key, e
                                    );
                                }
                            }
                            None => {
                                println!("Error getting logger: {}", logger_key);
                            }
                        }
                    }
                }
            }
        });

        Self(tx)
    }

    async fn init_logger(
        &self,
        logger_key: String,
        log_folder: PathBuf,
        log_name: String,
        log_size: u64,
        log_count: u16,
    ) {
        if let Err(e) = self
            .0
            .send(LoggerAction::InitLogger {
                logger_key,
                log_folder,
                log_name,
                log_size,
                log_count,
            })
            .await
        {
            eprintln!("Error in init_logger: {}", e);
        }
    }

    async fn set_logger_level(&self, log_level: LoggerLevel) {
        if let Err(e) = self
            .0
            .send(LoggerAction::SetLoggerLevel { log_level })
            .await
        {
            eprintln!("Error in set_logger_level: {}", e);
        }
    }
    async fn write_log(&self, logger_key: Option<String>, log_level: LoggerLevel, message: String) {
        if let Err(e) = self
            .0
            .send(LoggerAction::WriteLog {
                logger_key,
                log_level,
                message,
            })
            .await
        {
            eprintln!("Error in write_log: {}", e);
        }
    }
}

static LOGGER: Lazy<Logger> = Lazy::new(Logger::start_new);

pub async fn init_logger(
    logger_key: String,
    log_folder: PathBuf,
    log_name: String,
    log_size: u64,
    log_count: u16,
) {
    LOGGER
        .init_logger(logger_key, log_folder, log_name, log_size, log_count)
        .await;
}

pub async fn set_logger_level(log_level: LoggerLevel) {
    LOGGER.set_logger_level(log_level).await;
}

pub fn log(logger_key: String, log_level: LoggerLevel, message: String) {
    tokio::spawn(async move {
        LOGGER.write_log(Some(logger_key), log_level, message).await;
    });
}

fn write_log(log_level: LoggerLevel, message: String) {
    tokio::spawn(async move {
        LOGGER.write_log(None, log_level, message).await;
    });
}

pub fn write_info(message: String) {
    write_log(LoggerLevel::Information, message);
}

pub fn write_warn(message: String) {
    write_log(LoggerLevel::Warning, message);
}

pub fn write_err(message: String) {
    write_log(LoggerLevel::Error, message);
}

#[cfg(test)]
mod tests {
    use super::LoggerLevel;
    use crate::misc_helpers;
    use std::env;
    use std::fs;

    #[tokio::test]
    async fn logger_manager_test() {
        let mut temp_test_path = env::temp_dir();
        let logger_key = "agent_logger_test";
        temp_test_path.push(logger_key);

        // clean up and ignore the clean up errors
        _ = fs::remove_dir_all(&temp_test_path);

        super::init_logger(
            logger_key.to_string(),
            temp_test_path.clone(),
            logger_key.to_string(),
            200,
            6,
        )
        .await;

        for _ in [0; 20] {
            super::write_log(
                LoggerLevel::Verbose,
                String::from("This is a test message This is a test message"),
            );
            super::write_log(
                LoggerLevel::Verbose,
                String::from("This is a test message This is a test message"),
            );
            super::write_log(
                LoggerLevel::Information,
                "message from write_info".to_string(),
            );
            super::write_log(LoggerLevel::Warning, "message from write_warn".to_string());
            super::write_log(LoggerLevel::Error, "message from write_err".to_string());
        }

        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        let file_count = misc_helpers::get_files(&temp_test_path).unwrap();
        assert_eq!(6, file_count.len(), "log file count mismatch");

        // clean up and ignore the clean up errors
        _ = fs::remove_dir_all(&temp_test_path);
    }

    #[test]
    fn logger_level_test() {
        let info_level = LoggerLevel::Information;
        assert_eq!(LoggerLevel::from_string("Info"), LoggerLevel::Information);

        let verb_level = LoggerLevel::from_string("Verb");
        assert_eq!(verb_level, LoggerLevel::Verbose);
        assert!(
            info_level > verb_level,
            "Info level should be greater than Verb level"
        );

        assert!(
            LoggerLevel::from_string("Verb") >= verb_level,
            "Verb level should be greater than or equal to Verb level"
        );
    }
}
