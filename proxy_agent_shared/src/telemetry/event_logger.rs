// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use crate::logger_manager;
use crate::logger_manager::LoggerLevel;
use crate::misc_helpers;
use crate::telemetry::Event;
use concurrent_queue::ConcurrentQueue;
use once_cell::sync::Lazy;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

pub const INFO_LEVEL: &str = "Informational";
pub const WARN_LEVEL: &str = "Warning";
pub const ERROR_LEVEL: &str = "Error";
pub const CRITICAL_LEVEL: &str = "Critical";
pub const MAX_MESSAGE_LENGTH: usize = 1024 * 4; // 4KB

static EVENT_QUEUE: Lazy<ConcurrentQueue<Event>> =
    Lazy::new(|| ConcurrentQueue::<Event>::bounded(1000));
static SHUT_DOWN: Lazy<Arc<AtomicBool>> = Lazy::new(|| Arc::new(AtomicBool::new(false)));

pub async fn start<F, Fut>(
    event_dir: PathBuf,
    mut interval: Duration,
    max_event_file_count: usize,
    logger_key: &str,
    set_status_fn: F,
) where
    F: Fn(String) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let message = "Telemetry event logger thread started.";
    set_status_fn(message.to_string());

    logger_manager::log(
        logger_key.to_string(),
        LoggerLevel::Information,
        message.to_string(),
    );

    if let Err(e) = misc_helpers::try_create_folder(&event_dir) {
        let message = format!("Failed to create event folder with error: {}", e);
        set_status_fn(message.to_string());
    }

    let shutdown = SHUT_DOWN.clone();
    if interval == Duration::default() {
        interval = Duration::from_secs(60);
    }
    loop {
        if EVENT_QUEUE.is_closed() {
            let message = "Event queue already closed, stop processing events.";
            set_status_fn(message.to_string());
            logger_manager::log(
                logger_key.to_string(),
                LoggerLevel::Information,
                message.to_string(),
            );
            break;
        }
        tokio::time::sleep(interval).await;

        if shutdown.load(Ordering::Relaxed) {
            let message = "Stop signal received, exiting the event logger thread.";
            set_status_fn(message.to_string());

            logger_manager::log(
                logger_key.to_string(),
                LoggerLevel::Information,
                message.to_string(),
            );
            EVENT_QUEUE.close();
        }

        if EVENT_QUEUE.is_empty() {
            // no event in the queue, skip this loop
            continue;
        }

        let mut events: Vec<Event> = Vec::new();
        events.reserve_exact(EVENT_QUEUE.len());

        for event in EVENT_QUEUE.try_iter() {
            events.push(event);
        }

        // Check the event file counts,
        // if it exceeds the max file number, drop the new events
        match misc_helpers::get_files(&event_dir) {
            Ok(files) => {
                if files.len() >= max_event_file_count {
                    logger_manager::log(logger_key.to_string(), LoggerLevel::Warning,format!(
                        "Event files exceed the max file count {}, drop and skip the write to disk.",
                        max_event_file_count
                    ));
                    continue;
                }
            }
            Err(e) => {
                logger_manager::log(
                    logger_key.to_string(),
                    LoggerLevel::Warning,
                    format!("Failed to get event files with error: {}", e),
                );
            }
        }

        let mut file_path = event_dir.to_path_buf();

        file_path.push(format!("{}.json", misc_helpers::get_date_time_unix_nano()));
        match misc_helpers::json_write_to_file(&events, &file_path) {
            Ok(()) => {
                logger_manager::log(
                    logger_key.to_string(),
                    LoggerLevel::Verbeose,
                    format!(
                        "Write events to the file {} successfully",
                        file_path.display()
                    ),
                );
            }
            Err(e) => {
                logger_manager::log(
                    logger_key.to_string(),
                    LoggerLevel::Warning,
                    format!(
                        "Failed to write events to the file {} with error: {}",
                        file_path.display(),
                        e
                    ),
                );
            }
        }
    }
}

pub fn stop() {
    SHUT_DOWN.store(true, Ordering::Relaxed);
}

pub fn write_event(
    level: &str,
    message: String,
    method_name: &str,
    module_name: &str,
    logger_key: &str,
) {
    let event_message = if message.len() > MAX_MESSAGE_LENGTH {
        message[..MAX_MESSAGE_LENGTH].to_string()
    } else {
        message.to_string()
    };
    let logger_key = logger_key.to_string();
    match EVENT_QUEUE.push(Event::new(
        level.to_string(),
        event_message,
        method_name.to_string(),
        module_name.to_string(),
    )) {
        Ok(()) => {
            // wrap file log within event log
            if level == INFO_LEVEL {
                logger_manager::log(logger_key, LoggerLevel::Information, message);
            } else if level == WARN_LEVEL {
                logger_manager::log(logger_key, LoggerLevel::Warning, message);
            } else {
                logger_manager::log(logger_key, LoggerLevel::Error, message);
            }
        }
        Err(e) => {
            logger_manager::log(
                logger_key,
                LoggerLevel::Warning,
                format!("Failed to push event to the queue with error: {}", e),
            );
        }
    };
}

#[cfg(test)]
mod tests {
    use crate::logger_manager;
    use crate::misc_helpers;
    use std::env;
    use std::fs;
    use std::time::Duration;

    #[tokio::test]
    async fn event_logger_test() {
        let mut temp_test_path = env::temp_dir();
        let logger_key = "event_logger_test";
        temp_test_path.push(logger_key);
        // clean up and ignore the clean up errors
        _ = fs::remove_dir_all(&temp_test_path);

        let mut log_dir = temp_test_path.to_path_buf();
        log_dir.push("Logs");
        let mut events_dir: std::path::PathBuf = temp_test_path.to_path_buf();
        events_dir.push("Events");
        logger_manager::init_logger(
            logger_key.to_string(), // production code uses 'Agent_Log' to write.
            log_dir.clone(),
            logger_key.to_string(),
            10 * 1024 * 1024,
            20,
        )
        .await;

        let cloned_events_dir = events_dir.to_path_buf();
        tokio::spawn(async {
            super::start(
                cloned_events_dir,
                Duration::from_millis(100),
                3,
                logger_key,
                |_| {
                    async {
                        // do nothing
                    }
                },
            )
            .await;
        });

        // write some events to the queue and flush to disk
        write_events(logger_key).await;

        let files = misc_helpers::get_files(&events_dir).unwrap();
        let file_count = files.len();
        assert!(
            file_count > 0,
            "It should write some files to the event folder"
        );

        // write some events to the queue and flush to disk 3 times
        for _ in [0; 3] {
            write_events(logger_key).await;
        }

        let files = misc_helpers::get_files(&events_dir).unwrap();
        let file_count = files.len();
        assert_eq!(
            3, file_count,
            "Cannot write more files to the event folder after 3 times"
        );

        // stop it and no more files write to event folder
        super::stop();
        // wait for stop signal responded
        tokio::time::sleep(Duration::from_millis(500)).await;

        write_events(logger_key).await;

        let files = misc_helpers::get_files(&events_dir).unwrap();
        assert_eq!(
            file_count,
            files.len(),
            "No more files could write to event folder after stop()"
        );

        _ = fs::remove_dir_all(&temp_test_path);
    }

    async fn write_events(logger_key: &str) {
        for _ in [0; 10] {
            super::write_event(
                "Informational",
                "This is test event".to_string(),
                "event_logger_test",
                "event_logger_test",
                logger_key,
            );
        }
        // wait for the queue write to event folder
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}
