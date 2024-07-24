// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use crate::logger_manager;
use crate::misc_helpers;
use crate::telemetry::Event;
use concurrent_queue::ConcurrentQueue;
use once_cell::sync::Lazy;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

pub const INFO_LEVEL: &str = "Informational";
pub const WARN_LEVEL: &str = "Warning";
pub const ERROR_LEVEL: &str = "Error";
pub const CRITICAL_LEVEL: &str = "Critical";
pub const MAX_MESSAGE_LENGTH: usize = 1024 * 4; // 4KB

static EVENT_QUEUE: Lazy<ConcurrentQueue<Event>> =
    Lazy::new(|| ConcurrentQueue::<Event>::bounded(1000));
static SHUT_DOWN: Lazy<Arc<AtomicBool>> = Lazy::new(|| Arc::new(AtomicBool::new(false)));

pub fn start_async<F>(
    event_dir: PathBuf,
    interval: Duration,
    max_event_file_count: usize,
    logger_key: &str,
    set_status_fn: F,
) where
    F: Fn(String) + Send + 'static,
{
    let key = logger_key.to_string();
    _ = thread::Builder::new()
        .name("event_logger".to_string())
        .spawn(move || {
            _ = start(
                event_dir,
                interval,
                max_event_file_count,
                &key,
                set_status_fn,
            );
        });
}

fn start<F>(
    event_dir: PathBuf,
    mut interval: Duration,
    max_event_file_count: usize,
    logger_key: &str,
    set_status_fn: F,
) -> std::io::Result<()>
where
    F: Fn(String),
{
    let message = "Telemetry event logger thread started.";
    set_status_fn(message.to_string());

    logger_manager::write(logger_key, message.to_string());

    misc_helpers::try_create_folder(event_dir.to_path_buf())?;

    let shutdown = SHUT_DOWN.clone();
    if interval == Duration::default() {
        interval = Duration::from_secs(60);
    }
    loop {
        if EVENT_QUEUE.is_closed() {
            let message = "Event queue already closed, stop processing events.";
            set_status_fn(message.to_string());
            logger_manager::write_information(logger_key, message.to_string());
            break;
        }
        thread::sleep(interval);

        if shutdown.load(Ordering::Relaxed) {
            let message = "Stop signal received, exiting the event logger thread.";
            set_status_fn(message.to_string());

            logger_manager::write_information(logger_key, message.to_string());
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
                    logger_manager::write_warning(logger_key,format!(
                        "Event files exceed the max file count {}, drop and skip the write to disk.",
                        max_event_file_count
                    ));
                    continue;
                }
            }
            Err(e) => {
                logger_manager::write(
                    logger_key,
                    format!("Failed to get event files with error: {}", e),
                );
            }
        }

        let mut file_path = event_dir.to_path_buf();

        file_path.push(format!("{}.json", misc_helpers::get_date_time_unix_nano()));
        match misc_helpers::json_write_to_file(&events, file_path.to_path_buf()) {
            Ok(()) => {
                logger_manager::write(
                    logger_key,
                    format!(
                        "Write events to the file {} successfully",
                        misc_helpers::path_to_string(file_path)
                    ),
                );
            }
            Err(e) => {
                logger_manager::write_warning(
                    logger_key,
                    format!(
                        "Failed to write events to the file {} with error: {}",
                        misc_helpers::path_to_string(file_path),
                        e
                    ),
                );
            }
        }
    }

    Ok(())
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
    match EVENT_QUEUE.push(Event::new(
        level.to_string(),
        event_message,
        method_name.to_string(),
        module_name.to_string(),
    )) {
        Ok(()) => {
            // wrap file log within event log
            if level == INFO_LEVEL {
                logger_manager::write_information(logger_key, message);
            } else if level == WARN_LEVEL {
                logger_manager::write_warning(logger_key, message);
            } else {
                logger_manager::write_error(logger_key, message);
            }
        }
        Err(e) => {
            logger_manager::write_warning(
                logger_key,
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
    use std::thread;
    use std::time::Duration;
    #[test]
    fn event_logger_test() {
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
        );

        let cloned_events_dir = events_dir.to_path_buf();
        super::start_async(
            cloned_events_dir,
            Duration::from_millis(100),
            3,
            logger_key,
            |_s| {}, // empty function
        );

        // write some events to the queue and flush to disk
        write_events(logger_key);

        let files = misc_helpers::get_files(&events_dir).unwrap();
        let file_count = files.len();
        assert!(
            file_count > 0,
            "It should write some files to the event folder"
        );

        // write some events to the queue and flush to disk 3 times
        for _ in [0; 3] {
            write_events(logger_key);
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
        thread::sleep(Duration::from_millis(500));

        write_events(logger_key);

        let files = misc_helpers::get_files(&events_dir).unwrap();
        assert_eq!(
            file_count,
            files.len(),
            "No more files could write to event folder after stop()"
        );

        _ = fs::remove_dir_all(&temp_test_path);
    }

    fn write_events(logger_key: &str) {
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
        thread::sleep(Duration::from_millis(500));
    }
}
