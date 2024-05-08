// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use crate::logger_manager;
use crate::misc_helpers;
use crate::proxy_agent_aggregate_status::{ModuleState, ProxyAgentDetailStatus};
use crate::telemetry::Event;
use concurrent_queue::ConcurrentQueue;
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

pub const INFO_LEVEL: &str = "Informational";
pub const WARN_LEVEL: &str = "Warning";
pub const ERROR_LEVEL: &str = "Error";
pub const CRITICAL_LEVEL: &str = "Critical";
pub const MAX_STATE_COUNT: u32 = 120;
pub const MAX_MESSAGE_LENGTH: usize = 1024 * 4; // 4KB

static EVENT_QUEUE: Lazy<ConcurrentQueue<Event>> =
    Lazy::new(|| ConcurrentQueue::<Event>::bounded(1000));
static SHUT_DOWN: Lazy<Arc<AtomicBool>> = Lazy::new(|| Arc::new(AtomicBool::new(false)));
static mut STATE_MAP: Lazy<HashMap<String, (String, u32)>> =
    Lazy::new(|| HashMap::<String, (String, u32)>::new());
static mut STATUS_MESSAGE: Lazy<String> =
    Lazy::new(|| String::from("Telemetry event logger thread has not started yet."));

pub fn start_async(
    event_dir: PathBuf,
    interval: Duration,
    max_event_file_count: usize,
    logger_key: &str,
) {
    let key = logger_key.to_string();
    _ = thread::Builder::new()
        .name("event_logger".to_string())
        .spawn(move || {
            _ = start(event_dir, interval, max_event_file_count, &key);
        });
}

pub fn write_state_event(
    state_key: &str,
    state_value: &str,
    level: &str,
    message: String,
    method_name: &str,
    module_name: &str,
    logger_key: &str,
) {
    unsafe {
        match STATE_MAP.get(state_key) {
            Some(v) => {
                let value = v.0.to_string();
                let count = v.1;
                // State change or Timer expired
                if value != state_value || count >= MAX_STATE_COUNT {
                    // Update the state value and reset the count
                    STATE_MAP.insert(state_key.to_string(), (state_value.to_string(), 1));
                    write_event(
                        level,
                        message.to_string(),
                        method_name,
                        module_name,
                        logger_key,
                    );
                } else {
                    STATE_MAP.insert(state_key.to_string(), (state_value.to_string(), count + 1));
                }
            }
            None => {
                STATE_MAP.insert(state_key.to_string(), (state_value.to_string(), 1));
                write_event(level, message, method_name, module_name, logger_key);
            }
        }
    }
}

fn start(
    event_dir: PathBuf,
    mut interval: Duration,
    max_event_file_count: usize,
    logger_key: &str,
) -> std::io::Result<()> {
    let message = "Telemetry event logger thread started.";
    unsafe {
        *STATUS_MESSAGE = message.to_string();
    }
    _ = logger_manager::write(logger_key, message.to_string());

    misc_helpers::try_create_folder(event_dir.to_path_buf())?;

    let shutdown = SHUT_DOWN.clone();
    if interval == Duration::default() {
        interval = Duration::from_secs(60);
    }

    loop {
        if EVENT_QUEUE.is_closed() {
            let message = "Event queue already closed, stop processing events.";
            unsafe {
                *STATUS_MESSAGE = message.to_string();
            }
            logger_manager::write_information(logger_key, message.to_string());
            break;
        }
        thread::sleep(interval);

        if shutdown.load(Ordering::Relaxed) {
            let message = "Stop signal received, exiting the event logger thread.";
            unsafe {
                *STATUS_MESSAGE = message.to_string();
            }
            logger_manager::write_information(logger_key, message.to_string());
            EVENT_QUEUE.close();
        }

        let len = EVENT_QUEUE.len();
        if len == 0 {
            // no event in the queue, skip this loop
            continue;
        }

        let mut i = 0;
        let mut events: Vec<Event> = Vec::new();
        while i < len {
            i = i + 1;
            match EVENT_QUEUE.pop() {
                Ok(e) => events.push(e),
                Err(e) => {
                    logger_manager::write_warning(
                        logger_key,
                        format!("Failed to pop event from the queue with error: {}", e),
                    );
                }
            };
        }

        // Check the event file counts,
        // if it exceed the max file number, drop the new events
        match misc_helpers::get_files(&event_dir) {
            Ok(files) => {
                if files.len() >= max_event_file_count {
                    logger_manager::write_warning(logger_key,format!(
                        "Event files excceed the max file count {}, drop and skip the write to disk.",
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
    let event_message;
    if message.len() > MAX_MESSAGE_LENGTH {
        event_message = message[..MAX_MESSAGE_LENGTH].to_string();
    } else {
        event_message = message.to_string();
    }
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

pub fn get_status() -> ProxyAgentDetailStatus {
    let shutdown = SHUT_DOWN.clone();
    let status;
    if shutdown.load(Ordering::Relaxed) {
        status = ModuleState::STOPPED.to_string();
    } else {
        status = ModuleState::RUNNING.to_string();
    }

    ProxyAgentDetailStatus {
        status,
        message: unsafe { STATUS_MESSAGE.to_string() },
        states: None,
    }
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
        _ = super::start_async(cloned_events_dir, Duration::from_millis(100), 3, logger_key);

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
