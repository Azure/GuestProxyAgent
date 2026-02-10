// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

use crate::logger::logger_manager;
use crate::misc_helpers;
use crate::telemetry::Event;
use concurrent_queue::ConcurrentQueue;
use log::Level;
use once_cell::sync::Lazy;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

const MAX_MESSAGE_LENGTH: usize = 1024 * 4; // 4KB
static EVENT_QUEUE: Lazy<ConcurrentQueue<Event>> =
    Lazy::new(|| ConcurrentQueue::<Event>::bounded(1000));
static SHUT_DOWN: Lazy<Arc<AtomicBool>> = Lazy::new(|| Arc::new(AtomicBool::new(false)));
/// Store the event directory path, so that other modules can access it if needed.
static EVENTS_DIR: tokio::sync::OnceCell<PathBuf> = tokio::sync::OnceCell::const_new();
const MAX_EXTENSION_EVENT_FILE_COUNT: usize = 1000;

pub async fn start<F, Fut>(
    event_dir: PathBuf,
    mut interval: Duration,
    max_event_file_count: usize,
    set_status_fn: F,
) where
    F: Fn(String) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let message = "Telemetry event logger thread started.";
    set_status_fn(message.to_string());

    logger_manager::write_log(Level::Info, message.to_string());

    if let Err(e) = misc_helpers::try_create_folder(&event_dir) {
        let message = format!("Failed to create event folder with error: {e}");
        set_status_fn(message.to_string());
    }

    if EVENTS_DIR.set(event_dir.clone()).is_err() {
        let message = "Event directory is already set, cannot set it again.";
        set_status_fn(message.to_string());
        logger_manager::write_log(Level::Warn, message.to_string());
    }

    let shutdown = SHUT_DOWN.clone();
    if interval == Duration::default() {
        interval = Duration::from_secs(60);
    }
    loop {
        if EVENT_QUEUE.is_closed() {
            let message = "Event queue already closed, stop processing events.";
            set_status_fn(message.to_string());
            logger_manager::write_log(Level::Info, message.to_string());
            break;
        }
        tokio::time::sleep(interval).await;

        if shutdown.load(Ordering::Relaxed) {
            let message = "Stop signal received, exiting the event logger thread.";
            set_status_fn(message.to_string());

            logger_manager::write_log(Level::Info, message.to_string());
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
        match misc_helpers::search_files(
            &event_dir,
            crate::telemetry::GENERIC_EVENT_FILE_SEARCH_PATTERN,
        ) {
            Ok(files) => {
                if files.len() >= max_event_file_count {
                    logger_manager::write_log(Level::Warn, format!(
                        "Event files exceed the max file count {max_event_file_count}, drop and skip the write to disk."
                    ));
                    continue;
                }
            }
            Err(e) => {
                logger_manager::write_log(
                    Level::Warn,
                    format!("Failed to get event files with error: {e}"),
                );
            }
        }

        let mut file_path = event_dir.to_path_buf();
        file_path.push(crate::telemetry::new_generic_event_file_name());
        match misc_helpers::json_write_to_file(&events, &file_path) {
            Ok(()) => {
                logger_manager::write_log(
                    Level::Trace,
                    format!(
                        "Write events to the file {} successfully",
                        file_path.display()
                    ),
                );
            }
            Err(e) => {
                logger_manager::write_log(
                    Level::Warn,
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

/// Write event and log to file
/// This event will send out as `TelemetryGenericLogsEvent`
pub fn write_event(
    level: Level,
    message: String,
    method_name: &str,
    module_name: &str,
    logger_key: &str,
) {
    write_event_only(level, message.to_string(), method_name, module_name);

    // wrap file log within event log
    logger_manager::log(logger_key.to_string(), level, message);
}

/// Write event only without logging to file
/// This event will send out as `TelemetryGenericLogsEvent`
pub fn write_event_only(level: Level, message: String, method_name: &str, module_name: &str) {
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
        Ok(()) => {}
        Err(e) => {
            logger_manager::write_log(
                Level::Warn,
                format!("Failed to push event to the queue with error: {e}"),
            );
        }
    };
}

pub fn report_extension_status_event(
    extension: crate::telemetry::Extension,
    operation_status: crate::telemetry::OperationStatus,
) {
    let event_dir = match EVENTS_DIR.get() {
        Some(dir) => dir.clone(),
        None => {
            logger_manager::write_log(
                Level::Warn,
                "Event directory is not set, cannot report extension status event.".to_string(),
            );
            return;
        }
    };

    // Check the event file counts,
    // if it exceeds the max file number, drop the new events
    match misc_helpers::search_files(
        &event_dir,
        crate::telemetry::EXTENSION_EVENT_FILE_SEARCH_PATTERN,
    ) {
        Ok(files) => {
            if files.len() >= MAX_EXTENSION_EVENT_FILE_COUNT {
                logger_manager::write_log(Level::Warn, format!(
                        "Event files exceed the max file count {}, drop and skip the write to disk.",
                        MAX_EXTENSION_EVENT_FILE_COUNT
                    ));
                return;
            }
        }
        Err(e) => {
            logger_manager::write_log(
                Level::Warn,
                format!("Failed to get event files with error: {e}"),
            );
        }
    }

    let event = crate::telemetry::ExtensionStatusEvent::new(extension, operation_status);
    let mut file_path = event_dir.to_path_buf();
    file_path.push(crate::telemetry::new_extension_event_file_name());
    if let Err(e) = misc_helpers::json_write_to_file(&event, &file_path) {
        logger_manager::write_log(
            Level::Warn,
            format!(
                "Failed to write extension status event to the file {} with error: {}",
                file_path.display(),
                e
            ),
        );
    }
}

#[cfg(test)]
mod tests {
    use crate::misc_helpers;
    use std::env;
    use std::fs;
    use std::time::Duration;

    const TEST_EVENTS_DIR: &str = "test_events_dir";
    const TEST_LOGGER_KEY: &str = "test_logger_key";

    #[tokio::test]
    async fn event_logger_test() {
        let mut temp_test_path = env::temp_dir();
        temp_test_path.push(TEST_EVENTS_DIR);
        // clean up and ignore the clean up errors
        _ = fs::remove_dir_all(&temp_test_path);
        let mut events_dir: std::path::PathBuf = temp_test_path.to_path_buf();
        events_dir.push("Events");

        // When EVENTS_DIR is not set, report_extension_status_event should return early
        // This test verifies the function handles the case gracefully
        // Note: Since EVENTS_DIR is a static OnceCell, if other tests set it first,
        // this test will still pass but will write to that directory instead

        let extension = crate::telemetry::Extension {
            name: "test_extension".to_string(),
            version: "1.0.0".to_string(),
            is_internal: false,
            extension_type: "test_type".to_string(),
        };
        let operation_status = crate::telemetry::OperationStatus {
            operation_success: false,
            operation: "test_operation".to_string(),
            task_name: "test_task".to_string(),
            message: "error message".to_string(),
            duration: 50,
        };

        // This should not panic even if EVENTS_DIR is not set
        super::report_extension_status_event(extension, operation_status);

        // Start the event logger loop and set the EVENTS_DIR
        let cloned_events_dir = events_dir.to_path_buf();
        tokio::spawn(async {
            super::start(cloned_events_dir, Duration::from_millis(100), 3, |_| {
                async {
                    // do nothing
                }
            })
            .await;
        });

        // write some events to the queue and flush to disk
        write_events(TEST_LOGGER_KEY).await;

        let files = misc_helpers::get_files(&events_dir).unwrap();
        let file_count = files.len();
        assert!(
            file_count > 0,
            "It should write some files to the event folder"
        );

        // write some events to the queue and flush to disk 3 times
        for _ in [0; 3] {
            write_events(TEST_LOGGER_KEY).await;
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

        write_events(TEST_LOGGER_KEY).await;

        let files = misc_helpers::get_files(&events_dir).unwrap();
        assert_eq!(
            file_count,
            files.len(),
            "No more files could write to event folder after stop()"
        );

        // Create test extension and operation status
        let extension = crate::telemetry::Extension {
            name: "test_extension".to_string(),
            version: "1.0.0".to_string(),
            is_internal: true,
            extension_type: "test_type".to_string(),
        };
        let operation_status = crate::telemetry::OperationStatus {
            operation_success: true,
            operation: "test_operation".to_string(),
            task_name: "test_task".to_string(),
            message: "test_message".to_string(),
            duration: 100,
        };

        // Call report_extension_status_event
        super::report_extension_status_event(extension.clone(), operation_status.clone());

        // Wait for the file to be written
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Verify extension event file was created
        let files = misc_helpers::search_files(
            &events_dir,
            crate::telemetry::EXTENSION_EVENT_FILE_SEARCH_PATTERN,
        )
        .unwrap();
        assert!(
            !files.is_empty(),
            "Extension status event file should be created"
        );

        // Read and verify the event content
        let event: crate::telemetry::ExtensionStatusEvent =
            misc_helpers::json_read_from_file(&files[0]).unwrap();
        assert_eq!(event.extension.name, extension.name);
        assert_eq!(event.extension.version, extension.version);
        assert_eq!(event.extension.is_internal, extension.is_internal);
        assert_eq!(event.extension.extension_type, extension.extension_type);
        assert_eq!(
            event.operation_status.operation_success,
            operation_status.operation_success
        );
        assert_eq!(event.operation_status.operation, operation_status.operation);
        assert_eq!(event.operation_status.task_name, operation_status.task_name);
        assert_eq!(event.operation_status.message, operation_status.message);
        assert_eq!(event.operation_status.duration, operation_status.duration);

        _ = fs::remove_dir_all(&temp_test_path);
    }

    async fn write_events(logger_key: &str) {
        for _ in [0; 10] {
            super::write_event(
                log::Level::Info,
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
