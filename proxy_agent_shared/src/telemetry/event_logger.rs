// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

use crate::common_state::CommonState;
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
static DIRECT_SEND_CONFIG: tokio::sync::OnceCell<DirectSendConfig> =
    tokio::sync::OnceCell::const_new();
const MAX_EXTENSION_EVENT_FILE_COUNT: usize = 1000;

#[derive(Clone, Debug)]
pub struct DirectSendConfig {
    execution_mode: String,
    event_name: String,
    version: Option<String>,
    common_state: CommonState,
}

impl DirectSendConfig {
    pub fn new(
        execution_mode: String,
        event_name: String,
        version: Option<String>,
        common_state: CommonState,
    ) -> Self {
        Self {
            execution_mode,
            event_name,
            version,
            common_state,
        }
    }
}

/// Start the telemetry event logger loop in disk-only mode.
///
/// Events are buffered to disk and later picked up by the event reader. This is
/// used by callers (such as the extension) that do not have a direct in-memory
/// telemetry path. It deliberately does not reference the `event_sender` direct
/// path so that the direct-send machinery is not linked into binaries that only
/// use this entry point.
pub async fn start<F, Fut>(
    event_dir: PathBuf,
    interval: Duration,
    max_event_file_count: usize,
    set_status_fn: F,
) where
    F: Fn(String) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    // Disk-only mode: no events are sent directly, so every event falls through
    // to be buffered on disk.
    run_event_loop(
        event_dir,
        interval,
        max_event_file_count,
        set_status_fn,
        |events| async move { events },
    )
    .await;
}

/// Start the telemetry event logger loop with a direct in-memory send path.
///
/// Events are first attempted to be sent directly via the in-memory telemetry
/// queue (so VMs without disk write permission can still report telemetry).
/// Any events that cannot be enqueued directly fall back to being buffered on
/// disk.
pub async fn start_with_direct_send<F, Fut>(
    event_dir: PathBuf,
    interval: Duration,
    max_event_file_count: usize,
    direct_send_config: DirectSendConfig,
    set_status_fn: F,
) where
    F: Fn(String) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    if DIRECT_SEND_CONFIG.set(direct_send_config.clone()).is_err() {
        let message = "DirectSendConfig is already set, cannot set it again.";
        logger_manager::write_warn(message.to_string());
    }

    run_event_loop(
        event_dir,
        interval,
        max_event_file_count,
        set_status_fn,
        move |events| {
            let config = direct_send_config.clone();
            async move { try_direct_send_events(events, &config).await }
        },
    )
    .await;
}

/// Try to send the drained events directly via the in-memory telemetry queue,
/// returning the events that could not be enqueued directly (and therefore need
/// to be buffered on disk).
async fn try_direct_send_events(events: Vec<Event>, config: &DirectSendConfig) -> Vec<Event> {
    try_direct_send_events_with(
        events,
        config,
        crate::telemetry::event_sender::try_enqueue_generic_event,
    )
    .await
}

/// Implementation of [`try_direct_send_events`] with the enqueue operation
/// injected, so the filtering / notify logic can be unit-tested without the
/// global `event_sender` queue. `try_enqueue` returns `Ok` when the event was
/// accepted by the direct path and `Err` when it must fall back to disk.
async fn try_direct_send_events_with<E>(
    events: Vec<Event>,
    config: &DirectSendConfig,
    try_enqueue: E,
) -> Vec<Event>
where
    E: Fn(&Event, String, String, Option<String>) -> crate::result::Result<()>,
{
    let event_count = events.len();
    let remaining_events: Vec<Event> = events
        .into_iter()
        .filter(|event| {
            try_enqueue(
                event,
                config.execution_mode.clone(),
                config.event_name.clone(),
                config.version.clone(),
            )
            .is_err()
        })
        .collect();
    if remaining_events.len() < event_count {
        // some events were queued directly, notify the event_sender
        if let Err(e) = config.common_state.notify_telemetry_event().await {
            logger_manager::write_warn(format!(
                "event_logger::try_direct_send_events: failed to notify telemetry event with error: {e}"
            ));
        };
    }

    // return the possible remaining events
    remaining_events
}

/// Core event logger loop shared by the disk-only and direct-send entry points.
///
/// `direct_send` is given the events drained from the in-memory queue and
/// returns the events that still need to be buffered on disk. For disk-only
/// mode this is the identity function.
async fn run_event_loop<F, Fut, S, SFut>(
    event_dir: PathBuf,
    mut interval: Duration,
    max_event_file_count: usize,
    set_status_fn: F,
    direct_send: S,
) where
    F: Fn(String) -> Fut,
    Fut: std::future::Future<Output = ()>,
    S: Fn(Vec<Event>) -> SFut,
    SFut: std::future::Future<Output = Vec<Event>>,
{
    let message = "Telemetry event logger thread started.";
    set_status_fn(message.to_string()).await;

    logger_manager::write_log(Level::Info, message.to_string());

    if let Err(e) = misc_helpers::try_create_folder(&event_dir) {
        let message = format!("Failed to create event folder with error: {e}");
        logger_manager::write_warn(message.to_string());
    }

    if EVENTS_DIR.set(event_dir.clone()).is_err() {
        let message = "Event directory is already set, cannot set it again.";
        logger_manager::write_warn(message.to_string());
    }

    let shutdown = SHUT_DOWN.clone();
    if interval == Duration::default() {
        interval = Duration::from_secs(60);
    }
    loop {
        if EVENT_QUEUE.is_closed() {
            let message = "Event queue already closed, stop processing events.";
            logger_manager::write_log(Level::Info, message.to_string());
            break;
        }
        tokio::time::sleep(interval).await;

        if shutdown.load(Ordering::Relaxed) {
            let message = "Stop signal received, exiting the event logger thread.";
            set_status_fn(message.to_string()).await;

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

        // Try to send the events directly first; any events that cannot be sent
        // directly fall back to being buffered on disk below.
        let events: Vec<Event> = direct_send(events).await;
        if events.is_empty() {
            // all events were queued directly, skip the rest
            continue;
        }

        // Check the event file counts,
        // if it exceeds the max file number, drop the new events
        match misc_helpers::search_files(
            &event_dir,
            &crate::telemetry::GENERIC_EVENT_FILE_SEARCH_REGEX,
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
        match misc_helpers::json_write_to_file_async(&events, &file_path).await {
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

/// Push a Windows event to the telemetry event queue.
#[cfg(windows)]
pub fn push_windows_event(windows_event: crate::windows_events::models::WindowsEvent) {
    if let (Some(provider_name), Some(task_name)) =
        (&windows_event.provider_name, &windows_event.task_name)
    {
        let event_message = {
            let message = windows_event.get_message();
            if message.len() > MAX_MESSAGE_LENGTH {
                message[..MAX_MESSAGE_LENGTH].to_string()
            } else {
                message
            }
        };

        match EVENT_QUEUE.push(Event {
            EventLevel: windows_event.get_level_string(),
            Message: event_message,
            Version: crate::current_info::get_current_exe_version(),
            TaskName: task_name.clone(),
            EventPid: windows_event.process_id.to_string(),
            EventTid: windows_event.thread_id.to_string(),
            OperationId: provider_name.clone(),
            TimeStamp: windows_event.timestamp.clone(),
        }) {
            Ok(()) => {}
            Err(e) => {
                logger_manager::write_log(
                    Level::Warn,
                    format!("Failed to push event to the queue with error: {e}"),
                );
            }
        };
    }
}

pub async fn report_extension_status_event(
    extension: crate::telemetry::Extension,
    operation_status: crate::telemetry::OperationStatus,
) {
    let event = crate::telemetry::ExtensionStatusEvent::new(extension, operation_status);

    if let Some(config) = DIRECT_SEND_CONFIG.get() {
        // Try to send the event directly via the in-memory telemetry queue first,
        // so VMs without disk write permission can still report telemetry.
        // If the queue is full/closed, fall back to buffering the event on disk.
        if crate::telemetry::event_sender::try_enqueue_extension_event(
            &event,
            config.execution_mode.clone(),
        )
        .is_ok()
        {
            if let Err(e) = config.common_state.notify_telemetry_event().await {
                logger_manager::write_warn(format!(
                        "report_extension_status_event: failed to notify telemetry event with error: {e}"
                    ));
            }
            return;
        }
    }

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
        &crate::telemetry::EXTENSION_EVENT_FILE_SEARCH_REGEX,
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

    let mut file_path = event_dir.to_path_buf();
    file_path.push(crate::telemetry::new_extension_event_file_name());
    if let Err(e) = misc_helpers::json_write_to_file_async(&event, &file_path).await {
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
        super::report_extension_status_event(extension, operation_status).await;

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
        super::report_extension_status_event(extension.clone(), operation_status.clone()).await;

        // Wait for the file to be written
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Verify extension event file was created
        let files = misc_helpers::search_files(
            &events_dir,
            &crate::telemetry::EXTENSION_EVENT_FILE_SEARCH_REGEX,
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

    fn create_direct_send_config() -> super::DirectSendConfig {
        let common_state =
            crate::common_state::CommonState::start_new(tokio_util::sync::CancellationToken::new());
        super::DirectSendConfig::new(
            "ProxyAgent".to_string(),
            "MicrosoftAzureGuestProxyAgent".to_string(),
            Some("1.0.0".to_string()),
            common_state,
        )
    }

    fn create_event(message: &str) -> crate::telemetry::Event {
        crate::telemetry::Event::new(
            "Informational".to_string(),
            message.to_string(),
            "test_task".to_string(),
            "test_module".to_string(),
        )
    }

    #[tokio::test]
    async fn try_direct_send_events_empty_input() {
        let config = create_direct_send_config();

        // Empty input must return empty without touching the enqueue path.
        let remaining = super::try_direct_send_events_with(Vec::new(), &config, |_, _, _, _| {
            panic!("enqueue should not be called for empty input");
        })
        .await;

        assert!(
            remaining.is_empty(),
            "Empty input should produce no remaining events"
        );
    }

    #[tokio::test]
    async fn try_direct_send_events_all_enqueued() {
        let config = create_direct_send_config();
        let events = vec![
            create_event("event 1"),
            create_event("event 2"),
            create_event("event 3"),
        ];

        // Every event is accepted by the direct path, so nothing falls back to disk.
        let remaining =
            super::try_direct_send_events_with(events, &config, |_, _, _, _| Ok(())).await;

        assert!(
            remaining.is_empty(),
            "All events were enqueued, none should remain for disk fallback"
        );
    }

    #[tokio::test]
    async fn try_direct_send_events_all_fail_back_to_disk() {
        let config = create_direct_send_config();
        let events = vec![create_event("event 1"), create_event("event 2")];
        let expected_messages: Vec<String> = events.iter().map(|e| e.Message.clone()).collect();

        // Every enqueue fails, so all events must be returned for disk fallback,
        // preserving order.
        let remaining = super::try_direct_send_events_with(events, &config, |_, _, _, _| {
            Err(crate::error::Error::EnqueueEvent("queue full".to_string()))
        })
        .await;

        let remaining_messages: Vec<String> = remaining.iter().map(|e| e.Message.clone()).collect();
        assert_eq!(
            remaining_messages, expected_messages,
            "All events should fall back to disk (in order) when enqueue fails"
        );
    }

    #[tokio::test]
    async fn try_direct_send_events_partial_fallback() {
        let config = create_direct_send_config();
        let events = vec![
            create_event("send-ok"),
            create_event("force-fail"),
            create_event("send-ok"),
        ];

        // Only the event whose message is "force-fail" cannot be enqueued and
        // therefore must be returned for disk fallback.
        let remaining = super::try_direct_send_events_with(events, &config, |event, _, _, _| {
            if event.Message == "force-fail" {
                Err(crate::error::Error::EnqueueEvent("queue full".to_string()))
            } else {
                Ok(())
            }
        })
        .await;

        assert_eq!(
            remaining.len(),
            1,
            "Only the event that failed to enqueue should remain"
        );
        assert_eq!(remaining[0].Message, "force-fail");
    }

    #[tokio::test]
    async fn try_direct_send_events_notify_failed() {
        let config = create_direct_send_config();
        let events = vec![
            create_event("event 1"),
            create_event("event 2"),
            create_event("event 3"),
        ];

        config.common_state.cancel_cancellation_token();
        // Wait for the cancellation to take effect
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // check that the cancellation is effective
        assert!(
            config.common_state.notify_telemetry_event().await.is_err(),
            "Expected error when notifying telemetry event after cancellation"
        );

        // Every event is accepted by the direct path, even failed to notify the event_sender.
        let remaining =
            super::try_direct_send_events_with(events, &config, |_, _, _, _| Ok(())).await;
        assert!(
            remaining.is_empty(),
            "All events were enqueued, none should remain for disk fallback"
        );
    }
}
