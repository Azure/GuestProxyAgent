// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

//! This module provides functionality for Windows event
//! logging using the Windows Event Log API.
//! It allows registering an event source, writing logs to the Event Log.

use crate::error::Error;
use crate::logger::LoggerLevel;
use crate::misc_helpers;
use crate::result::Result;
use windows_sys::core::PWSTR;
use windows_sys::Win32::System::EventLog::{
    DeregisterEventSource, RegisterEventSourceW, ReportEventW,
}; // advapi32.dll
use windows_sys::Win32::System::EventLog::{
    EVENTLOG_ERROR_TYPE, EVENTLOG_INFORMATION_TYPE, EVENTLOG_WARNING_TYPE, REPORT_EVENT_TYPE,
};

const EVENT_QUEUE_CAPACITY: usize = 1024;
const MAX_EVENT_MESSAGE_LENGTH: usize = 32 * 1024;

struct EventLogMessage {
    log_level: LoggerLevel,
    event_id: u32,
    message: String,
}

/// Converts a `LoggerLevel` to a `REPORT_EVENT_TYPE`.
/// This function maps the logging levels to the corresponding Windows Event Log types.
fn to_event_level(level: LoggerLevel) -> REPORT_EVENT_TYPE {
    match level {
        LoggerLevel::Trace => EVENTLOG_INFORMATION_TYPE,
        LoggerLevel::Debug => EVENTLOG_INFORMATION_TYPE,
        LoggerLevel::Info => EVENTLOG_INFORMATION_TYPE,
        LoggerLevel::Warn => EVENTLOG_WARNING_TYPE,
        LoggerLevel::Error => EVENTLOG_ERROR_TYPE,
    }
}

/// A struct for writing windows etw events to the Windows Event Log.
/// It registers an event source and provides a method to write logs.
/// It also ensures that the event source is deregistered when the struct is dropped.
pub struct WindowsEventWriter {
    sender: Option<std::sync::mpsc::SyncSender<EventLogMessage>>,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl WindowsEventWriter {
    pub fn new(event_log_name: &str, source_name: &str) -> Result<Self> {
        // Add event source in the Windows Registry before retrieving the event source handle.
        // `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog\{event_log_name}\{source_name}`
        let key_name = format!(
            "SYSTEM\\CurrentControlSet\\Services\\EventLog\\{event_log_name}\\{source_name}"
        );
        let value = crate::misc_helpers::resolve_env_variables(
            r"%SystemRoot%\Microsoft.NET\Framework64\v4.0.30319\EventLogMessages.dll",
        );
        crate::windows::set_reg_string(&key_name, "EventMessageFile", value)?;

        let (sender, receiver) = std::sync::mpsc::sync_channel(EVENT_QUEUE_CAPACITY);
        let (startup_sender, startup_receiver) = std::sync::mpsc::sync_channel(0);
        let source_name = source_name.to_string();
        let worker = std::thread::Builder::new()
            .name("windows-event-writer".to_string())
            .spawn(move || run_event_writer(source_name, receiver, startup_sender))?;

        match startup_receiver.recv() {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                _ = worker.join();
                return Err(Error::WindowsApi("RegisterEventSourceW".to_string(), error));
            }
            Err(error) => {
                _ = worker.join();
                return Err(Error::Io(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    format!("Windows event writer failed to start: {error}"),
                )));
            }
        }

        Ok(WindowsEventWriter {
            sender: Some(sender),
            worker: Some(worker),
        })
    }

    pub fn write(&self, log_level: LoggerLevel, message: String) {
        self.write_with_event_id(log_level, 0, message);
    }

    pub fn write_with_event_id(&self, log_level: LoggerLevel, event_id: u32, message: String) {
        let mut message = message;
        misc_helpers::truncate_to_char_boundary(&mut message, MAX_EVENT_MESSAGE_LENGTH);

        if let Some(sender) = &self.sender {
            // Never block a request or runtime thread on redaction, event-log I/O, or queue space.
            if let Err(error) = sender.try_send(EventLogMessage {
                log_level,
                event_id,
                message,
            }) {
                eprintln!("Failed to enqueue Windows event log message: {error}");
            }
        }
    }
}

impl Drop for WindowsEventWriter {
    fn drop(&mut self) {
        // Closing the channel lets the backend drain queued events before releasing the source.
        self.sender.take();
        if let Some(worker) = self.worker.take() {
            _ = worker.join();
        }
    }
}

/// Runs the event writer in a background thread,
/// processing messages from the receiver and writing them to the Windows Event Log.
fn run_event_writer(
    source_name: String,
    receiver: std::sync::mpsc::Receiver<EventLogMessage>,
    startup_sender: std::sync::mpsc::SyncSender<std::io::Result<()>>,
) {
    // Register the event source with the Windows Event Log API.
    let source_name_wide = super::to_wide(&source_name);
    let event_source = unsafe { RegisterEventSourceW(std::ptr::null(), source_name_wide.as_ptr()) };
    if event_source == 0 {
        _ = startup_sender.send(Err(std::io::Error::last_os_error()));
        return;
    }
    // Notify the main thread that the event writer has started successfully.
    if startup_sender.send(Ok(())).is_err() {
        unsafe { DeregisterEventSource(event_source) };
        return;
    }

    for event in receiver {
        // This single backend worker keeps regex cache concurrency at one and keeps both redaction
        // and the blocking Windows API call off request/runtime threads.
        let message = crate::secrets_redactor::redact_secrets_string(event.message);
        let wide_message = super::to_wide(&message);
        let wide_message_ptrs: [PWSTR; 1] = [wide_message.as_ptr() as PWSTR];

        unsafe {
            ReportEventW(
                event_source,
                to_event_level(event.log_level),
                0,
                event.event_id,
                std::ptr::null_mut(),
                1,
                0,
                wide_message_ptrs.as_ptr() as *const *const u16,
                std::ptr::null(),
            );
        }
    }

    unsafe { DeregisterEventSource(event_source) };
}

#[cfg(test)]
mod tests {
    use super::WindowsEventWriter;
    use crate::logger::LoggerLevel;
    use crate::windows_events::evt_listener::{EvtListener, SourceFilter};
    use crate::windows_events::evt_query::WindowsEventReader;
    use chrono::DateTime;
    use std::sync::Arc;
    use std::sync::Mutex;

    /// This test verifies that the WindowsEventWriter can write to the Windows Event Log
    /// and that the written log can be queried successfully.
    /// It creates a new event source, writes a log message,
    /// and then queries the event log to verify that the message was written correctly.
    /// The test also checks for logs within a specific time range
    /// to ensure that the event log is being written correctly.
    /// # Note: This test picks `Application` as the event log name,
    ///     as `Windows Container` does have its own Registry but not its own Event Log System.
    ///     https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-registereventsourcew#remarks
    ///     RegisterEventSourceW retrieves a registered handle to the specified event log,
    ///     but if the source name cannot be found, the event logging service uses the `Application` log.
    #[test]
    fn write_event_log_test() {
        // According to the test log, it indicates that Windows Container may have few milliseconds difference against its current host time.
        // Therefore, we set the start time to 1 second before the current time.
        let start_time = chrono::Utc::now() - chrono::Duration::seconds(1);
        let end_time = start_time + chrono::Duration::seconds(60);

        let event_log_name = "Application";
        let source_name = "Azure_GuestProxyAgent_TestApplication";
        let event_id = 1001;
        let message = "This is a test log message";
        let event_writer = WindowsEventWriter::new(event_log_name, source_name).unwrap();

        let read_message: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let read_value = read_message.clone();
        // start evt_listener
        EvtListener::subscribe_by_sources_with_handler(
            &event_log_name.to_string(),
            &[SourceFilter {
                name: source_name.to_string(),
                event_ids: vec![event_id],
            }],
            false,
            move |event| {
                let read_message = read_message.clone();
                let message = event.get_message();
                let mut read_message = read_message.lock().unwrap();
                *read_message = Some(message);
            },
        )
        .unwrap();

        std::thread::sleep(std::time::Duration::from_secs(1)); // wait for the listener to start
                                                               // write the event log
        event_writer.write_with_event_id(LoggerLevel::Info, event_id, message.to_string());
        std::thread::sleep(std::time::Duration::from_secs(1)); // wait for the event log to be written and the listener to receive it
        println!(
            "EvtListener received message is {:?}",
            read_value.lock().unwrap()
        );
        assert_eq!(
            read_value.lock().unwrap().as_ref().unwrap(),
            message,
            "Event log data from listener does not match the expected message"
        );

        println!("Verifying event log for source: {}", source_name);
        let data = query_windows_event(event_log_name, source_name, None, None);
        assert_eq!(
            data, message,
            "Event log data does not match the expected message"
        );

        println!(
            "Verifying event log for source: {} after {}",
            source_name, start_time
        );
        let data = query_windows_event(event_log_name, source_name, Some(start_time), None);
        assert_eq!(
            data, message,
            "Event log data does not match the expected message"
        );

        println!(
            "Verifying event log for source: {} before {}",
            source_name, end_time
        );
        let data = query_windows_event(event_log_name, source_name, None, Some(end_time));
        assert_eq!(
            data, message,
            "Event log data does not match the expected message"
        );

        println!(
            "Verifying event log for source: {} between {} and {}",
            source_name, start_time, end_time
        );
        let data = query_windows_event(
            event_log_name,
            source_name,
            Some(start_time),
            Some(end_time),
        );
        assert_eq!(
            data, message,
            "Event log data does not match the expected message"
        );

        // Clean up: Remove the event log from the Windows Registry
        let key_name = format!(
            r"SYSTEM\CurrentControlSet\Services\EventLog\{}\{}",
            event_log_name, source_name
        );
        if let Err(e) = crate::windows::remove_reg_key(&key_name) {
            eprintln!("Failed to remove event source from registry: {}", e);
        }
    }

    fn query_windows_event(
        event_log_name: &str,
        source_name: &str,
        start_time: Option<DateTime<chrono::Utc>>,
        end_time: Option<DateTime<chrono::Utc>>,
    ) -> String {
        let mut reader =
            WindowsEventReader::new(event_log_name, source_name, start_time, end_time).unwrap();
        let data = reader
            .next()
            .map(|event| {
                event
                    .unwrap()
                    .event_data
                    .unwrap()
                    .data
                    .unwrap()
                    .iter()
                    .map(|d| d.value.clone().unwrap_or_default())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_else(|| vec!["No data found".to_string()]);

        return data.join("\n");
    }
}
