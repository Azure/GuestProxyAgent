// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

//! This module provides functionality for Windows event
//! logging using the Windows Event Log API.
//! It allows registering an event source, writing logs to the Event Log.

use crate::error::Error;
use crate::logger::LoggerLevel;
use crate::result::Result;
use windows_sys::core::PWSTR;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::EventLog::{
    DeregisterEventSource, RegisterEventSourceW, ReportEventW,
}; // advapi32.dll
use windows_sys::Win32::System::EventLog::{
    EVENTLOG_ERROR_TYPE, EVENTLOG_INFORMATION_TYPE, EVENTLOG_WARNING_TYPE, REPORT_EVENT_TYPE,
};

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
pub struct WindowsEventWritter {
    event_source: HANDLE,
}

impl WindowsEventWritter {
    pub fn new(event_log_name: &str, source_name: &str) -> Result<Self> {
        // Add event source in the Windows Registry before retrieving the event source handle.
        // `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog\{event_log_name}\{source_name}`
        let key_name = format!(
            "SYSTEM\\CurrentControlSet\\Services\\EventLog\\{event_log_name}\\{source_name}"
        );
        let value = crate::misc_helpers::resolve_env_variables(
            r"%SystemRoot%\Microsoft.NET\Framework64\v4.0.30319\EventLogMessages.dll",
        )?;
        crate::windows::set_reg_string(&key_name, "EventMessageFile", value)?;

        let source_name_wide = super::to_wide(source_name);
        let event_source =
            unsafe { RegisterEventSourceW(std::ptr::null(), source_name_wide.as_ptr()) };
        if event_source == 0 {
            return Err(Error::WindowsApi(
                "RegisterEventSourceW".to_string(),
                std::io::Error::last_os_error(),
            ));
        }

        Ok(WindowsEventWritter { event_source })
    }

    pub fn write(&self, log_level: LoggerLevel, message: String) {
        let wide_message = super::to_wide(&message);
        let wide_message_ptrs: [PWSTR; 1] = [wide_message.as_ptr() as PWSTR];

        unsafe {
            ReportEventW(
                self.event_source,
                to_event_level(log_level),
                0,
                0,
                std::ptr::null_mut(),
                1,
                0,
                wide_message_ptrs.as_ptr() as *const *const u16,
                std::ptr::null(),
            );
        }
    }
}

impl Drop for WindowsEventWritter {
    fn drop(&mut self) {
        unsafe {
            DeregisterEventSource(self.event_source);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::WindowsEventWritter;
    use crate::etw::etw_reader::WindowsEventReader;
    use crate::logger::LoggerLevel;
    use chrono::DateTime;

    /// This test verifies that the WindowsEventWritter can write to the Windows Event Log
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
        let message = "This is a test log message";
        let event_writer = WindowsEventWritter::new(event_log_name, source_name).unwrap();
        event_writer.write(LoggerLevel::Info, message.to_string());

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
                    .map(|d| d.to_string())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_else(|| vec!["No data found".to_string()]);

        return data.join("\n");
    }
}
