// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
//! This module provides functionality for Windows Application event
//! // logging using the Windows Event Log API.
//! // It allows registering an event source, writing logs, and reading events
//! // from the Application Event Log.

use crate::error::Error;
use crate::etw::Event;
use crate::logger::LoggerLevel;
use crate::result::Result;
use chrono::DateTime;
use std::ffi::OsStr;
use std::ffi::OsString;
use std::iter::once;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::ffi::OsStringExt;
use windows_sys::core::PWSTR;
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::Foundation::{ERROR_NO_MORE_ITEMS, HANDLE};
use windows_sys::Win32::System::EventLog::{
    DeregisterEventSource, RegisterEventSourceW, ReportEventW,
}; // advapi32.dll
use windows_sys::Win32::System::EventLog::{EvtClose, EvtNext, EvtQuery, EvtRender, EVT_HANDLE}; // wevtapi.dll
use windows_sys::Win32::System::EventLog::{
    EvtQueryReverseDirection, EvtRenderEventXml, EVENTLOG_ERROR_TYPE, EVENTLOG_INFORMATION_TYPE,
    EVENTLOG_WARNING_TYPE, REPORT_EVENT_TYPE,
};

/// Converts a string to a wide character vector (u16).
/// This is used to convert Rust strings to the format required by Windows API functions.
fn to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(once(0)).collect()
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

/// A struct for writing application events to the Windows Event Log.
/// It registers an event source and provides a method to write logs.
/// It also ensures that the event source is deregistered when the struct is dropped.
pub struct ApplicationEventWritter {
    event_source: HANDLE,
}

impl ApplicationEventWritter {
    pub fn new(source_name: &str) -> Result<Self> {
        let source_name_wide = to_wide(source_name);
        let event_source =
            unsafe { RegisterEventSourceW(std::ptr::null(), source_name_wide.as_ptr()) };
        if event_source == 0 {
            return Err(Error::WindowsApi(
                "RegisterEventSourceW".to_string(),
                std::io::Error::last_os_error(),
            ));
        }

        // register event source in the Windows Registry
        // `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog\Application\{source_name}`
        let key_name = format!(
            r"SYSTEM\CurrentControlSet\Services\EventLog\Application\{}",
            source_name
        );
        let value = crate::misc_helpers::resolve_env_variables(
            r"%SystemRoot%\Microsoft.NET\Framework64\v4.0.30319\EventLogMessages.dll",
        )?;
        crate::windows::set_reg_string(&key_name, "EventMessageFile", value)?;

        Ok(ApplicationEventWritter { event_source })
    }

    pub fn write_log(&self, log_level: LoggerLevel, message: String) {
        let wide_message = to_wide(&message);
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

impl Drop for ApplicationEventWritter {
    fn drop(&mut self) {
        unsafe {
            DeregisterEventSource(self.event_source);
        }
    }
}

pub struct WindowsEventReader {
    query_handle: EVT_HANDLE,
    current_event: EVT_HANDLE,
    source_name: String,
    start_time: Option<DateTime<chrono::Utc>>,
    end_time: Option<DateTime<chrono::Utc>>,
}

impl WindowsEventReader {
    pub fn new(
        event_name: &str,
        source_name: &str,
        start_time: Option<DateTime<chrono::Utc>>,
        end_time: Option<DateTime<chrono::Utc>>,
    ) -> Result<Self> {
        let event_name_wide = to_wide(event_name);
        let h_query = unsafe {
            EvtQuery(
                0,
                event_name_wide.as_ptr(),
                std::ptr::null(),
                EvtQueryReverseDirection,
            )
        };
        if h_query == 0 {
            return Err(Error::WindowsApi(
                "EvtQuery".to_string(),
                std::io::Error::last_os_error(),
            ));
        }

        Ok(WindowsEventReader {
            query_handle: h_query,
            current_event: 0,
            source_name: source_name.to_string(),
            start_time,
            end_time,
        })
    }
    // Additional methods for reading events can be implemented here
}

impl Drop for WindowsEventReader {
    fn drop(&mut self) {
        // Close the query handle and current event handle if they are open
        unsafe {
            EvtClose(self.query_handle);
            EvtClose(self.current_event);
        }
    }
}

impl Iterator for WindowsEventReader {
    type Item = Result<Event>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut returned: u32 = 0;

        if unsafe {
            EvtNext(
                self.query_handle,
                1,
                &mut self.current_event,
                0,
                0,
                &mut returned,
            )
        } == 0
        {
            let error_code = unsafe { GetLastError() };
            if error_code == ERROR_NO_MORE_ITEMS {
                // No more items to read
                return None;
            } else {
                return Some(Err(Error::WindowsApi(
                    "EvtNext".to_string(),
                    std::io::Error::from_raw_os_error(error_code as i32),
                )));
            }
        }

        if returned == 0 {
            return None; // No events read
        }

        // First call to get buffer size
        let mut buffer_used = 0;
        let mut property_count = 0;
        let status = unsafe {
            EvtRender(
                0,
                self.current_event,
                EvtRenderEventXml,
                0,
                std::ptr::null_mut(),
                &mut buffer_used,
                &mut property_count,
            )
        };
        if status != 0 || buffer_used == 0 {
            return Some(Err(Error::WindowsApi(
                "EvtRender_Buffer_Size".to_string(),
                std::io::Error::last_os_error(),
            )));
        }
        // Allocate buffer for rendering
        let mut buffer: Vec<u16> = vec![0; buffer_used as usize / 2];
        if unsafe {
            EvtRender(
                0,
                self.current_event,
                EvtRenderEventXml,
                buffer_used,
                buffer.as_mut_ptr() as *mut _,
                &mut buffer_used,
                &mut property_count,
            )
        } == 0
        {
            return Some(Err(Error::WindowsApi(
                "EvtRender".to_string(),
                std::io::Error::last_os_error(),
            )));
        }

        // Convert the buffer to a xml string
        let xml = OsString::from_wide(&buffer)
            .to_string_lossy()
            .trim_end_matches('\0')
            .to_string();

        // Parse the XML string into an Event struct
        match serde_xml_rs::from_str::<Event>(&xml) {
            Ok(event) => {
                let mut skip_event = false;
                // Check if the event is from the specified source
                if event.system.provider.name == Some(self.source_name.clone()) {
                    // Check if the event is within the specified time range
                    let time_created = event.system.time_created.system_time.clone();
                    if let Some(start_time) = self.start_time {
                        match time_created.clone() {
                            Some(time) => {
                                if let Ok(event_time) =
                                    time.parse::<chrono::DateTime<chrono::Utc>>()
                                {
                                    if event_time < start_time {
                                        skip_event = true; // Skip this event
                                    }
                                }
                            }
                            None => skip_event = true, // Skip this event if time is not available
                        }
                    }
                    if let Some(end_time) = self.end_time {
                        match time_created {
                            Some(time) => {
                                if let Ok(event_time) =
                                    time.parse::<chrono::DateTime<chrono::Utc>>()
                                {
                                    if event_time > end_time {
                                        skip_event = true; // Skip this event
                                    }
                                }
                            }
                            None => skip_event = true, // Skip this event if time is not available
                        }
                    }
                } else {
                    skip_event = true; // Skip this event
                }

                if skip_event {
                    self.next() // Skip to the next event
                } else {
                    Some(Ok(event)) // Return the event
                }
            }
            Err(e) => Some(Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Failed to parse event XML: {}", e),
            )))),
        }
    }
}

#[cfg(test)]
mod tests {
    use chrono::DateTime;

    #[test]
    fn write_event_log_test() {
        use super::ApplicationEventWritter;
        use crate::logger::LoggerLevel;

        let start_time = chrono::Utc::now();
        let end_time = start_time + chrono::Duration::seconds(60);

        let source_name = "TestApplication";
        let message = "This is a test log message";
        let event_writer = ApplicationEventWritter::new(source_name).unwrap();
        event_writer.write_log(LoggerLevel::Info, message.to_string());

        println!("Verifying event log for source: {}", source_name);
        let data = read_application_event(source_name, None, None);
        assert_eq!(
            data, message,
            "Event log data does not match the expected message"
        );

        println!(
            "Verifying event log for source: {} after {}",
            source_name, start_time
        );
        let data = read_application_event(source_name, Some(start_time), None);
        assert_eq!(
            data, message,
            "Event log data does not match the expected message"
        );

        println!(
            "Verifying event log for source: {} before {}",
            source_name, end_time
        );
        let data = read_application_event(source_name, None, Some(end_time));
        assert_eq!(
            data, message,
            "Event log data does not match the expected message"
        );

        println!(
            "Verifying event log for source: {} between {} and {}",
            source_name, start_time, end_time
        );
        let data = read_application_event(source_name, Some(start_time), Some(end_time));
        assert_eq!(
            data, message,
            "Event log data does not match the expected message"
        );

        // Clean up: Remove the event source from the Windows Registry
        let key_name = format!(
            r"SYSTEM\CurrentControlSet\Services\EventLog\Application\{}",
            source_name
        );
        if let Err(e) = crate::windows::remove_reg_key(&key_name) {
            eprintln!("Failed to remove event source from registry: {}", e);
        }
    }

    fn read_application_event(
        source_name: &str,
        start_time: Option<DateTime<chrono::Utc>>,
        end_time: Option<DateTime<chrono::Utc>>,
    ) -> String {
        let mut reader =
            super::WindowsEventReader::new("Application", source_name, start_time, end_time)
                .unwrap();
        let data = reader
            .next()
            .map(|event| {
                event
                    .unwrap()
                    .event_data
                    .data
                    .iter()
                    .map(|d| d.to_string())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_else(|| vec!["No data found".to_string()]);

        return data.join("\n");
    }
}
