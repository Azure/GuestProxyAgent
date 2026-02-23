// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

use crate::error::Error;
use crate::result::Result;
use chrono::DateTime;
use serde_derive::{Deserialize, Serialize};
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::Foundation::ERROR_NO_MORE_ITEMS;
use windows_sys::Win32::System::EventLog::{EvtClose, EvtNext, EvtQuery, EvtRender, EVT_HANDLE}; // wevtapi.dll
use windows_sys::Win32::System::EventLog::{EvtQueryReverseDirection, EvtRenderEventXml};

/// Represents an ETW event structure
/// as defined in the XML schema.
/// The structure is used to deserialize ETW events from XML format.
/// The `Event` struct contains a `System` and `EventData` field,
/// which hold the metadata and data of the event respectively.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename = "Event")]
pub struct Event {
    #[serde(rename = "System")]
    pub system: System,
    #[serde(rename = "EventData", skip_serializing_if = "Option::is_none")]
    pub event_data: Option<EventData>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct System {
    #[serde(rename = "Provider")]
    pub provider: Provider,
    #[serde(rename = "EventID")]
    pub event_id: u32,
    /// Version is only present in ETW events, not classic event log entries
    #[serde(rename = "Version", default)]
    pub version: u8,
    #[serde(rename = "Level")]
    pub level: u8,
    /// Task is only present in ETW events, not classic event log entries
    #[serde(rename = "Task", default)]
    pub task: u8,
    /// Opcode is only present in ETW events, not classic event log entries
    #[serde(rename = "Opcode", default)]
    pub opcode: u8,
    #[serde(rename = "Keywords", default)]
    pub keywords: String,
    #[serde(rename = "TimeCreated")]
    pub time_created: TimeCreated,
    #[serde(rename = "EventRecordID")]
    pub event_record_id: u64,
    /// Execution may not be present in some classic event log entries
    #[serde(rename = "Execution", default)]
    pub execution: Execution,
    #[serde(rename = "Channel")]
    pub channel: String,
    #[serde(rename = "Computer")]
    pub computer: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Provider {
    #[serde(rename = "@Name", skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "@EventSourceName", skip_serializing_if = "Option::is_none")]
    pub event_source_name: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TimeCreated {
    #[serde(rename = "@SystemTime", skip_serializing_if = "Option::is_none")]
    pub system_time: Option<String>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct Execution {
    #[serde(rename = "@ProcessID", default)]
    pub process_id: u32,
    #[serde(rename = "@ThreadID", default)]
    pub thread_id: u32,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct EventData {
    #[serde(rename = "Data")]
    pub data: Option<Vec<String>>,
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
        let event_name_wide = crate::etw::to_wide(event_name);
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
                    println!(
                        "Event '{}' Time Created: {:?}",
                        self.source_name, time_created
                    );

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
                format!("Failed to parse event XML: {e}"),
            )))),
        }
    }
}
