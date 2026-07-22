// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

//! Reader for the Windows Event Log via the `wevtapi` `Evt*` API.
//!
//! [`WindowsEventReader`] runs an `EvtQuery` over an event log channel and
//! yields the matching entries (decoded from each entry's XML) as
//! [`EvtEvent`](super::models::EvtEvent)s through its [`Iterator`]
//! implementation. Filtering by source (provider) name and an optional
//! inclusive `[start_time, end_time]` range is pushed into the `EvtQuery`
//! XPath so the Event Log service does the filtering and `EvtNext` only ever
//! returns matching entries. The XML schema lives in
//! [`super::models`] and is shared with the Event Log subscriber.

use super::evt_listener::xpath_literal;
use super::models::EvtEvent;
use crate::error::Error;
use crate::result::Result;
use chrono::{DateTime, Utc};
use windows_sys::Win32::Foundation::{
    GetLastError, ERROR_INSUFFICIENT_BUFFER, ERROR_NO_MORE_ITEMS,
};
use windows_sys::Win32::System::EventLog::{
    EvtClose, EvtNext, EvtQuery, EvtQueryReverseDirection, EvtRender, EvtRenderEventXml, EVT_HANDLE,
}; // wevtapi.dll

/// Iterates over Windows Event Log entries returned by an `EvtQuery`. The query
/// is built so the Event Log service returns only entries that match the
/// configured source name and time range.
pub struct WindowsEventReader {
    /// Query handle returned by `EvtQuery`.
    query_handle: EVT_HANDLE,
    /// Handle of the entry currently being rendered; `0` when none is open.
    current_event: EVT_HANDLE,
}

impl WindowsEventReader {
    /// Opens a reverse-chronological query over `channel` (e.g. `"Application"`).
    ///
    /// The iterator yields entries whose `Provider @Name` equals `source_name`
    /// and that fall within `[start_time, end_time]` when those bounds are
    /// supplied. The filtering is performed by the Event Log service via the
    /// `EvtQuery` XPath, not in the iterator.
    pub fn new(
        channel: &str,
        source_name: &str,
        start_time: Option<DateTime<Utc>>,
        end_time: Option<DateTime<Utc>>,
    ) -> Result<Self> {
        let channel_wide = crate::windows_events::to_wide(channel);
        let query = build_query(source_name, start_time, end_time);
        let query_wide = crate::windows_events::to_wide(&query);
        let query_handle = unsafe {
            EvtQuery(
                0,
                channel_wide.as_ptr(),
                query_wide.as_ptr(),
                EvtQueryReverseDirection,
            )
        };
        if query_handle == 0 {
            return Err(Error::WindowsApi(
                "EvtQuery".to_string(),
                std::io::Error::last_os_error(),
            ));
        }

        Ok(WindowsEventReader {
            query_handle,
            current_event: 0,
        })
    }

    /// Renders [`Self::current_event`] to its XML representation.
    fn render_current_event(&self) -> Result<String> {
        let mut buffer_used: u32 = 0;
        let mut property_count: u32 = 0;

        // Size query: `EvtRender` is expected to fail with
        // ERROR_INSUFFICIENT_BUFFER while reporting the required byte count.
        let rendered = unsafe {
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
        if rendered == 0 {
            let error_code = unsafe { GetLastError() };
            if error_code != ERROR_INSUFFICIENT_BUFFER {
                return Err(Error::WindowsApi(
                    "EvtRender (size query)".to_string(),
                    std::io::Error::from_raw_os_error(error_code as i32),
                ));
            }
        }
        if buffer_used == 0 {
            return Ok(String::new());
        }

        // `buffer_used` is a byte count; the payload is a UTF-16 string.
        let mut buffer: Vec<u16> = vec![0u16; (buffer_used as usize).div_ceil(2)];
        let rendered = unsafe {
            EvtRender(
                0,
                self.current_event,
                EvtRenderEventXml,
                buffer_used,
                buffer.as_mut_ptr().cast(),
                &mut buffer_used,
                &mut property_count,
            )
        };
        if rendered == 0 {
            return Err(Error::WindowsApi(
                "EvtRender".to_string(),
                std::io::Error::last_os_error(),
            ));
        }

        let len = ((buffer_used as usize) / 2).min(buffer.len());
        let xml = String::from_utf16_lossy(&buffer[..len]);
        Ok(xml.trim_end_matches('\0').to_string())
    }

    /// Closes the current entry handle if one is open.
    fn close_current_event(&mut self) {
        if self.current_event != 0 {
            unsafe { EvtClose(self.current_event) };
            self.current_event = 0;
        }
    }
}

/// Builds the `EvtQuery` XPath that selects entries whose `Provider @Name`
/// equals `source_name` and that fall within the optional inclusive
/// `[start_time, end_time]` range, so the Event Log service performs the
/// filtering instead of the iterator.
fn build_query(
    source_name: &str,
    start_time: Option<DateTime<Utc>>,
    end_time: Option<DateTime<Utc>>,
) -> String {
    let mut predicates = vec![format!("Provider[@Name={}]", xpath_literal(source_name))];

    let mut time_bounds = Vec::new();
    if let Some(start) = start_time {
        time_bounds.push(format!(
            "@SystemTime>='{}'",
            start.format("%Y-%m-%dT%H:%M:%S%.3fZ")
        ));
    }
    if let Some(end) = end_time {
        time_bounds.push(format!(
            "@SystemTime<='{}'",
            end.format("%Y-%m-%dT%H:%M:%S%.3fZ")
        ));
    }
    if !time_bounds.is_empty() {
        predicates.push(format!("TimeCreated[{}]", time_bounds.join(" and ")));
    }

    format!("*[System[{}]]", predicates.join(" and "))
}

impl Drop for WindowsEventReader {
    fn drop(&mut self) {
        self.close_current_event();
        if self.query_handle != 0 {
            unsafe { EvtClose(self.query_handle) };
            self.query_handle = 0;
        }
    }
}

impl Iterator for WindowsEventReader {
    type Item = Result<EvtEvent>;

    fn next(&mut self) -> Option<Self::Item> {
        // Release the previously rendered entry before fetching the next so
        // that only one entry handle is ever open at a time.
        self.close_current_event();

        let mut returned: u32 = 0;
        let fetched = unsafe {
            EvtNext(
                self.query_handle,
                1,
                &mut self.current_event,
                0,
                0,
                &mut returned,
            )
        };
        if fetched == 0 {
            let error_code = unsafe { GetLastError() };
            if error_code == ERROR_NO_MORE_ITEMS {
                return None;
            }
            return Some(Err(Error::WindowsApi(
                "EvtNext".to_string(),
                std::io::Error::from_raw_os_error(error_code as i32),
            )));
        }
        if returned == 0 {
            return None;
        }

        let xml = match self.render_current_event() {
            Ok(xml) => xml,
            Err(e) => return Some(Err(e)),
        };

        // The Event Log service already applied the source/time filter via the
        // query, so every returned entry is a match.
        match serde_xml_rs::from_str::<EvtEvent>(&xml) {
            Ok(event) => Some(Ok(event)),
            Err(e) => Some(Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Failed to parse event XML: {e}"),
            )))),
        }
    }
}
