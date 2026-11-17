// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
pub mod event_logger;
pub mod event_reader;
pub mod event_sender;
pub mod span;
pub mod telemetry_event;

use crate::{current_info, misc_helpers};
use serde_derive::{Deserialize, Serialize};

pub const GENERIC_EVENT_FILE_SEARCH_PATTERN: &str = r"^[0-9]+\.json$";
pub static GENERIC_EVENT_FILE_SEARCH_REGEX: std::sync::LazyLock<regex::Regex> =
    std::sync::LazyLock::new(|| regex::Regex::new(GENERIC_EVENT_FILE_SEARCH_PATTERN).unwrap());
pub fn new_generic_event_file_name() -> String {
    format!("{}.json", misc_helpers::get_date_time_unix_nano())
}
pub const EXTENSION_EVENT_FILE_SEARCH_PATTERN: &str = r"^extension_[0-9]+\.json$";
pub static EXTENSION_EVENT_FILE_SEARCH_REGEX: std::sync::LazyLock<regex::Regex> =
    std::sync::LazyLock::new(|| regex::Regex::new(EXTENSION_EVENT_FILE_SEARCH_PATTERN).unwrap());

pub fn new_extension_event_file_name() -> String {
    format!("extension_{}.json", misc_helpers::get_date_time_unix_nano())
}
pub const PERF_COUNTER_EVENT_FILE_SEARCH_PATTERN: &str = r"^perf_counter_[0-9]+\.json$";
pub static PERF_COUNTER_EVENT_FILE_SEARCH_REGEX: std::sync::LazyLock<regex::Regex> =
    std::sync::LazyLock::new(|| regex::Regex::new(PERF_COUNTER_EVENT_FILE_SEARCH_PATTERN).unwrap());

pub fn new_perf_counter_event_file_name() -> String {
    format!(
        "perf_counter_{}.json",
        misc_helpers::get_date_time_unix_nano()
    )
}

/// Represents a telemetry event for TelemetryGenericLogsEvent
#[derive(Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct Event {
    pub EventLevel: String, // Critical/Error/Warning/Verbose/Informational/LogAlways
    pub Message: String,
    pub Version: String,
    pub TaskName: String,
    pub EventPid: String,
    pub EventTid: String,
    pub OperationId: String,
    pub TimeStamp: String,
}

impl Event {
    pub fn new(level: String, message: String, task_name: String, operation_id: String) -> Self {
        Event {
            EventLevel: level,
            Message: message,
            Version: current_info::get_current_exe_version(),
            TaskName: task_name,
            EventPid: std::process::id().to_string(),
            EventTid: misc_helpers::get_thread_identity(),
            OperationId: operation_id,
            TimeStamp: misc_helpers::get_date_time_string_with_milliseconds(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Extension {
    pub name: String,
    pub version: String,
    pub is_internal: bool,
    pub extension_type: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct OperationStatus {
    pub operation_success: bool,
    pub operation: String,
    pub task_name: String,
    pub message: String,
    pub duration: i64,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ExtensionStatusEvent {
    pub extension: Extension,
    pub operation_status: OperationStatus,

    pub event_pid: String,
    pub event_tid: String,
    pub time_stamp: String,
}

impl ExtensionStatusEvent {
    /// Create a new ExtensionStatusEvent
    /// Rust does not recommend using too many arguments in a function,
    /// so we use structs to group related arguments together.
    /// # Arguments
    /// * `extension` - The extension information
    /// * `operation_status` - The operation status information
    /// # Returns
    /// A new instance of `ExtensionStatusEvent`
    pub fn new(extension: Extension, operation_status: OperationStatus) -> Self {
        ExtensionStatusEvent {
            extension,
            operation_status,
            event_pid: std::process::id().to_string(),
            event_tid: misc_helpers::get_thread_identity(),
            time_stamp: misc_helpers::get_date_time_string_with_milliseconds(),
        }
    }
}

/// Represents a performance counter (metric) sample that is sent to the
/// `GuestAgentPerformanceCounterEvents` table as `TelemetryPerfCounterEvent`.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct PerfCounterEvent {
    /// Counter category, e.g. "Process" or "Memory".
    pub category: String,
    /// Counter name, e.g. "% Processor Time" or "Private Bytes".
    pub counter: String,
    /// Counter instance, e.g. a process name; may be empty.
    pub instance: String,
    /// Sample value. Non-finite values (NaN/inf) are rejected and never sent.
    pub value: f64,
    pub task_name: String,

    pub event_pid: String,
    pub event_tid: String,
    pub time_stamp: String,
}

impl PerfCounterEvent {
    /// Create a new PerfCounterEvent stamped with the current process id, thread id and time.
    pub fn new(
        category: String,
        counter: String,
        instance: String,
        value: f64,
        task_name: String,
    ) -> Self {
        PerfCounterEvent {
            category,
            counter,
            instance,
            value,
            task_name,
            event_pid: std::process::id().to_string(),
            event_tid: misc_helpers::get_thread_identity(),
            time_stamp: misc_helpers::get_date_time_string_with_milliseconds(),
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_perf_counter_event_new() {
        let event = super::PerfCounterEvent::new(
            "Process".to_string(),
            "% Processor Time".to_string(),
            "GuestProxyAgent".to_string(),
            12.5,
            "monitor".to_string(),
        );
        assert_eq!(event.category, "Process");
        assert_eq!(event.counter, "% Processor Time");
        assert_eq!(event.instance, "GuestProxyAgent");
        assert_eq!(event.value, 12.5);
        assert_eq!(event.task_name, "monitor");
        assert_eq!(event.event_pid, std::process::id().to_string());
        assert!(!event.time_stamp.is_empty());

        let json = serde_json::to_string(&event).unwrap();
        let round_trip: super::PerfCounterEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(round_trip, event);
    }

    #[test]
    fn test_event_file_patterns_do_not_collide() {
        let perf = super::new_perf_counter_event_file_name();
        let ext = super::new_extension_event_file_name();
        let generic = super::new_generic_event_file_name();
        assert!(super::PERF_COUNTER_EVENT_FILE_SEARCH_REGEX.is_match(&perf));
        assert!(!super::PERF_COUNTER_EVENT_FILE_SEARCH_REGEX.is_match(&ext));
        assert!(!super::PERF_COUNTER_EVENT_FILE_SEARCH_REGEX.is_match(&generic));
        assert!(!super::EXTENSION_EVENT_FILE_SEARCH_REGEX.is_match(&perf));
        assert!(!super::GENERIC_EVENT_FILE_SEARCH_REGEX.is_match(&perf));
    }

    #[test]
    fn test_telemetry_new() {
        let event = super::Event::new(
            "Critical".to_string(),
            "test message".to_string(),
            "test task name".to_string(),
            "test operation id".to_string(),
        );
        assert_eq!(event.EventLevel, "Critical".to_string());
        assert_eq!(event.Message, "test message".to_string());
        assert_eq!(event.TaskName, "test task name".to_string());
        assert_eq!(event.OperationId, "test operation id".to_string());
    }

    #[test]
    fn test_extension_status_event_new() {
        let extension = super::Extension {
            name: "test extension".to_string(),
            version: "1.0.0".to_string(),
            is_internal: true,
            extension_type: "test type".to_string(),
        };
        let operation_status = super::OperationStatus {
            operation_success: true,
            task_name: "test task".to_string(),
            operation: "test operation".to_string(),
            message: "test message".to_string(),
            duration: 100,
        };
        let event = super::ExtensionStatusEvent::new(extension.clone(), operation_status.clone());
        assert_eq!(event.extension.name, extension.name);
        assert_eq!(event.extension.version, extension.version);
        assert_eq!(event.extension.is_internal, extension.is_internal);
        assert_eq!(event.extension.extension_type, extension.extension_type);
        assert_eq!(
            event.operation_status.operation_success,
            operation_status.operation_success
        );
        assert_eq!(event.operation_status.operation, operation_status.operation);
        assert_eq!(event.operation_status.message, operation_status.message);
        assert_eq!(event.operation_status.duration, operation_status.duration);
    }
}
