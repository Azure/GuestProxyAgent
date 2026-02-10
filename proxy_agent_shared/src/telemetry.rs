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
pub fn new_generic_event_file_name() -> String {
    format!("{}.json", misc_helpers::get_date_time_unix_nano())
}
pub const EXTENSION_EVENT_FILE_SEARCH_PATTERN: &str = r"^extension_[0-9]+\.json$";
pub fn new_extension_event_file_name() -> String {
    format!("extension_{}.json", misc_helpers::get_date_time_unix_nano())
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

#[cfg(test)]
mod tests {
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
