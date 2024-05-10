// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
pub mod event_logger;
pub mod span;

use crate::misc_helpers;
use serde_derive::{Deserialize, Serialize};

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
            Version: misc_helpers::get_current_version(),
            TaskName: task_name,
            EventPid: std::process::id().to_string(),
            EventTid: misc_helpers::get_thread_identity(),
            OperationId: operation_id,
            TimeStamp: misc_helpers::get_date_time_string_with_miliseconds(),
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
}
