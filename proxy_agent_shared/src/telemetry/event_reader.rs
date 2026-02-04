// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

//! This module contains the logic to read the telemetry event files.
//! //! The telemetry event files are written by the event_logger module.

use crate::common_state::CommonState;
use crate::current_info;
use crate::logger::logger_manager;
use crate::misc_helpers;
use crate::telemetry::event_sender;
use crate::telemetry::telemetry_event::TelemetryEvent;
use crate::telemetry::telemetry_event::TelemetryExtensionEventsEvent;
use crate::telemetry::telemetry_event::TelemetryGenericLogsEvent;
use crate::telemetry::Event;
use std::fs::remove_file;
use std::path::PathBuf;
use std::time::Duration;

/// Configuration for limiting EventReader behavior
#[derive(Default, Clone)]
pub struct EventReaderLimits {
    pub max_events_per_round: Option<usize>,
    pub max_event_file_size_bytes: Option<u64>,
    pub version: Option<String>,
}

impl EventReaderLimits {
    pub fn new() -> Self {
        EventReaderLimits::default()
    }

    pub fn with_max_events_per_round(mut self, max: usize) -> Self {
        self.max_events_per_round = Some(max);
        self
    }

    pub fn with_max_event_file_size_bytes(mut self, max: u64) -> Self {
        self.max_event_file_size_bytes = Some(max);
        self
    }

    pub fn with_version(mut self, version: String) -> Self {
        self.version = Some(version);
        self
    }
}

pub struct EventReader {
    dir_path: PathBuf,
    common_state: CommonState,
    execution_mode: String,
    event_name: String,
    limits: EventReaderLimits,
}

impl EventReader {
    /// Create a new EventReader without limits on event file size and max events per round.
    /// The event reader will read the event files from the specified directory.
    /// If delay_start is true, the event reader will delay start for 60 seconds.
    /// The common_state is used to store the vm metadata.
    /// The execution_mode is used to indicate the mode of the agent.
    /// The event_name is used to indicate the name of the event reader.
    pub fn new(
        dir_path: PathBuf,
        common_state: CommonState,
        execution_mode: String,
        event_name: String,
    ) -> EventReader {
        EventReader {
            dir_path,
            common_state,
            execution_mode,
            event_name,
            limits: EventReaderLimits::default(),
        }
    }

    /// Create a new EventReader with limits configuration.
    pub fn new_with_limits(
        dir_path: PathBuf,
        common_state: CommonState,
        execution_mode: String,
        event_name: String,
        limits: EventReaderLimits,
    ) -> EventReader {
        EventReader {
            dir_path,
            common_state,
            execution_mode,
            event_name,
            limits,
        }
    }

    pub async fn start(&self, delay_start: bool, interval: Option<Duration>) {
        if delay_start {
            // delay start the event_reader task to give additional CPU cycles to more important threads
            tokio::time::sleep(Duration::from_secs(60)).await;
        }
        logger_manager::write_info("telemetry event reader task started.".to_string());

        let interval = interval.unwrap_or(Duration::from_secs(300));
        let cancellation_token = self.common_state.get_cancellation_token();
        tokio::select! {
            _ = self.loop_reader(interval) => {}
            _ = cancellation_token.cancelled() => {
                logger_manager::write_warn("cancellation token signal received, stop the telemetry event reader task.".to_string());
            }
        }
    }

    async fn loop_reader(&self, interval: Duration) {
        loop {
            self.process_once().await;
            tokio::time::sleep(interval).await;
        }
    }

    /// Process the event files from the directory once.
    pub async fn process_once(&self) -> usize {
        let event_count: usize;
        // get all [0-9]+.json event filenames with numbers in the directory
        match misc_helpers::search_files(
            &self.dir_path,
            crate::telemetry::GENERIC_EVENT_FILE_SEARCH_PATTERN,
        ) {
            Ok(files) => {
                let file_count = files.len();
                event_count = self.process_events_and_clean(files).await;
                let message = format!(
                    "Telemetry event reader sent {event_count} events from {file_count} files"
                );
                logger_manager::write_info(message);
            }
            Err(e) => {
                logger_manager::write_warn(format!(
                    "Event Files not found in directory {}: {}",
                    self.dir_path.display(),
                    e
                ));
                event_count = 0;
            }
        }
        event_count
    }

    async fn process_events_and_clean(&self, files: Vec<PathBuf>) -> usize {
        let mut num_events_logged = 0;
        for file in files {
            if let Some(max_events) = self.limits.max_events_per_round {
                if num_events_logged >= max_events {
                    logger_manager::write_warn(format!(
                                "EventReader:: Reached the max number of events to be read per round: {}. Stop processing file {} this round.",
                                max_events,
                                file.display()
                            ));
                    // do not delete this event json file, will try process it at next round
                    break;
                }
            }

            match file.metadata() {
                Err(e) => {
                    logger_manager::write_warn(format!(
                        "EventReader:: Failed to get metadata for file {}: {}",
                        file.display(),
                        e
                    ));
                    continue;
                }
                Ok(metadata) => {
                    if let Some(max_size) = self.limits.max_event_file_size_bytes {
                        if metadata.len() > max_size {
                            logger_manager::write_warn(format!(
                                "EventReader:: File {} exceeds the size limit of {} bytes, skip it.",
                                file.display(),
                                max_size
                            ));
                            // clean up the file to avoid blocking further processing
                            Self::clean_file(file);
                            continue;
                        }
                    }
                }
            }
            match misc_helpers::json_read_from_file::<Vec<Event>>(&file) {
                Ok(events) => {
                    num_events_logged += events.len();
                    self.handle_events(events).await;
                }
                Err(e) => {
                    logger_manager::write_warn(format!(
                        "EventReader:: Failed to read events from file {}: {}",
                        file.display(),
                        e
                    ));
                }
            }
            Self::clean_file(file);
        }
        num_events_logged
    }

    async fn handle_events(&self, mut events: Vec<Event>) {
        let mut queued_event = false;
        while !events.is_empty() {
            match events.pop() {
                Some(event) => {
                    let telemetry_event = TelemetryGenericLogsEvent::from_event_log(
                        &event,
                        self.execution_mode.clone(),
                        self.event_name.clone(),
                        self.limits.version.clone(),
                    );
                    let telemetry_event = TelemetryEvent::GenericLogsEvent(telemetry_event);
                    event_sender::enqueue_event(telemetry_event);
                    queued_event = true;
                }
                None => {
                    break;
                }
            }
        }

        if queued_event {
            if let Err(e) = self.common_state.notify_telemetry_event().await {
                logger_manager::write_warn(format!(
                    "Failed to notify telemetry event with error: {e}"
                ));
            }
        }
    }

    fn clean_file(file: PathBuf) {
        match remove_file(&file) {
            Ok(_) => {
                logger_manager::write_info(format!("Removed File: {}", file.display()));
            }
            Err(e) => {
                logger_manager::write_warn(format!(
                    "Failed to remove file {}: {}",
                    file.display(),
                    e
                ));
            }
        }
    }

    pub async fn start_extension_status_event_processor(
        &self,
        delay_start: bool,
        interval: Option<Duration>,
    ) {
        if delay_start {
            // delay start the event_reader task to give additional CPU cycles to more important threads
            tokio::time::sleep(Duration::from_secs(60)).await;
        }

        logger_manager::write_info(
            "telemetry extension status event reader task started.".to_string(),
        );
        let interval = interval.unwrap_or(Duration::from_secs(60));
        let cancellation_token = self.common_state.get_cancellation_token();
        tokio::select! {
            _ = self.loop_extension_status_event_processor(interval ) => {}
            _ = cancellation_token.cancelled() => {
                logger_manager::write_warn("cancellation token signal received, stop the telemetry extension status event reader task.".to_string());
            }
        }
    }

    async fn loop_extension_status_event_processor(&self, interval: Duration) {
        loop {
            self.process_extension_status_events().await;
            tokio::time::sleep(interval).await;
        }
    }

    async fn process_extension_status_events(&self) -> usize {
        let mut event_count: usize = 0;
        // get all extension status event filenames in the directory
        match misc_helpers::search_files(
            &self.dir_path,
            crate::telemetry::EXTENSION_EVENT_FILE_SEARCH_PATTERN,
        ) {
            Ok(files) => {
                let file_count = files.len();
                for file in files {
                    event_count += self.process_one_extension_status_event_file(file).await;
                }
                logger_manager::write_info( format!(
                    "Telemetry event reader sent {event_count} extension status events from {file_count} files"
                ));
            }
            Err(e) => {
                logger_manager::write_warn(format!(
                    "Extension Status Event Files not found in directory {}: {}",
                    self.dir_path.display(),
                    e
                ));
            }
        }
        event_count
    }

    async fn process_one_extension_status_event_file(&self, file: PathBuf) -> usize {
        let mut num_events_logged = 0;

        match misc_helpers::json_read_from_file::<crate::telemetry::ExtensionStatusEvent>(&file) {
            Ok(event) => {
                num_events_logged += 1;
                let telemetry_event = TelemetryExtensionEventsEvent::from_extension_status_event(
                    &event,
                    self.execution_mode.clone(),
                    current_info::get_current_exe_version(),
                );
                let telemetry_event = TelemetryEvent::ExtensionEvent(telemetry_event);
                event_sender::enqueue_event(telemetry_event);
                if let Err(e) = self.common_state.notify_telemetry_event().await {
                    logger_manager::write_warn(format!(
                        "Failed to notify telemetry event with error: {e}"
                    ));
                }
            }
            Err(e) => {
                logger_manager::write_warn(format!(
                    "EventReader:: Failed to read extension status event from file {}: {}",
                    file.display(),
                    e
                ));
            }
        }

        Self::clean_file(file);
        num_events_logged
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::misc_helpers;
    use std::{env, fs};
    use tokio_util::sync::CancellationToken;

    #[tokio::test]
    async fn test_event_reader_thread() {
        let mut temp_dir = env::temp_dir();
        temp_dir.push("test_event_reader_thread");

        _ = fs::remove_dir_all(&temp_dir);
        let mut events_dir = temp_dir.to_path_buf();
        events_dir.push("Events");

        let common_state = CommonState::start_new(CancellationToken::new());
        let event_reader = EventReader::new(
            events_dir.clone(),
            common_state.clone(),
            "Test".to_string(),
            "test_event_reader_thread".to_string(),
        );

        // Write events to events dir
        let message = r#"{\"method\":\"GET\",\"url\":\"/machine/37569ad2-69a3-44fd-b653-813e62a177cf/68938c06%2D5233%2D4ff9%2Da173%2D0ac0a2754f8a.%5FWS2022?comp=config&type=hostingEnvironmentConfig&incarnation=2\",\"ip\":\"168.63.129.16\",\"port\":80,\"userId\":999,\"userName\":\"WS2022$\",\"processName\":\"C:\\\\WindowsAzure\\\\GuestAgent_2.7.41491.1071_2023-03-02_185502\\\\WindowsAzureGuestAgent.exe\",\"runAsElevated\":true,\"responseStatus\":\"200 OK\",\"elapsedTime\":8}"#;
        let mut events: Vec<Event> = Vec::new();
        for _ in [0; 10] {
            events.push(Event::new(
                "Informational".to_string(),
                message.to_string(),
                "test_deserialize_events_from_file".to_string(),
                "test_deserialize_events_from_file".to_string(),
            ));
        }
        logger_manager::write_info("10 events created.".to_string());
        misc_helpers::try_create_folder(&events_dir).unwrap();
        let mut file_path = events_dir.to_path_buf();
        file_path.push(format!("{}.json", misc_helpers::get_date_time_unix_nano()));
        misc_helpers::json_write_to_file(&events, &file_path).unwrap();
        tokio::time::sleep(Duration::from_millis(1)).await;
        let mut file_path = events_dir.to_path_buf();
        file_path.push(format!("{}.json", misc_helpers::get_date_time_unix_nano()));
        misc_helpers::json_write_to_file(&events, &file_path).unwrap();

        // test EventReader with limits
        let event_reader_limits = EventReaderLimits::new()
            .with_max_event_file_size_bytes(1024 * 10)
            .with_max_events_per_round(10)
            .with_version("test_version".to_string());
        let event_reader_with_limits = EventReader::new_with_limits(
            events_dir.clone(),
            common_state.clone(),
            "Test".to_string(),
            "test_event_reader_thread".to_string(),
            event_reader_limits.clone(),
        );
        // Check the events processed
        let events_processed = event_reader_with_limits.process_once().await;
        logger_manager::write_info(format!("Send {} events from event files", events_processed));
        //Should be 10 events processed and read into events Vector
        assert_eq!(events_processed, 10, "Events processed should be 10");
        let files = misc_helpers::get_files(&events_dir).unwrap();
        assert_eq!(1, files.len(), "Must still have 1 event file.");
        // test EventReader with limits - second round
        let events_processed = event_reader_with_limits.process_once().await;
        logger_manager::write_info(format!("Send {} events from event files", events_processed));
        //Should be 10 events processed and read into events Vector
        assert_eq!(events_processed, 10, "Events processed should be 10");
        let files = misc_helpers::get_files(&events_dir).unwrap();
        assert!(files.is_empty(), "Must have no event files.");

        // Write 2 event files again for next test
        tokio::time::sleep(Duration::from_millis(1)).await;
        let mut file_path = events_dir.to_path_buf();
        file_path.push(format!("{}.json", misc_helpers::get_date_time_unix_nano()));
        misc_helpers::json_write_to_file(&events, &file_path).unwrap();
        tokio::time::sleep(Duration::from_millis(1)).await;
        let mut file_path = events_dir.to_path_buf();
        file_path.push(format!("{}.json", misc_helpers::get_date_time_unix_nano()));
        misc_helpers::json_write_to_file(&events, &file_path).unwrap();
        let files = misc_helpers::get_files(&events_dir).unwrap();
        assert_eq!(2, files.len(), "Must have 2 event files.");

        // test EventReader without limits
        let events_processed = event_reader.process_once().await;
        logger_manager::write_info(format!("Send {} events from event files", events_processed));
        //Should be 20 events processed and read into events Vector
        assert_eq!(events_processed, 20, "Events processed should be 20");
        let files = misc_helpers::get_files(&events_dir).unwrap();
        assert!(files.is_empty(), "Must have no event files.");

        // Test not processing the non-json files, nor the file name containing non-numeric characters
        let mut file_path = events_dir.to_path_buf();
        file_path.push(format!(
            "{}.notjson",
            misc_helpers::get_date_time_unix_nano()
        ));
        misc_helpers::json_write_to_file(&events, &file_path).unwrap();
        let mut file_path = events_dir.to_path_buf();
        file_path.push(format!("a{}.json", misc_helpers::get_date_time_unix_nano()));
        misc_helpers::json_write_to_file(&events, &file_path).unwrap();
        let events_processed = event_reader.process_once().await;
        assert_eq!(0, events_processed, "events_processed must be 0.");
        let files = misc_helpers::get_files(&events_dir).unwrap();
        assert!(
            !files.is_empty(),
            ".notjson files should not been cleaned up."
        );

        common_state.cancel_cancellation_token();
        _ = fs::remove_dir_all(&temp_dir);
    }
}
