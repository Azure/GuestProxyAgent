// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

//! This module contains the logic to read the telemetry event files and send them to the wire server.
//! The telemetry event files are written by the event_logger module.

use crate::common_state;
use crate::common_state::CommonState;
use crate::host_clients::imds_client::ImdsClient;
use crate::host_clients::wire_server_client::WireServerClient;
use crate::logger::logger_manager;
use crate::misc_helpers;
use crate::result::Result;
use crate::telemetry::telemetry_event::TelemetryData;
use crate::telemetry::telemetry_event::TelemetryEvent;
use crate::telemetry::Event;
use std::fs::remove_file;
use std::path::PathBuf;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

#[cfg(test)]
const EMPTY_GUID: &str = "00000000-0000-0000-0000-000000000000";

const WIRE_SERVER_IP: &str = "168.63.129.16";
const WIRE_SERVER_PORT: u16 = 80u16;
const IMDS_IP: &str = "169.254.169.254";
const IMDS_PORT: u16 = 80u16;

/// VmMetaData contains the metadata of the VM.
/// The metadata is used to identify the VM and the image origin.
/// It will be part of the telemetry data send to the wire server.
/// The metadata is updated by the wire server and the IMDS client.
#[derive(Clone, Debug)]
pub struct VmMetaData {
    pub container_id: String,
    pub tenant_name: String,
    pub role_name: String,
    pub role_instance_name: String,
    pub subscription_id: String,
    pub resource_group_name: String,
    pub vm_id: String,
    pub image_origin: u64,
}

impl VmMetaData {
    #[cfg(test)]
    pub fn empty() -> Self {
        VmMetaData {
            container_id: EMPTY_GUID.to_string(),
            tenant_name: EMPTY_GUID.to_string(),
            role_name: EMPTY_GUID.to_string(),
            role_instance_name: EMPTY_GUID.to_string(),
            subscription_id: EMPTY_GUID.to_string(),
            resource_group_name: EMPTY_GUID.to_string(),
            vm_id: EMPTY_GUID.to_string(),
            image_origin: 3, // unknown
        }
    }
}

pub struct EventReader {
    dir_path: PathBuf,
    delay_start: bool,
    cancellation_token: CancellationToken,
    common_state: CommonState,
    execution_mode: String,
    event_name: String,
}

impl EventReader {
    pub fn new(
        dir_path: PathBuf,
        delay_start: bool,
        cancellation_token: CancellationToken,
        common_state: CommonState,
        execution_mode: String,
        event_name: String,
    ) -> EventReader {
        EventReader {
            dir_path,
            delay_start,
            cancellation_token,
            common_state,
            execution_mode,
            event_name,
        }
    }

    pub async fn start(
        &self,
        interval: Option<Duration>,
        server_ip: Option<&str>,
        server_port: Option<u16>,
    ) {
        logger_manager::write_info("telemetry event reader task started.".to_string());

        let wire_server_client = WireServerClient::new(
            server_ip.unwrap_or(WIRE_SERVER_IP),
            server_port.unwrap_or(WIRE_SERVER_PORT),
        );
        let imds_client = ImdsClient::new(
            server_ip.unwrap_or(IMDS_IP),
            server_port.unwrap_or(IMDS_PORT),
        );

        let interval = interval.unwrap_or(Duration::from_secs(300));
        tokio::select! {
            _ = self.loop_reader(interval,  wire_server_client, imds_client ) => {}
            _ = self.cancellation_token.cancelled() => {
                logger_manager::write_warn("cancellation token signal received, stop the telemetry event reader task.".to_string());
            }
        }
    }

    async fn loop_reader(
        &self,
        interval: Duration,
        wire_server_client: WireServerClient,
        imds_client: ImdsClient,
    ) {
        let mut first = true;

        loop {
            if first {
                if self.delay_start {
                    // delay start the event_reader task to give additional CPU cycles to more important threads
                    tokio::time::sleep(Duration::from_secs(60)).await;
                }
                first = false;
            }

            // refresh vm metadata
            match self
                .update_vm_meta_data(&wire_server_client, &imds_client)
                .await
            {
                Ok(()) => {
                    logger_manager::write_info("success updated the vm metadata.".to_string());
                }
                Err(e) => {
                    logger_manager::write_warn(format!(
                        "Failed to read vm metadata with error {e}."
                    ));
                }
            }

            if let Ok(Some(vm_meta_data)) = self.common_state.get_vm_meta_data().await {
                let _processed = self
                    .process_events(&wire_server_client, &vm_meta_data)
                    .await;
            }

            tokio::time::sleep(interval).await;
        }
    }

    async fn process_events(
        &self,
        wire_server_client: &WireServerClient,
        vm_meta_data: &VmMetaData,
    ) -> usize {
        let event_count: usize;
        // get all .json event files in the directory
        match misc_helpers::search_files(&self.dir_path, r"^(.*\.json)$") {
            Ok(files) => {
                let file_count = files.len();
                event_count = self
                    .process_events_and_clean(files, wire_server_client, vm_meta_data)
                    .await;
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

    async fn update_vm_meta_data(
        &self,
        wire_server_client: &WireServerClient,
        imds_client: &ImdsClient,
    ) -> Result<()> {
        let guid = self
            .common_state
            .get_state(common_state::SECURE_KEY_GUID.to_string())
            .await
            .unwrap_or(None);
        let key = self
            .common_state
            .get_state(common_state::SECURE_KEY_VALUE.to_string())
            .await
            .unwrap_or(None);
        let goal_state = wire_server_client
            .get_goalstate(guid.clone(), key.clone())
            .await?;
        let shared_config = wire_server_client
            .get_shared_config(
                goal_state.get_shared_config_uri(),
                guid.clone(),
                key.clone(),
            )
            .await?;

        let instance_info = imds_client
            .get_imds_instance_info(guid.clone(), key.clone())
            .await?;
        let vm_meta_data = VmMetaData {
            container_id: goal_state.get_container_id(),
            role_name: shared_config.get_role_name(),
            role_instance_name: shared_config.get_role_instance_name(),
            tenant_name: shared_config.get_deployment_name(),
            subscription_id: instance_info.get_subscription_id(),
            resource_group_name: instance_info.get_resource_group_name(),
            vm_id: instance_info.get_vm_id(),
            image_origin: instance_info.get_image_origin(),
        };

        self.common_state
            .set_vm_meta_data(Some(vm_meta_data))
            .await?;

        Ok(())
    }

    async fn process_events_and_clean(
        &self,
        files: Vec<PathBuf>,
        wire_server_client: &WireServerClient,
        vm_meta_data: &VmMetaData,
    ) -> usize {
        let mut num_events_logged = 0;
        for file in files {
            match misc_helpers::json_read_from_file::<Vec<Event>>(&file) {
                Ok(events) => {
                    num_events_logged += events.len();
                    self.send_events(events, wire_server_client, vm_meta_data)
                        .await;
                }
                Err(e) => {
                    logger_manager::write_warn(format!(
                        "Failed to read events from file {}: {}",
                        file.display(),
                        e
                    ));
                }
            }
            Self::clean_files(file);
        }
        num_events_logged
    }

    const MAX_MESSAGE_SIZE: usize = 1024 * 64;
    async fn send_events(
        &self,
        mut events: Vec<Event>,
        wire_server_client: &WireServerClient,
        vm_meta_data: &VmMetaData,
    ) {
        while !events.is_empty() {
            let mut telemetry_data = TelemetryData::new();
            let mut add_more_events = true;
            while !events.is_empty() && add_more_events {
                match events.pop() {
                    Some(event) => {
                        telemetry_data.add_event(TelemetryEvent::from_event_log(
                            &event,
                            vm_meta_data.clone(),
                            self.execution_mode.clone(),
                            self.event_name.clone(),
                        ));

                        if telemetry_data.get_size() >= Self::MAX_MESSAGE_SIZE {
                            telemetry_data.remove_last_event();
                            if telemetry_data.event_count() == 0 {
                                match serde_json::to_string(&event) {
                                    Ok(json) => {
                                        logger_manager::write_warn(format!(
                                            "Event data too large. Not sending to wire-server. Event: {json}.",
                                        ));
                                    }
                                    Err(_) => {
                                        logger_manager::write_warn(
                                        "Event data too large. Not sending to wire-server. Event cannot be displayed.".to_string()
                                        );
                                    }
                                }
                            } else {
                                events.push(event);
                            }
                            add_more_events = false;
                        }
                    }
                    None => {
                        break;
                    }
                }
            }

            Self::send_data_to_wire_server(telemetry_data, wire_server_client).await;
        }
    }

    async fn send_data_to_wire_server(
        telemetry_data: TelemetryData,
        wire_server_client: &WireServerClient,
    ) {
        if telemetry_data.event_count() == 0 {
            return;
        }

        for _ in [0; 5] {
            match wire_server_client
                .send_telemetry_data(telemetry_data.to_xml())
                .await
            {
                Ok(()) => {
                    break;
                }
                Err(e) => {
                    logger_manager::write_warn(format!(
                        "Failed to send telemetry data to host with error: {e}"
                    ));
                    // wait 15 seconds and retry
                    tokio::time::sleep(Duration::from_secs(15)).await;
                }
            }
        }
    }

    fn clean_files(file: PathBuf) {
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

    #[cfg(test)]
    async fn get_vm_meta_data(&self) -> VmMetaData {
        if let Ok(Some(vm_meta_data)) = self.common_state.get_vm_meta_data().await {
            vm_meta_data
        } else {
            VmMetaData::empty()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::misc_helpers;
    use crate::server_mock;
    use std::{env, fs};

    #[tokio::test]
    async fn test_event_reader_thread() {
        let mut temp_dir = env::temp_dir();
        temp_dir.push("test_event_reader_thread");

        _ = fs::remove_dir_all(&temp_dir);
        let mut events_dir = temp_dir.to_path_buf();
        events_dir.push("Events");

        // start wire_server listener
        let ip = "127.0.0.1";
        let port = 7071u16;
        let cancellation_token = CancellationToken::new();
        let common_state = CommonState::start_new();
        let event_reader = EventReader {
            dir_path: events_dir.clone(),
            delay_start: false,
            cancellation_token: cancellation_token.clone(),
            common_state: common_state.clone(),
            execution_mode: "Test".to_string(),
            event_name: "test_event_reader_thread".to_string(),
        };
        let wire_server_client = WireServerClient::new(ip, port);
        let imds_client = ImdsClient::new(ip, port);
        tokio::spawn(server_mock::start(
            ip.to_string(),
            port,
            cancellation_token.clone(),
        ));
        tokio::time::sleep(Duration::from_millis(100)).await;
        logger_manager::write_info("server_mock started.".to_string());

        match event_reader
            .update_vm_meta_data(&wire_server_client, &imds_client)
            .await
        {
            Ok(()) => {
                logger_manager::write_info("success updated the vm metadata.".to_string());
            }
            Err(e) => {
                logger_manager::write_warn(format!("Failed to read vm metadata with error {}.", e));
            }
        }

        // Write 10 events to events dir
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

        // Check the events processed
        let vm_meta_data = event_reader.get_vm_meta_data().await;
        let events_processed = event_reader
            .process_events(&wire_server_client, &vm_meta_data)
            .await;
        logger_manager::write_info(format!("Send {} events from event files", events_processed));
        //Should be 10 events written and read into events Vector
        assert_eq!(events_processed, 10, "Events processed should be 10");
        let files = misc_helpers::get_files(&events_dir).unwrap();
        assert!(files.is_empty(), "Events files not cleaned up.");

        // Test not processing the non-json files
        let mut file_path = events_dir.to_path_buf();
        file_path.push(format!(
            "{}.notjson",
            misc_helpers::get_date_time_unix_nano()
        ));
        misc_helpers::json_write_to_file(&events, &file_path).unwrap();
        let events_processed = event_reader
            .process_events(&wire_server_client, &vm_meta_data)
            .await;
        assert_eq!(0, events_processed, "events_processed must be 0.");
        let files = misc_helpers::get_files(&events_dir).unwrap();
        assert!(
            !files.is_empty(),
            ".notjson files should not been cleaned up."
        );

        cancellation_token.cancel();
        _ = fs::remove_dir_all(&temp_dir);
    }
}
