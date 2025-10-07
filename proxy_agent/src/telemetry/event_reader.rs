// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

//! This module contains the logic to read the telemetry event files and send them to the wire server.
//! The telemetry event files are written by the event_logger module.
//! Example
//! ```rust
//! use proxy_agent::telemetry::event_reader;
//! use proxy_agent::shared_state::agent_status::wrapper::AgentStatusSharedState;
//! use proxy_agent::shared_state::key_keeper::wrapper::KeyKeeperSharedState;
//! use proxy_agent::shared_state::telemetry::wrapper::TelemetrySharedState;
//! use std::path::PathBuf;
//! use std::time::Duration;
//! use tokio_util::sync::CancellationToken;
//!
//! // start the telemetry event reader with the shared state
//! let agent_status_shared_state = AgentStatusSharedState::start_new();
//! let key_keeper_shared_state = KeyKeeperSharedState::start_new();
//! let telemetry_shared_state = TelemetrySharedState::start_new();
//! let cancellation_token = CancellationToken::new();
//!
//! let dir_path = PathBuf::from("/tmp");
//! let interval = Some(Duration::from_secs(300));
//! let delay_start = false;
//! let server_ip = None;
//! let server_port = None;
//! let event_reader = event_reader::EventReader::new(
//!    dir_path,
//!    delay_start,
//!    cancellation_token,
//!    key_keeper_shared_state,
//!    telemetry_shared_state,
//!    agent_status_shared_state,
//! );
//!
//! tokio::spawn(event_reader.start(interval, server_ip, server_port));
//!
//! // stop the telemetry event reader
//! cancellation_token.cancel();
//! ```

use super::telemetry_event::TelemetryData;
use super::telemetry_event::TelemetryEvent;
use crate::common::{constants, logger, result::Result};
use crate::shared_state::agent_status_wrapper::AgentStatusModule;
use crate::shared_state::agent_status_wrapper::AgentStatusSharedState;
use crate::shared_state::key_keeper_wrapper::KeyKeeperSharedState;
use crate::shared_state::telemetry_wrapper::TelemetrySharedState;
use proxy_agent_shared::host_clients::imds_client::ImdsClient;
use proxy_agent_shared::host_clients::wire_server_client::WireServerClient;
use proxy_agent_shared::misc_helpers;
use proxy_agent_shared::proxy_agent_aggregate_status::ModuleState;
use proxy_agent_shared::telemetry::Event;
use std::fs::remove_file;
use std::path::PathBuf;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

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
            container_id: constants::EMPTY_GUID.to_string(),
            tenant_name: constants::EMPTY_GUID.to_string(),
            role_name: constants::EMPTY_GUID.to_string(),
            role_instance_name: constants::EMPTY_GUID.to_string(),
            subscription_id: constants::EMPTY_GUID.to_string(),
            resource_group_name: constants::EMPTY_GUID.to_string(),
            vm_id: constants::EMPTY_GUID.to_string(),
            image_origin: 3, // unknown
        }
    }
}

pub struct EventReader {
    dir_path: PathBuf,
    delay_start: bool,
    cancellation_token: CancellationToken,
    key_keeper_shared_state: KeyKeeperSharedState,
    telemetry_shared_state: TelemetrySharedState,
    agent_status_shared_state: AgentStatusSharedState,
}

impl EventReader {
    pub fn new(
        dir_path: PathBuf,
        delay_start: bool,
        cancellation_token: CancellationToken,
        key_keeper_shared_state: KeyKeeperSharedState,
        telemetry_shared_state: TelemetrySharedState,
        agent_status_shared_state: AgentStatusSharedState,
    ) -> EventReader {
        EventReader {
            dir_path,
            delay_start,
            cancellation_token,
            key_keeper_shared_state,
            telemetry_shared_state,
            agent_status_shared_state,
        }
    }

    pub async fn start(
        &self,
        interval: Option<Duration>,
        server_ip: Option<&str>,
        server_port: Option<u16>,
    ) {
        logger::write_information("telemetry event reader task started.".to_string());

        let wire_server_client = WireServerClient::new(
            server_ip.unwrap_or(constants::WIRE_SERVER_IP),
            server_port.unwrap_or(constants::WIRE_SERVER_PORT),
        );
        let imds_client = ImdsClient::new(
            server_ip.unwrap_or(constants::IMDS_IP),
            server_port.unwrap_or(constants::IMDS_PORT),
        );

        let interval = interval.unwrap_or(Duration::from_secs(300));
        tokio::select! {
            _ = self.loop_reader(interval,  wire_server_client, imds_client ) => {}
            _ = self.cancellation_token.cancelled() => {
                logger::write_warning("cancellation token signal received, stop the telemetry event reader task.".to_string());
                self.stop().await;
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
                    logger::write("success updated the vm metadata.".to_string());
                }
                Err(e) => {
                    logger::write_warning(format!("Failed to read vm metadata with error {e}."));
                }
            }

            if let Ok(Some(vm_meta_data)) = self.telemetry_shared_state.get_vm_meta_data().await {
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
                logger::write(message);
            }
            Err(e) => {
                logger::write_warning(format!(
                    "Event Files not found in directory {}: {}",
                    self.dir_path.display(),
                    e
                ));
                event_count = 0;
            }
        }
        event_count
    }

    async fn stop(&self) {
        let _ = self
            .agent_status_shared_state
            .set_module_state(ModuleState::STOPPED, AgentStatusModule::TelemetryReader)
            .await;
    }

    async fn update_vm_meta_data(
        &self,
        wire_server_client: &WireServerClient,
        imds_client: &ImdsClient,
    ) -> Result<()> {
        let guid = self
            .key_keeper_shared_state
            .get_current_key_guid()
            .await
            .unwrap_or(None);
        let key = self
            .key_keeper_shared_state
            .get_current_key_value()
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

        self.telemetry_shared_state
            .set_vm_meta_data(Some(vm_meta_data.clone()))
            .await?;

        logger::write(format!("Updated VM Metadata: {vm_meta_data:?}"));
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
                    Self::send_events(events, wire_server_client, vm_meta_data).await;
                }
                Err(e) => {
                    logger::write_warning(format!(
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
                        ));

                        if telemetry_data.get_size() >= Self::MAX_MESSAGE_SIZE {
                            telemetry_data.remove_last_event();
                            if telemetry_data.event_count() == 0 {
                                match serde_json::to_string(&event) {
                                    Ok(json) => {
                                        logger::write_warning(format!(
                                            "Event data too large. Not sending to wire-server. Event: {json}.",
                                        ));
                                    }
                                    Err(_) => {
                                        logger::write_warning(
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
                    logger::write_warning(format!(
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
                logger::write(format!("Removed File: {}", file.display()));
            }
            Err(e) => {
                logger::write_warning(format!("Failed to remove file {}: {}", file.display(), e));
            }
        }
    }

    #[cfg(test)]
    async fn get_vm_meta_data(&self) -> VmMetaData {
        if let Ok(Some(vm_meta_data)) = self.telemetry_shared_state.get_vm_meta_data().await {
            vm_meta_data
        } else {
            VmMetaData::empty()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::logger;
    use crate::key_keeper::key::Key;
    use proxy_agent_shared::misc_helpers;
    use proxy_agent_shared::server_mock;
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
        let key_keeper_shared_state = KeyKeeperSharedState::start_new();
        let event_reader = EventReader {
            dir_path: events_dir.clone(),
            delay_start: false,
            key_keeper_shared_state: key_keeper_shared_state.clone(),
            telemetry_shared_state: TelemetrySharedState::start_new(),
            cancellation_token: cancellation_token.clone(),
            agent_status_shared_state: AgentStatusSharedState::start_new(),
        };
        let wire_server_client = WireServerClient::new(ip, port);
        let imds_client = ImdsClient::new(ip, port);

        key_keeper_shared_state
            .update_key(Key::empty())
            .await
            .unwrap();
        tokio::spawn(server_mock::start(
            ip.to_string(),
            port,
            cancellation_token.clone(),
        ));
        tokio::time::sleep(Duration::from_millis(100)).await;
        logger::write("server_mock started.".to_string());

        match event_reader
            .update_vm_meta_data(&wire_server_client, &imds_client)
            .await
        {
            Ok(()) => {
                logger::write("success updated the vm metadata.".to_string());
            }
            Err(e) => {
                logger::write_warning(format!("Failed to read vm metadata with error {}.", e));
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
        logger::write("10 events created.".to_string());
        misc_helpers::try_create_folder(&events_dir).unwrap();
        let mut file_path = events_dir.to_path_buf();
        file_path.push(format!("{}.json", misc_helpers::get_date_time_unix_nano()));
        misc_helpers::json_write_to_file(&events, &file_path).unwrap();

        // Check the events processed
        let vm_meta_data = event_reader.get_vm_meta_data().await;
        let events_processed = event_reader
            .process_events(&wire_server_client, &vm_meta_data)
            .await;
        logger::write(format!("Send {} events from event files", events_processed));
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
