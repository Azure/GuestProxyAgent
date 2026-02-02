// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

//! This module contains the logic to send the telemetry event to the wire server.
use std::time::Duration;

use crate::common_state::{self, CommonState};
use crate::host_clients::imds_client::ImdsClient;
use crate::host_clients::wire_server_client::WireServerClient;
use crate::logger::logger_manager;
use crate::result::Result;
use crate::telemetry::telemetry_event::{
    TelemetryData, TelemetryEvent, TelemetryEventVMData, VmMetaData,
};
use concurrent_queue::ConcurrentQueue;
use once_cell::sync::Lazy;

static TELEMETRY_EVENT_QUEUE: Lazy<ConcurrentQueue<TelemetryEvent>> =
    Lazy::new(|| ConcurrentQueue::<TelemetryEvent>::bounded(1000));

const MAX_MESSAGE_SIZE: usize = 1024 * 64;
const WIRE_SERVER_IP: &str = "168.63.129.16";
const WIRE_SERVER_PORT: u16 = 80u16;
const IMDS_IP: &str = "169.254.169.254";
const IMDS_PORT: u16 = 80u16;

pub struct EventSender {
    common_state: CommonState,
}

impl EventSender {
    pub fn new(common_state: CommonState) -> Self {
        EventSender { common_state }
    }

    pub async fn start(&self, server_ip: Option<&str>, server_port: Option<u16>) {
        logger_manager::write_info("telemetry event sender task started.".to_string());
        let notify = match self.common_state.get_telemetry_event_notify().await {
            Ok(notify) => notify,
            Err(e) => {
                logger_manager::write_err(format!("Failed to get notify: {e}"));
                return;
            }
        };
        let cancellation_token = self.common_state.get_cancellation_token();

        loop {
            tokio::select! {
                _ = cancellation_token.cancelled() => {
                    logger_manager::write_info("telemetry event sender task cancelled.".to_string());
                    // Close the event queue to stop accepting new events
                    TELEMETRY_EVENT_QUEUE.close();
                    break;
                }
                _ = notify.notified() => {
                    self.process_event_queue(server_ip, server_port).await;
                }
            }
        }
    }

    async fn process_event_queue(&self, server_ip: Option<&str>, server_port: Option<u16>) {
        if TELEMETRY_EVENT_QUEUE.is_empty() {
            return;
        }

        let wire_server_client = WireServerClient::new(
            server_ip.unwrap_or(WIRE_SERVER_IP),
            server_port.unwrap_or(WIRE_SERVER_PORT),
        );
        let imds_client = ImdsClient::new(
            server_ip.unwrap_or(IMDS_IP),
            server_port.unwrap_or(IMDS_PORT),
        );
        // refresh vm metadata
        match self
            .update_vm_meta_data(&wire_server_client, &imds_client)
            .await
        {
            Ok(()) => {
                logger_manager::write_info("success updated the vm metadata.".to_string());
            }
            Err(e) => {
                logger_manager::write_warn(format!("Failed to update vm metadata with error {e}."));
            }
        }

        if let Ok(Some(vm_meta_data)) = self.common_state.get_vm_meta_data().await {
            let vm_data = TelemetryEventVMData::new_from_vm_meta_data(&vm_meta_data);
            self.send_events(&wire_server_client, &vm_data).await
        } else {
            logger_manager::write_warn(
                "VmMetaData is not available. Skipping sending telemetry events.".to_string(),
            );
        }
    }

    pub async fn update_vm_meta_data(
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

    async fn send_events(
        &self,
        wire_server_client: &WireServerClient,
        vm_data: &TelemetryEventVMData,
    ) {
        while !TELEMETRY_EVENT_QUEUE.close() && !TELEMETRY_EVENT_QUEUE.is_empty() {
            let mut telemetry_data = TelemetryData::new_with_vm_data(vm_data.clone());
            let mut add_more_events = true;
            while !TELEMETRY_EVENT_QUEUE.is_empty() && add_more_events {
                match TELEMETRY_EVENT_QUEUE.pop() {
                    Ok(event) => {
                        telemetry_data.add_event(event.clone());

                        if telemetry_data.get_size() >= MAX_MESSAGE_SIZE {
                            _ = telemetry_data.remove_last_event(event.clone());
                            if telemetry_data.event_count() == 0 {
                                logger_manager::write_warn(format!(
                                    "Event data too large. Not sending to wire-server. Event: {}.",
                                    event.to_xml_event(vm_data),
                                ));
                            } else if let Err(e) = TELEMETRY_EVENT_QUEUE.push(event) {
                                logger_manager::write_warn(format!(
                                    "Failed to re-enqueue telemetry event with error: {e}"
                                ));
                            }
                            add_more_events = false;
                        }
                    }
                    Err(err) => {
                        logger_manager::write_warn(format!(
                            "Failed to pop telemetry event from queue with error: {err}"
                        ));
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
}

pub(crate) fn enqueue_event(event: TelemetryEvent) {
    if let Err(e) = TELEMETRY_EVENT_QUEUE.push(event) {
        logger_manager::write_warn(format!("Failed to enqueue telemetry event with error: {e}"));
    }
}
