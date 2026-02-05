// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

//! This module contains the logic to send the telemetry event to the wire server.
use std::time::Duration;

use crate::common_state::{self, CommonState};
use crate::host_clients::imds_client::ImdsClient;
use crate::host_clients::wire_server_client::WireServerClient;
use crate::logger::{logger_manager, LoggerLevel};
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
        while !TELEMETRY_EVENT_QUEUE.is_closed() && !TELEMETRY_EVENT_QUEUE.is_empty() {
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

        let event_count = telemetry_data.event_count();
        for _ in [0; 5] {
            match wire_server_client
                .send_telemetry_data(telemetry_data.to_xml())
                .await
            {
                Ok(()) => {
                    logger_manager::write_log(
                        LoggerLevel::Trace,
                        format!("Successfully sent {event_count} telemetry events to wire server."),
                    );
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host_clients::wire_server_client::WireServerClient;
    use crate::telemetry::telemetry_event::{
        TelemetryExtensionEventsEvent, TelemetryGenericLogsEvent, VmMetaData,
    };
    use crate::telemetry::{Event, ExtensionStatusEvent};
    use tokio_util::sync::CancellationToken;

    fn create_test_vm_meta_data() -> VmMetaData {
        VmMetaData {
            container_id: "test-container-id".to_string(),
            tenant_name: "test-tenant".to_string(),
            role_name: "test-role".to_string(),
            role_instance_name: "test-role-instance".to_string(),
            subscription_id: "test-subscription-id".to_string(),
            resource_group_name: "test-resource-group".to_string(),
            vm_id: "test-vm-id".to_string(),
            image_origin: 1,
        }
    }

    fn create_test_event(message: &str) -> TelemetryEvent {
        let event_log = Event::new(
            "Informational".to_string(),
            message.to_string(),
            "test_task".to_string(),
            "test_module".to_string(),
        );
        TelemetryEvent::GenericLogsEvent(TelemetryGenericLogsEvent::from_event_log(
            &event_log,
            "test_execution_mode".to_string(),
            "test_event_name".to_string(),
            Some("1.0.0".to_string()),
        ))
    }

    fn create_test_extension_event() -> TelemetryEvent {
        let extension = crate::telemetry::Extension {
            name: "test_extension".to_string(),
            version: "1.0.0".to_string(),
            is_internal: true,
            extension_type: "test_type".to_string(),
        };
        let operation_status = crate::telemetry::OperationStatus {
            operation_success: true,
            operation: "install".to_string(),
            task_name: "test_task".to_string(),
            message: "Installation successful".to_string(),
            duration: 500,
        };
        let extension_status_event = ExtensionStatusEvent::new(extension, operation_status);
        let telemetry_event = TelemetryExtensionEventsEvent::from_extension_status_event(
            &extension_status_event,
            "production".to_string(),
            "1.0.0".to_string(),
        );
        TelemetryEvent::ExtensionEvent(telemetry_event)
    }

    #[tokio::test]
    async fn test_event_sender_new() {
        let cancellation_token = CancellationToken::new();
        let common_state = CommonState::start_new(cancellation_token);
        let event_sender = EventSender::new(common_state);

        // Verify EventSender was created (common_state is private, so we just check it doesn't panic)
        assert!(std::mem::size_of_val(&event_sender) > 0);
    }

    #[tokio::test]
    async fn test_common_state_vm_meta_data() {
        let cancellation_token = CancellationToken::new();
        let common_state = CommonState::start_new(cancellation_token);

        // Initially should be None
        let vm_meta_data = common_state.get_vm_meta_data().await.unwrap();
        assert!(vm_meta_data.is_none());

        // Set vm_meta_data
        let test_meta_data = create_test_vm_meta_data();
        common_state
            .set_vm_meta_data(Some(test_meta_data))
            .await
            .unwrap();

        // Verify it was set and TelemetryEventVMData conversion works
        let retrieved = common_state.get_vm_meta_data().await.unwrap().unwrap();
        let vm_data = TelemetryEventVMData::new_from_vm_meta_data(&retrieved);

        assert_eq!(vm_data.container_id, "test-container-id");
        assert_eq!(vm_data.tenant_name, "test-tenant");
        assert_eq!(vm_data.role_name, "test-role");
        assert_eq!(vm_data.role_instance_name, "test-role-instance");
        assert_eq!(vm_data.subscription_id, "test-subscription-id");
        assert_eq!(vm_data.resource_group_name, "test-resource-group");
        assert_eq!(vm_data.vm_id, "test-vm-id");
        assert_eq!(vm_data.image_origin, 1);

        // Test notify functionality
        let notify_result = common_state.get_telemetry_event_notify().await;
        assert!(notify_result.is_ok());
        assert!(common_state.notify_telemetry_event().await.is_ok());
    }

    #[test]
    fn test_queue_bounded_capacity() {
        // Create a local bounded queue for testing capacity behavior
        let test_queue: ConcurrentQueue<TelemetryEvent> = ConcurrentQueue::bounded(10);

        // Fill the queue
        for i in 0..10 {
            let event = create_test_event(&format!("Test message {}", i));
            assert!(
                test_queue.push(event).is_ok(),
                "Should be able to push event {}",
                i
            );
        }

        // Queue should be full now
        assert!(test_queue.is_full(), "Queue should be full after 10 pushes");

        // Try to push one more - should fail
        let extra_event = create_test_event("Extra event");
        assert!(
            test_queue.push(extra_event).is_err(),
            "Push should fail when queue is full"
        );
    }

    #[test]
    fn test_telemetry_event_xml_format() {
        let vm_meta_data = create_test_vm_meta_data();
        let vm_data = TelemetryEventVMData::new_from_vm_meta_data(&vm_meta_data);

        // Test single event XML
        let event = create_test_event("Test XML message");
        let event_xml = event.to_xml_event(&vm_data);
        assert!(event_xml.contains("<Event id=\"7\">"));
        assert!(event_xml.contains("<![CDATA["));
        assert!(event_xml.contains("]]></Event>"));
        assert!(event_xml.contains("TenantName"));
        assert!(event_xml.contains("test-tenant"));

        // Test provider ID
        assert_eq!(
            event.get_provider_id(),
            "FFF0196F-EE4C-4EAF-9AA5-776F622DEB4F"
        );

        // Test full TelemetryData XML structure
        let mut telemetry_data = TelemetryData::new_with_vm_data(vm_data);
        telemetry_data.add_event(event);
        let xml = telemetry_data.to_xml();

        assert!(xml.starts_with("<?xml version=\"1.0\"?>"));
        assert!(xml.contains("<TelemetryData version=\"1.0\">"));
        assert!(xml.contains("</TelemetryData>"));
        assert!(xml.contains("<Provider id=\"FFF0196F-EE4C-4EAF-9AA5-776F622DEB4F\">"));
        assert!(xml.contains("</Provider>"));
    }

    #[test]
    fn test_extension_event_xml_format() {
        let vm_meta_data = create_test_vm_meta_data();
        let vm_data = TelemetryEventVMData::new_from_vm_meta_data(&vm_meta_data);

        // Test extension event XML
        let event = create_test_extension_event();
        let event_xml = event.to_xml_event(&vm_data);
        assert!(event_xml.contains("<Event id=\"1\">"));
        assert!(event_xml.contains("<![CDATA["));
        assert!(event_xml.contains("]]></Event>"));
        assert!(event_xml.contains("ExtensionType"));
        assert!(event_xml.contains("test_type"));
        assert!(event_xml.contains("Name"));
        assert!(event_xml.contains("test_extension"));

        // Test provider ID for extension events
        assert_eq!(
            event.get_provider_id(),
            "69B669B9-4AF8-4C50-BDC4-6006FA76E975"
        );

        // Test TelemetryData with extension event
        let mut telemetry_data = TelemetryData::new_with_vm_data(vm_data);
        telemetry_data.add_event(event);
        let xml = telemetry_data.to_xml();
        assert!(xml.contains("<Provider id=\"69B669B9-4AF8-4C50-BDC4-6006FA76E975\">"));
    }

    #[test]
    fn test_mixed_events_xml_format() {
        let vm_meta_data = create_test_vm_meta_data();
        let vm_data = TelemetryEventVMData::new_from_vm_meta_data(&vm_meta_data);

        let mut telemetry_data = TelemetryData::new_with_vm_data(vm_data);

        // Add generic logs event
        let generic_event = create_test_event("Test generic message");
        telemetry_data.add_event(generic_event);

        // Add extension event
        let extension_event = create_test_extension_event();
        telemetry_data.add_event(extension_event);

        assert_eq!(telemetry_data.event_count(), 2);

        let xml = telemetry_data.to_xml();

        // Verify both providers are present
        assert!(xml.contains("<Provider id=\"FFF0196F-EE4C-4EAF-9AA5-776F622DEB4F\">"));
        assert!(xml.contains("<Provider id=\"69B669B9-4AF8-4C50-BDC4-6006FA76E975\">"));
        assert!(xml.contains("<Event id=\"7\">")); // Generic logs event
        assert!(xml.contains("<Event id=\"1\">")); // Extension event
    }

    #[test]
    fn test_queue_with_extension_events() {
        // Create a local bounded queue for testing
        let test_queue: ConcurrentQueue<TelemetryEvent> = ConcurrentQueue::bounded(10);

        // Add generic and extension events
        let generic_event = create_test_event("Generic message");
        let extension_event = create_test_extension_event();

        assert!(test_queue.push(generic_event.clone()).is_ok());
        assert!(test_queue.push(extension_event.clone()).is_ok());

        assert_eq!(test_queue.len(), 2);

        // Verify FIFO order and event types
        let popped1 = test_queue.pop();
        assert!(popped1.is_ok());
        assert_eq!(
            popped1.unwrap().get_provider_id(),
            "FFF0196F-EE4C-4EAF-9AA5-776F622DEB4F"
        );

        let popped2 = test_queue.pop();
        assert!(popped2.is_ok());
        assert_eq!(
            popped2.unwrap().get_provider_id(),
            "69B669B9-4AF8-4C50-BDC4-6006FA76E975"
        );

        assert!(test_queue.is_empty());
    }

    #[tokio::test]
    async fn test_update_vm_meta_data_with_mock_server() {
        let ip = "127.0.0.1";
        let port = 7072u16;

        let cancellation_token = CancellationToken::new();
        let common_state = CommonState::start_new(cancellation_token.clone());
        let event_sender = EventSender::new(common_state.clone());

        // Start mock server
        tokio::spawn(crate::server_mock::start(
            ip.to_string(),
            port,
            cancellation_token.clone(),
        ));
        tokio::time::sleep(Duration::from_millis(100)).await;

        let wire_server_client = WireServerClient::new(ip, port);
        let imds_client = ImdsClient::new(ip, port);

        // Initially vm_meta_data should be None
        let vm_meta_data = common_state.get_vm_meta_data().await.unwrap();
        assert!(vm_meta_data.is_none());

        // Update vm_meta_data
        let result = event_sender
            .update_vm_meta_data(&wire_server_client, &imds_client)
            .await;
        assert!(result.is_ok(), "update_vm_meta_data should succeed");

        // Verify vm_meta_data was set
        let vm_meta_data = common_state.get_vm_meta_data().await.unwrap();
        assert!(vm_meta_data.is_some(), "vm_meta_data should be set");

        let vm_data = vm_meta_data.unwrap();
        // Values come from mock server responses
        assert!(!vm_data.container_id.is_empty());
        assert!(!vm_data.role_name.is_empty());

        cancellation_token.cancel();
    }

    /// Consolidated test for all TELEMETRY_EVENT_QUEUE and wire server operations.
    /// This test must run in a single test function because the global static queue
    /// cannot be reopened once closed. The test covers:
    /// 1. Enqueue events and verify FIFO order
    /// 2. Process empty queue
    /// 3. Send data to wire server (empty and with events)
    /// 4. Enqueue and process events with mock server
    /// 5. EventSender lifecycle (cancellation) - must be last as it closes the queue
    #[tokio::test]
    async fn test_telemetry_event_queue_operations() {
        // ===== Part 1: Test enqueue and FIFO order =====
        // Clear the queue first
        while TELEMETRY_EVENT_QUEUE.pop().is_ok() {}

        // Mock server details
        let ip = "127.0.0.1";
        let port = 7071u16;

        // Create EventSender
        let cancellation_token = CancellationToken::new();
        let process_common_state = CommonState::start_new(cancellation_token.clone());
        let event_sender = EventSender::new(process_common_state.clone());

        // Enqueue events
        let event1 = create_test_event("Test message 1");
        let event2 = create_test_event("Test message 2");
        let event3 = create_test_event("Test message 3");

        enqueue_event(event1.clone());
        assert!(
            !TELEMETRY_EVENT_QUEUE.is_empty(),
            "Queue should not be empty after enqueue"
        );

        enqueue_event(event2.clone());
        enqueue_event(event3.clone());
        assert_eq!(TELEMETRY_EVENT_QUEUE.len(), 3, "Queue should have 3 events");

        // Verify FIFO order
        assert!(TELEMETRY_EVENT_QUEUE.pop().unwrap() == event1);
        assert!(TELEMETRY_EVENT_QUEUE.pop().unwrap() == event2);
        assert!(TELEMETRY_EVENT_QUEUE.pop().unwrap() == event3);
        assert!(TELEMETRY_EVENT_QUEUE.is_empty());

        // ===== Part 2: Test process empty queue - should return without error =====
        event_sender.process_event_queue(None, None).await;
        assert!(TELEMETRY_EVENT_QUEUE.is_empty());

        // ===== Part 3: Test enqueue mixed events (generic and extension) =====
        let generic_event = create_test_event("Generic event for queue");
        let extension_event = create_test_extension_event();

        enqueue_event(generic_event);
        enqueue_event(extension_event);
        assert_eq!(
            TELEMETRY_EVENT_QUEUE.len(),
            2,
            "Queue should have 2 mixed events"
        );

        // Clear for next test
        while TELEMETRY_EVENT_QUEUE.pop().is_ok() {}

        // ===== Part 4: Test enqueue and process with mock server =====
        // Enqueue events
        let event_a = create_test_event("Test event A for processing");
        let event_b = create_test_event("Test event B for processing");
        let event_c = create_test_event("Test event C for processing");

        enqueue_event(event_a);
        enqueue_event(event_b);
        enqueue_event(event_c);
        assert_eq!(
            TELEMETRY_EVENT_QUEUE.len(),
            3,
            "Queue should have 3 events after enqueue"
        );

        // Start the event sender in a separate task
        let handle = tokio::spawn(async move {
            event_sender.start(Some(ip), Some(port)).await;
        });

        // Give it a moment to start event sender task
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Notify to process events
        process_common_state.notify_telemetry_event().await.unwrap();

        // Give it a moment to process the events while the VM data is still not set as Mock server not started yet
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            TELEMETRY_EVENT_QUEUE.len(),
            3,
            "Queue should have 3 events after notify_telemetry_event but without VM data"
        );

        // Start mock server to respond to goalstate and shared config requests
        tokio::spawn(crate::server_mock::start(
            ip.to_string(),
            port,
            cancellation_token.clone(),
        ));
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Notify again to process events now that VM data can be retrieved
        process_common_state.notify_telemetry_event().await.unwrap();

        // Give it a moment to process the events (needs enough time for HTTP requests)
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Verify queue is empty after processing
        assert_eq!(
            TELEMETRY_EVENT_QUEUE.len(),
            0,
            "Queue should be empty after processing"
        );

        // Verify queue is NOT closed after processing
        assert!(
            !TELEMETRY_EVENT_QUEUE.is_closed(),
            "Queue should not be closed after processing"
        );

        // ===== Part 5: Test send_data_to_wire_server =====
        let wire_server_client = WireServerClient::new(ip, port);
        let vm_meta_data = create_test_vm_meta_data();
        let vm_data = TelemetryEventVMData::new_from_vm_meta_data(&vm_meta_data);

        // Test sending empty data - should return early without error
        let empty_data = TelemetryData::new_with_vm_data(vm_data.clone());
        assert_eq!(empty_data.event_count(), 0);
        EventSender::send_data_to_wire_server(empty_data, &wire_server_client).await;

        // Test sending data with events
        let mut telemetry_data = TelemetryData::new_with_vm_data(vm_data.clone());
        telemetry_data.add_event(create_test_event("Test event 1"));
        telemetry_data.add_event(create_test_event("Test event 2"));
        assert_eq!(telemetry_data.event_count(), 2);
        EventSender::send_data_to_wire_server(telemetry_data, &wire_server_client).await;

        // Test sending data with mixed events
        let mut mixed_data = TelemetryData::new_with_vm_data(vm_data);
        mixed_data.add_event(create_test_event("Generic event"));
        mixed_data.add_event(create_test_extension_event());
        assert_eq!(mixed_data.event_count(), 2);
        EventSender::send_data_to_wire_server(mixed_data, &wire_server_client).await;

        // ===== Part 6: Test EventSender lifecycle (cancellation) =====
        // This MUST be last as it closes the queue permanently

        // Cancel the token - this will close the queue, stop the event sender task and stop mock server
        process_common_state.cancel_cancellation_token();

        // Wait for the task to complete
        let result = tokio::time::timeout(Duration::from_secs(2), handle).await;
        assert!(result.is_ok(), "Event sender should stop when cancelled");

        // Verify queue is now closed
        assert!(
            TELEMETRY_EVENT_QUEUE.is_closed(),
            "Queue should be closed after cancellation"
        );
    }
}
