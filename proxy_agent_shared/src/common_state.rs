// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

//! This module contains the logic to get and update common states.

use crate::host_clients::imds_client::ImdsClient;
use crate::host_clients::wire_server_client::WireServerClient;
use crate::result::Result;
use crate::{error::Error, logger::logger_manager, telemetry::telemetry_event::VmMetaData};
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot, Notify};
use tokio_util::sync::CancellationToken;

pub const SECURE_KEY_GUID: &str = "key_guid";
pub const SECURE_KEY_VALUE: &str = "key_value";

enum CommonStateAction {
    SetVmMetaData {
        vm_meta_data: Option<VmMetaData>,
        response: oneshot::Sender<()>,
    },
    GetVmMetaData {
        response: oneshot::Sender<Option<VmMetaData>>,
    },
    SetState {
        key: String,
        value: String,
        response: oneshot::Sender<()>,
    },
    GetState {
        key: String,
        response: oneshot::Sender<Option<String>>,
    },
    GetTelemetryEventNotify {
        response: oneshot::Sender<Arc<Notify>>,
    },
}

#[derive(Clone, Debug)]
pub struct CommonState {
    /// The cancellation token is used to cancel the agent when the agent is stopped
    cancellation_token: CancellationToken,
    sender: mpsc::Sender<CommonStateAction>,
}

impl CommonState {
    pub fn start_new(cancellation_token: CancellationToken) -> Self {
        let (sender, mut receiver) = mpsc::channel(100);
        tokio::spawn(async move {
            let mut vm_meta_data: Option<VmMetaData> = None;
            let mut states: std::collections::HashMap<String, String> =
                std::collections::HashMap::new();
            let telemetry_event_notify = Arc::new(Notify::new());

            loop {
                match receiver.recv().await {
                    Some(CommonStateAction::SetVmMetaData {
                        vm_meta_data: meta_data,
                        response,
                    }) => {
                        vm_meta_data = meta_data.clone();
                        if response.send(()).is_err() {
                            logger_manager::write_warn(format!(
                                "Failed to send response to CommonStateAction::SetVmMetaData '{meta_data:?}'"
                            ));
                        }
                    }
                    Some(CommonStateAction::GetVmMetaData { response }) => {
                        if let Err(meta_data) = response.send(vm_meta_data.clone()) {
                            logger_manager::write_warn(format!(
                                "Failed to send response to CommonStateAction::GetVmMetaData '{meta_data:?}'"
                            ));
                        }
                    }
                    Some(CommonStateAction::SetState {
                        key,
                        value,
                        response,
                    }) => {
                        states.insert(key.clone(), value.clone());
                        if response.send(()).is_err() {
                            logger_manager::write_warn(format!(
                                "Failed to send response to CommonStateAction::SetState '{key}':'{value}'"
                            ));
                        }
                    }
                    Some(CommonStateAction::GetState { key, response }) => {
                        let value = states.get(&key).cloned();
                        if let Err(v) = response.send(value) {
                            logger_manager::write_warn(format!(
                                "Failed to send response to CommonStateAction::GetState '{key}':'{v:?}'"
                            ));
                        }
                    }
                    Some(CommonStateAction::GetTelemetryEventNotify { response }) => {
                        if let Err(notify) = response.send(telemetry_event_notify.clone()) {
                            logger_manager::write_warn(format!(
                                "Failed to send response to CommonStateAction::GetTelemetryEventNotify '{notify:?}'"
                            ));
                        }
                    }
                    None => {
                        break;
                    }
                }
            }
        });

        Self {
            cancellation_token,
            sender,
        }
    }

    /// Update the VM metadata based on the provided clients.
    pub async fn update_vm_meta_data(
        &self,
        wire_server_client: &WireServerClient,
        imds_client: &ImdsClient,
    ) -> Result<()> {
        use crate::common_state;

        let guid = self
            .get_state(common_state::SECURE_KEY_GUID.to_string())
            .await
            .unwrap_or(None);
        let key = self
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

        self.set_vm_meta_data(Some(vm_meta_data)).await?;

        Ok(())
    }

    pub async fn set_vm_meta_data(&self, vm_meta_data: Option<VmMetaData>) -> Result<()> {
        let (response, receiver) = oneshot::channel();
        self.sender
            .send(CommonStateAction::SetVmMetaData {
                vm_meta_data,
                response,
            })
            .await
            .map_err(|e| {
                Error::SendError(
                    "CommonStateAction::SetVmMetaData".to_string(),
                    e.to_string(),
                )
            })?;
        receiver
            .await
            .map_err(|e| Error::RecvError("CommonStateAction::SetVmMetaData".to_string(), e))
    }

    pub async fn get_vm_meta_data(&self) -> Result<Option<VmMetaData>> {
        let (response, receiver) = oneshot::channel();
        self.sender
            .send(CommonStateAction::GetVmMetaData { response })
            .await
            .map_err(|e| {
                Error::SendError(
                    "CommonStateAction::GetVmMetaData".to_string(),
                    e.to_string(),
                )
            })?;
        receiver
            .await
            .map_err(|e| Error::RecvError("CommonStateAction::GetVmMetaData".to_string(), e))
    }

    pub async fn set_state(&self, key: String, value: String) -> Result<()> {
        let (response, receiver) = oneshot::channel();
        self.sender
            .send(CommonStateAction::SetState {
                key,
                value,
                response,
            })
            .await
            .map_err(|e| {
                Error::SendError("CommonStateAction::SetState".to_string(), e.to_string())
            })?;
        receiver
            .await
            .map_err(|e| Error::RecvError("CommonStateAction::SetState".to_string(), e))
    }

    pub async fn get_state(&self, key: String) -> Result<Option<String>> {
        let (response, receiver) = oneshot::channel();
        self.sender
            .send(CommonStateAction::GetState { key, response })
            .await
            .map_err(|e| {
                Error::SendError("CommonStateAction::GetState".to_string(), e.to_string())
            })?;
        receiver
            .await
            .map_err(|e| Error::RecvError("CommonStateAction::GetState".to_string(), e))
    }

    pub async fn get_telemetry_event_notify(&self) -> Result<Arc<Notify>> {
        let (response, receiver) = oneshot::channel();
        self.sender
            .send(CommonStateAction::GetTelemetryEventNotify { response })
            .await
            .map_err(|e| {
                Error::SendError(
                    "CommonStateAction::GetTelemetryEventNotify".to_string(),
                    e.to_string(),
                )
            })?;
        receiver.await.map_err(|e| {
            Error::RecvError("CommonStateAction::GetTelemetryEventNotify".to_string(), e)
        })
    }

    pub async fn notify_telemetry_event(&self) -> Result<()> {
        let notify = self.get_telemetry_event_notify().await?;
        notify.notify_one();
        Ok(())
    }

    pub fn get_cancellation_token(&self) -> CancellationToken {
        self.cancellation_token.clone()
    }

    pub fn cancel_cancellation_token(&self) {
        self.cancellation_token.cancel();
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[tokio::test]
    async fn test_common_state_key_value_operations() {
        let cancellation_token = CancellationToken::new();
        let common_state = CommonState::start_new(cancellation_token);

        // Get non-existent key should return None
        let value = common_state
            .get_state("non_existent_key".to_string())
            .await
            .unwrap();
        assert!(value.is_none(), "Non-existent key should return None");

        // Set and get a key-value pair
        common_state
            .set_state(SECURE_KEY_GUID.to_string(), "test-guid-value".to_string())
            .await
            .unwrap();
        let value = common_state
            .get_state(SECURE_KEY_GUID.to_string())
            .await
            .unwrap();
        assert_eq!(value, Some("test-guid-value".to_string()));

        // Set and get another key-value pair
        common_state
            .set_state(SECURE_KEY_VALUE.to_string(), "test-key-value".to_string())
            .await
            .unwrap();
        let value = common_state
            .get_state(SECURE_KEY_VALUE.to_string())
            .await
            .unwrap();
        assert_eq!(value, Some("test-key-value".to_string()));

        // Update existing key
        common_state
            .set_state(
                SECURE_KEY_GUID.to_string(),
                "updated-guid-value".to_string(),
            )
            .await
            .unwrap();
        let value = common_state
            .get_state(SECURE_KEY_GUID.to_string())
            .await
            .unwrap();
        assert_eq!(value, Some("updated-guid-value".to_string()));

        // First key should still have its value
        let value = common_state
            .get_state(SECURE_KEY_VALUE.to_string())
            .await
            .unwrap();
        assert_eq!(value, Some("test-key-value".to_string()));
    }

    #[tokio::test]
    async fn test_common_state_multiple_operations() {
        let cancellation_token = CancellationToken::new();
        let common_state = CommonState::start_new(cancellation_token);

        // Perform multiple operations in sequence
        for i in 0..10 {
            let key = format!("key_{}", i);
            let value = format!("value_{}", i);
            common_state
                .set_state(key.clone(), value.clone())
                .await
                .unwrap();
            let retrieved = common_state.get_state(key).await.unwrap();
            assert_eq!(retrieved, Some(value));
        }

        // Verify all values are still accessible
        for i in 0..10 {
            let key = format!("key_{}", i);
            let expected_value = format!("value_{}", i);
            let retrieved = common_state.get_state(key).await.unwrap();
            assert_eq!(retrieved, Some(expected_value));
        }
    }

    #[tokio::test]
    async fn test_update_vm_meta_data_with_mock_server() {
        use crate::server_mock;

        let ip = "127.0.0.1";
        let port = 9073u16;

        let cancellation_token = CancellationToken::new();
        let common_state = CommonState::start_new(cancellation_token.clone());

        let port = server_mock::start(ip.to_string(), port, cancellation_token.clone())
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        let wire_server_client = WireServerClient::new(ip, port);
        let imds_client = ImdsClient::new(ip, port);

        // Initially vm_meta_data should be None
        let vm_meta_data = common_state.get_vm_meta_data().await.unwrap();
        assert!(vm_meta_data.is_none());

        // Update vm_meta_data
        let result = common_state
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
}
