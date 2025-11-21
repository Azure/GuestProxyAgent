// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

//! This module contains the logic to get and update global states.

use crate::result::Result;
use crate::{error::Error, logger::logger_manager, telemetry::event_reader::VmMetaData};
use tokio::sync::{mpsc, oneshot};

pub const SECURE_KEY_GUID: &str = "key_guid";
pub const SECURE_KEY_VALUE: &str = "key_value";

enum GlobalStateAction {
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
}

#[derive(Clone, Debug)]
pub struct GlobalStates(mpsc::Sender<GlobalStateAction>);

impl GlobalStates {
    pub fn start_new() -> Self {
        let (sender, mut receiver) = mpsc::channel(100);
        tokio::spawn(async move {
            let mut vm_meta_data: Option<VmMetaData> = None;
            let mut states: std::collections::HashMap<String, String> =
                std::collections::HashMap::new();
            loop {
                match receiver.recv().await {
                    Some(GlobalStateAction::SetVmMetaData {
                        vm_meta_data: meta_data,
                        response,
                    }) => {
                        vm_meta_data = meta_data.clone();
                        if response.send(()).is_err() {
                            logger_manager::write_warn(format!(
                                "Failed to send response to GlobalStateAction::SetVmMetaData '{meta_data:?}'"
                            ));
                        }
                    }
                    Some(GlobalStateAction::GetVmMetaData { response }) => {
                        if let Err(meta_data) = response.send(vm_meta_data.clone()) {
                            logger_manager::write_warn(format!(
                                "Failed to send response to GlobalStateAction::GetVmMetaData '{meta_data:?}'"
                            ));
                        }
                    }
                    Some(GlobalStateAction::SetState {
                        key,
                        value,
                        response,
                    }) => {
                        states.insert(key.clone(), value.clone());
                        if response.send(()).is_err() {
                            logger_manager::write_warn(format!(
                                "Failed to send response to GlobalStateAction::SetState '{key}':'{value}'"
                            ));
                        }
                    }
                    Some(GlobalStateAction::GetState { key, response }) => {
                        let value = states.get(&key).cloned();
                        if let Err(v) = response.send(value) {
                            logger_manager::write_warn(format!(
                                "Failed to send response to GlobalStateAction::GetState '{key}':'{v:?}'"
                            ));
                        }
                    }
                    None => {
                        break;
                    }
                }
            }
        });

        Self(sender)
    }

    pub async fn set_vm_meta_data(&self, vm_meta_data: Option<VmMetaData>) -> Result<()> {
        let (response, receiver) = oneshot::channel();
        self.0
            .send(GlobalStateAction::SetVmMetaData {
                vm_meta_data,
                response,
            })
            .await
            .map_err(|e| {
                Error::SendError(
                    "GlobalStateAction::SetVmMetaData".to_string(),
                    e.to_string(),
                )
            })?;
        receiver
            .await
            .map_err(|e| Error::RecvError("GlobalStateAction::SetVmMetaData".to_string(), e))
    }

    pub async fn get_vm_meta_data(&self) -> Result<Option<VmMetaData>> {
        let (response, receiver) = oneshot::channel();
        self.0
            .send(GlobalStateAction::GetVmMetaData { response })
            .await
            .map_err(|e| {
                Error::SendError(
                    "GlobalStateAction::GetVmMetaData".to_string(),
                    e.to_string(),
                )
            })?;
        receiver
            .await
            .map_err(|e| Error::RecvError("GlobalStateAction::GetVmMetaData".to_string(), e))
    }

    pub async fn set_state(&self, key: String, value: String) -> Result<()> {
        let (response, receiver) = oneshot::channel();
        self.0
            .send(GlobalStateAction::SetState {
                key,
                value,
                response,
            })
            .await
            .map_err(|e| {
                Error::SendError("GlobalStateAction::SetState".to_string(), e.to_string())
            })?;
        receiver
            .await
            .map_err(|e| Error::RecvError("GlobalStateAction::SetState".to_string(), e))
    }

    pub async fn get_state(&self, key: String) -> Result<Option<String>> {
        let (response, receiver) = oneshot::channel();
        self.0
            .send(GlobalStateAction::GetState { key, response })
            .await
            .map_err(|e| {
                Error::SendError("GlobalStateAction::GetState".to_string(), e.to_string())
            })?;
        receiver
            .await
            .map_err(|e| Error::RecvError("GlobalStateAction::GetState".to_string(), e))
    }
}
