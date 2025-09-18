// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

//! This module contains the logic to interact with the eBPF/redirector.
//! The redirector is used to redirect the traffic to the proxy server.
//! The eBPF is used to filter the traffic and redirect the traffic to the proxy server.
//! The redirector is used to set the local port, get the local port, set the eBPF object, get the eBPF object.
//! Example
//! ```rust
//! use proxy_agent::shared_state::redirector_wrapper::RedirectorSharedState;
//! use proxy_agent::redirector::BpfObject;
//! use std::sync::{Arc, Mutex};
//!
//! let redirector_shared_state = RedirectorSharedState::start_new();
//! let local_port = redirector_shared_state.get_local_port().await.unwrap();
//! redirector_shared_state.set_local_port(80).await.unwrap();
//! let bpf_object = Arc::new(Mutex::new(BpfObject::new()));
//! redirector_shared_state.update_bpf_object(bpf_object.clone()).await.unwrap();
//! let bpf_object = redirector_shared_state.get_bpf_object().await.unwrap().unwrap();
//! ```

use crate::redirector;
use proxy_agent_shared::common::error::Error;
use proxy_agent_shared::common::logger;
use proxy_agent_shared::common::result::Result;
use std::sync::{Arc, Mutex};
use tokio::sync::{mpsc, oneshot};

enum RedirectorAction {
    SetLocalPort {
        local_port: u16,
        response: oneshot::Sender<()>,
    },
    GetLocalPort {
        response: oneshot::Sender<u16>,
    },
    SetBpfObject {
        bpf_object: Option<Arc<Mutex<redirector::BpfObject>>>,
        response: oneshot::Sender<()>,
    },
    GetBpfObject {
        response: oneshot::Sender<Option<Arc<Mutex<redirector::BpfObject>>>>,
    },
}

#[derive(Clone, Debug)]
pub struct RedirectorSharedState(mpsc::Sender<RedirectorAction>);

impl RedirectorSharedState {
    pub fn start_new() -> Self {
        let (tx, mut rx) = mpsc::channel(100);
        tokio::spawn(async move {
            let mut local_port: u16 = 0;
            let mut bpf_object: Option<Arc<Mutex<redirector::BpfObject>>> = None;
            while let Some(action) = rx.recv().await {
                match action {
                    RedirectorAction::SetLocalPort {
                        local_port: new_local_port,
                        response,
                    } => {
                        local_port = new_local_port;
                        if response.send(()).is_err() {
                            logger::write_warning(format!(
                                "Failed to send response to RedirectorAction::SetLocalPort '{new_local_port}'"                                
                            ));
                        }
                    }
                    RedirectorAction::GetLocalPort { response } => {
                        if let Err(port) = response.send(local_port) {
                            logger::write_warning(format!(
                                "Failed to send response to RedirectorAction::GetLocalPort '{port}'"
                            ));
                        }
                    }
                    RedirectorAction::SetBpfObject {
                        bpf_object: new_bpf_object,
                        response,
                    } => {
                        bpf_object = new_bpf_object;
                        if response.send(()).is_err() {
                            logger::write_warning(
                                "Failed to send response to RedirectorAction::SetBpfObject"
                                    .to_string(),
                            );
                        }
                    }
                    RedirectorAction::GetBpfObject { response } => {
                        if response.send(bpf_object.clone()).is_err() {
                            logger::write_warning(
                                "Failed to send response to RedirectorAction::GetBpfObject"
                                    .to_string(),
                            );
                        }
                    }
                }
            }
        });
        RedirectorSharedState(tx)
    }

    pub async fn set_local_port(&self, local_port: u16) -> Result<()> {
        let (response_tx, response_rx) = oneshot::channel();
        self.0
            .send(RedirectorAction::SetLocalPort {
                local_port,
                response: response_tx,
            })
            .await
            .map_err(|e| {
                Error::SendError("RedirectorAction::SetLocalPort".to_string(), e.to_string())
            })?;
        response_rx
            .await
            .map_err(|e| Error::RecvError("RedirectorAction::SetLocalPort".to_string(), e))
    }

    pub async fn get_local_port(&self) -> Result<u16> {
        let (response_tx, response_rx) = oneshot::channel();
        self.0
            .send(RedirectorAction::GetLocalPort {
                response: response_tx,
            })
            .await
            .map_err(|e| {
                Error::SendError("RedirectorAction::GetLocalPort".to_string(), e.to_string())
            })?;
        response_rx
            .await
            .map_err(|e| Error::RecvError("RedirectorAction::GetLocalPort".to_string(), e))
    }

    async fn set_bpf_object(
        &self,
        bpf_object: Option<Arc<Mutex<redirector::BpfObject>>>,
    ) -> Result<()> {
        let (response_tx, response_rx) = oneshot::channel();
        self.0
            .send(RedirectorAction::SetBpfObject {
                bpf_object,
                response: response_tx,
            })
            .await
            .map_err(|e| {
                Error::SendError("RedirectorAction::SetBpfObject".to_string(), e.to_string())
            })?;
        response_rx
            .await
            .map_err(|e| Error::RecvError("RedirectorAction::SetBpfObject".to_string(), e))
    }

    pub async fn update_bpf_object(
        &self,
        bpf_object: Arc<Mutex<redirector::BpfObject>>,
    ) -> Result<()> {
        self.set_bpf_object(Some(bpf_object)).await
    }

    pub async fn clear_bpf_object(&self) -> Result<()> {
        self.set_bpf_object(None).await
    }

    pub async fn get_bpf_object(&self) -> Result<Option<Arc<Mutex<redirector::BpfObject>>>> {
        let (response_tx, response_rx) = oneshot::channel();
        self.0
            .send(RedirectorAction::GetBpfObject {
                response: response_tx,
            })
            .await
            .map_err(|e| {
                Error::SendError("RedirectorAction::GetBpfObject".to_string(), e.to_string())
            })?;
        response_rx
            .await
            .map_err(|e| Error::RecvError("RedirectorAction::GetBpfObject".to_string(), e))
    }
}
