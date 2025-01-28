// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

//! This module contains the logic to interact with the provision state of the GPA service.
//! The provision state is a bit field, which is used to store the provision state of the GPA service.
//! It contains the provision state, event log threads initialized, and provision finished.
//!
//! Example
//! ```rust
//! use proxy_agent::shared_state::provision_wrapper::ProvisionSharedState;
//! use proxy_agent::provision::ProvisionFlags;
//!
//! let provision_shared_state = ProvisionSharedState::start_new();
//! let state = ProvisionFlags::REDIRECTOR_READY|ProvisionFlags::PROXY_SERVER_READY;
//! let updated_state = provision_shared_state.update_one_state(state).await.unwrap();
//! assert_eq!(updated_state, state);
//! let reset_state = provision_shared_state.reset_one_state(ProvisionFlags::REDIRECTOR_READY).await.unwrap();
//! assert_eq!(reset_state, ProvisionFlags::PROXY_SERVER_READY);
//! let get_state = provision_shared_state.get_state().await.unwrap();
//! let set_event_log_threads_initialized = provision_shared_state.set_event_log_threads_initialized().await.unwrap();
//! let get_event_log_threads_initialized = provision_shared_state.get_event_log_threads_initialized().await.unwrap();
//! assert_eq!(get_event_log_threads_initialized, true);
//! let set_provision_finished = provision_shared_state.set_provision_finished(true).await.unwrap();
//! let get_provision_finished = provision_shared_state.get_provision_finished().await.unwrap();
//! assert_eq!(get_provision_finished, true);
//! let _= provision_shared_state.set_provision_finished(false).await.unwrap();
//! let get_provision_finished = provision_shared_state.get_provision_finished().await.unwrap();
//! assert_eq!(get_provision_finished, false);
//! ```

use crate::common::error::Error;
use crate::common::logger;
use crate::common::result::Result;
use crate::provision::ProvisionFlags;
use tokio::sync::{mpsc, oneshot};

enum ProvisionAction {
    UpdateState {
        state: ProvisionFlags,
        response: oneshot::Sender<ProvisionFlags>,
    },
    ResetState {
        state: ProvisionFlags,
        response: oneshot::Sender<ProvisionFlags>,
    },
    GetState {
        response: oneshot::Sender<ProvisionFlags>,
    },
    SetEventLogThreadsInitialized {
        response: oneshot::Sender<()>,
    },
    GetEventLogsThreadsInitialized {
        response: oneshot::Sender<bool>,
    },
    SetProvisionFinished {
        finished: bool,
        response: oneshot::Sender<bool>,
    },
    GetProvisionFinished {
        response: oneshot::Sender<bool>,
    },
}

#[derive(Clone, Debug)]
pub struct ProvisionSharedState(mpsc::Sender<ProvisionAction>);

impl ProvisionSharedState {
    pub fn start_new() -> Self {
        let (tx, mut rx) = mpsc::channel(100);
        tokio::spawn(async move {
            // The provision state, it is a bitflag field
            let mut provision_state: ProvisionFlags = ProvisionFlags::NONE;
            // The flag to indicate if the event log threads are initialized
            let mut provision_event_log_threads_initialized: bool = false;
            // The flag to indicate if the GPA service provision is finished
            let mut provision_finished: bool = false;
            while let Some(action) = rx.recv().await {
                match action {
                    ProvisionAction::UpdateState { state, response } => {
                        provision_state |= state;
                        if let Err(new_state) = response.send(provision_state.clone()) {
                            logger::write_warning(format!(
                                "Failed to send response to ProvisionAction::UpdateState with new state '{:?}'",
                                new_state
                            ));
                        }
                    }
                    ProvisionAction::ResetState { state, response } => {
                        provision_state &= !state;
                        if let Err(new_state) = response.send(provision_state.clone()) {
                            logger::write_warning(format!(
                                "Failed to send response to ProvisionAction::ResetState with new state '{:?}'",
                                new_state
                            ));
                        }
                    }
                    ProvisionAction::GetState { response } => {
                        if let Err(state) = response.send(provision_state.clone()) {
                            logger::write_warning(format!(
                                "Failed to send response to ProvisionAction::GetState with state '{:?}'",
                                state
                            ));
                        }
                    }
                    ProvisionAction::SetEventLogThreadsInitialized { response } => {
                        provision_event_log_threads_initialized = true;
                        if response.send(()).is_err() {
                            logger::write_warning("Failed to send response to ProvisionAction::SetEventLogThreadsInitialized".to_string());
                        }
                    }
                    ProvisionAction::GetEventLogsThreadsInitialized { response } => {
                        if let Err(initialized) =
                            response.send(provision_event_log_threads_initialized)
                        {
                            logger::write_warning(format!(
                                "Failed to send response to ProvisionAction::GetEventLogsThreadsInitialized with initialized '{:?}'",
                                initialized
                            ));
                        }
                    }
                    ProvisionAction::SetProvisionFinished { finished, response } => {
                        provision_finished = finished;
                        if response.send(finished).is_err() {
                            logger::write_warning(
                                "Failed to send response to ProvisionAction::SetProvisionFinished"
                                    .to_string(),
                            );
                        }
                    }
                    ProvisionAction::GetProvisionFinished { response } => {
                        if let Err(finished) = response.send(provision_finished) {
                            logger::write_warning(format!(
                                "Failed to send response to ProvisionAction::GetProvisionFinished with finished '{:?}'",
                                finished
                            ));
                        }
                    }
                }
            }
        });

        ProvisionSharedState(tx)
    }

    /// Update the one of the provision state
    /// # Arguments
    /// * `state` - ProvisionFlags
    /// # Returns
    /// * `ProvisionFlags` - the updated provision state
    /// # Errors - SendError, RecvError
    /// # Remarks
    /// * The provision state is a bit field, the state is updated by OR operation
    pub async fn update_one_state(&self, state: ProvisionFlags) -> Result<ProvisionFlags> {
        let (tx, rx) = oneshot::channel();
        self.0
            .send(ProvisionAction::UpdateState {
                state,
                response: tx,
            })
            .await
            .map_err(|e| {
                Error::SendError("ProvisionAction::UpdateState".to_string(), e.to_string())
            })?;
        rx.await
            .map_err(|e| Error::RecvError("ProvisionAction::UpdateState".to_string(), e))
    }

    /// Reset the provision state
    /// # Arguments
    /// * `state` - ProvisionFlags to reset/remove from the provision state
    /// # Returns
    /// * `ProvisionFlags` - the updated provision state
    /// # Errors - SendError, RecvError
    /// # Remarks
    /// * The provision state is a bit field, the state is updated by AND & NOT operation
    pub async fn reset_one_state(&self, state: ProvisionFlags) -> Result<ProvisionFlags> {
        let (tx, rx) = oneshot::channel();
        self.0
            .send(ProvisionAction::ResetState {
                state,
                response: tx,
            })
            .await
            .map_err(|e| {
                Error::SendError("ProvisionAction::ResetState".to_string(), e.to_string())
            })?;
        rx.await
            .map_err(|e| Error::RecvError("ProvisionAction::ResetState".to_string(), e))
    }

    pub async fn get_state(&self) -> Result<ProvisionFlags> {
        let (tx, rx) = oneshot::channel();
        self.0
            .send(ProvisionAction::GetState { response: tx })
            .await
            .map_err(|e| {
                Error::SendError("ProvisionAction::GetState".to_string(), e.to_string())
            })?;
        rx.await
            .map_err(|e| Error::RecvError("ProvisionAction::GetState".to_string(), e))
    }

    pub async fn set_event_log_threads_initialized(&self) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.0
            .send(ProvisionAction::SetEventLogThreadsInitialized { response: tx })
            .await
            .map_err(|e| {
                Error::SendError(
                    "ProvisionAction::SetEventLogThreadsInitialized".to_string(),
                    e.to_string(),
                )
            })?;
        rx.await.map_err(|e| {
            Error::RecvError(
                "ProvisionAction::SetEventLogThreadsInitialized".to_string(),
                e,
            )
        })
    }

    pub async fn get_event_log_threads_initialized(&self) -> Result<bool> {
        let (tx, rx) = oneshot::channel();
        self.0
            .send(ProvisionAction::GetEventLogsThreadsInitialized { response: tx })
            .await
            .map_err(|e| {
                Error::SendError(
                    "ProvisionAction::GetEventLogsThreadsInitialized".to_string(),
                    e.to_string(),
                )
            })?;
        rx.await.map_err(|e| {
            Error::RecvError(
                "ProvisionAction::GetEventLogsThreadsInitialized".to_string(),
                e,
            )
        })
    }

    pub async fn set_provision_finished(&self, finished: bool) -> Result<bool> {
        let (tx, rx) = oneshot::channel();
        self.0
            .send(ProvisionAction::SetProvisionFinished {
                finished,
                response: tx,
            })
            .await
            .map_err(|e| {
                Error::SendError(
                    "ProvisionAction::SetProvisionFinished".to_string(),
                    e.to_string(),
                )
            })?;
        rx.await
            .map_err(|e| Error::RecvError("ProvisionAction::SetProvisionFinished".to_string(), e))
    }

    pub async fn get_provision_finished(&self) -> Result<bool> {
        let (tx, rx) = oneshot::channel();
        self.0
            .send(ProvisionAction::GetProvisionFinished { response: tx })
            .await
            .map_err(|e| {
                Error::SendError(
                    "ProvisionAction::GetProvisionFinished".to_string(),
                    e.to_string(),
                )
            })?;
        rx.await
            .map_err(|e| Error::RecvError("ProvisionAction::GetProvisionFinished".to_string(), e))
    }
}
