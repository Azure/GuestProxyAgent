// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

//! This module contains the logic to interact with the proxy agent status.
//! The proxy agent status contains the 'state' and 'status message' of the key keeper, telemetry reader, telemetry logger, redirector, and proxy server modules.
//! The proxy agent status contains the 'connection count' of the proxy server.

use crate::common::error::Error;
use crate::common::logger;
use crate::common::result::Result;
use proxy_agent_shared::logger::LoggerLevel;
use proxy_agent_shared::proxy_agent_aggregate_status::{ModuleState, ProxyAgentDetailStatus};
use proxy_agent_shared::telemetry::event_logger;
use tokio::sync::{mpsc, oneshot};

const MAX_STATUS_MESSAGE_LENGTH: usize = 1024;

enum AgentStatusAction {
    SetStatusMessage {
        message: String,
        module: AgentStatusModule,
        response: oneshot::Sender<bool>,
    },
    GetStatusMessage {
        module: AgentStatusModule,
        response: oneshot::Sender<String>,
    },
    SetState {
        state: ModuleState,
        module: AgentStatusModule,
        response: oneshot::Sender<ModuleState>,
    },
    GetState {
        module: AgentStatusModule,
        response: oneshot::Sender<ModuleState>,
    },
    GetConnectionCount {
        response: oneshot::Sender<u128>,
    },
    IncreaseConnectionCount {
        response: oneshot::Sender<u128>,
    },
    IncreaseTcpConnectionCount {
        response: oneshot::Sender<u128>,
    },
}

#[derive(Clone, Debug)]
pub enum AgentStatusModule {
    KeyKeeper,
    TelemetryReader,
    TelemetryLogger,
    Redirector,
    ProxyServer,
    ProxyAgentStatus,
}

#[derive(Clone, Debug)]
pub struct AgentStatusSharedState(mpsc::Sender<AgentStatusAction>);

impl AgentStatusSharedState {
    pub fn start_new() -> Self {
        let (tx, mut rx) = mpsc::channel(100);
        tokio::spawn(async move {
            let mut key_keeper_state: ModuleState = ModuleState::UNKNOWN;
            let mut key_keeper_status_message: String = super::UNKNOWN_STATUS_MESSAGE.to_string();
            let mut telemetry_reader_state = ModuleState::UNKNOWN;
            let mut telemetry_logger_state = ModuleState::UNKNOWN;
            let mut telemetry_reader_status_message = super::UNKNOWN_STATUS_MESSAGE.to_string();
            let mut telemetry_logger_status_message = super::UNKNOWN_STATUS_MESSAGE.to_string();
            let mut redirector_state = ModuleState::UNKNOWN;
            let mut redirector_status_message = super::UNKNOWN_STATUS_MESSAGE.to_string();
            let mut proxy_server_state = ModuleState::UNKNOWN;
            let mut proxy_server_status_message = super::UNKNOWN_STATUS_MESSAGE.to_string();
            let mut proxy_agent_status_state = ModuleState::UNKNOWN;
            let mut proxy_agent_status_message = super::UNKNOWN_STATUS_MESSAGE.to_string();

            // The proxied connection count for the listener
            let mut tcp_connection_count: u128 = 0;
            let mut http_connection_count: u128 = 0;

            while let Some(action) = rx.recv().await {
                match action {
                    AgentStatusAction::SetStatusMessage {
                        message,
                        module,
                        response,
                    } => {
                        let mut updated = true;
                        match module {
                            AgentStatusModule::KeyKeeper => {
                                if key_keeper_status_message == message {
                                    updated = false;
                                } else {
                                    key_keeper_status_message = message;
                                }
                            }
                            AgentStatusModule::TelemetryReader => {
                                if telemetry_reader_status_message == message {
                                    updated = false;
                                } else {
                                    telemetry_reader_status_message = message;
                                }
                            }
                            AgentStatusModule::TelemetryLogger => {
                                if telemetry_logger_status_message == message {
                                    updated = false;
                                } else {
                                    telemetry_logger_status_message = message;
                                }
                            }
                            AgentStatusModule::Redirector => {
                                if redirector_status_message == message {
                                    updated = false;
                                } else {
                                    redirector_status_message = message;
                                }
                            }
                            AgentStatusModule::ProxyServer => {
                                if proxy_server_status_message == message {
                                    updated = false;
                                } else {
                                    proxy_server_status_message = message;
                                }
                            }
                            AgentStatusModule::ProxyAgentStatus => {
                                if proxy_agent_status_message == message {
                                    updated = false;
                                } else {
                                    proxy_agent_status_message = message;
                                }
                            }
                        }
                        if response.send(updated).is_err() {
                            logger::write_warning(format!("Failed to send response to AgentStatusAction::SetStatusMessage for module {module:?}"));
                        }
                    }
                    AgentStatusAction::GetStatusMessage { module, response } => {
                        let message = match module {
                            AgentStatusModule::KeyKeeper => key_keeper_status_message.clone(),
                            AgentStatusModule::TelemetryReader => {
                                telemetry_reader_status_message.clone()
                            }
                            AgentStatusModule::TelemetryLogger => {
                                telemetry_logger_status_message.clone()
                            }
                            AgentStatusModule::Redirector => redirector_status_message.clone(),
                            AgentStatusModule::ProxyServer => proxy_server_status_message.clone(),
                            AgentStatusModule::ProxyAgentStatus => {
                                proxy_agent_status_message.clone()
                            }
                        };
                        if let Err(message) = response.send(message) {
                            logger::write_warning(format!(
                                "Failed to send response to AgentStatusAction::GetStatusMessage for module '{module:?}' with message '{message:?}'"
                            ));
                        }
                    }
                    AgentStatusAction::SetState {
                        state,
                        module,
                        response,
                    } => {
                        match module {
                            AgentStatusModule::KeyKeeper => {
                                key_keeper_state = state.clone();
                            }
                            AgentStatusModule::TelemetryReader => {
                                telemetry_reader_state = state.clone()
                            }
                            AgentStatusModule::TelemetryLogger => {
                                telemetry_logger_state = state.clone();
                            }
                            AgentStatusModule::Redirector => {
                                redirector_state = state.clone();
                            }
                            AgentStatusModule::ProxyServer => {
                                proxy_server_state = state.clone();
                            }
                            AgentStatusModule::ProxyAgentStatus => {
                                proxy_agent_status_state = state.clone();
                            }
                        }
                        if let Err(state) = response.send(state) {
                            logger::write_warning(format!("Failed to send response to AgentStatusAction::SetState '{state:?}' for module '{module:?}'"));
                        }
                    }
                    AgentStatusAction::GetState { module, response } => {
                        let state = match module {
                            AgentStatusModule::KeyKeeper => key_keeper_state.clone(),
                            AgentStatusModule::TelemetryReader => telemetry_reader_state.clone(),
                            AgentStatusModule::TelemetryLogger => telemetry_logger_state.clone(),
                            AgentStatusModule::Redirector => redirector_state.clone(),
                            AgentStatusModule::ProxyServer => proxy_server_state.clone(),
                            AgentStatusModule::ProxyAgentStatus => proxy_agent_status_state.clone(),
                        };
                        if let Err(state) = response.send(state) {
                            logger::write_warning(format!(
                                "Failed to send response to AgentStatusAction::GetState for module '{module:?}' with state '{state:?}'"
                            ));
                        }
                    }
                    AgentStatusAction::GetConnectionCount { response } => {
                        if let Err(count) = response.send(http_connection_count) {
                            logger::write_warning(format!(
                                "Failed to send response to AgentStatusAction::GetConnectionCount with count '{count:?}'"
                            ));
                        }
                    }
                    AgentStatusAction::IncreaseConnectionCount { response } => {
                        // if overflow, reset to 0 and continue increase the count
                        http_connection_count = http_connection_count.overflowing_add(1).0;
                        if let Err(count) = response.send(http_connection_count) {
                            logger::write_warning(format!(
                                "Failed to send response to AgentStatusAction::IncreaseConnectionCount with count '{count:?}'"
                            ));
                        }
                    }
                    AgentStatusAction::IncreaseTcpConnectionCount { response } => {
                        // if overflow, reset to 0 and continue increase the count
                        tcp_connection_count = tcp_connection_count.overflowing_add(1).0;
                        if let Err(count) = response.send(tcp_connection_count) {
                            logger::write_warning(format!(
                                "Failed to send response to AgentStatusAction::IncreaseTcpConnectionCount with count '{count:?}'"
                            ));
                        }
                    }
                }
            }
        });

        AgentStatusSharedState(tx)
    }

    async fn get_module_state(&self, module: AgentStatusModule) -> Result<ModuleState> {
        let (response_tx, response_rx) = oneshot::channel();
        self.0
            .send(AgentStatusAction::GetState {
                module: module.clone(),
                response: response_tx,
            })
            .await
            .map_err(|e| {
                Error::SendError(
                    format!("AgentStatusAction::GetState ({module:?})"),
                    e.to_string(),
                )
            })?;
        response_rx
            .await
            .map_err(|e| Error::RecvError(format!("AgentStatusAction::GetState ({module:?})"), e))
    }

    pub async fn set_module_state(
        &self,
        state: ModuleState,
        module: AgentStatusModule,
    ) -> Result<ModuleState> {
        let (response_tx, response_rx) = oneshot::channel();
        self.0
            .send(AgentStatusAction::SetState {
                state,
                module: module.clone(),
                response: response_tx,
            })
            .await
            .map_err(|e| {
                Error::SendError(
                    format!("AgentStatusAction::SetState ({module:?})"),
                    e.to_string(),
                )
            })?;
        response_rx
            .await
            .map_err(|e| Error::RecvError(format!("AgentStatusAction::SetState ({module:?})"), e))
    }

    pub async fn get_module_status_message(&self, module: AgentStatusModule) -> Result<String> {
        let (response_tx, response_rx) = oneshot::channel();
        self.0
            .send(AgentStatusAction::GetStatusMessage {
                module: module.clone(),
                response: response_tx,
            })
            .await
            .map_err(|e| {
                Error::SendError(
                    format!("AgentStatusAction::GetStatusMessage ({module:?})"),
                    e.to_string(),
                )
            })?;
        response_rx.await.map_err(|e| {
            Error::RecvError(
                format!("AgentStatusAction::GetStatusMessage ({module:?})"),
                e,
            )
        })
    }

    /// Set the status message for the module
    /// # Arguments
    /// * `message` - The status message
    /// * `module` - The module name
    /// # Returns
    /// * `bool` - True if the status message is updated, false if the status message is not updated
    /// * 'error' if the message is not sent successfully
    pub async fn set_module_status_message(
        &self,
        message: String,
        module: AgentStatusModule,
    ) -> Result<bool> {
        let (response_tx, response_rx) = oneshot::channel();
        self.0
            .send(AgentStatusAction::SetStatusMessage {
                message: message.to_string(),
                module: module.clone(),
                response: response_tx,
            })
            .await
            .map_err(|e| {
                Error::SendError(
                    format!("AgentStatusAction::SetStatusMessage ({module:?})"),
                    e.to_string(),
                )
            })?;
        let update = response_rx.await.map_err(|e| {
            Error::RecvError(
                format!("AgentStatusAction::SetStatusMessage ({module:?})"),
                e,
            )
        })?;

        // Log the event if the status message is updated
        if update {
            event_logger::write_event(
                LoggerLevel::Warn,
                message,
                "set_module_status_message",
                &format!("{module:?}"),
                logger::AGENT_LOGGER_KEY,
            );
        }
        Ok(update)
    }

    pub async fn get_module_status(&self, module: AgentStatusModule) -> ProxyAgentDetailStatus {
        let state = match self.get_module_state(module.clone()).await {
            Ok(state) => state,
            Err(e) => {
                logger::write_warning(format!("Error getting module '{module:?}' status: {e}"));
                ModuleState::UNKNOWN
            }
        };
        let mut message = match self.get_module_status_message(module.clone()).await {
            Ok(message) => message,
            Err(e) => {
                logger::write_warning(format!(
                    "Error getting module '{module:?}' status message: {e}"
                ));
                super::UNKNOWN_STATUS_MESSAGE.to_string()
            }
        };
        if message.len() > MAX_STATUS_MESSAGE_LENGTH {
            event_logger::write_event(
                LoggerLevel::Warn,
                format!(
                    "Status message is too long, truncating to {MAX_STATUS_MESSAGE_LENGTH} characters. Message: {message}"
                ),
                "get_status",
                &format!("{state:?}"),
                logger::AGENT_LOGGER_KEY,
            );
            message = format!("{}...", &message[0..MAX_STATUS_MESSAGE_LENGTH]);
        }

        ProxyAgentDetailStatus {
            status: state,
            message,
            states: None,
        }
    }

    pub async fn get_connection_count(&self) -> Result<u128> {
        let (response_tx, response_rx) = oneshot::channel();
        self.0
            .send(AgentStatusAction::GetConnectionCount {
                response: response_tx,
            })
            .await
            .map_err(|e| {
                Error::SendError(
                    "AgentStatusAction::GetConnectionCount".to_string(),
                    e.to_string(),
                )
            })?;
        response_rx
            .await
            .map_err(|e| Error::RecvError("AgentStatusAction::GetConnectionCount".to_string(), e))
    }

    pub async fn increase_connection_count(&self) -> Result<u128> {
        let (response_tx, response_rx) = oneshot::channel();
        self.0
            .send(AgentStatusAction::IncreaseConnectionCount {
                response: response_tx,
            })
            .await
            .map_err(|e| {
                Error::SendError(
                    "AgentStatusAction::IncreaseConnectionCount".to_string(),
                    e.to_string(),
                )
            })?;
        response_rx.await.map_err(|e| {
            Error::RecvError("AgentStatusAction::IncreaseConnectionCount".to_string(), e)
        })
    }

    pub async fn increase_tcp_connection_count(&self) -> Result<u128> {
        let (response_tx, response_rx) = oneshot::channel();
        self.0
            .send(AgentStatusAction::IncreaseTcpConnectionCount {
                response: response_tx,
            })
            .await
            .map_err(|e| {
                Error::SendError(
                    "AgentStatusAction::IncreaseTcpConnectionCount".to_string(),
                    e.to_string(),
                )
            })?;
        response_rx.await.map_err(|e| {
            Error::RecvError(
                "AgentStatusAction::IncreaseTcpConnectionCount".to_string(),
                e,
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared_state;
    use proxy_agent_shared::proxy_agent_aggregate_status::ModuleState;

    #[tokio::test]
    async fn test_agent_status_shared_state() {
        let agent_status_shared_state = AgentStatusSharedState::start_new();

        let modules = vec![
            AgentStatusModule::KeyKeeper,
            AgentStatusModule::TelemetryReader,
            AgentStatusModule::TelemetryLogger,
            AgentStatusModule::Redirector,
            AgentStatusModule::ProxyServer,
            AgentStatusModule::ProxyAgentStatus,
        ];

        for module in modules {
            let state = agent_status_shared_state
                .get_module_state(module.clone())
                .await
                .unwrap();
            assert_eq!(ModuleState::UNKNOWN, state);
            let status_message = agent_status_shared_state
                .get_module_status_message(module.clone())
                .await
                .unwrap();
            assert_eq!(shared_state::UNKNOWN_STATUS_MESSAGE, status_message);

            let state = ModuleState::RUNNING;
            let status_message = format!("{:?} is running", module);
            agent_status_shared_state
                .set_module_state(state.clone(), module.clone())
                .await
                .unwrap();
            agent_status_shared_state
                .set_module_status_message(status_message.clone(), module.clone())
                .await
                .unwrap();
            let get_state = agent_status_shared_state
                .get_module_state(module.clone())
                .await
                .unwrap();
            let get_status_message = agent_status_shared_state
                .get_module_status_message(module.clone())
                .await
                .unwrap();
            assert_eq!(state, get_state);
            assert_eq!(status_message, get_status_message);
        }

        let tcp_id = agent_status_shared_state
            .increase_tcp_connection_count()
            .await
            .unwrap();
        assert_eq!(1, tcp_id);

        let connection_id = agent_status_shared_state
            .increase_connection_count()
            .await
            .unwrap();
        assert_eq!(1, connection_id);
        let connection_count = agent_status_shared_state
            .get_connection_count()
            .await
            .unwrap();
        assert_eq!(1, connection_count);

        let connection_id = agent_status_shared_state
            .increase_connection_count()
            .await
            .unwrap();
        assert_eq!(2, connection_id);
    }
}
