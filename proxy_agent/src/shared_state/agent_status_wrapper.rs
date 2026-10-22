// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

//! This module contains the logic to interact with the proxy agent status.
//! The proxy agent status contains the 'state' and 'status message' of the key keeper, telemetry reader, telemetry logger, redirector, and proxy server modules.
//! The proxy agent status contains the 'connection count' of the proxy server.
//! Listener status is stored per port. `ProxyServer` aliases the desired local port,
//! while `ProxyListener(port)` also exposes other listeners.
//! Only the desired listener and non-desired STARTING/RUNNING listeners are retained.
//! Stopped listeners on other ports are evicted immediately; reads never create entries.

use crate::common::constants;
use crate::common::error::Error;
use crate::common::logger;
use crate::common::result::Result;
use proxy_agent_shared::logger::LoggerLevel;
use proxy_agent_shared::proxy_agent_aggregate_status::{ModuleState, ProxyAgentDetailStatus};
use proxy_agent_shared::telemetry::event_logger;
use std::collections::HashMap;
use tokio::sync::{mpsc, oneshot, watch};

const MAX_STATUS_MESSAGE_LENGTH: usize = 1024;

enum AgentStatusAction {
    SetStatusMessage {
        message: String,
        module: AgentStatusModule,
        response: oneshot::Sender<bool>,
    },
    GetStatus {
        module: AgentStatusModule,
        response: oneshot::Sender<ModuleStatus>,
    },
    SetState {
        state: ModuleState,
        module: AgentStatusModule,
        response: oneshot::Sender<ModuleState>,
    },
    #[cfg(test)]
    GetStatusCount {
        response: oneshot::Sender<usize>,
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
    SetSoftAuditMode {
        enable_soft_audit: bool,
        response: oneshot::Sender<bool>,
    },
    GetSoftAuditMode {
        response: oneshot::Sender<bool>,
    },
    SetDesiredLocalPort {
        port: u16,
        response: oneshot::Sender<bool>,
    },
    SetFallbackReason {
        reason: Option<String>,
        response: oneshot::Sender<Option<String>>,
    },
    GetFallbackReason {
        response: oneshot::Sender<Option<String>>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum AgentStatusModule {
    KeyKeeper,
    TelemetryReader,
    TelemetryLogger,
    Redirector,
    /// Alias for the listener on the desired local port.
    ProxyServer,
    /// Status of the listener on this port, whether committed or not.
    ProxyListener(u16),
    ProxyAgentStatus,
}

impl AgentStatusModule {
    fn resolve(self, desired_local_port: u16) -> Self {
        match self {
            Self::ProxyServer => Self::ProxyListener(desired_local_port),
            module => module,
        }
    }

    fn should_retain_status(&self, state: &ModuleState, desired_local_port: u16) -> bool {
        match self {
            Self::ProxyListener(port) => {
                *port == desired_local_port
                    || matches!(state, ModuleState::STARTING | ModuleState::RUNNING)
            }
            _ => true,
        }
    }
}

#[derive(Clone)]
struct ModuleStatus {
    state: ModuleState,
    message: String,
}

impl Default for ModuleStatus {
    fn default() -> Self {
        Self {
            state: ModuleState::UNKNOWN,
            message: super::UNKNOWN_STATUS_MESSAGE.to_string(),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct RuntimeStatusSnapshot {
    pub soft_audit_enabled: bool,
    pub proxy_server_state: ModuleState,
    pub redirector_state: ModuleState,
    pub desired_local_port: u16,
}

impl Default for RuntimeStatusSnapshot {
    fn default() -> Self {
        Self {
            soft_audit_enabled: false,
            proxy_server_state: ModuleState::UNKNOWN,
            redirector_state: ModuleState::UNKNOWN,
            desired_local_port: constants::PROXY_AGENT_PORT,
        }
    }
}

impl RuntimeStatusSnapshot {
    pub fn both_running(&self) -> bool {
        self.proxy_server_state == ModuleState::RUNNING
            && self.redirector_state == ModuleState::RUNNING
    }

    pub fn either_stopped(&self) -> bool {
        self.proxy_server_state == ModuleState::STOPPED
            || self.redirector_state == ModuleState::STOPPED
    }

    pub fn both_at_ultimate_state(&self) -> bool {
        self.proxy_server_state.is_ultimate_state() && self.redirector_state.is_ultimate_state()
    }
}

#[derive(Clone, Debug)]
pub struct AgentStatusSharedState(
    mpsc::Sender<AgentStatusAction>,
    watch::Receiver<RuntimeStatusSnapshot>,
);

impl AgentStatusSharedState {
    pub fn start_new() -> Self {
        let (tx, mut rx) = mpsc::channel(100);
        let (runtime_status_tx, runtime_status_rx) =
            watch::channel(RuntimeStatusSnapshot::default());
        tokio::spawn(async move {
            let mut module_statuses: HashMap<AgentStatusModule, ModuleStatus> = HashMap::new();
            let mut soft_audit_mode_enabled: bool = false;
            let mut desired_local_port = constants::PROXY_AGENT_PORT;
            let mut fallback_reason: Option<String> = None;

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
                        let key = module.clone().resolve(desired_local_port);
                        let untracked_listener = matches!(
                            &key,
                            AgentStatusModule::ProxyListener(port)
                                if *port != desired_local_port && !module_statuses.contains_key(&key)
                        );
                        let updated = if untracked_listener {
                            logger::write_information(format!(
                                "Not retaining status message for untracked listener {key:?}: {message}"
                            ));
                            false
                        } else {
                            let status = module_statuses.entry(key).or_default();
                            let updated = status.message != message;
                            if updated {
                                status.message = message;
                            }
                            updated
                        };
                        if response.send(updated).is_err() {
                            logger::write_warning(format!("Failed to send response to AgentStatusAction::SetStatusMessage for module {module:?}"));
                        }
                    }
                    AgentStatusAction::GetStatus { module, response } => {
                        let status = module_statuses
                            .get(&module.clone().resolve(desired_local_port))
                            .cloned()
                            .unwrap_or_default();
                        if response.send(status).is_err() {
                            logger::write_warning(format!(
                                "Failed to send response to AgentStatusAction::GetStatus for module '{module:?}'"
                            ));
                        }
                    }
                    AgentStatusAction::SetState {
                        state,
                        module,
                        response,
                    } => {
                        let key = module.clone().resolve(desired_local_port);
                        if key.should_retain_status(&state, desired_local_port) {
                            module_statuses.entry(key).or_default().state = state.clone();
                        } else {
                            module_statuses.remove(&key);
                        }
                        runtime_status_tx.send_if_modified(|snapshot| {
                            let updated = RuntimeStatusSnapshot {
                                soft_audit_enabled: soft_audit_mode_enabled,
                                proxy_server_state: module_statuses
                                    .get(&AgentStatusModule::ProxyListener(desired_local_port))
                                    .map(|status| status.state.clone())
                                    .unwrap_or(ModuleState::UNKNOWN),
                                redirector_state: module_statuses
                                    .get(&AgentStatusModule::Redirector)
                                    .map(|status| status.state.clone())
                                    .unwrap_or(ModuleState::UNKNOWN),
                                desired_local_port,
                            };
                            if *snapshot == updated {
                                false
                            } else {
                                *snapshot = updated;
                                true
                            }
                        });
                        if let Err(state) = response.send(state) {
                            logger::write_warning(format!("Failed to send response to AgentStatusAction::SetState '{state:?}' for module '{module:?}'"));
                        }
                    }
                    #[cfg(test)]
                    AgentStatusAction::GetStatusCount { response } => {
                        if response.send(module_statuses.len()).is_err() {
                            logger::write_warning(
                                "Failed to send response to AgentStatusAction::GetStatusCount"
                                    .to_string(),
                            );
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
                    AgentStatusAction::SetSoftAuditMode {
                        enable_soft_audit,
                        response,
                    } => {
                        if soft_audit_mode_enabled != enable_soft_audit {
                            logger::write_warning(format!("enableSoftAudit value changed from {soft_audit_mode_enabled} to {enable_soft_audit} "));
                            soft_audit_mode_enabled = enable_soft_audit;
                            runtime_status_tx.send_if_modified(|snapshot| {
                                let updated = RuntimeStatusSnapshot {
                                    soft_audit_enabled: soft_audit_mode_enabled,
                                    proxy_server_state: module_statuses
                                        .get(&AgentStatusModule::ProxyListener(desired_local_port))
                                        .map(|status| status.state.clone())
                                        .unwrap_or(ModuleState::UNKNOWN),
                                    redirector_state: module_statuses
                                        .get(&AgentStatusModule::Redirector)
                                        .map(|status| status.state.clone())
                                        .unwrap_or(ModuleState::UNKNOWN),
                                    desired_local_port,
                                };
                                if *snapshot == updated {
                                    false
                                } else {
                                    *snapshot = updated;
                                    true
                                }
                            });
                        }
                        if !soft_audit_mode_enabled && fallback_reason.is_some() {
                            logger::write_warning(
                                "Soft audit mode has been disabled, reset fallback reason."
                                    .to_string(),
                            );
                            fallback_reason = None;
                        }
                        if let Err(value) = response.send(soft_audit_mode_enabled) {
                            logger::write_warning(format!("Failed to send response to AgentStatusAction::SetSoftAuditMode with value '{value}'"));
                        }
                    }
                    AgentStatusAction::GetSoftAuditMode { response } => {
                        if let Err(value) = response.send(soft_audit_mode_enabled) {
                            logger::write_warning(format!("Failed to send response to AgentStatusAction::GetSoftAuditMode with value '{value}'"));
                        }
                    }
                    AgentStatusAction::SetDesiredLocalPort { port, response } => {
                        let changed = desired_local_port != port;
                        if changed {
                            logger::write_warning(format!(
                                "Desired local proxy port changed from {desired_local_port} to {port}."
                            ));
                            desired_local_port = port;
                            module_statuses.retain(|module, status| {
                                module.should_retain_status(&status.state, desired_local_port)
                            });
                            let state = module_statuses
                                .get(&AgentStatusModule::ProxyListener(port))
                                .map(|status| status.state.clone())
                                .unwrap_or(ModuleState::UNKNOWN);
                            runtime_status_tx.send_modify(|snapshot| {
                                snapshot.desired_local_port = port;
                                snapshot.proxy_server_state = state;
                            });
                        }
                        if response.send(changed).is_err() {
                            logger::write_warning(format!(
                                "Failed to send response to AgentStatusAction::SetDesiredLocalPort for port '{port}'"
                            ));
                        }
                    }
                    AgentStatusAction::SetFallbackReason { reason, response } => {
                        if !soft_audit_mode_enabled {
                            // telemetry events only and no actual fallback reason should be set.
                            logger::write_warning(
                                "SetFallbackReason called while soft audit mode is disabled."
                                    .to_string(),
                            );
                            if let Err(value) = response.send(None) {
                                logger::write_warning(format!("Failed to send response to AgentStatusAction::SetFallbackReason with value '{value:?}'"));
                            }
                        } else {
                            fallback_reason = reason;
                            if let Err(value) = response.send(fallback_reason.clone()) {
                                logger::write_warning(format!("Failed to send response to AgentStatusAction::SetFallbackReason with value '{value:?}'"));
                            }
                        }
                    }
                    AgentStatusAction::GetFallbackReason { response } => {
                        if let Err(value) = {
                            if !soft_audit_mode_enabled {
                                // if soft audit mode is disabled, always return None as the fallback reason.
                                response.send(None)
                            } else {
                                response.send(fallback_reason.clone())
                            }
                        } {
                            logger::write_warning(format!("Failed to send response to AgentStatusAction::GetFallbackReason with value '{value:?}'"));
                        }
                    }
                }
            }
        });

        AgentStatusSharedState(tx, runtime_status_rx)
    }

    pub fn subscribe_runtime_status(&self) -> watch::Receiver<RuntimeStatusSnapshot> {
        self.1.clone()
    }

    async fn get_status(&self, module: AgentStatusModule) -> Result<ModuleStatus> {
        let (response_tx, response_rx) = oneshot::channel();
        self.0
            .send(AgentStatusAction::GetStatus {
                module: module.clone(),
                response: response_tx,
            })
            .await
            .map_err(|e| {
                Error::SendError(
                    format!("AgentStatusAction::GetStatus ({module:?})"),
                    e.to_string(),
                )
            })?;
        response_rx
            .await
            .map_err(|e| Error::RecvError(format!("AgentStatusAction::GetStatus ({module:?})"), e))
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
        Ok(self.get_status(module).await?.message)
    }

    /// Set the status message for the module
    /// # Arguments
    /// * `message` - The status message
    /// * `module` - The module name
    /// # Returns
    /// * `bool` - True if the status message is updated, false if the status message is not updated
    /// * 'error' if the message is not sent successfully
    ///
    /// Non-desired listeners must report STARTING or RUNNING before publishing messages.
    /// Messages for untracked non-desired listeners are logged but not retained.
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
        let ModuleStatus { state, mut message } = match self.get_status(module.clone()).await {
            Ok(status) => status,
            Err(e) => {
                logger::write_warning(format!("Error getting module '{module:?}' status: {e}"));
                ModuleStatus::default()
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

    pub async fn set_soft_audit_mode(&self, enabled: bool) -> Result<()> {
        let (response_tx, response_rx) = oneshot::channel();
        self.0
            .send(AgentStatusAction::SetSoftAuditMode {
                enable_soft_audit: enabled,
                response: response_tx,
            })
            .await
            .map_err(|e| {
                Error::SendError(
                    "AgentStatusAction::SetSoftAuditMode".to_string(),
                    e.to_string(),
                )
            })?;
        response_rx
            .await
            .map_err(|e| Error::RecvError("AgentStatusAction::SetSoftAuditMode".to_string(), e))?;
        Ok(())
    }

    pub async fn get_soft_audit_mode(&self) -> Result<bool> {
        let (response_tx, response_rx) = oneshot::channel();
        self.0
            .send(AgentStatusAction::GetSoftAuditMode {
                response: response_tx,
            })
            .await
            .map_err(|e| {
                Error::SendError(
                    "AgentStatusAction::GetSoftAuditMode".to_string(),
                    e.to_string(),
                )
            })?;
        response_rx
            .await
            .map_err(|e| Error::RecvError("AgentStatusAction::GetSoftAuditMode".to_string(), e))
    }

    /// Selects the listener used by `ProxyServer` reads, writes, and runtime-status notifications.
    pub async fn set_desired_local_port(&self, port: u16) -> Result<bool> {
        let (response_tx, response_rx) = oneshot::channel();
        self.0
            .send(AgentStatusAction::SetDesiredLocalPort {
                port,
                response: response_tx,
            })
            .await
            .map_err(|e| {
                Error::SendError(
                    "AgentStatusAction::SetDesiredLocalPort".to_string(),
                    e.to_string(),
                )
            })?;
        response_rx
            .await
            .map_err(|e| Error::RecvError("AgentStatusAction::SetDesiredLocalPort".to_string(), e))
    }

    pub async fn get_fallback_reason(&self) -> Result<Option<String>> {
        let (response_tx, response_rx) = oneshot::channel();
        self.0
            .send(AgentStatusAction::GetFallbackReason {
                response: response_tx,
            })
            .await
            .map_err(|e| {
                Error::SendError(
                    "AgentStatusAction::GetFallbackReason".to_string(),
                    e.to_string(),
                )
            })?;
        response_rx
            .await
            .map_err(|e| Error::RecvError("AgentStatusAction::GetFallbackReason".to_string(), e))
    }

    pub async fn set_fallback_reason(&self, reason: Option<String>) -> Result<()> {
        let (response_tx, response_rx) = oneshot::channel();
        self.0
            .send(AgentStatusAction::SetFallbackReason {
                reason,
                response: response_tx,
            })
            .await
            .map_err(|e| {
                Error::SendError(
                    "AgentStatusAction::SetFallbackReason".to_string(),
                    e.to_string(),
                )
            })?;
        response_rx
            .await
            .map_err(|e| Error::RecvError("AgentStatusAction::SetFallbackReason".to_string(), e))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared_state;
    use proxy_agent_shared::proxy_agent_aggregate_status::ModuleState;

    async fn status_count(status: &AgentStatusSharedState) -> usize {
        let (response_tx, response_rx) = oneshot::channel();
        status
            .0
            .send(AgentStatusAction::GetStatusCount {
                response: response_tx,
            })
            .await
            .unwrap();
        response_rx.await.unwrap()
    }

    async fn set_listener(
        status: &AgentStatusSharedState,
        port: u16,
        state: ModuleState,
        message: &str,
    ) {
        status
            .set_module_state(state, AgentStatusModule::ProxyListener(port))
            .await
            .unwrap();
        status
            .set_module_status_message(message.to_string(), AgentStatusModule::ProxyListener(port))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn status_reads_and_snapshot_updates_do_not_insert_unknown_entries() {
        let status = AgentStatusSharedState::start_new();
        for port in 0..256 {
            let unknown = status
                .get_module_status(AgentStatusModule::ProxyListener(port))
                .await;
            assert_eq!(ModuleState::UNKNOWN, unknown.status);
            assert_eq!(shared_state::UNKNOWN_STATUS_MESSAGE, unknown.message);
            assert_eq!(
                shared_state::UNKNOWN_STATUS_MESSAGE,
                status
                    .get_module_status_message(AgentStatusModule::ProxyListener(port))
                    .await
                    .unwrap(),
            );
        }
        assert_eq!(0, status_count(&status).await);
        status.set_desired_local_port(3081).await.unwrap();
        status.set_soft_audit_mode(true).await.unwrap();
        assert_eq!(0, status_count(&status).await);
        status
            .set_module_state(ModuleState::RUNNING, AgentStatusModule::KeyKeeper)
            .await
            .unwrap();
        assert_eq!(1, status_count(&status).await);
    }

    #[tokio::test]
    async fn retention_preserves_desired_failure_active_listeners_and_other_modules() {
        let status = AgentStatusSharedState::start_new();
        let port = constants::PROXY_AGENT_PORT;
        set_listener(&status, port, ModuleState::STOPPED, "Desired bind failed.").await;
        set_listener(
            &status,
            port + 1,
            ModuleState::STARTING,
            "Starting listener.",
        )
        .await;
        set_listener(&status, port + 2, ModuleState::RUNNING, "Running listener.").await;
        status
            .set_module_state(ModuleState::STOPPED, AgentStatusModule::Redirector)
            .await
            .unwrap();
        status
            .set_module_status_message(
                "Redirector stopped.".to_string(),
                AgentStatusModule::Redirector,
            )
            .await
            .unwrap();
        assert_eq!(4, status_count(&status).await);
        let desired = status
            .get_module_status(AgentStatusModule::ProxyServer)
            .await;
        assert_eq!(ModuleState::STOPPED, desired.status);
        assert_eq!("Desired bind failed.", desired.message);

        status.set_desired_local_port(port + 1).await.unwrap();
        assert_eq!(3, status_count(&status).await);
        assert_eq!(
            ModuleState::UNKNOWN,
            status
                .get_module_status(AgentStatusModule::ProxyListener(port))
                .await
                .status
        );
        assert_eq!(
            ModuleState::STARTING,
            status
                .get_module_status(AgentStatusModule::ProxyServer)
                .await
                .status
        );
        assert_eq!(
            "Running listener.",
            status
                .get_module_status_message(AgentStatusModule::ProxyListener(port + 2))
                .await
                .unwrap()
        );
        assert_eq!(
            "Redirector stopped.",
            status
                .get_module_status_message(AgentStatusModule::Redirector)
                .await
                .unwrap()
        );

        status
            .set_module_state(
                ModuleState::STOPPED,
                AgentStatusModule::ProxyListener(port + 2),
            )
            .await
            .unwrap();
        assert_eq!(2, status_count(&status).await);
        let retired = status
            .get_module_status(AgentStatusModule::ProxyListener(port + 2))
            .await;
        assert_eq!(ModuleState::UNKNOWN, retired.status);
        assert_eq!(shared_state::UNKNOWN_STATUS_MESSAGE, retired.message);
        assert!(!status
            .set_module_status_message(
                "Late shutdown message.".to_string(),
                AgentStatusModule::ProxyListener(port + 2),
            )
            .await
            .unwrap());
        assert_eq!(2, status_count(&status).await);
    }

    #[tokio::test]
    async fn repeated_port_changes_retain_only_the_desired_stopped_listener() {
        let status = AgentStatusSharedState::start_new();
        for port in 0..256 {
            status.set_desired_local_port(port).await.unwrap();
            set_listener(&status, port, ModuleState::STARTING, "Starting listener.").await;
            set_listener(&status, port, ModuleState::STOPPED, "Desired bind failed.").await;
            assert_eq!(1, status_count(&status).await);
            if port > 0 {
                assert!(!status
                    .set_module_status_message(
                        "Late failure message.".to_string(),
                        AgentStatusModule::ProxyListener(port - 1),
                    )
                    .await
                    .unwrap());
                assert_eq!(
                    ModuleState::UNKNOWN,
                    status
                        .get_module_status(AgentStatusModule::ProxyListener(port - 1))
                        .await
                        .status
                );
                assert_eq!(1, status_count(&status).await);
            }
        }
        let desired = status
            .get_module_status(AgentStatusModule::ProxyServer)
            .await;
        assert_eq!(ModuleState::STOPPED, desired.status);
        assert_eq!("Desired bind failed.", desired.message);
    }

    #[tokio::test]
    async fn failed_non_desired_attempts_do_not_accumulate_or_change_runtime_status() {
        let status = AgentStatusSharedState::start_new();
        set_listener(
            &status,
            constants::PROXY_AGENT_PORT,
            ModuleState::RUNNING,
            "Desired listener ready.",
        )
        .await;
        let mut updates = status.subscribe_runtime_status();
        updates.borrow_and_update();
        for port in 0..256 {
            set_listener(&status, port, ModuleState::STARTING, "Starting candidate.").await;
            assert_eq!(2, status_count(&status).await);
            status
                .set_module_state(ModuleState::STOPPED, AgentStatusModule::ProxyListener(port))
                .await
                .unwrap();
            assert_eq!(1, status_count(&status).await);
            assert!(!status
                .set_module_status_message(
                    "Late candidate failure.".to_string(),
                    AgentStatusModule::ProxyListener(port),
                )
                .await
                .unwrap());
            assert_eq!(1, status_count(&status).await);
        }
        assert!(!updates.has_changed().unwrap());
        assert_eq!(
            "Desired listener ready.",
            status
                .get_module_status_message(AgentStatusModule::ProxyServer)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn evicted_listener_can_restart_and_unknown_messages_do_not_accumulate() {
        let status = AgentStatusSharedState::start_new();
        let port = constants::PROXY_AGENT_PORT + 1;
        status
            .set_module_state(ModuleState::STOPPED, AgentStatusModule::ProxyListener(port))
            .await
            .unwrap();
        assert_eq!(0, status_count(&status).await);
        assert!(!status
            .set_module_status_message(
                "Untracked message.".to_string(),
                AgentStatusModule::ProxyListener(port),
            )
            .await
            .unwrap());
        set_listener(&status, port, ModuleState::STARTING, "Restarted listener.").await;
        assert_eq!(
            "Restarted listener.",
            status
                .get_module_status_message(AgentStatusModule::ProxyListener(port))
                .await
                .unwrap()
        );
        assert_eq!(1, status_count(&status).await);
        status
            .set_module_state(ModuleState::STOPPED, AgentStatusModule::ProxyListener(port))
            .await
            .unwrap();
        assert_eq!(0, status_count(&status).await);

        status.set_desired_local_port(port).await.unwrap();
        status
            .set_module_status_message(
                "Pending startup.".to_string(),
                AgentStatusModule::ProxyServer,
            )
            .await
            .unwrap();
        assert_eq!(1, status_count(&status).await);
        status.set_desired_local_port(port + 1).await.unwrap();
        assert_eq!(0, status_count(&status).await);
    }

    #[tokio::test]
    async fn proxy_server_selects_desired_listener() {
        let status = AgentStatusSharedState::start_new();
        let old_port = constants::PROXY_AGENT_PORT;
        let new_port = old_port + 1;
        set_listener(&status, old_port, ModuleState::STOPPED, "Old bind failed.").await;
        let mut updates = status.subscribe_runtime_status();
        updates.borrow_and_update();

        set_listener(&status, new_port, ModuleState::RUNNING, "Candidate ready.").await;
        assert!(!updates.has_changed().unwrap());
        let aggregate = status
            .get_module_status(AgentStatusModule::ProxyServer)
            .await;
        assert_eq!(ModuleState::STOPPED, aggregate.status);
        assert_eq!("Old bind failed.", aggregate.message);
        assert_eq!(
            ModuleState::RUNNING,
            status
                .get_module_status(AgentStatusModule::ProxyListener(new_port))
                .await
                .status,
        );

        assert!(status.set_desired_local_port(new_port).await.unwrap());
        assert!(updates.has_changed().unwrap());
        assert_eq!(
            ModuleState::RUNNING,
            updates.borrow_and_update().proxy_server_state
        );
        assert!(!status.set_desired_local_port(new_port).await.unwrap());
        set_listener(
            &status,
            old_port,
            ModuleState::STOPPED,
            "Retired listener stopped.",
        )
        .await;
        assert!(!updates.has_changed().unwrap());
        let aggregate = status
            .get_module_status(AgentStatusModule::ProxyServer)
            .await;
        assert_eq!(ModuleState::RUNNING, aggregate.status);
        assert_eq!("Candidate ready.", aggregate.message);
        assert_eq!(new_port, updates.borrow().desired_local_port);
    }

    #[tokio::test]
    async fn desired_listener_failure_is_not_masked_by_running_old_listener() {
        let status = AgentStatusSharedState::start_new();
        let port = constants::PROXY_AGENT_PORT;
        set_listener(&status, port, ModuleState::RUNNING, "Old listener ready.").await;
        status.set_desired_local_port(port + 1).await.unwrap();
        let mut updates = status.subscribe_runtime_status();
        updates.borrow_and_update();

        for state in [
            ModuleState::STARTING,
            ModuleState::RUNNING,
            ModuleState::STOPPED,
        ] {
            set_listener(&status, port + 1, state, "Candidate rejected.").await;
        }
        assert!(updates.has_changed().unwrap());
        assert_eq!(
            ModuleState::STOPPED,
            updates.borrow_and_update().proxy_server_state
        );
        let aggregate = status
            .get_module_status(AgentStatusModule::ProxyServer)
            .await;
        assert_eq!(ModuleState::STOPPED, aggregate.status);
        assert_eq!("Candidate rejected.", aggregate.message);
        assert_eq!(
            ModuleState::RUNNING,
            status
                .get_module_status(AgentStatusModule::ProxyListener(port))
                .await
                .status,
        );
        let rejected = status
            .get_module_status(AgentStatusModule::ProxyListener(port + 1))
            .await;
        assert_eq!(ModuleState::STOPPED, rejected.status);
        assert_eq!("Candidate rejected.", rejected.message);
        let not_started = status
            .get_module_status(AgentStatusModule::ProxyListener(port + 2))
            .await;
        assert_eq!(ModuleState::UNKNOWN, not_started.status);
        assert_eq!(shared_state::UNKNOWN_STATUS_MESSAGE, not_started.message);
    }

    #[tokio::test]
    async fn selecting_not_started_listener_updates_snapshot_and_getters_together() {
        let status = AgentStatusSharedState::start_new();
        let port = constants::PROXY_AGENT_PORT;
        set_listener(&status, port, ModuleState::RUNNING, "Old listener ready.").await;
        let mut updates = status.subscribe_runtime_status();
        updates.borrow_and_update();

        status.set_desired_local_port(port + 1).await.unwrap();
        assert!(updates.has_changed().unwrap());
        let snapshot = updates.borrow_and_update().clone();
        assert_eq!(port + 1, snapshot.desired_local_port);
        assert_eq!(ModuleState::UNKNOWN, snapshot.proxy_server_state);
        let aggregate = status
            .get_module_status(AgentStatusModule::ProxyServer)
            .await;
        assert_eq!(snapshot.proxy_server_state, aggregate.status);
        assert_eq!(shared_state::UNKNOWN_STATUS_MESSAGE, aggregate.message);
        assert!(!status.set_desired_local_port(port + 1).await.unwrap());
        assert!(!updates.has_changed().unwrap());

        status.set_soft_audit_mode(true).await.unwrap();
        assert_eq!(ModuleState::UNKNOWN, updates.borrow().proxy_server_state);
        set_listener(
            &status,
            port + 1,
            ModuleState::STARTING,
            "Desired listener starting.",
        )
        .await;
        assert_eq!(ModuleState::STARTING, updates.borrow().proxy_server_state);
        assert_eq!(
            ModuleState::STARTING,
            status
                .get_module_status(AgentStatusModule::ProxyServer)
                .await
                .status,
        );
    }

    #[tokio::test]
    async fn proxy_server_reads_state_and_message_from_one_desired_listener() {
        let status = AgentStatusSharedState::start_new();
        let port = constants::PROXY_AGENT_PORT;
        set_listener(&status, port, ModuleState::STARTING, "Starting listener.").await;
        set_listener(&status, port + 1, ModuleState::RUNNING, "Running listener.").await;

        let writer = status.clone();
        let switch = tokio::spawn(async move {
            for _ in 0..100 {
                writer.set_desired_local_port(port + 1).await.unwrap();
                writer.set_desired_local_port(port).await.unwrap();
            }
        });
        for _ in 0..100 {
            let aggregate = status
                .get_module_status(AgentStatusModule::ProxyServer)
                .await;
            match aggregate.status {
                ModuleState::RUNNING => assert_eq!("Running listener.", aggregate.message),
                ModuleState::STARTING => assert_eq!("Starting listener.", aggregate.message),
                state => panic!("Unexpected aggregate state: {state:?}"),
            }
        }
        switch.await.unwrap();

        status.set_desired_local_port(port + 1).await.unwrap();
        status
            .set_module_status_message(
                "Legacy alias update.".to_string(),
                AgentStatusModule::ProxyServer,
            )
            .await
            .unwrap();
        status
            .set_module_state(ModuleState::STOPPED, AgentStatusModule::ProxyServer)
            .await
            .unwrap();
        let selected = status
            .get_module_status(AgentStatusModule::ProxyListener(port + 1))
            .await;
        assert_eq!(ModuleState::STOPPED, selected.status);
        assert_eq!("Legacy alias update.", selected.message);
        assert_eq!(
            "Starting listener.",
            status
                .get_module_status_message(AgentStatusModule::ProxyListener(port))
                .await
                .unwrap(),
        );
    }

    #[tokio::test]
    async fn test_agent_status_shared_state() {
        let agent_status_shared_state = AgentStatusSharedState::start_new();
        let mut runtime_status_rx = agent_status_shared_state.subscribe_runtime_status();
        assert_eq!(
            RuntimeStatusSnapshot::default(),
            runtime_status_rx.borrow().clone()
        );
        assert_eq!(
            constants::PROXY_AGENT_PORT,
            runtime_status_rx.borrow().desired_local_port
        );
        assert!(agent_status_shared_state
            .set_desired_local_port(3081)
            .await
            .unwrap());
        assert_eq!(3081, runtime_status_rx.borrow().desired_local_port);
        assert!(!agent_status_shared_state
            .set_desired_local_port(3081)
            .await
            .unwrap());

        let modules = vec![
            AgentStatusModule::KeyKeeper,
            AgentStatusModule::TelemetryReader,
            AgentStatusModule::TelemetryLogger,
            AgentStatusModule::Redirector,
            AgentStatusModule::ProxyServer,
            AgentStatusModule::ProxyListener(3082),
            AgentStatusModule::ProxyAgentStatus,
        ];

        for module in modules {
            let state = agent_status_shared_state
                .get_status(module.clone())
                .await
                .unwrap()
                .state;
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
                .get_status(module.clone())
                .await
                .unwrap()
                .state;
            let get_status_message = agent_status_shared_state
                .get_module_status_message(module.clone())
                .await
                .unwrap();
            assert_eq!(state, get_state);
            assert_eq!(status_message, get_status_message);
        }
        assert_eq!(
            ModuleState::RUNNING,
            runtime_status_rx.borrow().proxy_server_state.clone()
        );
        assert_eq!(
            ModuleState::RUNNING,
            runtime_status_rx.borrow().redirector_state.clone()
        );

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

        assert!(!agent_status_shared_state
            .get_soft_audit_mode()
            .await
            .unwrap());
        agent_status_shared_state
            .set_soft_audit_mode(true)
            .await
            .unwrap();
        runtime_status_rx.changed().await.unwrap();
        assert!(runtime_status_rx.borrow().soft_audit_enabled);
        assert!(agent_status_shared_state
            .get_soft_audit_mode()
            .await
            .unwrap());
        agent_status_shared_state
            .set_soft_audit_mode(false)
            .await
            .unwrap();
        assert!(!agent_status_shared_state
            .get_soft_audit_mode()
            .await
            .unwrap());

        assert_eq!(
            None,
            agent_status_shared_state
                .get_fallback_reason()
                .await
                .unwrap()
        );
        agent_status_shared_state
            .set_fallback_reason(Some("ignored while disabled".to_string()))
            .await
            .unwrap();
        assert_eq!(
            None,
            agent_status_shared_state
                .get_fallback_reason()
                .await
                .unwrap()
        );

        agent_status_shared_state
            .set_soft_audit_mode(true)
            .await
            .unwrap();
        agent_status_shared_state
            .set_fallback_reason(Some("test fallback".to_string()))
            .await
            .unwrap();
        assert_eq!(
            Some("test fallback".to_string()),
            agent_status_shared_state
                .get_fallback_reason()
                .await
                .unwrap()
        );
        agent_status_shared_state
            .set_fallback_reason(None)
            .await
            .unwrap();
        assert_eq!(
            None,
            agent_status_shared_state
                .get_fallback_reason()
                .await
                .unwrap()
        );

        agent_status_shared_state
            .set_fallback_reason(Some("reset on disable".to_string()))
            .await
            .unwrap();
        agent_status_shared_state
            .set_soft_audit_mode(false)
            .await
            .unwrap();
        assert_eq!(
            None,
            agent_status_shared_state
                .get_fallback_reason()
                .await
                .unwrap()
        );
    }
}
