// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

//! Manages the proxy server and redirector as one runtime pair.

use crate::common::{constants, logger};
use crate::proxy::proxy_server::ProxyServer;
use crate::redirector::{self, Redirector};
use crate::shared_state::agent_status_wrapper::{
    AgentStatusModule, AgentStatusSharedState, RuntimeStatusSnapshot,
};
use crate::shared_state::SharedState;
use proxy_agent_shared::proxy_agent_aggregate_status::ModuleState;
use std::thread::JoinHandle as ThreadJoinHandle;
use std::time::Duration;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

const RECONCILE_INTERVAL: Duration = Duration::from_secs(1);
const STARTING_TIMEOUT: Duration = Duration::from_secs(60);

/// Policy for managing the runtime pair based on soft audit status changes.
#[derive(Clone, Copy, Debug, PartialEq)]
enum PairAction {
    /// No action is required for the pair.
    None,
    /// Start both modules in the pair.
    StartPair,
    /// Stop both modules in the pair.
    StopPairForSoftAudit,
}

fn evaluate_status(
    status: &RuntimeStatusSnapshot,
    previous_soft_audit_enabled: bool,
) -> PairAction {
    if status.both_running() {
        // If both modules are running, we don't need to take any action.
        return PairAction::None;
    }

    if status.soft_audit_enabled {
        // If soft audit is enabled and either module is stopped, we should stop the pair.
        PairAction::StopPairForSoftAudit
    } else if previous_soft_audit_enabled {
        // Restart once when soft audit changes from enabled to disabled.
        PairAction::StartPair
    } else {
        PairAction::None
    }
}

pub(crate) async fn set_fallback_reason_for_soft_audit(
    agent_status_shared_state: &AgentStatusSharedState,
) {
    let mut fallback_reason = String::new();
    let proxy_agent_detail_status = agent_status_shared_state
        .get_module_status(AgentStatusModule::Redirector)
        .await;
    if proxy_agent_detail_status.status == ModuleState::STOPPED {
        fallback_reason.push_str(&proxy_agent_detail_status.message);
        fallback_reason.push_str("\r\n");
    }

    let proxy_agent_detail_status = agent_status_shared_state
        .get_module_status(AgentStatusModule::ProxyServer)
        .await;
    if proxy_agent_detail_status.status == ModuleState::STOPPED {
        fallback_reason.push_str(&proxy_agent_detail_status.message);
        fallback_reason.push_str("\r\n");
    }

    if !fallback_reason.is_empty() {
        if let Err(e) = agent_status_shared_state
            .set_fallback_reason(Some(fallback_reason))
            .await
        {
            logger::write_error(format!("Failed to set fallback reason: {e}"));
        }
    }
}

/// Checks if the starting of a module has timed out based on its state and the time it has been in the STARTING state.
fn starting_timed_out(
    state: &ModuleState,
    starting_since: &mut Option<Instant>,
    now: Instant,
    time_out_duration: Duration,
) -> bool {
    if state != &ModuleState::STARTING {
        *starting_since = None;
        return false;
    }

    let started = starting_since.get_or_insert(now);
    now.duration_since(*started) >= time_out_duration
}

struct ProxyServerRuntime {
    cancellation_token: CancellationToken,
    thread: ThreadJoinHandle<()>,
}

struct RedirectorRuntime {
    cancellation_token: CancellationToken,
    start_task: JoinHandle<()>,
}

pub struct RuntimeCoordinator {
    shared_state: SharedState,
    proxy_server_runtime: Option<ProxyServerRuntime>,
    redirector_runtime: Option<RedirectorRuntime>,
    /// Tracks when the proxy server entered the STARTING state.
    proxy_starting_since: Option<Instant>,
    /// Tracks when the redirector entered the STARTING state.
    redirector_starting_since: Option<Instant>,
}

impl RuntimeCoordinator {
    pub fn start(shared_state: SharedState) -> JoinHandle<()> {
        tokio::spawn(async move {
            Self {
                shared_state,
                proxy_server_runtime: None,
                redirector_runtime: None,
                proxy_starting_since: None,
                redirector_starting_since: None,
            }
            .run()
            .await;
        })
    }

    async fn run(&mut self) {
        let service_cancellation_token = self.shared_state.get_cancellation_token();
        let mut runtime_status_rx = self
            .shared_state
            .get_agent_status_shared_state()
            .subscribe_runtime_status();

        // Initialize the previous soft audit enabled flag to false.
        let mut previous_soft_audit_enabled = false;

        if !service_cancellation_token.is_cancelled() {
            // Start both the proxy server and redirector initially.
            self.start_proxy_server().await;
            self.start_redirector().await;
        }

        loop {
            tokio::select! {
                _ = service_cancellation_token.cancelled() => break,
                result = runtime_status_rx.changed() => {
                    if result.is_err() {
                        logger::write_warning(
                            "Runtime status publisher stopped; stopping managed modules."
                                .to_string(),
                        );
                        break;
                    }
                }
                _ = tokio::time::sleep(RECONCILE_INTERVAL) => {}
            }

            if service_cancellation_token.is_cancelled() {
                break;
            }

            let status = runtime_status_rx.borrow_and_update().clone();

            // Handle any starting timeouts for the proxy server and redirector.
            if self.handle_starting_timeouts(&status).await {
                // If any starting timeouts were handled, skip the rest of the reconciliation loop.
                continue;
            }

            // Only reconcile the runtime pair if both modules are at their ultimate state.
            // This ensures that we only take actions when both the proxy server and redirector have reached a stable state,
            // it prevents premature actions based on transient states.
            if status.both_at_ultimate_state() {
                match evaluate_status(&status, previous_soft_audit_enabled) {
                    PairAction::None => {}
                    PairAction::StartPair => {
                        self.start_pair(&status).await;
                    }
                    PairAction::StopPairForSoftAudit => {
                        if !previous_soft_audit_enabled {
                            // set the fallback reason for soft audit.
                            set_fallback_reason_for_soft_audit(
                                &self.shared_state.get_agent_status_shared_state(),
                            )
                            .await;
                        }
                        self.stop_pair(&status).await;
                    }
                }
                previous_soft_audit_enabled = status.soft_audit_enabled;
            }
        }

        // Stop the runtime pair before exiting the run.
        self.stop_redirector("RuntimeCoordinator stopping Redirector".to_string())
            .await;
        self.stop_proxy_server("RuntimeCoordinator stopping ProxyServer".to_string())
            .await;
    }

    async fn handle_starting_timeouts(&mut self, status: &RuntimeStatusSnapshot) -> bool {
        let mut handled_timed_out = false;
        let now = Instant::now();
        if starting_timed_out(
            &status.proxy_server_state,
            &mut self.proxy_starting_since,
            now,
            STARTING_TIMEOUT,
        ) {
            logger::write_warning(format!(
                    "ProxyServer remained in STARTING for {STARTING_TIMEOUT:?}; treating it as stopped."
                ));
            handled_timed_out = true;
            self.proxy_starting_since = None;
            self.stop_proxy_server(
                "RuntimeCoordinator stopped ProxyServer due to timeout".to_string(),
            )
            .await;
        }
        if starting_timed_out(
            &status.redirector_state,
            &mut self.redirector_starting_since,
            now,
            STARTING_TIMEOUT,
        ) {
            logger::write_warning(format!(
                "Redirector remained in STARTING for {STARTING_TIMEOUT:?}; treating it as stopped."
            ));
            handled_timed_out = true;
            self.redirector_starting_since = None;
            self.stop_redirector(
                "RuntimeCoordinator stopped Redirector due to timeout".to_string(),
            )
            .await;
        }
        handled_timed_out
    }

    /// Starts the runtime pair, including the proxy server and redirector, if they are not already running.
    async fn start_pair(&mut self, status: &RuntimeStatusSnapshot) {
        if status.proxy_server_state != ModuleState::RUNNING {
            self.start_proxy_server().await;
        }
        if status.redirector_state != ModuleState::RUNNING {
            self.start_redirector().await;
        }
    }

    /// Starts the proxy server if it is not already running.
    async fn start_proxy_server(&mut self) {
        self.stop_proxy_server(
            "RuntimeCoordinator cleanup Stopped ProxyServer state before its startup".to_string(),
        )
        .await;

        let agent_status = self.shared_state.get_agent_status_shared_state();
        if let Err(e) = agent_status
            .set_module_state(ModuleState::STARTING, AgentStatusModule::ProxyServer)
            .await
        {
            logger::write_warning(format!(
                "Failed to mark ProxyServer as starting before runtime pair startup: {e}"
            ));
        }

        let proxy_cancellation_token = self.shared_state.get_cancellation_token().child_token();
        let proxy_server = ProxyServer::new(
            constants::PROXY_AGENT_PORT,
            &self.shared_state,
            proxy_cancellation_token.clone(),
        );
        let proxy_thread = match proxy_server.start_on_dedicated_runtime() {
            Ok(thread) => thread,
            Err(e) => {
                logger::write_error(format!(
                    "Failed to start the proxy server runtime thread: {e}"
                ));
                let _ = self
                    .shared_state
                    .get_agent_status_shared_state()
                    .set_module_state(ModuleState::STOPPED, AgentStatusModule::ProxyServer)
                    .await;
                return;
            }
        };
        self.proxy_server_runtime = Some(ProxyServerRuntime {
            cancellation_token: proxy_cancellation_token,
            thread: proxy_thread,
        });

        // set the starting time to track potential starting timeouts
        self.proxy_starting_since = Some(Instant::now());
    }

    /// Starts the redirector if it is not already running.
    async fn start_redirector(&mut self) {
        self.stop_redirector(
            "RuntimeCoordinator cleanup Stopped Redirector state before its startup".to_string(),
        )
        .await;

        let agent_status = self.shared_state.get_agent_status_shared_state();
        if let Err(e) = agent_status
            .set_module_state(ModuleState::STARTING, AgentStatusModule::Redirector)
            .await
        {
            logger::write_warning(format!(
                "Failed to mark Redirector as starting before runtime pair startup: {e}"
            ));
        }

        let redirector_cancellation_token =
            self.shared_state.get_cancellation_token().child_token();
        let redirector = Redirector::new(
            constants::PROXY_AGENT_PORT,
            &self.shared_state,
            redirector_cancellation_token.clone(),
        );
        let redirector_task = tokio::spawn(async move {
            redirector.start().await;
        });
        self.redirector_runtime = Some(RedirectorRuntime {
            cancellation_token: redirector_cancellation_token,
            start_task: redirector_task,
        });

        // set the starting time to track potential starting timeouts
        self.redirector_starting_since = Some(Instant::now());
    }

    /// Stops the pair due to other module stopped.
    /// It ensures that both components are properly stopped before returning.
    async fn stop_pair(&mut self, status: &RuntimeStatusSnapshot) {
        if status.redirector_state == ModuleState::RUNNING {
            self.stop_redirector(
                "RuntimeCoordinator stopped Redirector due to other module stopped".to_string(),
            )
            .await;
        }

        if status.proxy_server_state == ModuleState::RUNNING {
            self.stop_proxy_server(
                "RuntimeCoordinator stopped ProxyServer due to other module stopped".to_string(),
            )
            .await;
        }
    }

    /// It ensures that the redirector is properly stopped before returning.
    /// It also sets the appropriate status message in the agent status shared state.
    async fn stop_redirector(&mut self, message: String) {
        if let Some(runtime) = self.redirector_runtime.take() {
            runtime.cancellation_token.cancel();
            if let Err(e) = runtime.start_task.await {
                logger::write_warning(format!("Redirector start task failed while stopping: {e}"));
            }
        }
        let stop_result = redirector::close(
            self.shared_state.get_redirector_shared_state(),
            self.shared_state.get_agent_status_shared_state(),
        )
        .await;

        let message = match stop_result {
            Ok(()) => message,
            Err(e) => {
                logger::write_error(format!("Failed to stop Redirector: {e}"));
                format!("{message}. - Failed to stop Redirector: {e}")
            }
        };
        if let Err(e) = self
            .shared_state
            .get_agent_status_shared_state()
            .set_module_status_message(message, AgentStatusModule::Redirector)
            .await
        {
            logger::write_warning(format!(
                "Failed to set Redirector module status message: {e}"
            ));
        }
    }

    /// It ensures that the proxy server is properly stopped before returning.
    /// It also sets the appropriate status message in the agent status shared state.
    async fn stop_proxy_server(&mut self, message: String) {
        if let Some(runtime) = self.proxy_server_runtime.take() {
            runtime.cancellation_token.cancel();
            match tokio::task::spawn_blocking(move || runtime.thread.join()).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) => {
                    logger::write_warning("Proxy server runtime thread panicked.".to_string());
                }
                Err(e) => {
                    logger::write_warning(format!(
                        "Failed to join the proxy server runtime thread: {e}"
                    ));
                }
            }

            if let Err(e) = self
                .shared_state
                .get_agent_status_shared_state()
                .set_module_status_message(message, AgentStatusModule::ProxyServer)
                .await
            {
                logger::write_warning(format!(
                    "Failed to set ProxyServer module status message: {e}"
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{evaluate_status, starting_timed_out, PairAction, STARTING_TIMEOUT};
    use crate::shared_state::agent_status_wrapper::RuntimeStatusSnapshot;
    use proxy_agent_shared::proxy_agent_aggregate_status::ModuleState;
    use std::time::Duration;
    use tokio::time::Instant;

    fn status(
        soft_audit_enabled: bool,
        proxy_server_state: ModuleState,
        redirector_state: ModuleState,
    ) -> RuntimeStatusSnapshot {
        RuntimeStatusSnapshot {
            soft_audit_enabled,
            proxy_server_state,
            redirector_state,
        }
    }

    #[test]
    fn running_pair_requires_no_action() {
        assert_eq!(
            PairAction::None,
            evaluate_status(
                &status(false, ModuleState::RUNNING, ModuleState::RUNNING,),
                true,
            )
        );
        assert_eq!(
            PairAction::None,
            evaluate_status(
                &status(true, ModuleState::RUNNING, ModuleState::RUNNING,),
                false,
            )
        );
    }

    #[test]
    fn soft_audit_stops_a_non_running_pair() {
        assert_eq!(
            PairAction::StopPairForSoftAudit,
            evaluate_status(
                &status(true, ModuleState::RUNNING, ModuleState::STOPPED,),
                false,
            )
        );
        assert_eq!(
            PairAction::StopPairForSoftAudit,
            evaluate_status(
                &status(true, ModuleState::STOPPED, ModuleState::STOPPED,),
                true,
            )
        );
    }

    #[test]
    fn disabling_soft_audit_restarts_a_non_running_pair_once() {
        assert_eq!(
            PairAction::StartPair,
            evaluate_status(
                &status(false, ModuleState::STOPPED, ModuleState::RUNNING,),
                true,
            )
        );
        assert_eq!(
            PairAction::None,
            evaluate_status(
                &status(false, ModuleState::STOPPED, ModuleState::RUNNING,),
                false,
            )
        );
    }

    #[test]
    fn soft_audit_transition_stops_then_restarts_pair_once() {
        let mut previous_soft_audit_enabled = false;

        let enabled_with_stopped_pair = status(true, ModuleState::STOPPED, ModuleState::STOPPED);
        assert_eq!(
            PairAction::StopPairForSoftAudit,
            evaluate_status(&enabled_with_stopped_pair, previous_soft_audit_enabled)
        );
        previous_soft_audit_enabled = enabled_with_stopped_pair.soft_audit_enabled;

        let enabled_with_partially_stopped_pair =
            status(true, ModuleState::RUNNING, ModuleState::STOPPED);
        assert_eq!(
            PairAction::StopPairForSoftAudit,
            evaluate_status(
                &enabled_with_partially_stopped_pair,
                previous_soft_audit_enabled
            )
        );
        previous_soft_audit_enabled = enabled_with_partially_stopped_pair.soft_audit_enabled;

        let disabled_with_stopped_pair = status(false, ModuleState::STOPPED, ModuleState::STOPPED);
        assert_eq!(
            PairAction::StartPair,
            evaluate_status(&disabled_with_stopped_pair, previous_soft_audit_enabled)
        );
        previous_soft_audit_enabled = disabled_with_stopped_pair.soft_audit_enabled;

        assert_eq!(
            PairAction::None,
            evaluate_status(&disabled_with_stopped_pair, previous_soft_audit_enabled)
        );
    }

    #[test]
    fn ultimate_state_requires_both_modules_to_be_running_or_stopped() {
        assert!(
            !status(false, ModuleState::STARTING, ModuleState::RUNNING).both_at_ultimate_state()
        );
        assert!(
            !status(false, ModuleState::STOPPED, ModuleState::STARTING).both_at_ultimate_state()
        );
        assert!(
            !status(false, ModuleState::STARTING, ModuleState::STOPPED).both_at_ultimate_state()
        );
        assert!(!status(false, ModuleState::RUNNING, ModuleState::UNKNOWN).both_at_ultimate_state());
        assert!(status(false, ModuleState::RUNNING, ModuleState::STOPPED).both_at_ultimate_state());
        assert!(status(false, ModuleState::STOPPED, ModuleState::STOPPED).both_at_ultimate_state());
    }

    #[test]
    fn starting_module_is_not_actionable_before_timeout() {
        let now = Instant::now();
        let mut starting_since = Some(now - STARTING_TIMEOUT + Duration::from_secs(1));

        assert!(!starting_timed_out(
            &ModuleState::STARTING,
            &mut starting_since,
            now,
            STARTING_TIMEOUT,
        ));
    }

    #[test]
    fn starting_module_is_stopped_after_timeout() {
        let now = Instant::now();
        let mut starting_since = Some(now - STARTING_TIMEOUT);

        assert!(starting_timed_out(
            &ModuleState::STARTING,
            &mut starting_since,
            now,
            STARTING_TIMEOUT,
        ));

        assert!(!starting_timed_out(
            &ModuleState::RUNNING,
            &mut starting_since,
            now,
            STARTING_TIMEOUT,
        ));
        assert_eq!(None, starting_since);
    }
}
