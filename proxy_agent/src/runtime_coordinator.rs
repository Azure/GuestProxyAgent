// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

//! Manages the proxy server and redirector as one runtime pair.
//! Listener status is per port; the aggregate follows the desired local port.
//! Same-port restarts join the previous runtime before reuse.
//! A selected runtime is retained even if listener startup fails; health is reported separately.
//! The last selected port survives runtime cleanup to distinguish stops from port changes.

use crate::common::{constants, logger};
use crate::provision;
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

fn should_reconcile_proxy_port(
    status: &RuntimeStatusSnapshot,
    last_selected_local_port: Option<u16>,
) -> bool {
    match last_selected_local_port {
        Some(local_port) => local_port != status.desired_local_port,
        None => status.desired_local_port != constants::PROXY_AGENT_PORT,
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
    local_port: u16,
    cancellation_token: CancellationToken,
    /// Cancelled to approve provisioning notifications: immediately for initial startup,
    /// or when a replacement runtime is selected after attempting policy updates.
    listener_committed: CancellationToken,
    thread: Option<ThreadJoinHandle<()>>,
}

struct RedirectorRuntime {
    cancellation_token: CancellationToken,
    start_task: JoinHandle<()>,
}

pub struct RuntimeCoordinator {
    shared_state: SharedState,
    last_selected_local_port: Option<u16>,
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
                last_selected_local_port: None,
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
            // Start the proxy server with the default local port during service provisioning.
            // If the customer chooses a different port, it will be updated later.
            self.start_proxy_server(constants::PROXY_AGENT_PORT).await;
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

            if should_reconcile_proxy_port(&status, self.last_selected_local_port) {
                let listener_reconciled = self
                    .handoff_proxy_server(
                        status.desired_local_port,
                        status.redirector_state == ModuleState::RUNNING,
                    )
                    .await;
                if listener_reconciled && status.redirector_state != ModuleState::RUNNING {
                    // A STARTING redirector was created with the previous port. This call first
                    // cancels and cleans it up, then starts a new redirector with the current
                    // ProxyServerRuntime port.
                    self.start_redirector().await;
                }
                continue;
            }

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
            self.start_proxy_server(status.desired_local_port).await;
        }
        if status.redirector_state != ModuleState::RUNNING {
            self.start_redirector().await;
        }
    }

    /// Starts the proxy server if it is not already running.
    async fn start_proxy_server(&mut self, local_port: u16) {
        self.stop_proxy_server(
            "RuntimeCoordinator cleanup Stopped ProxyServer state before its startup".to_string(),
        )
        .await;

        // Start the proxy server runtime with the specified local port and
        // do not wait for its startup to complete.
        let proxy_server_runtime = self.start_proxy_runtime(local_port, None).await;
        self.proxy_server_runtime = Some(proxy_server_runtime);
        self.last_selected_local_port = Some(local_port);

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
        let local_port = self
            .proxy_server_runtime
            .as_ref()
            .map_or(constants::PROXY_AGENT_PORT, |runtime| runtime.local_port);
        let redirector = Redirector::new(
            local_port,
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
        // Preserve the original failure before stopping its healthy partner.
        set_fallback_reason_for_soft_audit(&self.shared_state.get_agent_status_shared_state())
            .await;

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
            let local_port = runtime.local_port;
            self.stop_proxy_runtime(runtime).await;

            if let Err(e) = self
                .shared_state
                .get_agent_status_shared_state()
                .set_module_status_message(message, AgentStatusModule::ProxyListener(local_port))
                .await
            {
                logger::write_warning(format!(
                    "Failed to set ProxyServer module status message: {e}"
                ));
            }
        }
    }

    /// Returns ownership even on startup failure or readiness timeout so it can be tracked and stopped.
    async fn start_proxy_runtime(
        &self,
        local_port: u16,
        startup_timeout: Option<Duration>,
    ) -> ProxyServerRuntime {
        let agent_status = self.shared_state.get_agent_status_shared_state();
        if let Err(e) = agent_status
            .set_module_state(
                ModuleState::STARTING,
                AgentStatusModule::ProxyListener(local_port),
            )
            .await
        {
            logger::write_warning(format!("Failed to mark proxy listener as starting: {e}"));
        }
        if let Err(e) = agent_status
            .set_module_status_message(
                format!("Starting proxy listener on port {local_port}."),
                AgentStatusModule::ProxyListener(local_port),
            )
            .await
        {
            logger::write_warning(format!("Failed to set listener startup message: {e}"));
        }
        let cancellation_token = self.shared_state.get_cancellation_token().child_token();
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let (proxy_server, listener_committed) = ProxyServer::new_managed(
            local_port,
            &self.shared_state,
            cancellation_token.clone(),
            Some(ready_tx),
        );
        if startup_timeout.is_none() {
            listener_committed.cancel();
        }
        let thread = match proxy_server.start_on_dedicated_runtime() {
            Ok(thread) => Some(thread),
            Err(e) => {
                let message = format!(
                    "Failed to start the proxy server runtime thread on port {local_port}: {e}"
                );
                logger::write_error(message.clone());
                if let Err(e) = agent_status
                    .set_module_status_message(
                        message,
                        AgentStatusModule::ProxyListener(local_port),
                    )
                    .await
                {
                    logger::write_warning(format!("Failed to set listener startup failure: {e}"));
                }
                if let Err(e) = agent_status
                    .set_module_state(
                        ModuleState::STOPPED,
                        AgentStatusModule::ProxyListener(local_port),
                    )
                    .await
                {
                    logger::write_warning(format!("Failed to mark proxy listener as stopped: {e}"));
                }
                None
            }
        };

        let runtime = ProxyServerRuntime {
            local_port,
            cancellation_token,
            listener_committed,
            thread,
        };

        if let Some(timeout) = startup_timeout {
            match tokio::time::timeout(timeout, ready_rx).await {
                Ok(Ok(Ok(()))) => {
                    logger::write_information(format!(
                        "Proxy listener on port {local_port} is ready."
                    ));
                }
                Ok(Ok(Err(e))) => {
                    logger::write_error(format!(
                        "Failed to start proxy listener on port {local_port}: {e}"
                    ));
                }
                Ok(Err(e)) => {
                    logger::write_error(format!(
                        "Proxy listener on port {local_port} stopped before reporting readiness: {e}"
                    ));
                }
                Err(_) => {
                    logger::write_error(format!(
                        "Timed out waiting for proxy listener on port {local_port} to become ready."
                    ));
                }
            }
        }

        runtime
    }

    async fn stop_proxy_runtime(&self, runtime: ProxyServerRuntime) {
        let local_port = runtime.local_port;
        runtime.cancellation_token.cancel();
        if let Some(thread) = runtime.thread {
            match tokio::task::spawn_blocking(move || thread.join()).await {
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
        }
        if let Err(e) = self
            .shared_state
            .get_agent_status_shared_state()
            .set_module_state(
                ModuleState::STOPPED,
                AgentStatusModule::ProxyListener(local_port),
            )
            .await
        {
            logger::write_warning(format!("Failed to mark proxy listener as stopped: {e}"));
        }
    }

    /// Reports whether the requested runtime was selected, not whether its listener is healthy.
    async fn handoff_proxy_server(
        &mut self,
        new_port: u16,
        redirector_ready_for_policy_update: bool,
    ) -> bool {
        let old_port: Option<u16> = self
            .proxy_server_runtime
            .as_ref()
            .map(|runtime| runtime.local_port);
        if old_port == Some(new_port) {
            return true;
        }

        match old_port {
            Some(old_port) => logger::write_warning(format!(
                "Starting proxy listener handoff from port {old_port} to {new_port}."
            )),
            None => logger::write_warning(format!(
                "Starting replacement proxy listener on port {new_port}."
            )),
        }

        // Start the new proxy runtime.
        let candidate = self
            .start_proxy_runtime(new_port, Some(STARTING_TIMEOUT))
            .await;

        // Redirect-map updates are skipped because no redirector is active.
        // When the redirector starts later, it uses the current listener port.
        if redirector_ready_for_policy_update {
            if let Err(e) = self
                .shared_state
                .get_redirector_shared_state()
                .set_local_port(new_port)
                .await
            {
                logger::write_error(format!(
                    "Failed to stage redirect policies for proxy port {new_port}: {e}"
                ));
                self.stop_proxy_runtime(candidate).await;
                return false;
            }

            provision::update_redirector_policy(
                self.shared_state.get_redirector_shared_state(),
                self.shared_state.get_access_control_shared_state(),
            )
            .await;
        }

        candidate.listener_committed.cancel();
        self.last_selected_local_port = Some(new_port);
        if let Some(old_runtime) = self.proxy_server_runtime.replace(candidate) {
            // Stop the old proxy runtime.
            let old_port = old_runtime.local_port;
            self.stop_proxy_runtime(old_runtime).await;
            logger::write_information(format!(
                "Completed proxy listener handoff from port {old_port} to {new_port}."
            ));
        } else {
            logger::write_information(format!(
                "Started replacement proxy listener on port {new_port}."
            ));
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::{
        evaluate_status, set_fallback_reason_for_soft_audit, should_reconcile_proxy_port,
        starting_timed_out, PairAction, RuntimeCoordinator, STARTING_TIMEOUT,
    };
    use crate::proxy_agent_status::ProxyAgentStatusTask;
    use crate::shared_state::agent_status_wrapper::{AgentStatusModule, RuntimeStatusSnapshot};
    use crate::shared_state::SharedState;
    use proxy_agent_shared::proxy_agent_aggregate_status::ModuleState;
    use std::time::Duration;
    use tokio::net::TcpListener;
    use tokio::time::Instant;

    fn coordinator() -> RuntimeCoordinator {
        RuntimeCoordinator {
            shared_state: SharedState::start_all(),
            last_selected_local_port: None,
            proxy_server_runtime: None,
            redirector_runtime: None,
            proxy_starting_since: None,
            redirector_starting_since: None,
        }
    }

    async fn set_desired_port(coordinator: &RuntimeCoordinator, port: u16) {
        coordinator
            .shared_state
            .get_agent_status_shared_state()
            .set_desired_local_port(port)
            .await
            .unwrap();
    }

    async fn wait_for_proxy_state(coordinator: &RuntimeCoordinator, expected: ModuleState) {
        let mut status = coordinator
            .shared_state
            .get_agent_status_shared_state()
            .subscribe_runtime_status();
        tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                if status.borrow_and_update().proxy_server_state == expected {
                    break;
                }
                status.changed().await.unwrap();
            }
        })
        .await
        .unwrap();
    }

    fn runtime_status(coordinator: &RuntimeCoordinator) -> RuntimeStatusSnapshot {
        coordinator
            .shared_state
            .get_agent_status_shared_state()
            .subscribe_runtime_status()
            .borrow()
            .clone()
    }

    async fn serialized_proxy_status(coordinator: &RuntimeCoordinator) -> serde_json::Value {
        let aggregate = ProxyAgentStatusTask::get_proxy_agent_aggregate_status(
            &coordinator.shared_state.get_agent_status_shared_state(),
            &coordinator.shared_state.get_key_keeper_shared_state(),
            &coordinator
                .shared_state
                .get_connection_summary_shared_state(),
        )
        .await;
        serde_json::to_value(aggregate.proxyAgentStatus).unwrap()
    }

    #[tokio::test]
    async fn healthy_soft_audit_then_failed_port_change_reports_original_fallback() {
        let mut coordinator = coordinator();
        let agent_status = coordinator.shared_state.get_agent_status_shared_state();
        agent_status.set_soft_audit_mode(true).await.unwrap();
        set_desired_port(&coordinator, 0).await;
        coordinator.start_proxy_server(0).await;
        wait_for_proxy_state(&coordinator, ModuleState::RUNNING).await;
        // Simulate a healthy redirector without loading real eBPF programs.
        agent_status
            .set_module_state(ModuleState::RUNNING, AgentStatusModule::Redirector)
            .await
            .unwrap();
        let healthy = runtime_status(&coordinator);
        assert_eq!(PairAction::None, evaluate_status(&healthy, false));
        let previous_soft_audit_enabled = healthy.soft_audit_enabled;
        assert!(serialized_proxy_status(&coordinator).await["auditFallback"].is_null());

        let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = occupied.local_addr().unwrap().port();
        set_desired_port(&coordinator, port).await;
        assert!(coordinator.handoff_proxy_server(port, true).await);
        let failed = runtime_status(&coordinator);
        assert!(failed.both_at_ultimate_state());
        assert_eq!(ModuleState::STOPPED, failed.proxy_server_state);
        assert_eq!(
            PairAction::StopPairForSoftAudit,
            evaluate_status(&failed, previous_soft_audit_enabled),
        );
        let original_error = agent_status
            .get_module_status(AgentStatusModule::ProxyServer)
            .await
            .message;
        assert!(original_error.contains("Failed to bind"));
        coordinator.stop_pair(&failed).await;

        let reported = serialized_proxy_status(&coordinator).await;
        assert_eq!(
            serde_json::json!({
                "fallbacked": true,
                "reason": format!("{original_error}\r\n"),
            }),
            reported["auditFallback"],
        );
        assert_eq!("STOPPED", reported["ebpfProgramStatus"]["status"]);
        assert!(reported["ebpfProgramStatus"]["message"]
            .as_str()
            .unwrap()
            .contains("RuntimeCoordinator stopped Redirector"));
        for _ in 0..3 {
            coordinator.stop_pair(&runtime_status(&coordinator)).await;
            assert_eq!(
                serde_json::json!({
                    "fallbacked": true,
                    "reason": format!(
                        "{}\r\n{original_error}\r\n",
                        reported["ebpfProgramStatus"]["message"].as_str().unwrap(),
                    ),
                }),
                serialized_proxy_status(&coordinator).await["auditFallback"],
            );
        }

        agent_status.set_soft_audit_mode(false).await.unwrap();
        assert!(serialized_proxy_status(&coordinator).await["auditFallback"].is_null());
        agent_status
            .set_module_status_message(
                "A new redirector failure".to_string(),
                AgentStatusModule::Redirector,
            )
            .await
            .unwrap();
        agent_status
            .set_module_status_message(
                "A new listener failure".to_string(),
                AgentStatusModule::ProxyListener(port),
            )
            .await
            .unwrap();
        set_fallback_reason_for_soft_audit(&agent_status).await;
        assert!(serialized_proxy_status(&coordinator).await["auditFallback"].is_null());
        agent_status.set_soft_audit_mode(true).await.unwrap();
        coordinator.stop_pair(&runtime_status(&coordinator)).await;
        let renewed = serialized_proxy_status(&coordinator).await;
        assert_eq!(
            serde_json::json!({
                "fallbacked": true,
                "reason": "A new redirector failure\r\nA new listener failure\r\n",
            }),
            renewed["auditFallback"],
        );
        assert_ne!(reported["auditFallback"], renewed["auditFallback"]);
        coordinator
            .stop_proxy_server("Test cleanup.".to_string())
            .await;
        coordinator.shared_state.get_cancellation_token().cancel();
    }

    #[tokio::test]
    async fn soft_audit_overwrites_fallback_reason_on_every_reconciliation() {
        let mut coordinator = coordinator();
        let agent_status = coordinator.shared_state.get_agent_status_shared_state();
        agent_status.set_soft_audit_mode(true).await.unwrap();
        set_desired_port(&coordinator, 0).await;
        for (module, message) in [
            (AgentStatusModule::Redirector, "Initial redirector failure"),
            (
                AgentStatusModule::ProxyListener(0),
                "Initial listener failure",
            ),
        ] {
            agent_status
                .set_module_state(ModuleState::STOPPED, module.clone())
                .await
                .unwrap();
            agent_status
                .set_module_status_message(message.to_string(), module)
                .await
                .unwrap();
        }
        coordinator.stop_pair(&runtime_status(&coordinator)).await;
        assert_eq!(
            serde_json::json!({
                "fallbacked": true,
                "reason": "Initial redirector failure\r\nInitial listener failure\r\n",
            }),
            serialized_proxy_status(&coordinator).await["auditFallback"],
        );
        agent_status
            .set_module_status_message(
                "Updated redirector failure".to_string(),
                AgentStatusModule::Redirector,
            )
            .await
            .unwrap();
        agent_status
            .set_module_status_message(
                "Updated listener failure".to_string(),
                AgentStatusModule::ProxyListener(0),
            )
            .await
            .unwrap();
        for _ in 0..3 {
            assert!(runtime_status(&coordinator).soft_audit_enabled);
            coordinator.stop_pair(&runtime_status(&coordinator)).await;
            assert_eq!(
                serde_json::json!({
                    "fallbacked": true,
                    "reason": "Updated redirector failure\r\nUpdated listener failure\r\n",
                }),
                serialized_proxy_status(&coordinator).await["auditFallback"],
            );
        }
        coordinator.shared_state.get_cancellation_token().cancel();
    }

    #[tokio::test]
    async fn healthy_soft_audit_does_not_create_a_fallback_reason() {
        let coordinator = coordinator();
        let agent_status = coordinator.shared_state.get_agent_status_shared_state();
        agent_status.set_soft_audit_mode(true).await.unwrap();
        for module in [
            AgentStatusModule::Redirector,
            AgentStatusModule::ProxyServer,
        ] {
            agent_status
                .set_module_state(ModuleState::RUNNING, module)
                .await
                .unwrap();
        }
        set_fallback_reason_for_soft_audit(&agent_status).await;
        assert!(serialized_proxy_status(&coordinator).await["auditFallback"].is_null());
        agent_status
            .set_fallback_reason(Some("Existing fallback".to_string()))
            .await
            .unwrap();
        set_fallback_reason_for_soft_audit(&agent_status).await;
        assert_eq!(
            "Existing fallback",
            serialized_proxy_status(&coordinator).await["auditFallback"]["reason"],
        );
        coordinator.shared_state.get_cancellation_token().cancel();
    }

    #[tokio::test]
    async fn soft_audit_stop_does_not_reconcile_the_selected_port_again() {
        let mut coordinator = coordinator();
        set_desired_port(&coordinator, 0).await;
        coordinator.start_proxy_server(0).await;
        wait_for_proxy_state(&coordinator, ModuleState::RUNNING).await;
        let listener_token = coordinator
            .proxy_server_runtime
            .as_ref()
            .unwrap()
            .cancellation_token
            .clone();
        let agent_status = coordinator.shared_state.get_agent_status_shared_state();
        agent_status.set_soft_audit_mode(true).await.unwrap();
        agent_status
            .set_module_state(ModuleState::STOPPED, AgentStatusModule::Redirector)
            .await
            .unwrap();
        let status = runtime_status(&coordinator);
        assert!(status.both_at_ultimate_state());
        assert_eq!(
            PairAction::StopPairForSoftAudit,
            evaluate_status(&status, false),
        );
        coordinator.stop_pair(&status).await;
        wait_for_proxy_state(&coordinator, ModuleState::STOPPED).await;
        assert!(listener_token.is_cancelled());

        for _ in 0..3 {
            let status = runtime_status(&coordinator);
            assert_eq!(Some(0), coordinator.last_selected_local_port);
            assert!(!should_reconcile_proxy_port(
                &status,
                coordinator.last_selected_local_port,
            ));
            assert_eq!(
                PairAction::StopPairForSoftAudit,
                evaluate_status(&status, true),
            );
            coordinator.stop_pair(&status).await;
            assert!(coordinator.proxy_server_runtime.is_none());
            assert!(coordinator.redirector_runtime.is_none());
        }
        coordinator.shared_state.get_cancellation_token().cancel();
    }

    #[tokio::test]
    async fn changed_port_is_selected_once_after_soft_audit_stop() {
        let mut coordinator = coordinator();
        set_desired_port(&coordinator, 0).await;
        coordinator.start_proxy_server(0).await;
        wait_for_proxy_state(&coordinator, ModuleState::RUNNING).await;
        let agent_status = coordinator.shared_state.get_agent_status_shared_state();
        agent_status.set_soft_audit_mode(true).await.unwrap();
        agent_status
            .set_module_state(ModuleState::STOPPED, AgentStatusModule::Redirector)
            .await
            .unwrap();
        coordinator.stop_pair(&runtime_status(&coordinator)).await;

        let reserved = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let new_port = reserved.local_addr().unwrap().port();
        drop(reserved);
        set_desired_port(&coordinator, new_port).await;
        assert!(should_reconcile_proxy_port(
            &runtime_status(&coordinator),
            coordinator.last_selected_local_port,
        ));
        assert!(coordinator.handoff_proxy_server(new_port, false).await);
        assert_eq!(Some(new_port), coordinator.last_selected_local_port);
        let selected = coordinator.proxy_server_runtime.as_ref().unwrap();
        assert_eq!(new_port, selected.local_port);
        assert!(selected.listener_committed.is_cancelled());
        let listener_token = selected.cancellation_token.clone();
        assert!(!should_reconcile_proxy_port(
            &runtime_status(&coordinator),
            coordinator.last_selected_local_port,
        ));

        coordinator.stop_pair(&runtime_status(&coordinator)).await;
        assert!(listener_token.is_cancelled());
        assert!(coordinator.proxy_server_runtime.is_none());
        assert!(!should_reconcile_proxy_port(
            &runtime_status(&coordinator),
            coordinator.last_selected_local_port,
        ));
        set_desired_port(&coordinator, crate::common::constants::PROXY_AGENT_PORT).await;
        assert!(should_reconcile_proxy_port(
            &runtime_status(&coordinator),
            coordinator.last_selected_local_port,
        ));
        coordinator.shared_state.get_cancellation_token().cancel();
    }

    #[tokio::test]
    async fn disabling_soft_audit_restarts_listener_at_the_selected_port_once() {
        let reserved = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = reserved.local_addr().unwrap().port();
        drop(reserved);
        let mut coordinator = coordinator();
        set_desired_port(&coordinator, port).await;
        coordinator.start_proxy_server(port).await;
        wait_for_proxy_state(&coordinator, ModuleState::RUNNING).await;
        let agent_status = coordinator.shared_state.get_agent_status_shared_state();
        agent_status.set_soft_audit_mode(true).await.unwrap();
        agent_status
            .set_module_state(ModuleState::STOPPED, AgentStatusModule::Redirector)
            .await
            .unwrap();
        coordinator.stop_pair(&runtime_status(&coordinator)).await;
        assert_eq!(Some(port), coordinator.last_selected_local_port);

        agent_status.set_soft_audit_mode(false).await.unwrap();
        // Simulate redirector recovery so start_pair cannot load real eBPF programs.
        agent_status
            .set_module_state(ModuleState::RUNNING, AgentStatusModule::Redirector)
            .await
            .unwrap();
        let status = runtime_status(&coordinator);
        assert!(!should_reconcile_proxy_port(
            &status,
            coordinator.last_selected_local_port,
        ));
        assert_eq!(PairAction::StartPair, evaluate_status(&status, true));
        coordinator.start_pair(&status).await;
        wait_for_proxy_state(&coordinator, ModuleState::RUNNING).await;
        let selected = coordinator.proxy_server_runtime.as_ref().unwrap();
        assert_eq!(port, selected.local_port);
        assert_eq!(Some(port), coordinator.last_selected_local_port);
        assert!(tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok());
        assert_eq!(
            PairAction::None,
            evaluate_status(&runtime_status(&coordinator), false),
        );
        assert!(coordinator.redirector_runtime.is_none());
        coordinator
            .stop_proxy_server("Test cleanup.".to_string())
            .await;
        coordinator.shared_state.get_cancellation_token().cancel();
    }

    #[tokio::test]
    async fn handoff_records_selected_port_when_desired_port_changes_again() {
        let mut coordinator = coordinator();
        let reserved = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let latest_port = reserved.local_addr().unwrap().port();
        set_desired_port(&coordinator, 0).await;
        let earlier_status = runtime_status(&coordinator);
        assert!(should_reconcile_proxy_port(
            &earlier_status,
            coordinator.last_selected_local_port,
        ));

        set_desired_port(&coordinator, latest_port).await;
        assert!(
            coordinator
                .handoff_proxy_server(earlier_status.desired_local_port, false)
                .await
        );
        assert_eq!(Some(0), coordinator.last_selected_local_port);
        assert_eq!(
            0,
            coordinator
                .proxy_server_runtime
                .as_ref()
                .unwrap()
                .local_port,
        );
        assert!(should_reconcile_proxy_port(
            &runtime_status(&coordinator),
            coordinator.last_selected_local_port,
        ));

        drop(reserved);
        assert!(coordinator.handoff_proxy_server(latest_port, false).await);
        assert_eq!(Some(latest_port), coordinator.last_selected_local_port);
        assert!(!should_reconcile_proxy_port(
            &runtime_status(&coordinator),
            coordinator.last_selected_local_port,
        ));
        coordinator
            .stop_proxy_server("Test cleanup.".to_string())
            .await;
        coordinator.shared_state.get_cancellation_token().cancel();
    }

    #[tokio::test]
    async fn handoff_cancels_bind_retries_without_overwriting_desired_listener() {
        let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let old_port = occupied.local_addr().unwrap().port();
        let mut coordinator = coordinator();
        set_desired_port(&coordinator, old_port).await;
        coordinator.start_proxy_server(old_port).await;

        set_desired_port(&coordinator, 0).await;
        assert!(tokio::time::timeout(
            Duration::from_secs(2),
            coordinator.handoff_proxy_server(0, false),
        )
        .await
        .unwrap());
        let agent_status = coordinator.shared_state.get_agent_status_shared_state();
        let aggregate = agent_status
            .get_module_status(AgentStatusModule::ProxyServer)
            .await;
        assert_eq!(ModuleState::RUNNING, aggregate.status);
        let retired = agent_status
            .get_module_status(AgentStatusModule::ProxyListener(old_port))
            .await;
        assert_eq!(ModuleState::UNKNOWN, retired.status);
        assert_eq!(
            PairAction::None,
            evaluate_status(&status(true, aggregate.status, ModuleState::RUNNING), false),
        );

        coordinator
            .stop_proxy_server("Test cleanup.".to_string())
            .await;
        wait_for_proxy_state(&coordinator, ModuleState::STOPPED).await;
    }

    #[tokio::test]
    async fn policy_update_failure_keeps_new_runtime_and_allows_old_port_reuse() {
        let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let old_port = occupied.local_addr().unwrap().port();
        let mut coordinator = coordinator();
        set_desired_port(&coordinator, old_port).await;
        coordinator.start_proxy_server(old_port).await;
        wait_for_proxy_state(&coordinator, ModuleState::STOPPED).await;
        let agent_status = coordinator.shared_state.get_agent_status_shared_state();
        let failed = agent_status
            .get_module_status(AgentStatusModule::ProxyServer)
            .await;
        assert!(failed.message.contains("Failed to bind"));
        assert_eq!(Some(old_port), coordinator.last_selected_local_port);
        let mut updates = agent_status.subscribe_runtime_status();
        updates.borrow_and_update();
        let redirector_state = coordinator.shared_state.get_redirector_shared_state();
        redirector_state.set_local_port(old_port).await.unwrap();

        // Missing BPF policies must not reject the selected runtime or restore the old port.
        set_desired_port(&coordinator, 0).await;
        assert!(coordinator.handoff_proxy_server(0, true).await);
        assert_eq!(Some(0), coordinator.last_selected_local_port);
        assert!(updates.has_changed().unwrap());
        let after = agent_status
            .get_module_status(AgentStatusModule::ProxyServer)
            .await;
        assert_eq!(ModuleState::RUNNING, after.status);
        let retired = agent_status
            .get_module_status(AgentStatusModule::ProxyListener(old_port))
            .await;
        assert_eq!(ModuleState::UNKNOWN, retired.status);
        assert_eq!(
            ModuleState::RUNNING,
            agent_status
                .get_module_status(AgentStatusModule::ProxyListener(0))
                .await
                .status,
        );
        let selected = coordinator.proxy_server_runtime.as_ref().unwrap();
        assert_eq!(0, selected.local_port);
        assert!(!selected.cancellation_token.is_cancelled());
        assert!(selected.listener_committed.is_cancelled());
        assert_eq!(0, redirector_state.get_local_port().await.unwrap());

        drop(occupied);
        set_desired_port(&coordinator, old_port).await;
        coordinator.start_proxy_server(old_port).await;
        wait_for_proxy_state(&coordinator, ModuleState::RUNNING).await;
        let restarted = agent_status
            .get_module_status(AgentStatusModule::ProxyListener(old_port))
            .await;
        assert_eq!(ModuleState::RUNNING, restarted.status);
        assert!(!restarted.message.contains("Failed to bind"));
        assert!(tokio::net::TcpStream::connect(("127.0.0.1", old_port))
            .await
            .is_ok());
        coordinator
            .stop_proxy_server("Test cleanup.".to_string())
            .await;
    }

    #[tokio::test]
    async fn failed_desired_runtime_and_policies_replace_healthy_old_listener() {
        let reserved = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = reserved.local_addr().unwrap().port();
        drop(reserved);
        let mut coordinator = coordinator();
        set_desired_port(&coordinator, port).await;
        coordinator.start_proxy_server(port).await;
        wait_for_proxy_state(&coordinator, ModuleState::RUNNING).await;
        let agent_status = coordinator.shared_state.get_agent_status_shared_state();
        let mut updates = agent_status.subscribe_runtime_status();
        updates.borrow_and_update();
        let redirector_state = coordinator.shared_state.get_redirector_shared_state();
        redirector_state.set_local_port(port).await.unwrap();

        let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let candidate_port = occupied.local_addr().unwrap().port();
        set_desired_port(&coordinator, candidate_port).await;
        assert!(coordinator.handoff_proxy_server(candidate_port, true).await);
        assert_eq!(Some(candidate_port), coordinator.last_selected_local_port);
        let failed = agent_status
            .get_module_status(AgentStatusModule::ProxyListener(candidate_port))
            .await;
        assert_eq!(ModuleState::STOPPED, failed.status);
        assert!(failed.message.contains("Failed to bind"));
        let selected = coordinator.proxy_server_runtime.as_ref().unwrap();
        assert_eq!(candidate_port, selected.local_port);
        assert!(selected.thread.is_some());
        assert!(!selected.cancellation_token.is_cancelled());
        assert_eq!(
            candidate_port,
            redirector_state.get_local_port().await.unwrap()
        );
        assert!(updates.has_changed().unwrap());
        assert_eq!(ModuleState::STOPPED, updates.borrow().proxy_server_state);
        assert_eq!(
            ModuleState::STOPPED,
            agent_status
                .get_module_status(AgentStatusModule::ProxyServer)
                .await
                .status,
        );
        let after = agent_status
            .get_module_status(AgentStatusModule::ProxyListener(port))
            .await;
        assert_eq!(ModuleState::UNKNOWN, after.status);
        let _retired_port = TcpListener::bind(("127.0.0.1", port)).await.unwrap();

        coordinator
            .stop_proxy_server("Test cleanup.".to_string())
            .await;
        assert_eq!(Some(candidate_port), coordinator.last_selected_local_port);
        assert!(!should_reconcile_proxy_port(
            &runtime_status(&coordinator),
            coordinator.last_selected_local_port,
        ));
    }

    #[tokio::test]
    async fn policy_update_failure_without_previous_runtime_keeps_new_listener() {
        let mut coordinator = coordinator();
        set_desired_port(&coordinator, 0).await;
        let agent_status = coordinator.shared_state.get_agent_status_shared_state();
        agent_status
            .set_module_state(ModuleState::STOPPED, AgentStatusModule::ProxyServer)
            .await
            .unwrap();
        let mut updates = agent_status.subscribe_runtime_status();
        updates.borrow_and_update();
        let redirector_state = coordinator.shared_state.get_redirector_shared_state();
        redirector_state
            .set_local_port(crate::common::constants::PROXY_AGENT_PORT)
            .await
            .unwrap();

        assert!(coordinator.handoff_proxy_server(0, true).await);
        let selected = coordinator.proxy_server_runtime.as_ref().unwrap();
        assert_eq!(0, selected.local_port);
        assert!(selected.listener_committed.is_cancelled());
        assert_eq!(0, redirector_state.get_local_port().await.unwrap());
        assert!(updates.has_changed().unwrap());
        assert_eq!(ModuleState::RUNNING, updates.borrow().proxy_server_state);
        assert_eq!(
            ModuleState::RUNNING,
            agent_status
                .get_module_status(AgentStatusModule::ProxyServer)
                .await
                .status,
        );
        assert_eq!(
            ModuleState::RUNNING,
            agent_status
                .get_module_status(AgentStatusModule::ProxyListener(0))
                .await
                .status,
        );
        coordinator
            .stop_proxy_server("Test cleanup.".to_string())
            .await;
        wait_for_proxy_state(&coordinator, ModuleState::STOPPED).await;
    }

    #[tokio::test]
    async fn startup_timeout_returns_owned_runtime_until_explicit_cleanup() {
        let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = occupied.local_addr().unwrap().port();
        let mut coordinator = coordinator();
        set_desired_port(&coordinator, port).await;

        let runtime = coordinator
            .start_proxy_runtime(port, Some(Duration::from_millis(20)))
            .await;
        assert_eq!(port, runtime.local_port);
        assert!(runtime.thread.is_some());
        assert!(!runtime.cancellation_token.is_cancelled());
        coordinator.proxy_server_runtime = Some(runtime);
        let agent_status = coordinator.shared_state.get_agent_status_shared_state();
        assert_eq!(
            ModuleState::STARTING,
            agent_status
                .get_module_status(AgentStatusModule::ProxyServer)
                .await
                .status,
        );

        tokio::time::timeout(
            Duration::from_secs(2),
            coordinator.stop_proxy_server("Test cleanup.".to_string()),
        )
        .await
        .unwrap();
        assert!(coordinator.proxy_server_runtime.is_none());
        wait_for_proxy_state(&coordinator, ModuleState::STOPPED).await;
    }

    #[tokio::test]
    async fn initial_listener_does_not_override_requested_port() {
        let mut coordinator = coordinator();
        let desired_port = crate::common::constants::PROXY_AGENT_PORT + 1;
        set_desired_port(&coordinator, desired_port).await;
        coordinator.start_proxy_server(0).await;
        let agent_status = coordinator.shared_state.get_agent_status_shared_state();
        let snapshot = agent_status.subscribe_runtime_status().borrow().clone();
        assert_eq!(desired_port, snapshot.desired_local_port);
        assert_eq!(ModuleState::UNKNOWN, snapshot.proxy_server_state);
        assert_eq!(
            ModuleState::UNKNOWN,
            agent_status
                .get_module_status(AgentStatusModule::ProxyServer)
                .await
                .status,
        );
        coordinator
            .stop_proxy_server("Test cleanup.".to_string())
            .await;
    }

    fn status(
        soft_audit_enabled: bool,
        proxy_server_state: ModuleState,
        redirector_state: ModuleState,
    ) -> RuntimeStatusSnapshot {
        RuntimeStatusSnapshot {
            soft_audit_enabled,
            proxy_server_state,
            redirector_state,
            desired_local_port: crate::common::constants::PROXY_AGENT_PORT,
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
    fn proxy_port_change_is_reconciled_while_redirector_is_stopped() {
        let mut status = status(false, ModuleState::RUNNING, ModuleState::STOPPED);
        status.desired_local_port = 3081;

        assert!(should_reconcile_proxy_port(&status, Some(3080)));
    }

    #[test]
    fn changed_port_is_reconciled_before_any_listener_is_selected() {
        let mut status = status(false, ModuleState::STOPPED, ModuleState::RUNNING);
        status.desired_local_port = 3081;

        assert!(should_reconcile_proxy_port(&status, None));
        status.desired_local_port = crate::common::constants::PROXY_AGENT_PORT;
        assert!(!should_reconcile_proxy_port(&status, None));
    }

    #[test]
    fn soft_audit_does_not_suppress_proxy_port_reconciliation() {
        let mut status = status(true, ModuleState::STOPPED, ModuleState::STOPPED);
        status.desired_local_port = 3081;

        assert!(should_reconcile_proxy_port(&status, Some(3080)));
        assert!(should_reconcile_proxy_port(&status, None));
        assert!(!should_reconcile_proxy_port(&status, Some(3081)));
    }

    #[test]
    fn returning_to_default_port_is_reconciled_after_custom_port_selection() {
        let status = status(true, ModuleState::STOPPED, ModuleState::STOPPED);
        assert!(should_reconcile_proxy_port(&status, Some(3081)));
        assert!(!should_reconcile_proxy_port(
            &status,
            Some(crate::common::constants::PROXY_AGENT_PORT),
        ));
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
