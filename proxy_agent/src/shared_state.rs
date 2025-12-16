// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

pub mod access_control_wrapper;
pub mod agent_status_wrapper;
pub mod connection_summary_wrapper;
pub mod key_keeper_wrapper;
pub mod provision_wrapper;
pub mod proxy_server_wrapper;
pub mod redirector_wrapper;

use proxy_agent_shared::common_state::CommonState;
use tokio_util::sync::CancellationToken;

const UNKNOWN_STATUS_MESSAGE: &str = "Status unknown.";

/// The shared state is used to share the state between different modules.
/// It contains the cancellation token, which is used to cancel the agent when the agent is stopped.
/// It also contains the senders for the key keeper, telemetry event, provision, agent status, redirector, and proxy server modules.
/// The shared state is used to start the modules and get the senders for the modules.
/// The shared state is used to get the cancellation token and cancel the cancellation token.
/// Example:
/// ```rust
/// use proxy_agent::shared_state::SharedState;
/// let shared_state = SharedState::start_all();
/// let key_keeper_shared_state = shared_state.get_key_keeper_shared_state();
/// let common_state = shared_state.get_common_state();
/// let provision_shared_state = shared_state.get_provision_shared_state();
/// let agent_status_shared_state = shared_state.get_agent_status_shared_state();
/// let redirector_shared_state = shared_state.get_redirector_shared_state();
/// let proxy_server_shared_state = shared_state.get_proxy_server_shared_state();
/// let cancellation_token = shared_state.get_cancellation_token();
/// shared_state.cancel_cancellation_token();
/// ```
#[derive(Clone)]
pub struct SharedState {
    /// The cancellation token is used to cancel the agent when the agent is stopped
    cancellation_token: CancellationToken,
    /// The sender for the common states
    common_state: proxy_agent_shared::common_state::CommonState,
    /// The sender for the key keeper module
    key_keeper_shared_state: key_keeper_wrapper::KeyKeeperSharedState,
    /// The sender for the provision module
    provision_shared_state: provision_wrapper::ProvisionSharedState,
    /// The sender for the agent status module
    agent_status_shared_state: agent_status_wrapper::AgentStatusSharedState,
    /// The sender for the redirector module
    redirector_shared_state: redirector_wrapper::RedirectorSharedState,
    /// The sender for the proxy server module
    proxy_server_shared_state: proxy_server_wrapper::ProxyServerSharedState,
    /// The sender for the access control module
    access_control_shared_state: access_control_wrapper::AccessControlSharedState,
    /// The sender for the connection summary module
    connection_summary_shared_state: connection_summary_wrapper::ConnectionSummarySharedState,
}

impl SharedState {
    pub fn start_all() -> Self {
        SharedState {
            cancellation_token: CancellationToken::new(),
            key_keeper_shared_state: key_keeper_wrapper::KeyKeeperSharedState::start_new(),
            common_state: CommonState::start_new(),
            provision_shared_state: provision_wrapper::ProvisionSharedState::start_new(),
            agent_status_shared_state: agent_status_wrapper::AgentStatusSharedState::start_new(),
            redirector_shared_state: redirector_wrapper::RedirectorSharedState::start_new(),
            proxy_server_shared_state: proxy_server_wrapper::ProxyServerSharedState::start_new(),
            access_control_shared_state:
                access_control_wrapper::AccessControlSharedState::start_new(),
            connection_summary_shared_state:
                connection_summary_wrapper::ConnectionSummarySharedState::start_new(),
        }
    }

    pub fn get_key_keeper_shared_state(&self) -> key_keeper_wrapper::KeyKeeperSharedState {
        self.key_keeper_shared_state.clone()
    }

    pub fn get_common_state(&self) -> CommonState {
        self.common_state.clone()
    }

    pub fn get_provision_shared_state(&self) -> provision_wrapper::ProvisionSharedState {
        self.provision_shared_state.clone()
    }

    pub fn get_agent_status_shared_state(&self) -> agent_status_wrapper::AgentStatusSharedState {
        self.agent_status_shared_state.clone()
    }

    pub fn get_redirector_shared_state(&self) -> redirector_wrapper::RedirectorSharedState {
        self.redirector_shared_state.clone()
    }

    pub fn get_proxy_server_shared_state(&self) -> proxy_server_wrapper::ProxyServerSharedState {
        self.proxy_server_shared_state.clone()
    }

    pub fn get_access_control_shared_state(
        &self,
    ) -> access_control_wrapper::AccessControlSharedState {
        self.access_control_shared_state.clone()
    }

    pub fn get_connection_summary_shared_state(
        &self,
    ) -> connection_summary_wrapper::ConnectionSummarySharedState {
        self.connection_summary_shared_state.clone()
    }

    pub fn get_cancellation_token(&self) -> CancellationToken {
        self.cancellation_token.clone()
    }

    pub fn cancel_cancellation_token(&self) {
        self.cancellation_token.cancel();
    }
}

/// The shared state for the lower priority event threads, including event logger & reader tasks and status reporting task
/// It contains the cancellation token, which is used to cancel the event threads when the agent is stopped.
/// It also contains the senders for the key keeper, provision, agent status, and connection summary modules.
/// This struct contains multiple shared states to avoid too_many_arguments error from `cargo clippy`.
#[derive(Clone)]
pub struct EventThreadsSharedState {
    pub cancellation_token: CancellationToken,
    pub common_state: CommonState,
    pub key_keeper_shared_state: key_keeper_wrapper::KeyKeeperSharedState,
    pub provision_shared_state: provision_wrapper::ProvisionSharedState,
    pub agent_status_shared_state: agent_status_wrapper::AgentStatusSharedState,
    pub connection_summary_shared_state: connection_summary_wrapper::ConnectionSummarySharedState,
}

impl EventThreadsSharedState {
    pub fn new(shared_state: &SharedState) -> Self {
        EventThreadsSharedState {
            cancellation_token: shared_state.get_cancellation_token(),
            common_state: shared_state.get_common_state(),
            key_keeper_shared_state: shared_state.get_key_keeper_shared_state(),
            provision_shared_state: shared_state.get_provision_shared_state(),
            agent_status_shared_state: shared_state.get_agent_status_shared_state(),
            connection_summary_shared_state: shared_state.get_connection_summary_shared_state(),
        }
    }
}
