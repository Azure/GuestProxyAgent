// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use crate::common::{config, logger};
use crate::shared_state::monitor_wrapper;
use crate::{
    key_keeper,
    shared_state::{key_keeper_wrapper, SharedState},
};
use proxy_agent_shared::proxy_agent_aggregate_status::{ModuleState, ProxyAgentDetailStatus};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub async fn start_async(interval: Duration, shared_state: Arc<Mutex<SharedState>>) {
    tokio::spawn(async move {
        start(interval, shared_state).await;
    });
}

async fn start(mut interval: Duration, shared_state: Arc<Mutex<SharedState>>) {
    if interval == Duration::default() {
        interval = Duration::from_secs(60);
    }

    monitor_wrapper::set_status_message(shared_state.clone(), "Monitor task started".to_string());
    loop {
        if monitor_wrapper::get_shutdown(shared_state.clone()) {
            let message = "Stop signal received, exiting the monitor task.";
            monitor_wrapper::set_status_message(shared_state.clone(), message.to_string());
            logger::write_warning(message.to_string());

            break;
        }

        if redirect_should_run(shared_state.clone()) {
            // TODO:: check redirector started or not
        }

        tokio::time::sleep(interval).await;
    }
}

fn redirect_should_run(shared_state: Arc<Mutex<SharedState>>) -> bool {
    if key_keeper_wrapper::get_current_secure_channel_state(shared_state.clone())
        != key_keeper::DISABLE_STATE
    {
        true
    } else {
        config::get_start_redirector()
    }
}

pub fn stop(shared_state: Arc<Mutex<SharedState>>) {
    monitor_wrapper::set_shutdown(shared_state, true);
}

pub fn get_status(shared_state: Arc<Mutex<SharedState>>) -> ProxyAgentDetailStatus {
    let status = if monitor_wrapper::get_shutdown(shared_state.clone()) {
        ModuleState::STOPPED.to_string()
    } else {
        ModuleState::RUNNING.to_string()
    };

    ProxyAgentDetailStatus {
        status,
        message: monitor_wrapper::get_status_message(shared_state.clone()),
        states: None,
    }
}
