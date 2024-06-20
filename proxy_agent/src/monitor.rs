// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use crate::common::{config, logger};
use crate::{
    key_keeper,
    shared_state::{key_keeper_wrapper, SharedState},
};
use once_cell::sync::Lazy;
use proxy_agent_shared::proxy_agent_aggregate_status::{ModuleState, ProxyAgentDetailStatus};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

static SHUT_DOWN: Lazy<Arc<AtomicBool>> = Lazy::new(|| Arc::new(AtomicBool::new(false)));
static mut STATUS_MESSAGE: Lazy<String> =
    Lazy::new(|| String::from("Monitor thread has not started yet."));

pub fn start_async(interval: Duration, shared_state: Arc<Mutex<SharedState>>) {
    _ = thread::Builder::new()
        .name("monitor".to_string())
        .spawn(move || {
            start(interval, shared_state);
        });
}

fn start(mut interval: Duration, shared_state: Arc<Mutex<SharedState>>) {
    let shutdown = SHUT_DOWN.clone();
    if interval == Duration::default() {
        interval = Duration::from_secs(60);
    }

    unsafe {
        *STATUS_MESSAGE = "Monitor thread started".to_string();
    }

    loop {
        if shutdown.load(Ordering::Relaxed) {
            let message = "Stop signal received, exiting the monitor thread.";
            unsafe {
                *STATUS_MESSAGE = message.to_string();
            }
            logger::write_warning(message.to_string());

            break;
        }

        if redirect_should_run(shared_state.clone()) {
            // TODO:: check redirector started or not
        }

        thread::sleep(interval);
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

pub fn stop() {
    SHUT_DOWN.store(true, Ordering::Relaxed);
}

pub fn get_status() -> ProxyAgentDetailStatus {
    let shutdown = SHUT_DOWN.clone();

    let status = if shutdown.load(Ordering::Relaxed) {
        ModuleState::STOPPED.to_string()
    } else {
        ModuleState::RUNNING.to_string()
    };

    ProxyAgentDetailStatus {
        status,
        message: unsafe { STATUS_MESSAGE.to_string() },
        states: None,
    }
}
