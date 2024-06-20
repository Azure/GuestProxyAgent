// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

use crate::key_keeper::key::Key;
use std::sync::{Arc, Mutex};

const UNKNOWN_STATUS_MESSAGE: &str = "Status unknown.";

#[derive(Clone)]
pub struct SharedState {
    // key_keeper
    key: Option<Key>,
    current_secure_channel_state: String,
    wireserver_rule_id: String,
    imds_rule_id: String,
    key_keeper_shutdown: bool,
    key_keeper_status_message: String,
    // proxy_listener
    proxy_listner_shutdown: bool,
    connection_count: u128,
    proxy_listner_status_message: String,
    // Add more state fields as needed,
    // keep the fields related to the same module together
    // keep the fields as private to avoid the direct access from outside via Arc<Mutex<SharedState>>.lock().unwrap()
    // use wrapper functions to access the state fields, it does quick release the lock
}

pub fn new_shared_state() -> Arc<Mutex<SharedState>> {
    let shared_state = SharedState::default();
    Arc::new(Mutex::new(shared_state))
}

impl Default for SharedState {
    fn default() -> Self {
        SharedState {
            // key_keeper
            key: None,
            current_secure_channel_state: crate::key_keeper::UNKNOWN_STATE.to_string(),
            wireserver_rule_id: String::new(),
            imds_rule_id: String::new(),
            key_keeper_shutdown: false,
            key_keeper_status_message: UNKNOWN_STATUS_MESSAGE.to_string(),
            // proxy_listener
            proxy_listner_shutdown: false,
            connection_count: 0,
            proxy_listner_status_message: UNKNOWN_STATUS_MESSAGE.to_string(),
        }
    }
}

/// wrapper functions for KeyKeeper related state fields
pub mod key_keeper_wrapper {
    use super::SharedState;
    use crate::key_keeper::key::Key;
    use std::sync::{Arc, Mutex};

    pub fn set_key(shared_state: Arc<Mutex<SharedState>>, key: Key) {
        shared_state.lock().unwrap().key = Some(key);
    }

    pub fn get_key(shared_state: Arc<Mutex<SharedState>>) -> Option<Key> {
        shared_state.lock().unwrap().key.clone()
    }

    pub fn get_current_key_value(shared_state: Arc<Mutex<SharedState>>) -> Option<String> {
        get_key(shared_state).map(|k| k.key)
    }

    pub fn get_current_key_guid(shared_state: Arc<Mutex<SharedState>>) -> Option<String> {
        get_key(shared_state).map(|k| k.guid)
    }

    pub fn get_current_key_incarnation(shared_state: Arc<Mutex<SharedState>>) -> Option<u32> {
        get_key(shared_state).map(|k| k.incarnationId)?
    }

    pub fn set_current_secure_channel_state(shared_state: Arc<Mutex<SharedState>>, state: String) {
        shared_state.lock().unwrap().current_secure_channel_state = state;
    }

    pub fn get_current_secure_channel_state(shared_state: Arc<Mutex<SharedState>>) -> String {
        shared_state
            .lock()
            .unwrap()
            .current_secure_channel_state
            .to_string()
    }

    pub fn set_wireserver_rule_id(shared_state: Arc<Mutex<SharedState>>, rule_id: String) {
        shared_state.lock().unwrap().wireserver_rule_id = rule_id;
    }

    pub fn get_wireserver_rule_id(shared_state: Arc<Mutex<SharedState>>) -> String {
        shared_state.lock().unwrap().wireserver_rule_id.to_string()
    }

    pub fn set_imds_rule_id(shared_state: Arc<Mutex<SharedState>>, rule_id: String) {
        shared_state.lock().unwrap().imds_rule_id = rule_id;
    }

    pub fn get_imds_rule_id(shared_state: Arc<Mutex<SharedState>>) -> String {
        shared_state.lock().unwrap().imds_rule_id.to_string()
    }

    pub fn set_shutdown(shared_state: Arc<Mutex<SharedState>>, shutdown: bool) {
        shared_state.lock().unwrap().key_keeper_shutdown = shutdown;
    }

    pub fn get_shutdown(shared_state: Arc<Mutex<SharedState>>) -> bool {
        shared_state.lock().unwrap().key_keeper_shutdown
    }

    pub fn set_status_message(shared_state: Arc<Mutex<SharedState>>, status_message: String) {
        shared_state.lock().unwrap().key_keeper_status_message = status_message;
    }

    pub fn get_status_message(shared_state: Arc<Mutex<SharedState>>) -> String {
        shared_state
            .lock()
            .unwrap()
            .key_keeper_status_message
            .to_string()
    }
}

pub mod proxy_listener_wrapper {
    use super::SharedState;
    use std::sync::{Arc, Mutex};

    pub fn set_shutdown(shared_state: Arc<Mutex<SharedState>>, shutdown: bool) {
        shared_state.lock().unwrap().proxy_listner_shutdown = shutdown;
    }

    pub fn get_shutdown(shared_state: Arc<Mutex<SharedState>>) -> bool {
        shared_state.lock().unwrap().proxy_listner_shutdown
    }

    pub fn set_connection_count(shared_state: Arc<Mutex<SharedState>>, count: u128) {
        shared_state.lock().unwrap().connection_count = count;
    }

    pub fn get_connection_count(shared_state: Arc<Mutex<SharedState>>) -> u128 {
        shared_state.lock().unwrap().connection_count
    }

    pub fn set_status_message(shared_state: Arc<Mutex<SharedState>>, status_message: String) {
        shared_state.lock().unwrap().proxy_listner_status_message = status_message;
    }

    pub fn get_status_message(shared_state: Arc<Mutex<SharedState>>) -> String {
        shared_state
            .lock()
            .unwrap()
            .proxy_listner_status_message
            .to_string()
    }
}
