// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

use crate::proxy::authorization_rules::AuthorizationRules;
use crate::redirector;
use crate::telemetry::event_reader::VMMetaData;
use crate::{key_keeper::key::Key, proxy::User};
use proxy_agent_shared::proxy_agent_aggregate_status::ProxyConnectionSummary;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

#[cfg(windows)]
use windows_service::service_control_handler::ServiceStatusHandle;

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
    // proxy_authenticator
    wireserver_rules: Option<AuthorizationRules>,
    imds_rules: Option<AuthorizationRules>,
    // provision
    provision_state: u8,
    provision_event_log_threads_initialized: bool,
    // redirector
    redirector_is_started: bool,
    redirector_status_message: String,
    redirector_local_port: u16,
    bpf_object: Option<Arc<Mutex<redirector::RedirectorObject>>>,
    // monitor
    monitor_shutdown: bool,
    monitor_status_message: String,
    // agent_status
    agent_status_shutdown: bool,
    proxy_summary: HashMap<String, ProxyConnectionSummary>,
    failed_authenticate_summary: HashMap<String, ProxyConnectionSummary>,
    // proxy
    proxy_uers: HashMap<u64, User>,
    // telemetry
    vm_metadata: Option<VMMetaData>,
    telemetry_reader_shutdown: bool,
    telemetry_logger_shutdown: bool,
    telemetry_logger_status_message: String,
    // service
    #[cfg(windows)]
    service_status_handle: Option<ServiceStatusHandle>,
    // Add more state fields as needed,
    // keep the fields related to the same module together
    // keep the fields as private to avoid the direct access from outside via Arc<Mutex<SharedState>>.lock().unwrap()
    // use wrapper functions to access the state fields, it does quick release the lock
}

impl SharedState {
    pub fn new() -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(SharedState::default()))
    }
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
            // proxy_authenticator
            wireserver_rules: None,
            imds_rules: None,
            // provision
            provision_state: 0,
            provision_event_log_threads_initialized: false,
            // redirector
            redirector_is_started: false,
            redirector_status_message: UNKNOWN_STATUS_MESSAGE.to_string(),
            redirector_local_port: 0,
            bpf_object: None,
            // monitor
            monitor_shutdown: false,
            monitor_status_message: UNKNOWN_STATUS_MESSAGE.to_string(),
            // agent_status
            agent_status_shutdown: false,
            proxy_summary: HashMap::new(),
            failed_authenticate_summary: HashMap::new(),
            // proxy
            proxy_uers: HashMap::new(),
            // telemetry
            vm_metadata: None,
            telemetry_reader_shutdown: false,
            telemetry_logger_shutdown: false,
            telemetry_logger_status_message: UNKNOWN_STATUS_MESSAGE.to_string(),
            // service
            #[cfg(windows)]
            service_status_handle: None,
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

    /// Update the current secure channel state
    /// # Arguments
    /// * `shared_state` - Arc<Mutex<SharedState>>
    /// * `state` - String
    /// # Returns
    /// * `bool` - true if the state is update successfully
    /// *        - false if state is the same as the current state  
    pub fn update_current_secure_channel_state(
        shared_state: Arc<Mutex<SharedState>>,
        state: String,
    ) -> bool {
        let mut current_state = shared_state.lock().unwrap();
        if current_state.current_secure_channel_state == state {
            false
        } else {
            current_state.current_secure_channel_state = state;
            true
        }
    }

    pub fn get_current_secure_channel_state(shared_state: Arc<Mutex<SharedState>>) -> String {
        shared_state
            .lock()
            .unwrap()
            .current_secure_channel_state
            .to_string()
    }

    /// Update the WireServer rule ID
    /// # Arguments
    /// * `shared_state` - Arc<Mutex<SharedState>>
    /// * `rule_id` - String
    /// # Returns
    /// * `bool` - true if the rule ID is update successfully
    /// *        - false if rule ID is the same as the current state  
    /// * `String` - the rule Id before the update operation
    pub fn update_wireserver_rule_id(
        shared_state: Arc<Mutex<SharedState>>,
        rule_id: String,
    ) -> (bool, String) {
        let mut state = shared_state.lock().unwrap();
        let old_rule_id = state.wireserver_rule_id.clone();
        if old_rule_id == rule_id {
            (false, old_rule_id)
        } else {
            state.wireserver_rule_id = rule_id;
            (true, old_rule_id)
        }
    }

    pub fn get_wireserver_rule_id(shared_state: Arc<Mutex<SharedState>>) -> String {
        shared_state.lock().unwrap().wireserver_rule_id.to_string()
    }

    /// Update the IMDS rule ID
    /// # Arguments
    /// * `shared_state` - Arc<Mutex<SharedState>>
    /// * `rule_id` - String
    /// # Returns
    /// * `bool` - true if the rule ID is update successfully
    /// * `String` - the rule Id before the update operation
    pub fn update_imds_rule_id(
        shared_state: Arc<Mutex<SharedState>>,
        rule_id: String,
    ) -> (bool, String) {
        let mut state = shared_state.lock().unwrap();
        let old_rule_id = state.imds_rule_id.clone();
        if old_rule_id == rule_id {
            (false, old_rule_id)
        } else {
            state.imds_rule_id = rule_id;
            (true, old_rule_id)
        }
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

    /// Increase the connection count
    /// # Arguments
    /// * `shared_state` - Arc<Mutex<SharedState>>
    /// # Returns
    /// * `u128` - the updated connection count
    /// # Remarks
    /// * If the connection count reaches u128::MAX, it will reset to 0
    pub fn increase_connection_count(shared_state: Arc<Mutex<SharedState>>) -> u128 {
        let mut state = shared_state.lock().unwrap();
        (state.connection_count, _) = state.connection_count.overflowing_add(1);
        state.connection_count
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

pub mod proxy_authenticator_wrapper {
    use super::SharedState;
    use crate::proxy::authorization_rules::AuthorizationRules;
    use std::sync::{Arc, Mutex};

    pub fn set_wireserver_rules(
        shared_state: Arc<Mutex<SharedState>>,
        rules: Option<AuthorizationRules>,
    ) {
        shared_state.lock().unwrap().wireserver_rules = rules;
    }

    pub fn get_wireserver_rules(
        shared_state: Arc<Mutex<SharedState>>,
    ) -> Option<AuthorizationRules> {
        shared_state.lock().unwrap().wireserver_rules.clone()
    }

    pub fn set_imds_rules(
        shared_state: Arc<Mutex<SharedState>>,
        rules: Option<AuthorizationRules>,
    ) {
        shared_state.lock().unwrap().imds_rules = rules;
    }

    pub fn get_imds_rules(shared_state: Arc<Mutex<SharedState>>) -> Option<AuthorizationRules> {
        shared_state.lock().unwrap().imds_rules.clone()
    }
}

pub mod provision_wrapper {
    use super::SharedState;
    use std::sync::{Arc, Mutex};

    /// Update the provision state
    /// # Arguments
    /// * `shared_state` - Arc<Mutex<SharedState>>
    /// * `state` - u8
    /// # Returns
    /// * `u8` - the updated provision state
    /// # Remarks
    /// * The provision state is a bit field, the state is updated by OR operation
    pub fn update_state(shared_state: Arc<Mutex<SharedState>>, state: u8) -> u8 {
        let mut shared_state = shared_state.lock().unwrap();
        shared_state.provision_state |= state;
        shared_state.provision_state
    }

    pub fn get_state(shared_state: Arc<Mutex<SharedState>>) -> u8 {
        shared_state.lock().unwrap().provision_state
    }

    pub fn set_event_log_threads_initialized(
        shared_state: Arc<Mutex<SharedState>>,
        initialized: bool,
    ) {
        shared_state
            .lock()
            .unwrap()
            .provision_event_log_threads_initialized = initialized;
    }

    pub fn get_event_log_threads_initialized(shared_state: Arc<Mutex<SharedState>>) -> bool {
        shared_state
            .lock()
            .unwrap()
            .provision_event_log_threads_initialized
    }
}

pub mod redirector_wrapper {
    use super::SharedState;
    use crate::redirector;
    use std::sync::{Arc, Mutex};

    pub fn set_is_started(shared_state: Arc<Mutex<SharedState>>, is_started: bool) {
        shared_state.lock().unwrap().redirector_is_started = is_started;
    }

    pub fn get_is_started(shared_state: Arc<Mutex<SharedState>>) -> bool {
        shared_state.lock().unwrap().redirector_is_started
    }

    pub fn set_status_message(shared_state: Arc<Mutex<SharedState>>, status_message: String) {
        shared_state.lock().unwrap().redirector_status_message = status_message;
    }

    pub fn get_status_message(shared_state: Arc<Mutex<SharedState>>) -> String {
        shared_state
            .lock()
            .unwrap()
            .redirector_status_message
            .to_string()
    }

    pub fn set_local_port(shared_state: Arc<Mutex<SharedState>>, local_port: u16) {
        shared_state.lock().unwrap().redirector_local_port = local_port;
    }

    pub fn get_local_port(shared_state: Arc<Mutex<SharedState>>) -> u16 {
        shared_state.lock().unwrap().redirector_local_port
    }

    pub fn set_bpf_object(
        shared_state: Arc<Mutex<SharedState>>,
        bpf_object: redirector::BpfObject,
    ) {
        shared_state.lock().unwrap().bpf_object = Some(Arc::new(Mutex::new(
            redirector::RedirectorObject(bpf_object),
        )));
    }

    pub fn clear_bpf_object(shared_state: Arc<Mutex<SharedState>>) {
        shared_state.lock().unwrap().bpf_object = None;
    }

    pub fn get_bpf_object(
        shared_state: Arc<Mutex<SharedState>>,
    ) -> Option<Arc<Mutex<redirector::RedirectorObject>>> {
        shared_state.lock().unwrap().bpf_object.clone()
    }
}

pub mod monitor_wrapper {
    use super::SharedState;
    use std::sync::{Arc, Mutex};

    pub fn set_shutdown(shared_state: Arc<Mutex<SharedState>>, shutdown: bool) {
        shared_state.lock().unwrap().monitor_shutdown = shutdown;
    }

    pub fn get_shutdown(shared_state: Arc<Mutex<SharedState>>) -> bool {
        shared_state.lock().unwrap().monitor_shutdown
    }

    pub fn set_status_message(shared_state: Arc<Mutex<SharedState>>, status_message: String) {
        shared_state.lock().unwrap().monitor_status_message = status_message;
    }

    pub fn get_status_message(shared_state: Arc<Mutex<SharedState>>) -> String {
        shared_state
            .lock()
            .unwrap()
            .monitor_status_message
            .to_string()
    }
}

pub mod agent_status_wrapper {
    use proxy_agent_shared::proxy_agent_aggregate_status::ProxyConnectionSummary;

    use crate::proxy::proxy_summary::ProxySummary;

    use super::SharedState;
    use std::sync::{Arc, Mutex};

    pub fn set_shutdown(shared_state: Arc<Mutex<SharedState>>, shutdown: bool) {
        shared_state.lock().unwrap().agent_status_shutdown = shutdown;
    }

    pub fn get_shutdown(shared_state: Arc<Mutex<SharedState>>) -> bool {
        shared_state.lock().unwrap().agent_status_shutdown
    }

    pub fn clear_all_summary(shared_state: Arc<Mutex<SharedState>>) {
        let mut state = shared_state.lock().unwrap();
        state.proxy_summary.clear();
        state.failed_authenticate_summary.clear();
    }

    pub fn add_one_connection_summary(
        shared_state: Arc<Mutex<SharedState>>,
        summary: ProxySummary,
        add_to_failed_authenticate_summry: bool,
    ) {
        let mut shared_state = shared_state.lock().unwrap();
        let summary_map = if add_to_failed_authenticate_summry {
            &mut shared_state.proxy_summary
        } else {
            &mut shared_state.failed_authenticate_summary
        };

        let summary_key = summary.to_key_string();
        if let std::collections::hash_map::Entry::Vacant(e) = summary_map.entry(summary_key.clone())
        {
            e.insert(summary.to_proxy_connection_summary());
        } else if let Some(connection_summary) = summary_map.get_mut(&summary_key) {
            //increase_count(connection_summary);
            connection_summary.count += 1;
        }
    }

    pub fn get_all_connection_summary(
        shared_state: Arc<Mutex<SharedState>>,
        from_failed_authenticate: bool,
    ) -> Vec<ProxyConnectionSummary> {
        let shared_state = shared_state.lock().unwrap();
        let summary_map = if from_failed_authenticate {
            &shared_state.proxy_summary
        } else {
            &shared_state.failed_authenticate_summary
        };
        let mut copy_summary: Vec<ProxyConnectionSummary> = Vec::new();
        for (_, connection_summary) in summary_map.iter() {
            copy_summary.push(connection_summary.clone());
        }
        copy_summary
    }
}

pub mod proxy_wrapper {
    use super::SharedState;
    use crate::proxy::User;
    use std::sync::{Arc, Mutex};

    pub fn add_user(shared_state: Arc<Mutex<SharedState>>, user: User) {
        shared_state
            .lock()
            .unwrap()
            .proxy_uers
            .insert(user.logon_id, user);
    }

    pub fn get_user(shared_state: Arc<Mutex<SharedState>>, logon_id: u64) -> Option<User> {
        shared_state
            .lock()
            .unwrap()
            .proxy_uers
            .get(&logon_id)
            .cloned()
    }

    pub fn get_users_count(shared_state: Arc<Mutex<SharedState>>) -> usize {
        shared_state.lock().unwrap().proxy_uers.len()
    }

    // TODO:: need caller to refresh the users info regularly
    pub fn clear_all_users(shared_state: Arc<Mutex<SharedState>>) {
        shared_state.lock().unwrap().proxy_uers.clear();
    }
}

pub mod telemetry_wrapper {
    use super::SharedState;
    use crate::telemetry::event_reader::VMMetaData;
    use std::sync::{Arc, Mutex};

    pub fn set_vm_metadata(shared_state: Arc<Mutex<SharedState>>, vm_metadata: VMMetaData) {
        shared_state.lock().unwrap().vm_metadata = Some(vm_metadata);
    }

    pub fn get_vm_metadata(shared_state: Arc<Mutex<SharedState>>) -> Option<VMMetaData> {
        shared_state.lock().unwrap().vm_metadata.clone()
    }

    pub fn set_reader_shutdown(shared_state: Arc<Mutex<SharedState>>, shutdown: bool) {
        shared_state.lock().unwrap().telemetry_reader_shutdown = shutdown;
    }

    pub fn get_reader_shutdown(shared_state: Arc<Mutex<SharedState>>) -> bool {
        shared_state.lock().unwrap().telemetry_reader_shutdown
    }

    pub fn set_logger_shutdown(shared_state: Arc<Mutex<SharedState>>, shutdown: bool) {
        shared_state.lock().unwrap().telemetry_logger_shutdown = shutdown;
    }

    pub fn get_logger_shutdown(shared_state: Arc<Mutex<SharedState>>) -> bool {
        shared_state.lock().unwrap().telemetry_logger_shutdown
    }

    pub fn set_logger_status_message(
        shared_state: Arc<Mutex<SharedState>>,
        status_message: String,
    ) {
        shared_state.lock().unwrap().telemetry_logger_status_message = status_message;
    }

    pub fn get_logger_status_message(shared_state: Arc<Mutex<SharedState>>) -> String {
        shared_state
            .lock()
            .unwrap()
            .telemetry_logger_status_message
            .to_string()
    }
}

#[cfg(windows)]
pub mod service_wrapper {
    use super::SharedState;
    use std::sync::{Arc, Mutex};
    use windows_service::service_control_handler::ServiceStatusHandle;

    pub fn set_service_status_handle(
        shared_state: Arc<Mutex<SharedState>>,
        status_handle: ServiceStatusHandle,
    ) {
        shared_state.lock().unwrap().service_status_handle = Some(status_handle);
    }

    pub fn get_service_status_handle(
        shared_state: Arc<Mutex<SharedState>>,
    ) -> Option<ServiceStatusHandle> {
        shared_state.lock().unwrap().service_status_handle
    }
}
