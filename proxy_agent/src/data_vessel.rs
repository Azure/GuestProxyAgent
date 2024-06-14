// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

use crate::{common::logger, key_keeper::key::Key};
use std::sync::mpsc::Sender;

const UNKNOWN_STATUS_MESSAGE: &str = "Status unknown.";
pub enum DataAction {
    Stop,
    // KeyKeeper
    KeyKeeperSetKey {
        key: Option<Key>,
        response: std::sync::mpsc::Sender<bool>,
    },
    KeyKeeperGetKeyValue {
        response: std::sync::mpsc::Sender<Option<Key>>,
    },
    KeyKeeperSetSecureChannelState {
        state: String,
        response: std::sync::mpsc::Sender<bool>,
    },
    KeyKeeperGetSecureChannelState {
        response: std::sync::mpsc::Sender<String>,
    },
    KeyKeeperSetStatusMessage {
        status_message: String,
        response: std::sync::mpsc::Sender<bool>,
    },
    KeyKeeperGetStatusMessage {
        response: std::sync::mpsc::Sender<String>,
    },
    KeyKeeperSetWireserverRuleId {
        wireserver_rule_id: String,
        response: std::sync::mpsc::Sender<bool>,
    },
    KeyKeeperGetWireserverRuleId {
        response: std::sync::mpsc::Sender<String>,
    },
    KeyKeeperSetImdsRuleId {
        imds_rule_id: String,
        response: std::sync::mpsc::Sender<bool>,
    },
    KeyKeeperGetImdsRuleId {
        response: std::sync::mpsc::Sender<String>,
    },
    KeyKeeperSetShutdown {
        shutdown: bool,
        response: std::sync::mpsc::Sender<bool>,
    },
    KeyKeeperGetShutdown {
        response: std::sync::mpsc::Sender<bool>,
    },
    // ProxyListener
    ProxyListenerSetConnectionCount {
        count: u128,
        response: std::sync::mpsc::Sender<bool>,
    },
    ProxyListenerGetConnectionCount {
        response: std::sync::mpsc::Sender<u128>,
    },
    ProxyListenerSetStatusMessage {
        status_message: String,
        response: std::sync::mpsc::Sender<bool>,
    },
    ProxyListenerGetStatusMessage {
        response: std::sync::mpsc::Sender<String>,
    },
    ProxyListenerSetShutdown {
        shutdown: bool,
        response: std::sync::mpsc::Sender<bool>,
    },
    ProxyListenerGetShutdown {
        response: std::sync::mpsc::Sender<bool>,
    },
}

#[derive(Clone, Debug)]
pub struct DataVessel {
    sender: Sender<DataAction>,
}
impl DataVessel {
    pub fn start_new_async() -> Self {
        let (sender, receiver) = std::sync::mpsc::channel::<DataAction>();

        std::thread::spawn(move || {
            // chached data are defined here
            let mut current_key: Option<Key> = None;
            let mut current_secure_channel_state: String =
                crate::key_keeper::UNKNOWN_STATE.to_string();
            let mut wireserver_rule_id: String = String::new();
            let mut imds_rule_id: String = String::new();
            let mut key_keeper_status_message: String = UNKNOWN_STATUS_MESSAGE.to_string();
            let mut key_keeper_shutdown: bool = false;
            let mut proxy_listner_shutdown: bool = false;
            let mut connection_count: u128 = 0;
            let mut proxy_listner_status_message = UNKNOWN_STATUS_MESSAGE.to_string();

            while let Ok(action) = receiver.recv() {
                match action {
                    DataAction::Stop => {
                        break;
                    }
                    DataAction::KeyKeeperSetKey { key, response } => {
                        // Set the key from the key keeper
                        current_key = key;
                        _ = response.send(true);
                    }
                    DataAction::KeyKeeperGetKeyValue { response } => {
                        // Get the key from the key keeper
                        _ = response.send(current_key.clone());
                    }
                    DataAction::KeyKeeperSetSecureChannelState { state, response } => {
                        // Set the secure channel state
                        current_secure_channel_state = state;
                        _ = response.send(true);
                    }
                    DataAction::KeyKeeperGetSecureChannelState { response } => {
                        // Get the secure channel state
                        _ = response.send(current_secure_channel_state.to_string());
                    }
                    DataAction::KeyKeeperSetStatusMessage {
                        status_message,
                        response,
                    } => {
                        // Set the status message
                        key_keeper_status_message = status_message;
                        _ = response.send(true);
                    }
                    DataAction::KeyKeeperGetStatusMessage { response } => {
                        // Get the status message
                        _ = response.send(key_keeper_status_message.to_string());
                    }
                    DataAction::KeyKeeperSetWireserverRuleId {
                        wireserver_rule_id: rule_id,
                        response,
                    } => {
                        // Set the wireserver rule id
                        wireserver_rule_id = rule_id;
                        _ = response.send(true);
                    }
                    DataAction::KeyKeeperGetWireserverRuleId { response } => {
                        // Get the wireserver rule id
                        _ = response.send(wireserver_rule_id.to_string());
                    }
                    DataAction::KeyKeeperSetImdsRuleId {
                        imds_rule_id: rule_id,
                        response,
                    } => {
                        // Set the imds rule id
                        imds_rule_id = rule_id;
                        _ = response.send(true);
                    }
                    DataAction::KeyKeeperGetImdsRuleId { response } => {
                        // Get the imds rule id
                        _ = response.send(imds_rule_id.to_string());
                    }
                    DataAction::KeyKeeperSetShutdown { shutdown, response } => {
                        // Set the key keeper shutdown status
                        key_keeper_shutdown = shutdown;
                        _ = response.send(true);
                    }
                    DataAction::KeyKeeperGetShutdown { response } => {
                        // Get the key keeper shutdown status
                        _ = response.send(key_keeper_shutdown);
                    }
                    DataAction::ProxyListenerSetConnectionCount { count, response } => {
                        // Increase the connection count
                        connection_count = count;
                        _ = response.send(true);
                    }
                    DataAction::ProxyListenerGetConnectionCount { response } => {
                        // Get the connection count
                        _ = response.send(connection_count);
                    }
                    DataAction::ProxyListenerSetStatusMessage {
                        status_message,
                        response,
                    } => {
                        // Set the status message
                        proxy_listner_status_message = status_message;
                        _ = response.send(true);
                    }
                    DataAction::ProxyListenerGetStatusMessage { response } => {
                        // Get the status message
                        _ = response.send(proxy_listner_status_message.to_string());
                    }
                    DataAction::ProxyListenerSetShutdown { shutdown, response } => {
                        // Set the proxy listener shutdown status
                        proxy_listner_shutdown = shutdown;
                        _ = response.send(true);
                    }
                    DataAction::ProxyListenerGetShutdown { response } => {
                        // Get the proxy listener shutdown status
                        _ = response.send(proxy_listner_shutdown);
                    }
                }
            }
        });

        DataVessel { sender }
    }

    pub fn stop(self) {
        let _ = self.sender.send(DataAction::Stop);
    }
}

/// KeyKeeper implementation
impl DataVessel {
    pub fn update_current_key(&self, key: Key) -> bool {
        let (response, receiver) = std::sync::mpsc::channel::<bool>();
        let _ = self.sender.send(DataAction::KeyKeeperSetKey {
            key: Some(key),
            response,
        });
        match receiver.recv() {
            Ok(result) => result,
            Err(e) => {
                logger::write_warning(format!("Failed to update current key with error: {e}"));
                false
            }
        }
    }

    fn get_current_key(&self) -> Option<Key> {
        let (response, receiver) = std::sync::mpsc::channel::<Option<Key>>();
        let _ = self
            .sender
            .clone()
            .send(DataAction::KeyKeeperGetKeyValue { response });
        match receiver.recv() {
            Ok(key) => key,
            Err(e) => {
                logger::write_warning(format!("Failed to get current key with error: {e}"));
                // return empty key if failed to get the key
                None
            }
        }
    }

    pub fn get_current_key_value(&self) -> Option<String> {
        match self.get_current_key() {
            Some(key) => Some(key.key),
            None => None,
        }
    }

    pub fn get_current_key_guid(&self) -> Option<String> {
        match self.get_current_key() {
            Some(key) => Some(key.guid),
            None => None,
        }
    }

    pub fn get_current_key_incarnation(&self) -> Option<u32> {
        self.get_current_key()?.incarnationId
    }

    pub fn update_secure_channel_state(&self, state: String) -> bool {
        let (response, receiver) = std::sync::mpsc::channel::<bool>();
        let _ = self
            .sender
            .send(DataAction::KeyKeeperSetSecureChannelState { state, response });
        match receiver.recv() {
            Ok(result) => result,
            Err(e) => {
                logger::write_warning(format!(
                    "Failed to update secure channel state with error: {e}"
                ));
                false
            }
        }
    }

    pub fn get_secure_channel_state(&self) -> String {
        let (response, receiver) = std::sync::mpsc::channel::<String>();
        let _ = self
            .sender
            .clone()
            .send(DataAction::KeyKeeperGetSecureChannelState { response });
        match receiver.recv() {
            Ok(state) => state,
            Err(e) => {
                logger::write_warning(format!(
                    "Failed to get secure channel state with error: {e}"
                ));
                // return unknown if failed to get the state
                crate::key_keeper::UNKNOWN_STATE.to_string()
            }
        }
    }

    pub fn update_key_keeper_status_message(&self, status_message: String) -> bool {
        let (response, receiver) = std::sync::mpsc::channel::<bool>();
        let _ = self.sender.send(DataAction::KeyKeeperSetStatusMessage {
            status_message,
            response,
        });
        match receiver.recv() {
            Ok(result) => result,
            Err(e) => {
                logger::write_warning(format!("Failed to update status message with error: {e}"));
                false
            }
        }
    }

    pub fn get_key_keeper_status_message(&self) -> String {
        let (response, receiver) = std::sync::mpsc::channel::<String>();
        let _ = self
            .sender
            .clone()
            .send(DataAction::KeyKeeperGetStatusMessage { response });
        match receiver.recv() {
            Ok(message) => message,
            Err(e) => {
                logger::write_warning(format!("Failed to get status message with error: {e}"));
                // return unknown if failed to get the message
                UNKNOWN_STATUS_MESSAGE.to_string()
            }
        }
    }

    pub fn update_wireserver_rule_id(&self, rule_id: String) -> bool {
        let (response, receiver) = std::sync::mpsc::channel::<bool>();
        let _ = self.sender.send(DataAction::KeyKeeperSetWireserverRuleId {
            wireserver_rule_id: rule_id,
            response,
        });
        match receiver.recv() {
            Ok(result) => result,
            Err(e) => {
                logger::write_warning(format!(
                    "Failed to update wireserver rule id with error: {e}"
                ));
                false
            }
        }
    }

    pub fn get_wireserver_rule_id(&self) -> String {
        let (response, receiver) = std::sync::mpsc::channel::<String>();
        let _ = self
            .sender
            .clone()
            .send(DataAction::KeyKeeperGetWireserverRuleId { response });
        match receiver.recv() {
            Ok(rule_id) => rule_id,
            Err(e) => {
                logger::write_warning(format!("Failed to get wireserver rule id with error: {e}"));
                // return empty string if failed to get the rule id
                String::new()
            }
        }
    }

    pub fn update_imds_rule_id(&self, rule_id: String) -> bool {
        let (response, receiver) = std::sync::mpsc::channel::<bool>();
        let _ = self.sender.send(DataAction::KeyKeeperSetImdsRuleId {
            imds_rule_id: rule_id,
            response,
        });
        match receiver.recv() {
            Ok(result) => result,
            Err(e) => {
                logger::write_warning(format!("Failed to update imds rule id with error: {e}"));
                false
            }
        }
    }

    pub fn get_imds_rule_id(&self) -> String {
        let (response, receiver) = std::sync::mpsc::channel::<String>();
        let _ = self
            .sender
            .clone()
            .send(DataAction::KeyKeeperGetImdsRuleId { response });
        match receiver.recv() {
            Ok(rule_id) => rule_id,
            Err(e) => {
                logger::write_warning(format!("Failed to get imds rule id with error: {e}"));
                // return empty string if failed to get the rule id
                String::new()
            }
        }
    }

    pub fn shutdown_key_keeper(&self) -> bool {
        let (response, receiver) = std::sync::mpsc::channel::<bool>();
        let _ = self.sender.send(DataAction::KeyKeeperSetShutdown {
            shutdown: true,
            response,
        });
        match receiver.recv() {
            Ok(result) => result,
            Err(e) => {
                logger::write_warning(format!(
                    "Failed to shutdown key keeper thread with error: {e}"
                ));
                false
            }
        }
    }

    pub fn is_key_keeper_shutdown(&self) -> bool {
        let (response, receiver) = std::sync::mpsc::channel::<bool>();
        let _ = self
            .sender
            .send(DataAction::KeyKeeperGetShutdown { response });
        match receiver.recv() {
            Ok(result) => result,
            Err(e) => {
                logger::write_warning(format!(
                    "Failed to get key keeper shutdown status with error: {e}"
                ));
                false
            }
        }
    }
}

/// ProxyListener implementation
impl DataVessel {
    pub fn set_connection_count(&self, count: u128) -> bool {
        let (response, receiver) = std::sync::mpsc::channel::<bool>();
        let _ = self
            .sender
            .send(DataAction::ProxyListenerSetConnectionCount { count, response });
        match receiver.recv() {
            Ok(result) => result,
            Err(e) => {
                logger::write_warning(format!("Failed to set connection count with error: {e}"));
                false
            }
        }
    }

    pub fn get_connection_count(&self) -> u128 {
        let (response, receiver) = std::sync::mpsc::channel::<u128>();
        let _ = self
            .sender
            .clone()
            .send(DataAction::ProxyListenerGetConnectionCount { response });
        match receiver.recv() {
            Ok(count) => count,
            Err(e) => {
                logger::write_warning(format!("Failed to get connection count with error: {e}"));
                0
            }
        }
    }

    pub fn update_proxy_listener_status_message(&self, status_message: String) -> bool {
        let (response, receiver) = std::sync::mpsc::channel::<bool>();
        let _ = self.sender.send(DataAction::ProxyListenerSetStatusMessage {
            status_message,
            response,
        });
        match receiver.recv() {
            Ok(result) => result,
            Err(e) => {
                logger::write_warning(format!(
                    "Failed to update proxy listener status message with error: {e}"
                ));
                false
            }
        }
    }

    pub fn get_proxy_listener_status_message(&self) -> String {
        let (response, receiver) = std::sync::mpsc::channel::<String>();
        let _ = self
            .sender
            .clone()
            .send(DataAction::ProxyListenerGetStatusMessage { response });
        match receiver.recv() {
            Ok(message) => message,
            Err(e) => {
                logger::write_warning(format!(
                    "Failed to get proxy listener status message with error: {e}"
                ));
                // return unknown if failed to get the message
                UNKNOWN_STATUS_MESSAGE.to_string()
            }
        }
    }

    pub fn shutdown_proxy_listener(&self) -> bool {
        let (response, receiver) = std::sync::mpsc::channel::<bool>();
        let _ = self.sender.send(DataAction::ProxyListenerSetShutdown {
            shutdown: true,
            response,
        });
        match receiver.recv() {
            Ok(result) => result,
            Err(e) => {
                logger::write_warning(format!(
                    "Failed to shutdown proxy listener thread with error: {e}"
                ));
                false
            }
        }
    }

    pub fn is_proxy_listener_shutdown(&self) -> bool {
        let (response, receiver) = std::sync::mpsc::channel::<bool>();
        let _ = self
            .sender
            .send(DataAction::ProxyListenerGetShutdown { response });
        match receiver.recv() {
            Ok(result) => result,
            Err(e) => {
                logger::write_warning(format!(
                    "Failed to get proxy listener shutdown status with error: {e}"
                ));
                false
            }
        }
    }
}
