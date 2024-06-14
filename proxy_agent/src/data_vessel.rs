// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

use crate::{common::logger, key_keeper::key::Key};
use std::sync::mpsc::Sender;

const UNKNOWN_STATUS_MESSAGE: &str = "Status unknown.";
pub enum DataAction {
    Stop,
    KeyKeeperSetKey {
        key: Key,
        response: std::sync::mpsc::Sender<bool>,
    },
    KeyKeeperGetKeyValue {
        response: std::sync::mpsc::Sender<Key>,
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
            let mut current_key: Key = Key::empty(); // start with empyt key
            let mut current_secure_channel_state: String =
                crate::key_keeper::UNKNOWN_STATE.to_string();
            let mut wireserver_rule_id: String = String::new();
            let mut imds_rule_id: String = String::new();
            let mut key_keeper_status_message: String = UNKNOWN_STATUS_MESSAGE.to_string();

            while let Ok(action) = receiver.recv() {
                match action {
                    DataAction::Stop => {
                        break;
                    }
                    DataAction::KeyKeeperSetKey { key, response } => {
                        // Set the key from the key keeper
                        current_key = key.clone();
                        _ = response.send(true);
                    }
                    DataAction::KeyKeeperGetKeyValue { response } => {
                        // Get the key from the key keeper
                        _ = response.send(current_key.clone());
                    }
                    DataAction::KeyKeeperSetSecureChannelState { state, response } => {
                        // Set the secure channel state
                        current_secure_channel_state = state.to_string();
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
                        key_keeper_status_message = status_message.to_string();
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
                        wireserver_rule_id = rule_id.to_string();
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
                        imds_rule_id = rule_id.to_string();
                        _ = response.send(true);
                    }
                    DataAction::KeyKeeperGetImdsRuleId { response } => {
                        // Get the imds rule id
                        _ = response.send(imds_rule_id.to_string());
                    }
                }
            }
        });

        DataVessel { sender }
    }

    pub fn stop(&self) {
        let _ = self.sender.send(DataAction::Stop);
    }
}

/// KeyKeeper implementation
impl DataVessel {
    pub fn update_current_key(&self, key: Key) -> bool {
        let (response, receiver) = std::sync::mpsc::channel::<bool>();
        let _ = self
            .sender
            .send(DataAction::KeyKeeperSetKey { key, response });
        match receiver.recv() {
            Ok(result) => result,
            Err(e) => {
                logger::write_warning(format!("Failed to update current key with error: {e}"));
                false
            }
        }
    }

    fn get_current_key(&self) -> Key {
        let (response, receiver) = std::sync::mpsc::channel::<Key>();
        let _ = self
            .sender
            .clone()
            .send(DataAction::KeyKeeperGetKeyValue { response });
        match receiver.recv() {
            Ok(key) => key,
            Err(e) => {
                logger::write_warning(format!("Failed to get current key with error: {e}"));
                // return empty key if failed to get the key
                Key::empty()
            }
        }
    }

    pub fn get_current_key_value(&self) -> String {
        self.get_current_key().key
    }

    pub fn get_current_key_guid(&self) -> String {
        self.get_current_key().guid
    }

    pub fn get_current_key_incarnation(&self) -> Option<u32> {
        self.get_current_key().incarnationId
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
}
