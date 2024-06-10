// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

use crate::key_keeper::key::Key;
use std::sync::mpsc::Sender;

pub enum DataAction {
    Stop,
    KeyKeeperSetKey {
        key: Key,
        response: std::sync::mpsc::Sender<bool>,
    },
    KeyKeeperGetKeyValue {
        response: std::sync::mpsc::Sender<Key>,
    },
}

pub fn start_receiver_async() -> Sender<DataAction> {
    let (sender, receiver) = std::sync::mpsc::channel::<DataAction>();

    std::thread::spawn(move || {
        // chached data are defined here
        let mut cached_key: Key = Key::empty();

        while let Ok(action) = receiver.recv() {
            match action {
                DataAction::Stop => {
                    break;
                }
                DataAction::KeyKeeperSetKey { key, response } => {
                    // Set the key from the key keeper
                    cached_key = key.clone();
                    let _ = response.send(true);
                }
                DataAction::KeyKeeperGetKeyValue { response } => {
                    // Get the key from the key keeper
                    let _ = response.send(cached_key.clone());
                }
            }
        }
    });

    sender
}

pub mod key_keeper {
    use crate::data_vessel::DataAction;
    use crate::key_keeper::key::Key;
    use std::sync::mpsc::Sender;

    pub fn update_current_key(sender: Sender<DataAction>, key: Key) -> bool {
        let (response, receiver) = std::sync::mpsc::channel::<bool>();
        let _ = sender.send(DataAction::KeyKeeperSetKey { key, response });
        receiver.recv().unwrap_or(false)
    }

    fn get_current_key(sender: Sender<DataAction>) -> Key {
        let (response, receiver) = std::sync::mpsc::channel::<Key>();
        let _ = sender.send(DataAction::KeyKeeperGetKeyValue { response });
        receiver.recv().unwrap_or(Key::empty())
    }

    pub fn get_current_key_value(sender: Sender<DataAction>) -> String {
        get_current_key(sender).key.to_string()
    }

    pub fn get_current_key_guid(sender: Sender<DataAction>) -> String {
        get_current_key(sender).guid.to_string()
    }

    pub fn get_current_key_incarnation(sender: Sender<DataAction>) -> Option<u32> {
        get_current_key(sender).incarnationId
    }
}
