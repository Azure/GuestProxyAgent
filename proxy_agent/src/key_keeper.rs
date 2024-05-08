// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
pub mod key;

use self::key::Key;
use crate::common::{constants, helpers, logger};
use crate::provision;
use crate::{acl, redirector};
use once_cell::sync::Lazy;
use proxy_agent_shared::misc_helpers;
use proxy_agent_shared::proxy_agent_aggregate_status::{ModuleState, ProxyAgentDetailStatus};
use proxy_agent_shared::telemetry::event_logger;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::{path::PathBuf, thread, time::Duration};
use url::Url;

//pub const RUNNING_STATE: &str = "running";
pub const DISABLE_STATE: &str = "disabled";
pub const MUST_SIG_WIRESERVER: &str = "wireserver";
pub const MUST_SIG_WIRESERVER_IMDS: &str = "wireserverandimds";
const UNKNOWN_STATE: &str = "Unknown";
static FREQUENT_PULL_INTERVAL: Duration = Duration::from_secs(1); // 1 second
const FREQUENT_PULL_TIMEOUT_IN_MILLISECONDS: u128 = 300000; // 5 minutes
const PROVISION_TIMEUP_IN_MILLISECONDS: u128 = 120000; // 2 minute
const DELAY_START_EVENT_THREADS_IN_MILLISECONDS: u128 = 60000; // 1 minute

static mut CURRENT_SECURE_CHANNEL_STATE: Lazy<String> = Lazy::new(|| String::from(UNKNOWN_STATE)); // state starts from Unknown
static mut CURRENT_KEY: Lazy<Key> = Lazy::new(|| Key::empty());
static SHUT_DOWN: Lazy<Arc<AtomicBool>> = Lazy::new(|| Arc::new(AtomicBool::new(false)));
static mut STATUS_MESSAGE: Lazy<String> =
    Lazy::new(|| String::from("Key latch thread has not started yet."));
static mut WIRESERVER_RULE_ID: Lazy<String> = Lazy::new(|| String::from(""));
static mut IMDS_RULE_ID: Lazy<String> = Lazy::new(|| String::from(""));

pub fn get_secure_channel_state() -> String {
    unsafe { CURRENT_SECURE_CHANNEL_STATE.to_string() }
}

pub fn get_current_key_guid() -> String {
    unsafe { CURRENT_KEY.guid.to_string() }
}

pub fn get_current_key() -> String {
    unsafe { CURRENT_KEY.key.to_string() }
}

fn get_current_key_incarnation() -> Option<u32> {
    unsafe { CURRENT_KEY.incarnationId.clone() }
}

pub fn poll_status_async(
    base_url: Url,
    key_dir: PathBuf,
    interval: Duration,
    config_start_redirector: bool,
) {
    thread::spawn(move || {
        poll_secure_channel_status(base_url, key_dir, interval, config_start_redirector);
    });
}

// poll secure channel status at interval
fn poll_secure_channel_status(
    base_url: Url,
    key_dir: PathBuf,
    interval: Duration,
    config_start_redirector: bool,
) {
    let message = "poll secure channel status thread started.";
    unsafe {
        *STATUS_MESSAGE = message.to_string();
    }
    logger::write(message.to_string());

    // launch redirector initialization when the key keeper thread is running
    if config_start_redirector {
        redirector::start_async(constants::PROXY_AGENT_PORT);
    }

    _ = misc_helpers::try_create_folder(key_dir.to_path_buf());
    logger::write(format!(
        "key folder {} created if not exists before.",
        misc_helpers::path_to_string(key_dir.to_path_buf())
    ));

    match acl::acl_directory(key_dir.to_path_buf()) {
        Ok(()) => {
            logger::write(format!(
                "key folder {} ACLed if has not before.",
                misc_helpers::path_to_string(key_dir.to_path_buf())
            ));
        }
        Err(e) => {
            logger::write_warning(format!(
                "key folder {} ACLed failed with error {}.",
                misc_helpers::path_to_string(key_dir.to_path_buf()),
                e
            ));
        }
    }

    let mut first_iteration: bool = true;
    let mut started_event_threads: bool = false;
    let mut provision_timeup: bool = false;
    let shutdown = SHUT_DOWN.clone();
    loop {
        if shutdown.load(Ordering::Relaxed) {
            let message = "Stop signal received, exiting the poll_secure_channel_status thread.";
            unsafe {
                *STATUS_MESSAGE = message.to_string();
            }
            logger::write_warning(message.to_string());
            break;
        }

        if !first_iteration {
            // skip the sleep for the first loop
            let sleep;
            if get_secure_channel_state() == UNKNOWN_STATE
                && helpers::get_elapsed_time_in_millisec() < FREQUENT_PULL_TIMEOUT_IN_MILLISECONDS
            {
                // frequent poll the secure channel status every second for the first 5 minutes
                // until the secure channel state is known
                sleep = FREQUENT_PULL_INTERVAL;
            } else {
                sleep = interval;
            }
            thread::sleep(sleep);
        }
        first_iteration = false;

        if !provision_timeup
            && helpers::get_elapsed_time_in_millisec() > PROVISION_TIMEUP_IN_MILLISECONDS
        {
            provision::provision_timeup(None);
            provision_timeup = true;
        }

        if !started_event_threads
            && helpers::get_elapsed_time_in_millisec() > DELAY_START_EVENT_THREADS_IN_MILLISECONDS
        {
            provision::start_event_threads();
            started_event_threads = true;
        }

        let status;
        match key::get_status(base_url.clone()) {
            Ok(s) => status = s,
            Err(e) => {
                let err_string = format!("{:?}", e);
                let message: String = format!(
                    "Failed to get key status - {}",
                    match e.into_inner() {
                        Some(err) => err.to_string(),
                        None => err_string,
                    }
                );
                unsafe {
                    *STATUS_MESSAGE = message.to_string();
                }
                logger::write_warning(message);
                continue;
            }
        };
        let mut guid;
        match &status.keyGuid {
            Some(id) => guid = id.to_string(),
            None => guid = String::new(),
        }

        logger::write_information(format!(
            "Got key status successfully: {}.",
            status.to_string()
        ));

        let wireserver_rule_id = status.get_wireserver_rule_id();
        let imds_rule_id = status.get_imds_rule_id();
        unsafe {
            if wireserver_rule_id != *WIRESERVER_RULE_ID {
                logger::write_warning(format!(
                    "Wireserver rule id changed from {} to {}.",
                    *WIRESERVER_RULE_ID, wireserver_rule_id
                ));
                *WIRESERVER_RULE_ID = wireserver_rule_id.to_string();
                //TODO update the authorization rule details for wireserver
            }
        }
        unsafe {
            if imds_rule_id != *IMDS_RULE_ID {
                logger::write_warning(format!(
                    "IMDS rule id changed from {} to {}.",
                    *IMDS_RULE_ID, imds_rule_id
                ));
                *IMDS_RULE_ID = imds_rule_id.to_string();
                //TODO update the authorization rule details for imds
            }
        }

        let mut key_file = key_dir.to_path_buf().join(guid.to_string());
        key_file.set_extension("key");
        let state = status.get_secure_channel_state();

        // check if need fetch the key
        if state != DISABLE_STATE && guid != get_current_key_guid() {
            // search the key locally first
            let mut key_found = false;
            if guid != "" {
                // the key already latched before
                if key_file.exists() {
                    // read the key details locally and update
                    match misc_helpers::json_read_from_file(key_file.to_path_buf()) {
                        Ok(key) => {
                            // update in memory
                            unsafe {
                                *CURRENT_KEY = key;
                            }
                            let message = helpers::write_startup_event(
                                "Found key details from local and ready to use.",
                                "poll_secure_channel_status",
                                "key_keeper",
                                logger::AGENT_LOGGER_KEY,
                            );
                            unsafe {
                                *STATUS_MESSAGE = message.to_string();
                            }
                            key_found = true;

                            provision::key_latched();
                        }
                        Err(e) => {
                            let message = format!("Failed to read latched key details from file: {:?}. Will try acquire the key details from Server.",
                                e);
                            event_logger::write_event(
                                event_logger::WARN_LEVEL,
                                message.to_string(),
                                "poll_secure_channel_status",
                                "key_keeper",
                                logger::AGENT_LOGGER_KEY,
                            );
                        }
                    };
                } else {
                    let message = "The latched key file does not exist locally. Will try acquire the key details from Server.".to_string();
                    event_logger::write_event(
                        event_logger::WARN_LEVEL,
                        message.to_string(),
                        "poll_secure_channel_status",
                        "key_keeper",
                        logger::AGENT_LOGGER_KEY,
                    );
                }
            }

            // if key has not latched before,
            // or not found
            // or could not read locally,
            // try fetch from server
            if !key_found {
                let key;
                match key::acquire_key(base_url.clone()) {
                    Ok(k) => key = k,
                    Err(e) => {
                        logger::write_warning(format!("Failed to acquire key details: {:?}", e));
                        continue;
                    }
                };

                // key has not latched before,
                // set the key_file full path from key details
                if guid == "" {
                    guid = key.guid.to_string();
                    key_file = key_dir.to_path_buf().join(guid.to_string());
                    key_file.set_extension("key");
                }
                _ = misc_helpers::json_write_to_file(&key, key_file);
                logger::write_information(format!(
                    "Successfully acquired the key '{}' details from server and saved locally.",
                    guid.to_string()
                ));

                // double check the key details saved correctly to local disk
                if check_local_key(key_dir.to_path_buf(), &key) {
                    match key::attest_key(base_url.clone(), &key) {
                        Ok(()) => {
                            // update in memory
                            unsafe {
                                *CURRENT_KEY = key;
                            }
                            helpers::write_startup_event(
                                "Successfully attest the key and ready to use.",
                                "poll_secure_channel_status",
                                "key_keeper",
                                logger::AGENT_LOGGER_KEY,
                            );
                            unsafe {
                                *STATUS_MESSAGE = message.to_string();
                            }

                            provision::key_latched();
                        }
                        Err(e) => {
                            logger::write_warning(format!("Failed to attest the key: {:?}", e));
                            continue;
                        }
                    }
                } else {
                    logger::write_warning(format!(
                        "Saved key '{}' details lost locally.",
                        guid.to_string()
                    ));
                }
            }
        }

        // update the current secure channel state if different
        if state != get_secure_channel_state() {
            unsafe {
                *CURRENT_SECURE_CHANNEL_STATE = state.to_string();
            }

            // customer has not enforce the secure channel state
            if state == DISABLE_STATE {
                let message = helpers::write_startup_event(
                    "Customer has not enforce the secure channel state.",
                    "poll_secure_channel_status",
                    "key_keeper",
                    logger::AGENT_LOGGER_KEY,
                );
                // Update the status message and let the provision to continue
                unsafe {
                    *STATUS_MESSAGE = message.to_string();
                }
                provision::key_latched();
            }
        }
    }
}

// key is saved locally correctly
// true if the key file found and its guid and key value are corrected;
// other wise return false
fn check_local_key(key_dir: PathBuf, key: &Key) -> bool {
    let guid = key.guid.to_string();
    let mut key_file = key_dir.to_path_buf().join(guid);
    key_file.set_extension("key");
    if !key_file.exists() {
        // guid.key file does not exist locally
        return false;
    }

    match misc_helpers::json_read_from_file::<Key>(key_file.to_path_buf()) {
        Ok(local_key) => local_key.guid == key.guid && local_key.key == key.key,
        Err(_) => {
            // failed to parse guid.key file
            return false;
        }
    }
}

pub fn stop() {
    SHUT_DOWN.store(true, Ordering::Relaxed);
}

pub fn get_status() -> ProxyAgentDetailStatus {
    let shutdown = SHUT_DOWN.clone();
    let status;
    if shutdown.load(Ordering::Relaxed) {
        status = ModuleState::STOPPED.to_string();
    } else {
        status = ModuleState::RUNNING.to_string();
    }

    let state_message = unsafe { STATUS_MESSAGE.to_string() };
    let mut states = HashMap::new();
    states.insert("secureChannelState".to_string(), get_secure_channel_state());
    states.insert("keyGuid".to_string(), get_current_key_guid());
    states.insert("wireServerRuleId".to_string(), unsafe { WIRESERVER_RULE_ID.to_string() });
    states.insert("imdsRuleId".to_string(), unsafe { IMDS_RULE_ID.to_string() });
   match get_current_key_incarnation() {
        Some(incarnation) => {
            states.insert("keyIncarnationId".to_string(), incarnation.to_string());
        }
        None => {}
    }

    ProxyAgentDetailStatus {
        status,
        message: state_message,
        states: Some(states),
    }
}

#[cfg(test)]
mod tests {
    use super::key::Key;
    use crate::common::logger;
    use crate::key_keeper;
    use crate::test_mock::server_mock;
    use proxy_agent_shared::{logger_manager, misc_helpers};
    use std::env;
    use std::fs;
    use std::thread;
    use std::time::Duration;
    use url::Url;

    #[test]
    fn check_local_key_test() {
        let mut temp_test_path = env::temp_dir();
        let logger_key = "check_local_key_test";
        temp_test_path.push(logger_key);
        // clean up and ignore the clean up errors
        _ = fs::remove_dir_all(&temp_test_path);
        logger_manager::init_logger(
            logger_key.to_string(),
            temp_test_path.clone(),
            logger_key.to_string(),
            200,
            6,
        );
        _ = misc_helpers::try_create_folder(temp_test_path.to_path_buf());

        let key_str = r#"{
            "authorizationScheme": "Azure-HMAC-SHA256",        
            "guid": "9cf81e97-0316-4ad3-94a7-8ccbdee8ccbf",        
            "issued": "2021-05-05T 12:00:00Z",        
            "key": "4A404E635266556A586E3272357538782F413F4428472B4B6250645367566B59"        
        }"#;
        let key: Key = serde_json::from_str(key_str).unwrap();
        let mut key_file = temp_test_path.to_path_buf().join(key.guid.to_string());
        key_file.set_extension("key");
        _ = misc_helpers::json_write_to_file(&key, key_file);

        assert_eq!(
            true,
            super::check_local_key(temp_test_path.to_path_buf(), &key)
        );

        _ = fs::remove_dir_all(&temp_test_path);
    }

    #[test]
    fn poll_secure_channel_status_tests() {
        let mut temp_test_path = env::temp_dir();
        temp_test_path.push("poll_secure_channel_status_tests");
        let mut log_dir = temp_test_path.to_path_buf();
        log_dir.push("Logs");
        let mut keys_dir = temp_test_path.to_path_buf();
        keys_dir.push("Keys");

        // clean up and ignore the clean up errors
        match fs::remove_dir_all(&temp_test_path) {
            Ok(_) => {}
            Err(e) => {
                print!("Failed to remove_dir_all with error {}.", e);
            }
        }

        // init main logger
        logger_manager::init_logger(
            logger::AGENT_LOGGER_KEY.to_string(), // production code uses 'Agent_Log' to write.
            log_dir.clone(),
            "logger_key".to_string(),
            10 * 1024 * 1024,
            20,
        );

        // start wire_server listener
        let ip = "127.0.0.1";
        let port = 8081u16;
        thread::spawn(move || {
            server_mock::start(ip.to_string(), port);
        });
        thread::sleep(Duration::from_millis(100));

        // start with disabled secure channel state
        server_mock::set_secure_channel_state(false);

        // start poll_secure_channel_status
        let cloned_keys_dir = keys_dir.to_path_buf();
        key_keeper::poll_status_async(
            Url::parse("http://127.0.0.1:8081/").unwrap(),
            cloned_keys_dir,
            Duration::from_millis(10),
            false,
        );

        for _ in [0; 5] {
            // wait poll_secure_channel_status run at least one loop
            thread::sleep(Duration::from_millis(100));
            if keys_dir.exists() {
                break;
            }
        }

        let key_files: Vec<std::path::PathBuf> = misc_helpers::get_files(&keys_dir).unwrap();
        assert!(
            key_files.len() == 0,
            "Should not write key file at disable secure channel state"
        );

        // set secure channel state to running
        server_mock::set_secure_channel_state(true);
        // wait poll_secure_channel_status run at least one loop
        thread::sleep(Duration::from_millis(100));
        let key_files = misc_helpers::get_files(&keys_dir).unwrap();
        assert_eq!(
            1,
            key_files.len(),
            "Should write key file at running secure channel state"
        );

        // stop poll
        key_keeper::stop();
        server_mock::stop(ip.to_string(), port);

        // clean up and ignore the clean up errors
        _ = fs::remove_dir_all(&temp_test_path);
    }
}
