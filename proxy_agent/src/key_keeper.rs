// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
pub mod key;

use self::key::Key;
use crate::common::{constants, helpers, logger};
use crate::provision;
use crate::proxy::proxy_authentication;
use crate::shared_state::{key_keeper_wrapper, SharedState};
use crate::{acl, redirector};
use proxy_agent_shared::misc_helpers;
use proxy_agent_shared::proxy_agent_aggregate_status::{ModuleState, ProxyAgentDetailStatus};
use proxy_agent_shared::telemetry::event_logger;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::{path::PathBuf, thread, time::Duration};
use url::Url;

//pub const RUNNING_STATE: &str = "running";
pub const DISABLE_STATE: &str = "disabled";
pub const MUST_SIG_WIRESERVER: &str = "wireserver";
pub const MUST_SIG_WIRESERVER_IMDS: &str = "wireserverandimds";
pub const UNKNOWN_STATE: &str = "Unknown";
static FREQUENT_PULL_INTERVAL: Duration = Duration::from_secs(1); // 1 second
const FREQUENT_PULL_TIMEOUT_IN_MILLISECONDS: u128 = 300000; // 5 minutes
const PROVISION_TIMEUP_IN_MILLISECONDS: u128 = 120000; // 2 minute
const DELAY_START_EVENT_THREADS_IN_MILLISECONDS: u128 = 60000; // 1 minute

pub async fn poll_status_async(
    base_url: Url,
    key_dir: PathBuf,
    interval: Duration,
    config_start_redirector: bool,
    shared_state: Arc<Mutex<SharedState>>,
) {
    tokio::spawn(async move {
        poll_secure_channel_status(
            base_url,
            key_dir,
            interval,
            config_start_redirector,
            shared_state,
        )
        .await;
    });
}

// poll secure channel status at interval
async fn poll_secure_channel_status(
    base_url: Url,
    key_dir: PathBuf,
    interval: Duration,
    config_start_redirector: bool,
    shared_state: Arc<Mutex<SharedState>>,
) {
    let message = "poll secure channel status thread started.";
    key_keeper_wrapper::set_status_message(shared_state.clone(), message.to_string());
    logger::write(message.to_string());

    // launch redirector initialization when the key keeper thread is running
    if config_start_redirector {
        redirector::start_async(constants::PROXY_AGENT_PORT, shared_state.clone());
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
    loop {
        if key_keeper_wrapper::get_shutdown(shared_state.clone()) {
            let message = "Stop signal received, exiting the poll_secure_channel_status thread.";
            key_keeper_wrapper::set_status_message(shared_state.clone(), message.to_string());
            logger::write_warning(message.to_string());
            break;
        }

        if !first_iteration {
            // skip the sleep for the first loop

            let sleep = if key_keeper_wrapper::get_current_secure_channel_state(shared_state.clone())
                    == UNKNOWN_STATE
                    && FREQUENT_PULL_INTERVAL < interval        // test internal is less than 1 second
                    && helpers::get_elapsed_time_in_millisec()
                        < FREQUENT_PULL_TIMEOUT_IN_MILLISECONDS
            {
                // frequent poll the secure channel status every second for the first 5 minutes
                // until the secure channel state is known
                FREQUENT_PULL_INTERVAL
            } else {
                interval
            };
            thread::sleep(sleep);
        }
        first_iteration = false;

        if !provision_timeup
            && helpers::get_elapsed_time_in_millisec() > PROVISION_TIMEUP_IN_MILLISECONDS
        {
            provision::provision_timeup(None, shared_state.clone());
            provision_timeup = true;
        }

        if !started_event_threads
            && helpers::get_elapsed_time_in_millisec() > DELAY_START_EVENT_THREADS_IN_MILLISECONDS
        {
            provision::start_event_threads(shared_state.clone());
            started_event_threads = true;
        }

        let status = match key::get_status(base_url.clone()).await {
            Ok(s) => s,
            Err(e) => {
                let err_string = format!("{:?}", e);
                let message: String = format!(
                    "Failed to get key status - {}",
                    match e.into_inner() {
                        Some(err) => err.to_string(),
                        None => err_string,
                    }
                );
                key_keeper_wrapper::set_status_message(shared_state.clone(), message.to_string());
                logger::write_warning(message);
                continue;
            }
        };
        logger::write_information(format!("Got key status successfully: {}.", status));

        let wireserver_rule_id = status.get_wireserver_rule_id();
        let imds_rule_id: String = status.get_imds_rule_id();
        let (updated, old_wire_server_rule_id) = key_keeper_wrapper::update_wireserver_rule_id(
            shared_state.clone(),
            wireserver_rule_id.to_string(),
        );
        if updated {
            logger::write_warning(format!(
                "Wireserver rule id changed from {} to {}.",
                old_wire_server_rule_id, wireserver_rule_id
            ));
            proxy_authentication::set_wireserver_rules(
                shared_state.clone(),
                status.get_wireserver_rules(),
            );
        }

        let (updated, old_imds_rule_id) =
            key_keeper_wrapper::update_imds_rule_id(shared_state.clone(), imds_rule_id.to_string());
        if updated {
            logger::write_warning(format!(
                "IMDS rule id changed from {} to {}.",
                old_imds_rule_id, imds_rule_id
            ));
            proxy_authentication::set_imds_rules(shared_state.clone(), status.get_imds_rules());
        }

        let state = status.get_secure_channel_state();
        // check if need fetch the key
        if state != DISABLE_STATE
            && (status.keyGuid.is_none()  // key has not latched yet
                || status.keyGuid != key_keeper_wrapper::get_current_key_guid(shared_state.clone()))
        {
            let mut key_found = false;
            if let Some(guid) = &status.keyGuid {
                // key latched before and search the key locally first
                let mut key_file = key_dir.to_path_buf().join(guid);
                key_file.set_extension("key");
                // the key already latched before
                if key_file.exists() {
                    // read the key details locally and update
                    match misc_helpers::json_read_from_file::<Key>(key_file.to_path_buf()) {
                        Ok(key) => {
                            key_keeper_wrapper::set_key(shared_state.clone(), key.clone());

                            let message = helpers::write_startup_event(
                                "Found key details from local and ready to use.",
                                "poll_secure_channel_status",
                                "key_keeper",
                                logger::AGENT_LOGGER_KEY,
                            );
                            key_keeper_wrapper::set_status_message(
                                shared_state.clone(),
                                message.to_string(),
                            );
                            key_found = true;

                            provision::key_latched(shared_state.clone());
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
                let key = match key::acquire_key(base_url.clone()).await {
                    Ok(k) => k,
                    Err(e) => {
                        logger::write_warning(format!("Failed to acquire key details: {:?}", e));
                        continue;
                    }
                };

                // key has not latched before,
                // set the key_file full path from key details
                let guid = key.guid.to_string();
                let mut key_file = key_dir.to_path_buf().join(&guid);
                key_file.set_extension("key");
                _ = misc_helpers::json_write_to_file(&key, key_file);
                logger::write_information(format!(
                    "Successfully acquired the key '{}' details from server and saved locally.",
                    guid
                ));

                // double check the key details saved correctly to local disk
                if check_local_key(key_dir.to_path_buf(), &key) {
                    match key::attest_key(base_url.clone(), &key).await {
                        Ok(()) => {
                            // update in memory
                            key_keeper_wrapper::set_key(shared_state.clone(), key.clone());

                            let message = helpers::write_startup_event(
                                "Successfully attest the key and ready to use.",
                                "poll_secure_channel_status",
                                "key_keeper",
                                logger::AGENT_LOGGER_KEY,
                            );
                            key_keeper_wrapper::set_status_message(
                                shared_state.clone(),
                                message.to_string(),
                            );
                            provision::key_latched(shared_state.clone());
                        }
                        Err(e) => {
                            logger::write_warning(format!("Failed to attest the key: {:?}", e));
                            continue;
                        }
                    }
                } else {
                    logger::write_warning(format!("Saved key '{}' details lost locally.", guid));
                }
            }
        }

        // update the current secure channel state if different
        if key_keeper_wrapper::update_current_secure_channel_state(
            shared_state.clone(),
            state.to_string(),
        ) {
            // update the redirector policy map
            redirector::update_wire_server_redirect_policy(
                status.get_wire_server_mode() != DISABLE_STATE,
                shared_state.clone(),
            );
            redirector::update_imds_redirect_policy(
                status.get_imds_mode() != DISABLE_STATE,
                shared_state.clone(),
            );

            // customer has not enforce the secure channel state
            if state == DISABLE_STATE {
                let message = helpers::write_startup_event(
                    "Customer has not enforce the secure channel state.",
                    "poll_secure_channel_status",
                    "key_keeper",
                    logger::AGENT_LOGGER_KEY,
                );
                // Update the status message and let the provision to continue
                key_keeper_wrapper::set_status_message(shared_state.clone(), message.to_string());
                // clear key in memory for disabled state
                key_keeper_wrapper::clear_key(shared_state.clone());
                provision::key_latched(shared_state.clone());
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
            false
        }
    }
}

pub fn stop(shared_state: Arc<Mutex<SharedState>>) {
    key_keeper_wrapper::set_shutdown(shared_state.clone(), true);
}

pub fn get_status(shared_state: Arc<Mutex<SharedState>>) -> ProxyAgentDetailStatus {
    let status = if key_keeper_wrapper::get_shutdown(shared_state.clone()) {
        ModuleState::STOPPED.to_string()
    } else {
        ModuleState::RUNNING.to_string()
    };

    let mut states = HashMap::new();
    states.insert(
        "secureChannelState".to_string(),
        key_keeper_wrapper::get_current_secure_channel_state(shared_state.clone()),
    );
    if let Some(key_guid) = key_keeper_wrapper::get_current_key_guid(shared_state.clone()) {
        states.insert("keyGuid".to_string(), key_guid);
    }
    states.insert(
        "wireServerRuleId".to_string(),
        key_keeper_wrapper::get_wireserver_rule_id(shared_state.clone()),
    );
    states.insert(
        "imdsRuleId".to_string(),
        key_keeper_wrapper::get_imds_rule_id(shared_state.clone()),
    );
    if let Some(incarnation) = key_keeper_wrapper::get_current_key_incarnation(shared_state.clone())
    {
        states.insert("keyIncarnationId".to_string(), incarnation.to_string());
    }

    ProxyAgentDetailStatus {
        status,
        message: key_keeper_wrapper::get_status_message(shared_state.clone()),
        states: Some(states),
    }
}

#[cfg(test)]
mod tests {
    use super::key::Key;
    use crate::common::logger;
    use crate::key_keeper;
    use crate::shared_state::SharedState;
    use crate::test_mock::server_mock;
    use proxy_agent_shared::{logger_manager, misc_helpers};
    use std::env;
    use std::fs;
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
        let mut key_file = temp_test_path.to_path_buf().join(key.guid.clone());
        key_file.set_extension("key");
        _ = misc_helpers::json_write_to_file(&key, key_file);

        assert!(super::check_local_key(temp_test_path.to_path_buf(), &key));

        _ = fs::remove_dir_all(&temp_test_path);
    }

    // this test is to test poll_secure_channel_status
    // it requires more threads to run server and client
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn poll_secure_channel_status_tests() {
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

        let shared_state = SharedState::new();
        // start wire_server listener
        let ip = "127.0.0.1";
        let port = 8081u16;
        let cloned_shared_state = shared_state.clone();
        tokio::spawn(async move {
            let _ = server_mock::start(ip.to_string(), port, cloned_shared_state.clone()).await;
        });
        tokio::time::sleep(Duration::from_millis(100)).await;

        // start with disabled secure channel state
        server_mock::set_secure_channel_state(false);

        // start poll_secure_channel_status
        let cloned_keys_dir = keys_dir.to_path_buf();
        key_keeper::poll_status_async(
            Url::parse("http://127.0.0.1:8081/").unwrap(),
            cloned_keys_dir,
            Duration::from_millis(10),
            false,
            shared_state.clone(),
        )
        .await;

        for _ in [0; 5] {
            // wait poll_secure_channel_status run at least one loop
            tokio::time::sleep(Duration::from_millis(100)).await;
            if keys_dir.exists() {
                break;
            }
        }

        let key_files: Vec<std::path::PathBuf> = misc_helpers::get_files(&keys_dir).unwrap();
        assert!(
            key_files.is_empty(),
            "Should not write key file at disable secure channel state"
        );

        // set secure channel state to running
        server_mock::set_secure_channel_state(true);
        // wait poll_secure_channel_status run at least one loop
        tokio::time::sleep(Duration::from_millis(100)).await;
        let key_files = misc_helpers::get_files(&keys_dir).unwrap();
        assert_eq!(
            1,
            key_files.len(),
            "Should write key file at running secure channel state"
        );

        // stop poll
        key_keeper::stop(shared_state.clone());
        server_mock::stop(ip.to_string(), port, shared_state.clone());

        // clean up and ignore the clean up errors
        _ = fs::remove_dir_all(&temp_test_path);
    }
}
