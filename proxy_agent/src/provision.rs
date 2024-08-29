// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

use crate::common::http::{self, http_request::HttpRequest, request::Request, response::Response};
use crate::common::{config, constants, helpers, logger};
use crate::proxy::proxy_listener;
use crate::shared_state::{provision_wrapper, telemetry_wrapper, SharedState};
use crate::telemetry::event_reader;
use crate::{key_keeper, proxy_agent_status, redirector};
use proxy_agent_shared::misc_helpers;
use proxy_agent_shared::telemetry::event_logger;
use serde_derive::{Deserialize, Serialize};
use std::io::{Error, ErrorKind};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const STATUS_TAG_TMP_FILE_NAME: &str = "status.tag.tmp";
const STATUS_TAG_FILE_NAME: &str = "status.tag";

bitflags::bitflags! {
    #[derive(Clone)]
    pub struct ProvisionFlags: u8 {
        const NONE = 0;
        const REDIRECTOR_READY = 1;
        const KEY_LATCH_READY = 2;
        const LISTENER_READY = 4;
        const ALL_READY = 7;
    }
}

#[derive(Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct ProivsionState {
    finished: bool,
    errorMessage: String,
}

pub const PROVISION_URL_PATH: &str = "/provision";

pub fn redirector_ready(shared_state: Arc<Mutex<SharedState>>) {
    update_provision_state(ProvisionFlags::REDIRECTOR_READY, None, shared_state);
}

pub fn key_latched(shared_state: Arc<Mutex<SharedState>>) {
    update_provision_state(ProvisionFlags::KEY_LATCH_READY, None, shared_state);
}

pub fn listener_started(shared_state: Arc<Mutex<SharedState>>) {
    update_provision_state(ProvisionFlags::LISTENER_READY, None, shared_state);
}

fn update_provision_state(
    state: ProvisionFlags,
    provision_dir: Option<PathBuf>,
    shared_state: Arc<Mutex<SharedState>>,
) {
    let provision_state = provision_wrapper::update_state(shared_state.clone(), state);
    if provision_state.contains(ProvisionFlags::ALL_READY) {
        provision_wrapper::set_provision_finished(shared_state.clone());

        // write provision success state here
        write_provision_state(provision_dir, shared_state.clone());

        // start event threads right after provision successfully
        start_event_threads(shared_state.clone());
    }
}

pub fn provision_timeup(provision_dir: Option<PathBuf>, shared_state: Arc<Mutex<SharedState>>) {
    let provision_state = provision_wrapper::get_state(shared_state.clone());
    if !provision_state.contains(ProvisionFlags::ALL_READY) {
        provision_wrapper::set_provision_finished(shared_state.clone());

        // write provision state
        write_provision_state(provision_dir, shared_state.clone());
    }
}

pub fn start_event_threads(shared_state: Arc<Mutex<SharedState>>) {
    let logger_threads_initialized =
        provision_wrapper::get_event_log_threads_initialized(shared_state.clone());
    if logger_threads_initialized {
        return;
    }

    let cloned_state = shared_state.clone();
    event_logger::start_async(
        config::get_events_dir(),
        Duration::default(),
        config::get_max_event_file_count(),
        logger::AGENT_LOGGER_KEY,
        move |status: String| {
            telemetry_wrapper::set_logger_status_message(cloned_state.clone(), status);
        },
    );
    tokio::spawn(event_reader::start(
        config::get_events_dir(),
        Some(Duration::from_secs(300)),
        true,
        shared_state.clone(),
    ));
    provision_wrapper::set_event_log_threads_initialized(shared_state.clone(), true);

    tokio::spawn(proxy_agent_status::start(
        Duration::default(),
        shared_state.clone(),
    ));
}

fn write_provision_state(provision_dir: Option<PathBuf>, shared_state: Arc<Mutex<SharedState>>) {
    let provision_dir = provision_dir.unwrap_or_else(config::get_keys_dir);

    let provisioned_file: PathBuf = provision_dir.join("provisioned.tag");
    _ = misc_helpers::try_create_folder(provision_dir.to_path_buf());
    _ = std::fs::write(
        provisioned_file,
        misc_helpers::get_date_time_string_with_milliseconds(),
    );

    let failed_state_message = get_provision_failed_state_message(shared_state.clone());
    let status_file: PathBuf = provision_dir.join(STATUS_TAG_TMP_FILE_NAME);
    match std::fs::write(status_file, failed_state_message.as_bytes()) {
        Ok(_) => {
            match std::fs::rename(
                provision_dir.join(STATUS_TAG_TMP_FILE_NAME),
                provision_dir.join(STATUS_TAG_FILE_NAME),
            ) {
                Ok(_) => {}
                Err(e) => {
                    logger::write_error(format!("Failed to rename status file with error: {e}"));
                }
            }
        }
        Err(e) => {
            logger::write_error(format!("Failed to write temp status file with error: {e}"));
        }
    }
}

/// Get provision failed state message
fn get_provision_failed_state_message(shared_state: Arc<Mutex<SharedState>>) -> String {
    let provision_state = provision_wrapper::get_state(shared_state.clone());

    let mut state = String::new(); //provision success, write 0 byte to file
    if !provision_state.contains(ProvisionFlags::REDIRECTOR_READY) {
        state.push_str(&format!(
            "ebpfProgramStatus - {}\r\n",
            redirector::get_status(shared_state.clone()).message
        ));
    }

    if !provision_state.contains(ProvisionFlags::KEY_LATCH_READY) {
        state.push_str(&format!(
            "keyLatchStatus - {}\r\n",
            key_keeper::get_status(shared_state.clone()).message
        ));
    }

    if !provision_state.contains(ProvisionFlags::LISTENER_READY) {
        state.push_str(&format!(
            "proxyListenerStatus - {}\r\n",
            proxy_listener::get_status(shared_state.clone()).message
        ));
    }

    state
}

pub fn get_provision_state(shared_state: Arc<Mutex<SharedState>>) -> ProivsionState {
    ProivsionState {
        finished: provision_wrapper::get_provision_finished(shared_state.clone()),
        errorMessage: get_provision_failed_state_message(shared_state),
    }
}

/// Get current provision status and wait until provision finished or timeout
/// it serves for --status --wait command line option
pub async fn get_provision_status_wait(port: u16, duration: Option<Duration>) -> (bool, String) {
    loop {
        let provision_state = get_current_provision_status(port);
        let (finished, message) = match provision_state {
            Ok(state) => (state.finished, state.errorMessage),
            Err(e) => {
                println!(
                    "Failed to query the current provision state with error: {}.",
                    e
                );
                (false, String::new())
            }
        };
        if finished {
            return (finished, message);
        }

        if let Some(d) = duration {
            if d.as_millis() >= helpers::get_elapsed_time_in_millisec() {
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        }

        // wait timedout return as 'not finished'
        return (false, String::new());
    }
}

// Get current provision status from GPA service via http request
// return value
//  bool - true provision finished; false provision not finished
//  String - provision error message, empty means provision success or provision failed.
fn get_current_provision_status(port: u16) -> std::io::Result<ProivsionState> {
    let provision_url =
        url::Url::parse(&format!("http://127.0.0.1:{}{}", port, PROVISION_URL_PATH)).map_err(
            |e| {
                std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Failed to parse provision url with error: {}", e),
                )
            },
        )?;
    let mut req = Request::new(PROVISION_URL_PATH.to_string(), "GET".to_string());
    req.headers
        .add_header(constants::METADATA_HEADER.to_string(), "True ".to_string());

    let mut http_request = HttpRequest::new(provision_url, req);
    http_request
        .request
        .headers
        .add_header("Host".to_string(), http_request.get_host());

    let response = http::get_response_in_string(&mut http_request)?;
    let response_body = response.get_body_as_string()?;
    if response.status != Response::OK {
        return Err(Error::new(
            ErrorKind::Other,
            format!("Host response {} - {}", response.status, response_body),
        ));
    }

    let state: ProivsionState = serde_json::from_str(&response_body)?;
    Ok(state)
}

#[cfg(test)]
mod tests {
    use crate::common::logger;
    use crate::provision::ProvisionFlags;
    use crate::proxy::proxy_connection::Connection;
    use crate::proxy::proxy_listener;
    use crate::shared_state::provision_wrapper;
    use crate::shared_state::SharedState;
    use proxy_agent_shared::logger_manager;
    use std::env;
    use std::fs;
    use std::time::Duration;

    #[tokio::test]
    async fn provision_state_test() {
        let mut temp_test_path = env::temp_dir();
        let logger_key = "provision_state_test";
        temp_test_path.push(logger_key);

        // clean up and ignore the clean up errors
        _ = fs::remove_dir_all(&temp_test_path);

        logger_manager::init_logger(
            logger::AGENT_LOGGER_KEY.to_string(), // production code uses 'Agent_Log' to write.
            temp_test_path.clone(),
            logger_key.to_string(),
            10 * 1024 * 1024,
            20,
        );
        Connection::init_logger(temp_test_path.to_path_buf());

        // start listener, the port must different from the one used in production code
        let shared_state = SharedState::new();
        let port: u16 = 8092;
        proxy_listener::start_async(port, 1, shared_state.clone());

        // give some time to let the listener started
        let sleep_duration = Duration::from_millis(100);
        tokio::time::sleep(sleep_duration).await;

        let provision_status = super::get_provision_status_wait(port, None).await;
        assert!(!provision_status.0, "provision_status.0 must be false");
        assert_eq!(
            0,
            provision_status.1.len(),
            "provision_status.1 must be empty"
        );

        let dir1 = temp_test_path.to_path_buf();
        let dir2 = temp_test_path.to_path_buf();
        let dir3 = temp_test_path.to_path_buf();
        let s1 = shared_state.clone();
        let s2 = shared_state.clone();
        let s3 = shared_state.clone();
        let handles = vec![
            tokio::task::spawn_blocking(|| {
                super::update_provision_state(ProvisionFlags::REDIRECTOR_READY, Some(dir1), s1);
            }),
            tokio::task::spawn_blocking(|| {
                super::update_provision_state(ProvisionFlags::KEY_LATCH_READY, Some(dir2), s2);
            }),
            tokio::task::spawn_blocking(|| {
                super::update_provision_state(ProvisionFlags::LISTENER_READY, Some(dir3), s3);
            }),
        ];

        for handle in handles {
            handle.await.unwrap();
        }

        let provisioned_file = temp_test_path.join("provisioned.tag");
        assert!(provisioned_file.exists());

        let status_file = temp_test_path.join(super::STATUS_TAG_FILE_NAME);
        assert!(status_file.exists());
        assert_eq!(
            0,
            status_file.metadata().unwrap().len(),
            "success status.tag file must be empty"
        );

        let provision_status =
            super::get_provision_status_wait(port, Some(Duration::from_millis(5))).await;
        assert!(provision_status.0, "provision_status.0 must be true");
        assert_eq!(
            0,
            provision_status.1.len(),
            "provision_status.1 must be empty"
        );

        let event_threads_initialized =
            provision_wrapper::get_event_log_threads_initialized(shared_state.clone());
        assert!(event_threads_initialized);

        // stop listener
        proxy_listener::stop(port, shared_state);

        // clean up and ignore the clean up errors
        _ = fs::remove_dir_all(&temp_test_path);
    }
}
