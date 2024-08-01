// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use crate::common::{config, helpers, logger};
use crate::proxy::proxy_server;
use crate::shared_state::{provision_wrapper, telemetry_wrapper, SharedState};
use crate::telemetry::event_reader;
use crate::{key_keeper, proxy_agent_status, redirector};
use proxy_agent_shared::misc_helpers;
use proxy_agent_shared::telemetry::event_logger;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const STATUS_TAG_TMP_FILE_NAME: &str = "status.tag.tmp";
const STATUS_TAG_FILE_NAME: &str = "status.tag";

pub fn redirector_ready(shared_state: Arc<Mutex<SharedState>>) {
    update_provision_state(1, None, shared_state);
}

pub fn key_latched(shared_state: Arc<Mutex<SharedState>>) {
    update_provision_state(2, None, shared_state);
}

pub fn listener_started(shared_state: Arc<Mutex<SharedState>>) {
    update_provision_state(4, None, shared_state);
}

fn update_provision_state(
    state: u8,
    provision_dir: Option<PathBuf>,
    shared_state: Arc<Mutex<SharedState>>,
) {
    let provision_state = provision_wrapper::update_state(shared_state.clone(), state);
    if provision_state == 7 {
        // write provision success state here
        write_provision_state(true, provision_dir, shared_state.clone());

        // start event threads right after provision successfully
        start_event_threads(shared_state.clone());
    }
}

pub fn provision_timeup(provision_dir: Option<PathBuf>, shared_state: Arc<Mutex<SharedState>>) {
    let provision_state = provision_wrapper::get_state(shared_state.clone());
    if provision_state != 7 {
        // write provision fail state here
        write_provision_state(false, provision_dir, shared_state.clone());
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
    event_reader::start_async(
        config::get_events_dir(),
        Duration::from_secs(300),
        true,
        shared_state.clone(),
        None,
    );
    provision_wrapper::set_event_log_threads_initialized(shared_state.clone(), true);
    proxy_agent_status::start_async(Duration::default(), shared_state.clone());
}

fn write_provision_state(
    provision_success: bool,
    provision_dir: Option<PathBuf>,
    shared_state: Arc<Mutex<SharedState>>,
) {
    let provision_dir = provision_dir.unwrap_or_else(config::get_keys_dir);

    let provisioned_file: PathBuf = provision_dir.join("provisioned.tag");
    _ = misc_helpers::try_create_folder(provision_dir.to_path_buf());
    _ = std::fs::write(
        provisioned_file,
        misc_helpers::get_date_time_string_with_milliseconds(),
    );

    let mut status = String::new(); //provision success, write 0 byte to file
    if !provision_success {
        status.push_str(&format!(
            "keyLatchStatus - {}\r\n",
            key_keeper::get_status(shared_state.clone()).message
        ));
        status.push_str(&format!(
            "ebpfProgramStatus - {}\r\n",
            redirector::get_status(shared_state.clone()).message
        ));
        status.push_str(&format!(
            "proxyListenerStatus - {}\r\n",
            proxy_server::get_status(shared_state.clone()).message
        ));
    }

    let status_file: PathBuf = provision_dir.join(STATUS_TAG_TMP_FILE_NAME);
    match std::fs::write(status_file, status.as_bytes()) {
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

pub fn get_provision_status_wait(
    provision_dir: Option<PathBuf>,
    duration: Option<Duration>,
) -> (bool, String) {
    loop {
        let provision_status = get_provision_status(provision_dir.clone());
        if provision_status.0 {
            return provision_status;
        }

        if let Some(d) = duration {
            if d.as_millis() >= helpers::get_elapsed_time_in_millisec() {
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }
        }

        return provision_status;
    }
}

// Get provision status
// return value
//  bool - true provision finished; false provision not finished
//  String - provision error message, empty means provision success or provision failed.
fn get_provision_status(provision_dir: Option<PathBuf>) -> (bool, String) {
    let provision_dir = provision_dir.unwrap_or_else(config::get_keys_dir);

    let status_file: PathBuf = provision_dir.join(STATUS_TAG_FILE_NAME);
    if !status_file.exists() {
        return (false, String::new());
    }

    match std::fs::read_to_string(status_file) {
        Ok(status) => (true, status),
        Err(e) => {
            println!("Failed to read status.tag file with error: {}", e);
            (false, String::new())
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::shared_state::provision_wrapper;
    use crate::shared_state::SharedState;
    use std::env;
    use std::fs;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn provision_state_test() {
        let mut temp_test_path = env::temp_dir();
        temp_test_path.push("update_provision_state_test");

        // clean up and ignore the clean up errors
        _ = fs::remove_dir_all(&temp_test_path);

        let provision_status =
            super::get_provision_status_wait(Some(temp_test_path.to_path_buf()), None);
        assert!(!provision_status.0, "provision_status.0 must be false");
        assert_eq!(
            0,
            provision_status.1.len(),
            "provision_status.1 must be empty"
        );

        let shared_state = SharedState::new();
        let dir1 = temp_test_path.to_path_buf();
        let dir2 = temp_test_path.to_path_buf();
        let dir3 = temp_test_path.to_path_buf();
        let s1 = shared_state.clone();
        let s2 = shared_state.clone();
        let s3 = shared_state.clone();
        let handles = vec![
            thread::spawn(move || super::update_provision_state(1, Some(dir1), s1)),
            thread::spawn(move || super::update_provision_state(2, Some(dir2), s2)),
            thread::spawn(move || super::update_provision_state(4, Some(dir3), s3)),
        ];

        for handle in handles {
            handle.join().unwrap();
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

        let provision_status = super::get_provision_status_wait(
            Some(temp_test_path.to_path_buf()),
            Some(Duration::from_millis(5)),
        );
        assert!(provision_status.0, "provision_status.0 must be true");
        assert_eq!(
            0,
            provision_status.1.len(),
            "provision_status.1 must be empty"
        );

        let event_threads_initialized =
            provision_wrapper::get_event_log_threads_initialized(shared_state.clone());
        assert!(event_threads_initialized);

        // write status.tag file
        _ = fs::write(status_file, "this is test message".as_bytes());
        let provision_status = super::get_provision_status(Some(temp_test_path.to_path_buf()));
        assert!(provision_status.0, "provision_status.0 must be true");
        assert!(
            !provision_status.1.is_empty(),
            "provision_status.1 should not empty"
        );

        // clean up and ignore the clean up errors
        _ = fs::remove_dir_all(&temp_test_path);
    }
}
