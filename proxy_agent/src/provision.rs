// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use crate::common::{config, helpers, logger};
use crate::proxy::proxy_listener;
use crate::telemetry::event_reader;
use crate::{key_keeper, proxy_agent_status, redirector};
use once_cell::sync::Lazy;
use proxy_agent_shared::misc_helpers;
use proxy_agent_shared::telemetry::event_logger;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const STATUS_TAG_TMP_FILE_NAME: &str = "status.tag.tmp";
const STATUS_TAG_FILE_NAME: &str = "status.tag";
static mut STATE: Lazy<Arc<Mutex<u8>>> = Lazy::new(|| Arc::new(Mutex::new(0)));
static mut LOGGER_THREADS_INITIALIZED: Lazy<Arc<Mutex<bool>>> =
    Lazy::new(|| Arc::new(Mutex::new(false)));

pub fn redirector_ready() {
    update_provision_state(1, None);
}

pub fn key_latched() {
    update_provision_state(2, None);
}

pub fn listener_started() {
    update_provision_state(4, None);
}

fn update_provision_state(state: u8, provision_dir: Option<PathBuf>) {
    unsafe {
        let cloned_state: Arc<Mutex<u8>> = Arc::clone(&*STATE);
        let cloned_state = cloned_state.lock();
        match cloned_state {
            Ok(mut cloned_state) => {
                *cloned_state |= state;

                if *cloned_state == 7 {
                    // write provision success state here
                    write_provision_state(true, provision_dir);

                    // start event threads right after provision successfully
                    start_event_threads();
                }
            }
            Err(e) => {
                _ = logger::write_error(format!("Failed to lock provision state with error: {e}"));
                return;
            }
        }
    }
}

pub fn provision_timeup(provision_dir: Option<PathBuf>) {
    unsafe {
        let cloned_state = Arc::clone(&*STATE);
        let cloned_state = cloned_state.lock();
        match cloned_state {
            Ok(cloned_state) => {
                if *cloned_state != 7 {
                    // write provision fail state here
                    write_provision_state(false, provision_dir);
                }
            }
            Err(e) => {
                _ = logger::write_error(format!("Failed to lock provision state with error: {e}"));
                return;
            }
        }
    }
}

pub fn start_event_threads() {
    unsafe {
        let cloned = Arc::clone(&*LOGGER_THREADS_INITIALIZED);
        let cloned = cloned.lock();
        match cloned {
            Ok(mut cloned) => {
                if *cloned {
                    return;
                }

                event_logger::start_async(
                    config::get_events_dir(),
                    Duration::default(),
                    config::get_max_event_file_count(),
                    logger::AGENT_LOGGER_KEY,
                );
                event_reader::start_async(config::get_events_dir(), Duration::from_secs(300), true);
                *cloned = true;
                proxy_agent_status::start_async(Duration::default());
            }
            Err(e) => {
                _ = logger::write_error(format!("Failed to lock provision state with error: {e}"));
                return;
            }
        }
    }
}

fn write_provision_state(provision_success: bool, provision_dir: Option<PathBuf>) {
    let provision_dir = match provision_dir {
        Some(dir) => dir,
        None => config::get_keys_dir(),
    };

    let provisioned_file: PathBuf = provision_dir.join("provisioned.tag");
    _ = misc_helpers::try_create_folder(provision_dir.to_path_buf());
    _ = std::fs::write(
        provisioned_file,
        misc_helpers::get_date_time_string_with_miliseconds(),
    );

    let mut status = String::new(); //provision success, write 0 byte to file
    if !provision_success {
        status.push_str(&format!(
            "keyLatchStatus - {}\r\n",
            key_keeper::get_status().message
        ));
        status.push_str(&format!(
            "ebpfProgramStatus - {}\r\n",
            redirector::get_status().message
        ));
        status.push_str(&format!(
            "proxyListenerStatus - {}\r\n",
            proxy_listener::get_status().message
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
                    _ = logger::write_error(format!(
                        "Failed to rename status file with error: {e}"
                    ));
                }
            }
        }
        Err(e) => {
            _ = logger::write_error(format!("Failed to write temp status file with error: {e}"));
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

        match duration {
            Some(d) => {
                if d.as_millis() >= helpers::get_elapsed_time_in_millisec() {
                    std::thread::sleep(Duration::from_millis(100));
                    continue;
                }
            }
            None => {}
        }

        return provision_status;
    }
}

// Get provision status
// return value
//  bool - true provision finished; false provision not finished
//  String - provision error message, emtpy means provision success or provision failed.
fn get_provision_status(provision_dir: Option<PathBuf>) -> (bool, String) {
    let provision_dir = match provision_dir {
        Some(dir) => dir,
        None => config::get_keys_dir(),
    };

    let status_file: PathBuf = provision_dir.join(STATUS_TAG_FILE_NAME);
    if !status_file.exists() {
        return (false, String::new());
    }

    match std::fs::read_to_string(status_file) {
        Ok(status) => {
            return (true, status);
        }
        Err(e) => {
            println!("Failed to read status.tag file with error: {}", e);
            return (false, String::new());
        }
    }
}

#[cfg(test)]
mod tests {
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

        let dir1 = temp_test_path.to_path_buf();
        let dir2 = temp_test_path.to_path_buf();
        let dir3 = temp_test_path.to_path_buf();
        let handles = vec![
            thread::spawn(move || super::update_provision_state(1, Some(dir1))),
            thread::spawn(move || super::update_provision_state(2, Some(dir2))),
            thread::spawn(move || super::update_provision_state(4, Some(dir3))),
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
            unsafe { super::LOGGER_THREADS_INITIALIZED.lock().unwrap().clone() };
        assert!(event_threads_initialized);

        // write status.tag file
        _ = fs::write(status_file, "this is test message".as_bytes());
        let provision_status = super::get_provision_status(Some(temp_test_path.to_path_buf()));
        assert!(provision_status.0, "provision_status.0 must be true");
        assert!(
            provision_status.1.len() > 0,
            "provision_status.1 should not empty"
        );

        // clean up and ignore the clean up errors
        _ = fs::remove_dir_all(&temp_test_path);
    }
}
