// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use once_cell::sync::Lazy;
use proxy_agent_shared::logger_manager;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

pub static mut LOGGER_KEY: Lazy<Option<Arc<Mutex<String>>>> = Lazy::new(|| None);

pub fn init_logger(log_folder: String, log_name: &str) {
    force_init_logger(log_folder, log_name, false);
}

pub fn get_logger_key() -> String {
    unsafe {
        match &*LOGGER_KEY {
            Some(logger_key) => logger_key.lock().unwrap().as_str().to_string(),
            None => {
                eprintln!("Logge has not init, please call 'init' first");
                return "".to_string();
            }
        }
    }
}

fn force_init_logger(log_folder: String, log_name: &str, force: bool) {
    logger_manager::init_logger(
        log_name.to_string(),
        PathBuf::from(log_folder),
        log_name.to_string(),
        20 * 1024 * 1024,
        30,
    );
    unsafe {
        if LOGGER_KEY.is_some() && !force {
            return;
        }
        *LOGGER_KEY = Some(Arc::new(Mutex::new(log_name.to_string())));
    }
}

pub fn write(message: String) {
    let logger_key = get_logger_key();
    logger_manager::write(&logger_key, message);
}

#[cfg(test)]
mod test {
    use std::{env, fs, path::PathBuf};

    #[test]
    fn test_write_logger() {
        let mut temp_test_path = env::temp_dir();
        temp_test_path.push("test_init_logger");
        let log_folder: String = temp_test_path.join("log").to_str().unwrap().to_string();
        let log_name = "test.log";
        super::force_init_logger(log_folder, log_name, true);
        unsafe {
            assert!(super::LOGGER_KEY.is_some());
        }
        let message = "test message".to_string();
        super::write(message);
        unsafe {
            assert!(super::LOGGER_KEY.is_some());
        }

        //Check if log file exists
        let log_file: PathBuf = temp_test_path.join("log").join("test.log".to_string());
        assert_eq!(log_file.exists(), true);

        _ = fs::remove_dir_all(&temp_test_path);
    }
}
