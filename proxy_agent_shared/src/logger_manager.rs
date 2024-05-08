// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use crate::rolling_logger::RollingLogger;
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

static mut LOGGERS: Lazy<HashMap<String, Arc<Mutex<RollingLogger>>>> = Lazy::new(|| HashMap::new());
static mut FIRST_LOGGER_KEY: Lazy<Option<Arc<Mutex<String>>>> = Lazy::new(|| None);

pub fn init_logger(
    logger_key: String,
    log_folder: PathBuf,
    log_name: String,
    log_size: u64,
    log_count: u16,
) {
    unsafe {
        if LOGGERS.contains_key(&logger_key) {
            println!("logger '{logger_key}' already exists.");
            return;
        }

        let logger = RollingLogger::create_new(log_folder, log_name, log_size, log_count);
        LOGGERS.insert(logger_key.to_string(), Arc::new(Mutex::new(logger)));
        println!("logger '{logger_key}' created.");

        if FIRST_LOGGER_KEY.is_none() {
            *FIRST_LOGGER_KEY = Some(Arc::new(Mutex::new(logger_key)));
        }
    }
}

pub fn get_logger(logger_key: &str) -> Arc<Mutex<RollingLogger>> {
    get_logger_arc(logger_key).unwrap()
}

fn get_logger_arc(logger_key: &str) -> std::io::Result<Arc<Mutex<RollingLogger>>> {
    unsafe {
        if !LOGGERS.contains_key(logger_key) {
            return Err(Error::new(
                ErrorKind::Unsupported,
                format!("Logger '{logger_key}' has not init, please call 'init_logger' first."),
            ));
        }

        let logger = &LOGGERS[logger_key];
        Ok(Arc::clone(logger))
    }
}

pub fn write(logger_key: &str, message: String) {
    match get_logger(logger_key).lock() {
        Ok(mut logger) => {
            match logger.write(message) {
                Ok(_) => {}
                Err(e) => {
                    println!("Error writing to logger: {}", e)
                }
            };
        }
        Err(e) => {
            println!("Error getting logger: {}", e)
        }
    };
}

pub fn write_information(logger_key: &str, message: String) {
    match get_logger(logger_key).lock() {
        Ok(mut logger) => {
            match logger.write_information(message) {
                Ok(_) => {}
                Err(e) => {
                    println!("Error writing to logger: {}", e)
                }
            };
        }
        Err(e) => {
            println!("Error getting logger: {}", e)
        }
    };
}

pub fn write_warning(logger_key: &str, message: String) {
    match get_logger(logger_key).lock() {
        Ok(mut logger) => {
            match logger.write_warning(message) {
                Ok(_) => {}
                Err(e) => {
                    println!("Error writing to logger: {}", e)
                }
            };
        }
        Err(e) => {
            println!("Error getting logger: {}", e)
        }
    };
}

pub fn write_error(logger_key: &str, message: String) {
    match get_logger(logger_key).lock() {
        Ok(mut logger) => {
            match logger.write_error(message) {
                Ok(_) => {}
                Err(e) => {
                    println!("Error writing to logger: {}", e)
                }
            };
        }
        Err(e) => {
            println!("Error getting logger: {}", e)
        }
    };
}

pub fn write_info(message: String) {
    unsafe {
        match FIRST_LOGGER_KEY.as_ref() {
            Some(logger_key) => {
                write_information(&logger_key.lock().unwrap(), message);
            }
            None => {
                println!("No logger has been created.");
            }
        }
    }
}

pub fn write_warn(message: String) {
    unsafe {
        match FIRST_LOGGER_KEY.as_ref() {
            Some(logger_key) => {
                write_warning(&logger_key.lock().unwrap(), message);
            }
            None => {
                println!("No logger has been created.");
            }
        }
    }
}

pub fn write_err(message: String) {
    unsafe {
        match FIRST_LOGGER_KEY.as_ref() {
            Some(logger_key) => {
                write_error(&logger_key.lock().unwrap(), message);
            }
            None => {
                println!("No logger has been created.");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::fs;
    use std::thread;

    #[test]
    fn logger_manager_test() {
        let mut temp_test_path = env::temp_dir();
        let logger_key = "agent_logger_test";
        temp_test_path.push(logger_key);

        // clean up and ignore the clean up errors
        _ = fs::remove_dir_all(&temp_test_path);

        super::init_logger(
            logger_key.to_string(),
            temp_test_path.clone(),
            logger_key.to_string(),
            200,
            6,
        );

        let mut handles = vec![];

        for _ in [0; 20] {
            let handle = thread::spawn(|| {
                super::get_logger(logger_key)
                    .lock()
                    .unwrap()
                    .write(String::from(
                        "This is a test message This is a test message",
                    ))
                    .unwrap();
                super::get_logger(logger_key)
                    .lock()
                    .unwrap()
                    .write(String::from(
                        "This is a test message This is a test message",
                    ))
                    .unwrap();
                super::write_info("message from write_info".to_string());
                super::write_warn("message from write_warn".to_string());
                super::write_err("message from write_err".to_string());
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        let file_count = super::get_logger(logger_key)
            .lock()
            .unwrap()
            .get_log_files()
            .unwrap();
        assert_eq!(6, file_count.len(), "log file count mismatch");

        // clean up and ignore the clean up errors
        _ = fs::remove_dir_all(&temp_test_path);
    }
}
