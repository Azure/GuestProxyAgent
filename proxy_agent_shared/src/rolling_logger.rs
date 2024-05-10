// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use crate::misc_helpers;
use std::fs::{self, File, OpenOptions};
use std::io::{LineWriter, Write};
use std::path::PathBuf;

pub struct RollingLogger {
    log_dir: PathBuf,
    log_file_name: String,
    log_file_extension: String,

    max_log_file_size: u64,  // max log file size in KB
    max_log_file_count: u16, // max log file count, if exceed the count, the older log files will be removed.

    initialized: bool,

    //log_file: File,
    log_writer: Option<LineWriter<File>>,
}

fn get_log_header(severity: &str) -> String {
    format!(
        "{} {} {}",
        misc_helpers::get_thread_identity(),
        misc_helpers::get_date_time_string_with_miliseconds(),
        severity
    )
}

impl RollingLogger {
    pub fn new(dir: String, file_name: String) -> RollingLogger {
        RollingLogger::create_new(PathBuf::from(dir), file_name, 20 * 1024 * 1024, 20)
    }

    pub fn create_new(
        dir: PathBuf,
        file_name: String,
        log_size: u64,
        log_count: u16,
    ) -> RollingLogger {
        let mut logger = RollingLogger {
            log_dir: dir,
            log_file_name: file_name,
            log_file_extension: String::from("log"),
            max_log_file_size: log_size,
            max_log_file_count: log_count,
            initialized: false,
            log_writer: None, // will initialize later
        };
        logger.init().unwrap();

        logger
    }

    fn init(&mut self) -> std::io::Result<()> {
        if !self.initialized {
            self.open_file()?;
            self.initialized = true;
        }

        Ok(())
    }

    fn open_file(&mut self) -> std::io::Result<()> {
        misc_helpers::try_create_folder(self.log_dir.to_path_buf())?;

        let file_full_path = self.get_current_file_full_path(None);
        let f: File;
        if file_full_path.exists() {
            f = OpenOptions::new().append(true).open(file_full_path)?;
        } else {
            f = File::create(file_full_path)?;
        }

        self.log_writer = Some(LineWriter::new(f));

        Ok(())
    }

    pub fn write(&mut self, message: String) -> std::io::Result<()> {
        let header = get_log_header("[VERB]    ");
        self.write_line(header + &message)
    }

    pub fn write_information(&mut self, message: String) -> std::io::Result<()> {
        let header = get_log_header("[INFO]    ");
        self.write_line(header + &message)
    }

    pub fn write_warning(&mut self, message: String) -> std::io::Result<()> {
        let header = get_log_header("[WARN]    ");
        self.write_line(header + &message)
    }

    pub fn write_error(&mut self, message: String) -> std::io::Result<()> {
        let header = get_log_header("[ERROR]   ");
        self.write_line(header + &message)
    }

    pub fn write_line(&mut self, message: String) -> std::io::Result<()> {
        self.roll_if_needed()?;
        self.log_writer
            .as_mut()
            .unwrap()
            .write_all(message.as_bytes())?;
        self.log_writer.as_mut().unwrap().write_all(b"\n")
    }

    fn archive_file(&mut self) -> std::io::Result<()> {
        let new_file_name = self.get_current_file_full_path(Some(format!(
            "{}-{}",
            misc_helpers::get_date_time_string_with_miliseconds(),
            misc_helpers::get_date_time_unix_nano()
        )));

        let current_name = self.get_current_file_full_path(None);
        fs::rename(current_name, new_file_name)?;

        let log_files = self.get_log_files()?;
        // delete oldest files
        let max_count: usize = self.max_log_file_count.into();
        let file_count = log_files.len();
        if file_count >= max_count {
            let mut count = max_count;
            for log in log_files {
                fs::remove_file(log)?;
                count = count + 1;

                if count > file_count {
                    break;
                }
            }
        }

        Ok(())
    }

    pub fn get_log_files(&self) -> std::io::Result<Vec<PathBuf>> {
        // search log files
        let mut log_files: Vec<PathBuf> = Vec::new();
        for entry in fs::read_dir(&self.log_dir)? {
            let entry = entry?;
            let file_full_path = entry.path();
            let metadata = fs::metadata(&file_full_path)?;
            if !metadata.is_file() && file_full_path.ends_with(&self.log_file_extension) {
                continue;
            }

            let file_name = entry.file_name().into_string().unwrap();
            if !file_name.starts_with(&self.log_file_name) {
                continue;
            }

            log_files.push(file_full_path);
        }

        log_files.sort();
        Ok(log_files)
    }

    fn get_current_file_full_path(&self, timestamp: Option<String>) -> PathBuf {
        let mut full_path = PathBuf::from(&self.log_dir);
        let mut file_name = String::from(&self.log_file_name);

        match timestamp {
            Some(time) => {
                file_name.push_str(".");
                file_name.push_str(&time.replace(":", "."));
                file_name.push_str(".log")
            }
            None => {}
        };

        full_path.push(&file_name);
        full_path.set_extension(&self.log_file_extension);

        full_path
    }

    fn roll_if_needed(&mut self) -> std::io::Result<()> {
        self.init()?;

        let file = self.get_current_file_full_path(None);
        let file_length = file.metadata()?.len();
        let should_roll = file_length >= self.max_log_file_size;

        if should_roll {
            self.archive_file()?;
            self.open_file()?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::RollingLogger;
    use std::env;
    use std::fs;

    #[test]
    fn logger_new() {
        let mut temp_test_path = env::temp_dir();
        temp_test_path.push("logger_new_tests");

        let mut logger =
            RollingLogger::create_new(temp_test_path.clone(), String::from("proxyagent"), 1024, 10);

        logger
            .write(String::from("This is a test message"))
            .unwrap();

        // clean up and ignore the clean up errors
        _ = fs::remove_dir_all(temp_test_path);
    }

    #[test]
    fn logger_roll_if_needed() {
        let mut temp_test_path = env::temp_dir();
        temp_test_path.push("logger_roll_if_needed");

        // clean up and ignore the clean up errors
        _ = fs::remove_dir_all(&temp_test_path);

        let mut logger =
            RollingLogger::create_new(temp_test_path.clone(), String::from("proxyagent"), 100, 6);

        // test without deleting old files
        for _ in [0; 10] {
            logger
                .write(String::from("This is a test message"))
                .unwrap();
        }
        let file_count = logger.get_log_files().unwrap();
        assert_eq!(5, file_count.len(), "log file count mismatch");

        // test with deleting old files
        for _ in [0; 10] {
            logger
                .write(String::from("This is a test message"))
                .unwrap();
        }
        let file_count = logger.get_log_files().unwrap();
        assert_eq!(6, file_count.len(), "log file count mismatch");

        // clean up and ignore the clean up errors
        _ = fs::remove_dir_all(&temp_test_path);
    }
}
