// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use crate::misc_helpers;
use crate::result::Result;
use log::Level;
use std::fs::{self, File, OpenOptions};
use std::io::{LineWriter, Write};
use std::path::PathBuf;

#[derive(Debug)]
pub struct RollingLogger {
    log_dir: PathBuf,
    log_file_name: String,
    log_file_extension: String,

    max_log_file_size: u64,  // max log file size in KB
    max_log_file_count: u16, // max log file count, if exceed the count, the older log files will be removed.
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
        RollingLogger {
            log_dir: dir,
            log_file_name: file_name,
            log_file_extension: String::from("log"),
            max_log_file_size: log_size,
            max_log_file_count: log_count,
        }
    }

    fn get_log_header(severity: &str) -> String {
        format!(
            "{} {}",
            misc_helpers::get_date_time_string_with_milliseconds(),
            severity
        )
    }

    fn open_file(&self) -> Result<LineWriter<File>> {
        misc_helpers::try_create_folder(&self.log_dir)?;

        let file_full_path = self.get_current_file_full_path(None);
        let f = if file_full_path.exists() {
            OpenOptions::new().append(true).open(file_full_path)?
        } else {
            File::create(file_full_path)?
        };

        Ok(LineWriter::new(f))
    }

    pub fn write(&self, level: Level, message: String) -> Result<()> {
        let log_header = Self::get_log_header(&format!("[{}]    ", level))[..34].to_string();
        let message = format!("{}{}", log_header, message);
        self.write_line(message)
    }

    fn write_line(&self, message: String) -> Result<()> {
        self.roll_if_needed()?;

        if let Ok(mut writer) = self.open_file() {
            writer.write_all(message.as_bytes())?;
            writer.write_all(b"\n")?;
            writer.flush()?;
        }

        Ok(())
    }

    fn archive_file(&self) -> Result<()> {
        let new_file_name = self.get_current_file_full_path(Some(format!(
            "{}-{}",
            misc_helpers::get_date_time_string_with_milliseconds(),
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
                count += 1;

                if count > file_count {
                    break;
                }
            }
        }

        Ok(())
    }

    pub fn get_log_files(&self) -> Result<Vec<PathBuf>> {
        // search log files
        let mut log_files: Vec<PathBuf> = Vec::new();
        for entry in fs::read_dir(&self.log_dir)? {
            let entry = entry?;
            let file_full_path = entry.path();
            let metadata = fs::metadata(&file_full_path)?;
            if !metadata.is_file() && file_full_path.ends_with(&self.log_file_extension) {
                continue;
            }

            // log file name should able convert to string safely; if not, ignore this file entry
            if let Ok(file_name) = entry.file_name().into_string() {
                if !file_name.starts_with(&self.log_file_name) {
                    continue;
                }
            }

            log_files.push(file_full_path);
        }

        log_files.sort();
        Ok(log_files)
    }

    fn get_current_file_full_path(&self, timestamp: Option<String>) -> PathBuf {
        let mut full_path = PathBuf::from(&self.log_dir);
        let mut file_name = String::from(&self.log_file_name);

        if let Some(time) = timestamp {
            file_name.push('.');
            file_name.push_str(&time.replace(':', "."));
            file_name.push_str(".log")
        }

        full_path.push(&file_name);
        full_path.set_extension(&self.log_file_extension);

        full_path
    }

    fn roll_if_needed(&self) -> Result<()> {
        self.open_file()?;

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

        let logger =
            RollingLogger::create_new(temp_test_path.clone(), String::from("proxyagent"), 1024, 10);
        logger
            .write(log::Level::Info, String::from("This is a test message"))
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

        let logger =
            RollingLogger::create_new(temp_test_path.clone(), String::from("proxyagent"), 100, 6);

        // test without deleting old files
        for _ in [0; 10] {
            logger
                .write(log::Level::Info, String::from("This is a test message"))
                .unwrap();
        }
        let file_count = logger.get_log_files().unwrap();
        assert_eq!(5, file_count.len(), "log file count mismatch");

        // test with deleting old files
        for _ in [0; 10] {
            logger
                .write(log::Level::Trace, String::from("This is a test message"))
                .unwrap();
        }
        let file_count = logger.get_log_files().unwrap();
        assert_eq!(6, file_count.len(), "log file count mismatch");

        // clean up and ignore the clean up errors
        _ = fs::remove_dir_all(&temp_test_path);
    }
}
