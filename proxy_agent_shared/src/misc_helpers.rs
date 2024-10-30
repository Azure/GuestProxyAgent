// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use crate::result::Result;
use regex::bytes::Regex;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::{
    fs::{self, File},
    path::{Path, PathBuf},
    process::Command,
};
use thread_id;
use time::{format_description, OffsetDateTime};

#[cfg(windows)]
use super::windows;

#[cfg(not(windows))]
use super::linux;

pub fn get_thread_identity() -> String {
    format!("{:0>8}", thread_id::get())
}

pub fn get_date_time_string_with_milliseconds() -> String {
    let date_format =
        format_description::parse("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond]")
            .unwrap();

    let time_str = OffsetDateTime::now_utc().format(&date_format).unwrap();
    time_str.chars().take(23).collect()
}

pub fn get_date_time_string() -> String {
    let date_format =
        format_description::parse("[year]-[month]-[day]T[hour]:[minute]:[second]Z").unwrap();

    let time_str = OffsetDateTime::now_utc().format(&date_format).unwrap();
    time_str.chars().collect()
}

// This format is also the preferred HTTP date format. https://httpwg.org/specs/rfc9110.html#http.date
pub fn get_date_time_rfc1123_string() -> String {
    let date_format = format_description::parse(
        "[weekday repr:short], [day] [month repr:short] [year] [hour]:[minute]:[second] GMT",
    )
    .unwrap();

    let time_str = OffsetDateTime::now_utc().format(&date_format).unwrap();
    time_str.chars().collect()
}

pub fn get_date_time_unix_nano() -> i128 {
    OffsetDateTime::now_utc().unix_timestamp_nanos()
}

pub fn try_create_folder(dir: &Path) -> Result<()> {
    match dir.try_exists() {
        Ok(exists) => {
            if !exists {
                fs::create_dir_all(dir)?; // Recursively create a directory and all of its parent components if they are missing
            }
        }
        Err(error) => panic!(
            "Problem check the directory '{}' exists: {:?}",
            dir.display(),
            error
        ),
    };

    Ok(())
}

pub fn json_write_to_file<T>(obj: &T, file_path: &Path) -> Result<()>
where
    T: ?Sized + Serialize,
{
    let file = File::create(file_path)?;
    serde_json::to_writer_pretty(file, obj)?;

    Ok(())
}

pub fn json_read_from_file<T>(file_path: &Path) -> Result<T>
where
    T: DeserializeOwned,
{
    let file = File::open(file_path)?;
    let obj: T = serde_json::from_reader(file)?;

    Ok(obj)
}

pub fn json_clone<T>(obj: &T) -> Result<T>
where
    T: Serialize + DeserializeOwned,
{
    let json = serde_json::to_string(obj)?;
    serde_json::from_str(&json).map_err(Into::into)
}

pub fn get_current_exe_dir() -> PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop();
    path
}

pub fn get_long_os_version() -> String {
    // os
    let os;
    #[cfg(windows)]
    {
        os = windows::get_long_os_version();
    }
    #[cfg(not(windows))]
    {
        os = linux::get_long_os_version();
    }
    os
}

pub fn get_processor_arch() -> String {
    //arch
    let arch;
    #[cfg(windows)]
    {
        arch = windows::get_processor_arch();
    }
    #[cfg(not(windows))]
    {
        arch = linux::get_processor_arch()
    }
    arch
}

pub fn path_to_string(path: &Path) -> String {
    path.display().to_string()
}

pub fn get_file_name(path: &Path) -> String {
    match path.file_name() {
        Some(s) => s.to_str().unwrap_or("InvalidPath").to_string(),
        None => "InvalidPath".to_string(),
    }
}

const VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn get_current_version() -> String {
    VERSION.to_string()
}

pub fn get_files(dir: &Path) -> Result<Vec<PathBuf>> {
    // search files
    let mut files: Vec<PathBuf> = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let file_full_path = entry.path();
        let metadata = fs::metadata(&file_full_path)?;
        if !metadata.is_file() {
            continue;
        }
        files.push(file_full_path);
    }
    files.sort();
    Ok(files)
}

/// Search files in a directory with a regex pattern
/// # Arguments
/// * `dir` - The directory to search
/// * `search_regex_pattern` - The regex pattern to search
/// # Returns
/// A vector of PathBufs that match the search pattern in ascending order
/// # Errors
/// Returns an error if the regex pattern is invalid or if there is an IO error
/// # Example
/// ```rust
/// use std::path::PathBuf;
/// use proxy_agent_shared::misc_helpers;
/// let dir = PathBuf::from("C:\\");
/// let search_regex_pattern = r"^(.*\.log)$";  // search for files with .log extension
/// let files = misc_helpers::search_files(&dir, search_regex_pattern).unwrap();
///
/// let search_regex_pattern = r"^MyFile.*\.json$"; // Regex pattern to match "MyFile*.json"
/// let files = misc_helpers::search_files(&dir, search_regex_pattern).unwrap();
/// ```
pub fn search_files(dir: &Path, search_regex_pattern: &str) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    let regex = Regex::new(search_regex_pattern)?;

    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let file_full_path = entry.path();
        let metadata = fs::metadata(&file_full_path)?;
        if !metadata.is_file() {
            continue;
        }
        let file_name = get_file_name(&file_full_path);
        if regex.is_match(file_name.as_bytes()) {
            files.push(file_full_path);
        }
    }
    files.sort();
    Ok(files)
}

pub fn execute_command(
    program: &str,
    args: Vec<&str>,
    default_error_code: i32,
) -> (i32, String, String) {
    match Command::new(program).args(args).output() {
        Ok(output) => {
            return (
                output.status.code().unwrap_or(default_error_code),
                String::from_utf8_lossy(&output.stdout).to_string(),
                String::from_utf8_lossy(&output.stderr).to_string(),
            );
        }
        Err(e) => {
            let error = format!("Failed to execute command {} with error {}", program, e);
            (default_error_code, String::new(), error)
        }
    }
}

pub fn get_proxy_agent_version(proxy_agent_exe: &Path) -> String {
    if !proxy_agent_exe.exists() {
        return "Unknown".to_string();
    }
    if !proxy_agent_exe.is_file() {
        return "Unknown".to_string();
    }

    let output = execute_command(&path_to_string(proxy_agent_exe), vec!["--version"], -1);
    if output.0 != 0 {
        "Unknown".to_string()
    } else {
        return output.1.trim().to_string();
    }
}

#[cfg(test)]
mod tests {
    use serde_derive::{Deserialize, Serialize};
    use std::env;
    use std::fs;
    use std::path::PathBuf;

    #[derive(Serialize, Deserialize)]
    struct TestStruct {
        thread_id: String,
        date_time_string_with_milliseconds: String,
        date_time_string: String,
        date_time_rfc1123_string: String,
        date_time_unix_nano: i128,
        long_os_version: String,
        current_exe_dir: String,
    }

    #[test]
    fn json_write_read_from_file_test() {
        let mut temp_test_path = env::temp_dir();
        temp_test_path.push("json_Write_read_from_file_test");
        // clean up and ignore the clean up errors
        _ = fs::remove_dir_all(&temp_test_path);
        super::try_create_folder(&temp_test_path).unwrap();

        let json_file = temp_test_path.as_path();
        let json_file = json_file.join("test.json");

        let test = TestStruct {
            thread_id: super::get_thread_identity(),
            date_time_string_with_milliseconds: super::get_date_time_string_with_milliseconds(),
            date_time_string: super::get_date_time_string(),
            date_time_rfc1123_string: super::get_date_time_rfc1123_string(),
            date_time_unix_nano: super::get_date_time_unix_nano(),
            long_os_version: super::get_long_os_version(),
            current_exe_dir: super::get_current_exe_dir().to_str().unwrap().to_string(),
        };

        super::json_write_to_file(&test, &json_file).unwrap();
        let json = super::json_read_from_file::<TestStruct>(&json_file).unwrap();

        assert_eq!(test.thread_id, json.thread_id);
        assert_eq!(
            test.date_time_string_with_milliseconds,
            json.date_time_string_with_milliseconds
        );
        assert_eq!(test.date_time_string, json.date_time_string);
        assert_eq!(test.date_time_rfc1123_string, json.date_time_rfc1123_string);
        assert_eq!(test.date_time_unix_nano, json.date_time_unix_nano);
        assert_eq!(test.long_os_version, json.long_os_version);
        assert_eq!(test.current_exe_dir, json.current_exe_dir);

        _ = fs::remove_dir_all(&temp_test_path);
    }

    #[test]
    fn path_to_string_test() {
        let path = "path_to_string_test";
        let path_str = super::path_to_string(&PathBuf::from(path));
        assert_eq!(path_str, path, "path_str mismatch");
    }

    #[test]
    fn execute_command_test() {
        let mut temp_test_path = env::temp_dir();
        temp_test_path.push("execute_command_test");
        // clean up and ignore the clean up errors
        _ = fs::remove_dir_all(&temp_test_path);
        super::try_create_folder(&temp_test_path).unwrap();

        let program: &str;
        let script_content: &str;
        let script_file_name: &str;

        #[cfg(windows)]
        {
            program = "powershell.exe";
            script_file_name = "test.ps1";
            script_content = r#"write-host "this is stdout message"
            write-error "This is stderr message"
            exit 1
            "#;
        }
        #[cfg(not(windows))]
        {
            program = "sh";
            script_file_name = "test.sh";
            script_content = r#"echo "this is stdout message"
            >&2 echo "This is stderr message"
            exit 1
            "#;
        }

        let script_file_path = temp_test_path.join(script_file_name);
        _ = fs::write(&script_file_path, script_content);

        let default_error_code = -1;
        let output = super::execute_command(
            program,
            vec![&super::path_to_string(&script_file_path)],
            default_error_code,
        );
        assert_eq!(1, output.0, "exit code mismatch");
        assert_eq!(
            "this is stdout message",
            output.1.trim(),
            "stdout message mismatch"
        );
        assert!(
            output.2.contains("This is stderr message"),
            "stderr message mismatch"
        );

        _ = fs::remove_dir_all(&temp_test_path);
    }

    #[test]
    fn get_file_name_test() {
        let path = PathBuf::from("test.txt");
        let file_name = super::get_file_name(&path);
        assert_eq!("test.txt", file_name, "file_name mismatch");

        let path = PathBuf::new();
        let file_name = super::get_file_name(&path);
        assert_eq!("InvalidPath", file_name, "file_name mismatch");
    }

    #[test]
    fn search_files_test() {
        let mut temp_test_path = env::temp_dir();
        temp_test_path.push("search_files_test");
        // clean up and ignore the clean up errors
        _ = fs::remove_dir_all(&temp_test_path);
        super::try_create_folder(&temp_test_path).unwrap();

        let test = TestStruct {
            thread_id: super::get_thread_identity(),
            date_time_string_with_milliseconds: super::get_date_time_string_with_milliseconds(),
            date_time_string: super::get_date_time_string(),
            date_time_rfc1123_string: super::get_date_time_rfc1123_string(),
            date_time_unix_nano: super::get_date_time_unix_nano(),
            long_os_version: super::get_long_os_version(),
            current_exe_dir: super::get_current_exe_dir().to_str().unwrap().to_string(),
        };

        // write 2 json files to the temp_test_path
        let json_file = temp_test_path.as_path();
        let json_file = json_file.join("test.json");
        super::json_write_to_file(&test, &json_file).unwrap();
        let json_file = temp_test_path.as_path();
        let json_file = json_file.join("test_1.json");
        super::json_write_to_file(&test, &json_file).unwrap();

        let files = super::search_files(&temp_test_path, "test.json").unwrap();
        assert_eq!(
            1,
            files.len(),
            "file count mismatch with 'test.json' search"
        );

        let files = super::search_files(&temp_test_path, r"^test.*\.json$").unwrap();
        assert_eq!(
            2,
            files.len(),
            "file count mismatch with 'test*.json' search"
        );
        assert_eq!(
            "test.json",
            super::get_file_name(&files[0]),
            "First file name mismatch"
        );
        assert_eq!(
            "test_1.json",
            super::get_file_name(&files[1]),
            "Second file name mismatch"
        );

        _ = fs::remove_dir_all(&temp_test_path);
    }

    #[test]
    fn json_clone_test() {
        let test = TestStruct {
            thread_id: super::get_thread_identity(),
            date_time_string_with_milliseconds: super::get_date_time_string_with_milliseconds(),
            date_time_string: super::get_date_time_string(),
            date_time_rfc1123_string: super::get_date_time_rfc1123_string(),
            date_time_unix_nano: super::get_date_time_unix_nano(),
            long_os_version: super::get_long_os_version(),
            current_exe_dir: super::get_current_exe_dir().to_str().unwrap().to_string(),
        };

        let cloned = super::json_clone(&test).unwrap();

        assert_eq!(test.thread_id, cloned.thread_id);
        assert_eq!(
            test.date_time_string_with_milliseconds,
            cloned.date_time_string_with_milliseconds
        );
        assert_eq!(test.date_time_string, cloned.date_time_string);
        assert_eq!(
            test.date_time_rfc1123_string,
            cloned.date_time_rfc1123_string
        );
        assert_eq!(test.date_time_unix_nano, cloned.date_time_unix_nano);
        assert_eq!(test.long_os_version, cloned.long_os_version);
        assert_eq!(test.current_exe_dir, cloned.current_exe_dir);
    }
}
