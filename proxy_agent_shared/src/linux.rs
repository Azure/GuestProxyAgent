// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use crate::error::{CommandErrorType, Error};
use crate::logger::logger_manager;
use crate::misc_helpers;
use crate::result::Result;
use once_cell::sync::Lazy;
use os_info::Info;
use serde_derive::{Deserialize, Serialize};
use std::path::PathBuf;
use std::{fs, str};

pub const SERVICE_CONFIG_FOLDER_PATH: &str = "/usr/lib/systemd/system/";
pub const EXE_FOLDER_PATH: &str = "/usr/sbin";
pub const OS_RELEASE_PATH: &str = "/etc/os-release";
pub const OS_VERSION: &str = "VERSION_ID=";
pub const OS_NAME: &str = "NAME=";

#[derive(Serialize, Deserialize)]
struct FileMount {
    filesystems: Vec<FileSystem>,
}

#[derive(Serialize, Deserialize)]
struct FileSystem {
    target: String,
    source: String,
    fstype: String,
    options: String,
}

static OS_INFO: Lazy<Info> = Lazy::new(os_info::get);
pub fn get_os_version() -> String {
    let linux_type = OS_INFO.os_type().to_string().to_lowercase();
    if linux_type == "linux" {
        match fs::read_to_string(OS_RELEASE_PATH) {
            Ok(output) => {
                for line in output.lines() {
                    if line.starts_with(OS_VERSION) {
                        let version = line
                            .trim_start_matches(OS_VERSION)
                            .trim_matches('"')
                            .to_string();
                        return version;
                    }
                }
            }
            Err(e) => {
                let message = format!(
                    "Failed to read os-release file in get_os_version(): {OS_RELEASE_PATH} with error: {e}",
                );
                logger_manager::write_warn(message);
                return "Unknown".to_string();
            }
        }
    }
    OS_INFO.version().to_string()
}
pub fn get_long_os_version() -> String {
    format!("Linux:{}-{}", get_os_type(), get_os_version())
}

pub fn get_os_type() -> String {
    let linux_type = OS_INFO.os_type().to_string().to_lowercase();
    if linux_type == "linux" {
        match fs::read_to_string(OS_RELEASE_PATH) {
            Ok(output) => {
                for line in output.lines() {
                    if line.starts_with(OS_NAME) {
                        let name = line
                            .trim_start_matches(OS_NAME)
                            .trim_matches('"')
                            .to_string();
                        return name;
                    }
                }
            }
            Err(e) => {
                let message = format!(
                    "Failed to read os-release file in get_os_type(): {OS_RELEASE_PATH} with error: {e}",
                );
                logger_manager::write_warn(message);
                return "Unknown".to_string();
            }
        }
    }
    OS_INFO.os_type().to_string()
}

pub fn get_processor_arch() -> String {
    match OS_INFO.architecture() {
        Some(arch) => arch.to_string(),
        None => "Unknown".to_string(),
    }
}

pub fn get_cgroup2_mount_path() -> Result<PathBuf> {
    let output = misc_helpers::execute_command("findmnt", vec!["-t", "cgroup2", "--json"], -1)?;
    if !output.is_success() {
        return Err(Error::Command(CommandErrorType::Findmnt, output.message()));
    }

    let mount: FileMount = serde_json::from_str(&output.stdout())?;
    if !mount.filesystems.is_empty() {
        let cgroup2_path = mount.filesystems[0].target.to_string();
        return Ok(PathBuf::from(cgroup2_path));
    }

    Err(Error::Command(
        CommandErrorType::Findmnt,
        format!("Cannot find cgroup2 file mount: {}.", output.message()),
    ))
}

#[cfg(test)]
mod tests {
    use crate::misc_helpers;

    #[test]
    fn get_os_version_tests() {
        let os_version = super::get_os_version();
        assert_ne!("", os_version, "os version cannot be empty");
        let long_os_version = super::get_long_os_version();
        assert!(
            long_os_version.starts_with("Linux"),
            "long_os_version must starts with 'Linux'"
        );
        assert!(
            long_os_version.ends_with(&os_version),
            "long_os_version must ends with os_version"
        )
    }

    #[test]
    fn get_processor_arch_test() {
        let processor_arch = super::get_processor_arch();
        assert_ne!(
            "unknown", processor_arch,
            "processor arch cannot be 'unknown'"
        );
    }

    #[test]
    fn get_cgroup2_mount_path_test() {
        match super::get_cgroup2_mount_path() {
            Ok(cgroup2_path) => {
                println!(
                    "Got cgroup2 mount path: '{}'",
                    misc_helpers::path_to_string(&cgroup2_path)
                );
                assert!(
                    cgroup2_path.is_dir(),
                    "cgroup2_path {} must be a dir",
                    misc_helpers::path_to_string(&cgroup2_path)
                );
                assert!(
                    cgroup2_path.exists(),
                    "cgroup2_path {} must be exists",
                    misc_helpers::path_to_string(&cgroup2_path)
                );
            }
            Err(e) => {
                // This test is not critical, so just print the error message.
                // This test could fail in some cases, like running in a container/VM without CGROUP2 mounted.
                println!("Failed to get the cgroup2 mount path {}.", e);
            }
        };
    }
}
