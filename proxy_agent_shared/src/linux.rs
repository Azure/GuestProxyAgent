// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use crate::misc_helpers;
use once_cell::sync::Lazy;
use os_info::Info;
use serde_derive::{Deserialize, Serialize};
use std::{
    io::{Error, ErrorKind},
    path::PathBuf,
};

pub const SERVICE_CONFIG_FOLDER_PATH: &str = "/lib/systemd/system/";
pub const SERVICE_PACKAGE_LINK_NAME: &str = "/usr/lib/azure-proxy-agent/package";

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
    OS_INFO.version().to_string()
}
pub fn get_long_os_version() -> String {
    format!("Linux:{}-{}", OS_INFO.os_type(), OS_INFO.version())
}

pub fn get_os_type() -> String {
    OS_INFO.os_type().to_string()
}

pub fn get_processor_arch() -> String {
    match OS_INFO.architecture() {
        Some(arch) => arch.to_string(),
        None => "Unknown".to_string(),
    }
}

pub fn get_cgroup2_mount_path() -> std::io::Result<PathBuf> {
    let output = misc_helpers::execute_command("findmnt", vec!["-t", "cgroup2", "--json"], -1);
    if output.0 != 0 {
        return Err(Error::new(
            ErrorKind::Other,
            format!(
                "findmnt command failed with exit code '{}', stdout :{}, stderr: {}.",
                output.0, output.1, output.2
            ),
        ));
    }

    let mount: FileMount = serde_json::from_str(&output.1)?;
    if mount.filesystems.len() > 0 {
        let cgroup2_path = mount.filesystems[0].target.to_string();
        return Ok(PathBuf::from(cgroup2_path));
    }

    return Err(Error::new(
        ErrorKind::Other,
        format!(
            "findmnt command cannot find cgroup2 file mount: {}.",
            output.1
        ),
    ));
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
                    misc_helpers::path_to_string(cgroup2_path.to_path_buf())
                );
                assert!(
                    cgroup2_path.is_dir(),
                    "cgroup2_path {} must be a dir",
                    misc_helpers::path_to_string(cgroup2_path.to_path_buf())
                );
                assert!(
                    cgroup2_path.exists(),
                    "cgroup2_path {} must be exists",
                    misc_helpers::path_to_string(cgroup2_path.to_path_buf())
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
