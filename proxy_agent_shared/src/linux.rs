// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use crate::error::{CommandErrorType, Error};
use crate::logger::logger_manager;
use crate::misc_helpers;
use crate::result::Result;
use once_cell::sync::Lazy;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::sign::Signer;
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

pub fn compute_signature(hex_encoded_key: &str, input_to_sign: &[u8]) -> Result<String> {
    match hex::decode(hex_encoded_key) {
        Ok(key) => {
            let pkey = PKey::hmac(&key)
                .map_err(|e| Error::ComputeSignature("PKey HMAC".to_string(), e))?;
            let mut signer = Signer::new(MessageDigest::sha256(), &pkey)
                .map_err(|e| Error::ComputeSignature("Signer".to_string(), e))?;
            signer
                .update(input_to_sign)
                .map_err(|e| Error::ComputeSignature("Signer update".to_string(), e))?;
            let signature = signer
                .sign_to_vec()
                .map_err(|e| Error::ComputeSignature("Signer sign_to_vec".to_string(), e))?;
            Ok(hex::encode(signature))
        }
        Err(e) => Err(Error::Hex(hex_encoded_key.to_string(), e)),
    }
}

/// Set the CPU quota for a service.
/// The CPU quota is set in percentage of the one CPU time available.
/// For example, if the total CPU time available is 100%, setting the CPU quota to 50% will limit the service to use up to 50% of the total CPU time available.
pub fn set_cpu_quota(service_name: &str, cpu_quota: u16) -> Result<()> {
    misc_helpers::execute_command(
        "systemctl",
        vec![
            "set-property",
            service_name,
            &format!("CPUQuota={cpu_quota}%"),
        ],
        -1,
    )?;

    Ok(())
}

#[derive(Debug)]
pub struct MemStatus {
    pub vmrss_kb: Option<u64>,
    pub vmhwm_kb: Option<u64>,
}

pub fn read_proc_memory_status(pid: u32) -> Result<MemStatus> {
    let s = fs::read_to_string(format!("/proc/{pid}/status"))?;
    let mut vmrss_kb = None;
    let mut vmhwm_kb = None;
    for line in s.lines() {
        if line.starts_with("VmRSS:") {
            // Format: "VmRSS:\t  12345 kB"
            let val = line.split_whitespace().nth(1).and_then(|x| x.parse().ok());
            vmrss_kb = val;
        } else if line.starts_with("VmHWM:") {
            let val = line.split_whitespace().nth(1).and_then(|x| x.parse().ok());
            vmhwm_kb = val;
        }
    }
    Ok(MemStatus { vmrss_kb, vmhwm_kb })
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
