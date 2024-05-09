// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#[cfg(windows)]
mod windows;

#[cfg(not(windows))]
mod linux;

use crate::common::{config, logger};
use proxy_agent_shared::misc_helpers;
use proxy_agent_shared::proxy_agent_aggregate_status::{ModuleState, ProxyAgentDetailStatus};
use proxy_agent_shared::telemetry::event_logger;
use serde_derive::{Deserialize, Serialize};
use std::path::PathBuf;
use std::{env, thread};

#[derive(Serialize, Deserialize)]
#[repr(C)]
pub struct AuditEntry {
    pub logon_id: u64,
    pub process_id: u32,
    pub is_admin: i32,
    pub destination_ipv4: u32,
    pub destination_port: u16,
}

impl AuditEntry {
    pub fn empty() -> Self {
        AuditEntry {
            logon_id: 0,
            process_id: 0,
            is_admin: 0,
            destination_ipv4: 0,
            destination_port: 0,
        }
    }
}

const MAX_STATUS_MESSAGE_LENGTH: usize = 1024;

pub fn start_async(local_port: u16) {
    thread::spawn(move || {
        start(local_port);
    });
}

fn start(local_port: u16) -> bool {
    for _ in 0..5 {
        #[cfg(windows)]
        {
            windows::start(local_port);
        }
        #[cfg(not(windows))]
        {
            linux::start(local_port);
        }

        let level;
        if is_started() {
            level = event_logger::INFO_LEVEL;
        } else {
            level = event_logger::ERROR_LEVEL;
        }
        event_logger::write_event(
            level,
            get_status_message(),
            "start",
            "redirector",
            logger::AGENT_LOGGER_KEY,
        );
        if is_started() {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    return is_started();
}

pub fn close(local_port: u16) {
    #[cfg(windows)]
    {
        windows::close(local_port);
    }
    #[cfg(not(windows))]
    {
        linux::close(local_port);
    }
}

fn get_status_message() -> String {
    #[cfg(windows)]
    {
        return windows::get_status();
    }
    #[cfg(not(windows))]
    {
        return linux::get_status();
    }
}

pub fn get_status() -> ProxyAgentDetailStatus {
    let mut message = get_status_message();
    if message.len() > MAX_STATUS_MESSAGE_LENGTH {
        event_logger::write_event(
            event_logger::WARN_LEVEL,
            format!(
                "Status message is too long, truncating to {} characters. Message: {}",
                MAX_STATUS_MESSAGE_LENGTH,
                message.to_string()
            ),
            "get_status",
            "redirector",
            logger::AGENT_LOGGER_KEY,
        );

        message = format!("{}...", message[0..MAX_STATUS_MESSAGE_LENGTH].to_string());
    }
    let status;
    if is_started() {
        status = ModuleState::RUNNING.to_string();
    } else {
        status = ModuleState::STOPPED.to_string();
    }

    ProxyAgentDetailStatus {
        status,
        message,
        states: None,
    }
}

pub fn is_started() -> bool {
    #[cfg(windows)]
    {
        return windows::is_started();
    }
    #[cfg(not(windows))]
    {
        linux::is_started()
    }
}

pub fn lookup_audit(source_port: u16) -> std::io::Result<AuditEntry> {
    #[cfg(windows)]
    {
        windows::lookup_audit(source_port)
    }
    #[cfg(not(windows))]
    {
        linux::lookup_audit(source_port)
    }
}

pub fn get_audit_from_stream(_tcp_stream: &std::net::TcpStream) -> std::io::Result<AuditEntry> {
    #[cfg(windows)]
    {
        windows::get_audit_from_redirect_context(_tcp_stream)
    }
    #[cfg(not(windows))]
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "get_audit_from_redirect_context for linux is not supported",
        ));
    }
}

pub fn ip_to_string(ip: u32) -> String {
    let mut ip_str = String::new();

    let seg_number = 16 * 16;
    let seg = ip % seg_number;
    ip_str.push_str(seg.to_string().as_str());
    ip_str.push('.');

    let ip = ip / seg_number;
    let seg = ip % seg_number;
    ip_str.push_str(seg.to_string().as_str());
    ip_str.push('.');

    let ip = ip / seg_number;
    let seg = ip % seg_number;
    ip_str.push_str(seg.to_string().as_str());
    ip_str.push('.');

    let ip = ip / seg_number;
    let seg = ip % seg_number;
    ip_str.push_str(seg.to_string().as_str());

    ip_str
}

pub fn string_to_ip(ip_str: &str) -> u32 {
    let ip_str_seg: Vec<&str> = ip_str.split('.').collect();
    if ip_str_seg.len() != 4 {
        logger::write_warning(format!("string_to_ip:: ip_str {} is invalid", ip_str));
        return 0;
    }

    let mut ip: u32 = 0;
    let mut seg: u32 = 1;
    let seg_number = 16 * 16;
    for str in ip_str_seg {
        match str.parse::<u8>() {
            Ok(n) => {
                ip += (n as u32) * seg;
            }
            Err(e) => {
                logger::write_warning(format!(
                    "string_to_ip:: error parsing ip segment {} with error: {}",
                    ip_str, e
                ));
                return 0;
            }
        }
        if seg < 16777216 {
            seg = seg * seg_number;
        }
    }

    ip
}

pub fn get_ebpf_file_path() -> PathBuf {
    // get ebpf file full path from environment variable
    let mut bpf_file_path = match env::var(super::constants::AZURE_PROXY_AGENT_ENV_EBPF_FULL_PATH) {
        Ok(file_path) => PathBuf::from(file_path),
        Err(_) => PathBuf::new(),
    };
    if !bpf_file_path.exists() {
        // default to current exe folder
        bpf_file_path = misc_helpers::get_current_exe_dir();
        bpf_file_path.push(config::get_ebpf_program_name());
    }
    bpf_file_path
}

#[cfg(test)]
mod tests {
    use crate::common::constants;
    use proxy_agent_shared::misc_helpers;
    use std::env;
    use std::fs;
    use std::fs::File;
    use std::io::Write;
    use std::path::PathBuf;

    #[test]
    fn ip_to_string_test() {
        let ip = 0x10813FA8u32;
        let ip_str = super::ip_to_string(ip);
        assert_eq!("168.63.129.16", ip_str, "ip_str mismatch.");
        let new_ip = super::string_to_ip(&ip_str);
        assert_eq!(ip, new_ip, "ip mismatch.");

        let ip = 0x100007Fu32;
        let ip_str = super::ip_to_string(ip);
        assert_eq!("127.0.0.1", ip_str, "ip_str mismatch.");

        let new_ip = super::string_to_ip("1270.0.0.1");
        assert_eq!(0, new_ip, "ip must be 0 since the 1270.0.0.1 is invalid.");
        let new_ip = super::string_to_ip("1270.0.1");
        assert_eq!(0, new_ip, "ip must be 0 since the 1270.0.1 is invalid.");
    }

    #[test]
    fn get_ebpf_file_path_test() {
        let mut temp_test_path: PathBuf = env::temp_dir();
        temp_test_path.push("get_ebpf_file_path_test");
        _ = fs::remove_dir_all(&temp_test_path);
        match misc_helpers::try_create_folder(temp_test_path.to_path_buf()) {
            Ok(_) => {}
            Err(err) => panic!("Failed to create folder: {}", err),
        }
        let test_file_path = temp_test_path.join("test_ebpf.o");
        File::create(&test_file_path)
            .unwrap()
            .write_all("test data".as_bytes())
            .unwrap();

        // no env variable set
        env::remove_var(constants::AZURE_PROXY_AGENT_ENV_EBPF_FULL_PATH);
        let ebpf_file_path = super::get_ebpf_file_path();
        assert_ne!(
            test_file_path.to_path_buf(),
            ebpf_file_path,
            "ebpf file path should not be the same as the test file path when no env variable set"
        );

        // set env variable to the invalid test ebpf file
        let invalid_ebfp_file_path = temp_test_path.join("invalid_test_ebpf.o");
        env::set_var(
            constants::AZURE_PROXY_AGENT_ENV_EBPF_FULL_PATH,
            misc_helpers::path_to_string(invalid_ebfp_file_path),
        );
        let ebpf_file_path = super::get_ebpf_file_path();
        assert_ne!(
            test_file_path.to_path_buf(),
            ebpf_file_path,
            "ebpf file path should not be the same as the test file path when env variable set to an invalid file path"
        );

        // set env variable to the valid test ebpf file
        env::set_var(
            constants::AZURE_PROXY_AGENT_ENV_EBPF_FULL_PATH,
            misc_helpers::path_to_string(test_file_path.to_path_buf()),
        );
        let ebpf_file_path = super::get_ebpf_file_path();
        assert_eq!(
            test_file_path.to_path_buf(),
            ebpf_file_path,
            "ebpf file path should be the same as the test file path when env variable set to a valid file path"
        );

        // clean up
        env::remove_var(constants::AZURE_PROXY_AGENT_ENV_EBPF_FULL_PATH);
        _ = fs::remove_dir_all(&temp_test_path);
    }
}
