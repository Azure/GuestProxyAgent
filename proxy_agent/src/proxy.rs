// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

//! This module contains the logic to get user and process details.
//! When eBPF redirects the http traffic, it writes the uid and pid information to the eBPF map.
//! The GPA service reads the audit/claims information via uid & pid.
//! The GPA service uses the audit/claims information to authorize the requests before forwarding to the remote endpoints.
//!
//! Example
//! ```rust
//! use proxy_agent::proxy;
//! use proxy_agent::shared_state::proxy_server_wrapper::ProxyServerSharedState;
//!
//! // Get the user details
//! let logon_id = 999u64;
//! let proxy_server_shared_state = ProxyServerSharedState::start_new();
//! let user = proxy::get_user(logon_id, proxy_server_shared_state.clone()).unwrap();
//!
//! // Get the process details
//! let pid = std::process::id();
//! let process = proxy::Process::from_pid(pid);
//!
//! // Get the claims from the audit entry
//! let mut entry = proxy::AuditEntry::empty();
//! entry.logon_id = 999; // LocalSystem logon_id
//! entry.process_id = std::process::id();
//! entry.destination_ipv4 = 0x10813FA8;
//! entry.destination_port = 80;
//! entry.is_admin = 1;
//! let claims = proxy::Claims::from_audit_entry(&entry, "127.0.0.1".parse().unwrap(), proxy_server_shared_state.clone()).unwrap();
//! println!("{}", serde_json::to_string(&claims).unwrap());
//! ```

pub mod authorization_rules;
pub mod proxy_authorizer;
pub mod proxy_connection;
pub mod proxy_server;
pub mod proxy_summary;

#[cfg(windows)]
mod windows;

use crate::common::result::Result;
use crate::redirector::AuditEntry;
use crate::shared_state::proxy_server_wrapper::ProxyServerSharedState;
use serde_derive::{Deserialize, Serialize};
use std::{ffi::OsString, net::IpAddr, path::PathBuf};

#[cfg(not(windows))]
use sysinfo::{Pid, ProcessRefreshKind, RefreshKind, System, UpdateKind};

#[derive(Serialize, Deserialize, Clone)]
#[allow(non_snake_case)]
pub struct Claims {
    pub userId: u64,
    pub userName: String,
    pub userGroups: Vec<String>,
    pub processId: u32,
    pub processName: OsString,
    pub processFullPath: PathBuf,
    pub processCmdLine: String,
    pub runAsElevated: bool,
    pub clientIp: String,
    pub clientPort: u16,
}

struct Process {
    pub command_line: String,
    pub name: OsString,
    pub exe_full_name: PathBuf,
    pub pid: u32,
}

#[derive(Clone)]
pub struct User {
    pub logon_id: u64,
    pub user_name: String,
    pub user_groups: Vec<String>,
}

const UNDEFINED: &str = "undefined";
const EMPTY: &str = "empty";

async fn get_user(
    logon_id: u64,
    proxy_server_shared_state: ProxyServerSharedState,
) -> Result<User> {
    // cache the logon_id -> user_name
    if let Ok(Some(user)) = proxy_server_shared_state.get_user(logon_id).await {
        Ok(user)
    } else {
        let user = User::from_logon_id(logon_id)?;
        if let Err(e) = proxy_server_shared_state.add_user(user.clone()).await {
            println!("Failed to add user: {} to cache", e);
        }
        Ok(user)
    }
}

#[cfg(not(windows))]
fn get_process_info(process_id: u32) -> (PathBuf, String) {
    let mut process_name = PathBuf::default();
    let mut process_cmd_line = UNDEFINED.to_string();

    let pid = Pid::from_u32(process_id);
    let sys = System::new_with_specifics(
        RefreshKind::new().with_processes(
            ProcessRefreshKind::new()
                .with_cmd(UpdateKind::Always)
                .with_exe(UpdateKind::Always),
        ),
    );
    if let Some(p) = sys.process(pid) {
        process_name = match p.exe() {
            Some(path) => path.to_path_buf(),
            None => PathBuf::default(),
        };
        process_cmd_line = p.cmd().join(" ");
    }

    (process_name, process_cmd_line)
}

impl Claims {
    pub fn empty() -> Self {
        Claims {
            userId: 0,
            userName: EMPTY.to_string(),
            userGroups: Vec::new(),
            processId: 0,
            processName: OsString::from(EMPTY),
            processFullPath: PathBuf::from(EMPTY),
            processCmdLine: EMPTY.to_string(),
            runAsElevated: false,
            clientIp: EMPTY.to_string(),
            clientPort: 0,
        }
    }

    pub async fn from_audit_entry(
        entry: &AuditEntry,
        client_ip: IpAddr,
        client_port: u16,
        proxy_server_shared_state: ProxyServerSharedState,
    ) -> Result<Self> {
        let p = Process::from_pid(entry.process_id);
        let u = get_user(entry.logon_id, proxy_server_shared_state).await?;
        Ok(Claims {
            userId: entry.logon_id,
            userName: u.user_name.to_string(),
            userGroups: u.user_groups.clone(),
            processId: p.pid,
            processName: p.name,
            processFullPath: p.exe_full_name,
            processCmdLine: p.command_line.to_string(),
            runAsElevated: entry.is_admin == 1,
            clientIp: client_ip.to_string(),
            clientPort: client_port,
        })
    }
}

impl Process {
    pub fn from_pid(pid: u32) -> Self {
        let (process_full_path, cmd);
        #[cfg(windows)]
        {
            let handler = windows::get_process_handler(pid).unwrap_or_else(|e| {
                println!("Failed to get process handler: {}", e);
                0
            });
            let base_info = windows::query_basic_process_info(handler);
            match base_info {
                Ok(_) => {
                    process_full_path = windows::get_process_full_name(handler).unwrap_or_default();
                    cmd = windows::get_process_cmd(handler).unwrap_or(UNDEFINED.to_string());
                }
                Err(e) => {
                    process_full_path = PathBuf::default();
                    cmd = UNDEFINED.to_string();
                    println!("Failed to query basic process info: {}", e);
                }
            }
        }
        #[cfg(not(windows))]
        {
            let process_info = get_process_info(pid);
            process_full_path = process_info.0;
            cmd = process_info.1;
        }

        let process_name = process_full_path
            .file_name()
            .unwrap_or_default()
            .to_os_string();

        Process {
            command_line: cmd,
            name: process_name,
            exe_full_name: process_full_path,
            pid,
        }
    }
}

impl User {
    pub fn from_logon_id(logon_id: u64) -> Result<Self> {
        let user_name;
        let mut user_groups: Vec<String> = Vec::new();

        #[cfg(windows)]
        {
            let user = windows::get_user(logon_id)?;
            user_name = user.0;
            for g in user.1 {
                user_groups.push(g.to_string());
            }
        }
        #[cfg(not(windows))]
        {
            match uzers::get_user_by_uid(logon_id as u32) {
                Some(u) => {
                    user_name = u.name().to_string_lossy().to_string();
                    let g: Option<Vec<uzers::Group>> =
                        uzers::get_user_groups(&user_name, u.primary_group_id());

                    if let Some(groups) = g {
                        for group in groups {
                            user_groups.push(group.name().to_string_lossy().to_string());
                        }
                    }
                }
                None => user_name = UNDEFINED.to_string(),
            }
        }

        Ok(User {
            logon_id,
            user_name: user_name.to_string(),
            user_groups: user_groups.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use proxy_agent_shared::logger_manager;

    use super::Claims;
    use crate::{
        common::logger, redirector::AuditEntry,
        shared_state::proxy_server_wrapper::ProxyServerSharedState,
    };
    use std::{env, fs, net::IpAddr};

    #[tokio::test]
    async fn user_test() {
        let mut temp_test_path = env::temp_dir();
        let logger_key = "user_test";
        temp_test_path.push(logger_key);

        // clean up and ignore the clean up errors
        _ = fs::remove_dir_all(&temp_test_path);

        logger_manager::init_logger(
            logger::AGENT_LOGGER_KEY.to_string(), // production code uses 'Agent_Log' to write.
            temp_test_path.clone(),
            logger_key.to_string(),
            10 * 1024 * 1024,
            20,
        )
        .await;

        let logon_id;
        let expected_user_name;
        #[cfg(windows)]
        {
            logon_id = 999u64;
            expected_user_name = "SYSTEM";
        }
        #[cfg(not(windows))]
        {
            logon_id = 0u64;
            expected_user_name = "root";
        }
        let proxy_server_shared_state = ProxyServerSharedState::start_new();

        let user = super::get_user(logon_id, proxy_server_shared_state.clone())
            .await
            .unwrap();
        println!("UserName: {}", user.user_name);
        println!("UserGroups: {}", user.user_groups.join(", "));
        assert_eq!(expected_user_name, user.user_name, "user name mismatch.");
        #[cfg(windows)]
        {
            assert_eq!(0, user.user_groups.len(), "SYSTEM has no group.");
        }
        #[cfg(not(windows))]
        {
            assert!(
                !user.user_groups.is_empty(),
                "user_groups should not be empty."
            );
        }

        // test the USERS.len will not change
        let len = proxy_server_shared_state.get_users_count().await.unwrap();
        _ = super::get_user(logon_id, proxy_server_shared_state.clone());
        _ = super::get_user(logon_id, proxy_server_shared_state.clone());
        _ = super::get_user(logon_id, proxy_server_shared_state.clone());
        _ = super::get_user(logon_id, proxy_server_shared_state.clone());
        assert_eq!(
            len,
            proxy_server_shared_state.get_users_count().await.unwrap(),
            "users count should not change"
        )
    }

    #[tokio::test]
    async fn entry_to_claims() {
        let mut entry = AuditEntry::empty();
        entry.logon_id = 999; // LocalSystem logon_id
        entry.process_id = std::process::id();
        entry.destination_ipv4 = 0x10813FA8;
        entry.destination_port = 80;
        entry.is_admin = 1;
        let proxy_server_shared_state = ProxyServerSharedState::start_new();

        let claims = Claims::from_audit_entry(
            &entry,
            IpAddr::from([127, 0, 0, 1]),
            0, // doesn't matter for this test
            proxy_server_shared_state.clone(),
        )
        .await
        .unwrap();
        println!("{}", serde_json::to_string(&claims).unwrap());

        assert!(claims.runAsElevated, "runAsElevated must be true");
        assert_ne!(String::new(), claims.userName, "userName cannot be empty.");
        assert!(
            !claims.processName.is_empty(),
            "processName cannot be empty."
        );
        assert!(
            !claims.processFullPath.as_os_str().is_empty(),
            "processFullPath cannot be empty."
        );
        assert_ne!(
            claims.processName,
            claims.processFullPath.as_os_str(),
            "processName and processFullPath should not be the same."
        );
        assert_ne!(
            String::new(),
            claims.processCmdLine,
            "processCmdLine cannot be empty."
        );
    }
}
