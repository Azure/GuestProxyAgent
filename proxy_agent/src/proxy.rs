// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
pub mod authorization_rules;
pub mod proxy_authentication;
pub mod proxy_connection;
pub mod proxy_server;
pub mod proxy_summary;

#[cfg(windows)]
mod windows;

use crate::shared_state::{shared_state_wrapper, SharedState};
use crate::{redirector::AuditEntry, shared_state::proxy_wrapper};
use serde_derive::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::{net::IpAddr, path::PathBuf};

#[cfg(not(windows))]
use sysinfo::{Pid, PidExt, ProcessExt, System, SystemExt};

#[derive(Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct Claims {
    pub userId: u64,
    pub userName: String,
    pub userGroups: Vec<String>,
    pub processId: u32,
    pub processName: String,
    pub processFullPath: String,
    pub processCmdLine: String,
    pub runAsElevated: bool,
    pub clientIp: String,
}

struct Process {
    pub command_line: String,
    pub name: String,
    pub exe_full_name: String,
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

fn get_user(logon_id: u64, shared_state: Arc<Mutex<SharedState>>) -> std::io::Result<User> {
    // cache the logon_id -> user_name
    match proxy_wrapper::get_user(shared_state.clone(), logon_id) {
        Some(user) => Ok(user),
        None => {
            let user = User::from_logon_id(shared_state.clone(), logon_id)?;
            proxy_wrapper::add_user(shared_state.clone(), user.clone());
            Ok(user)
        }
    }
}

#[cfg(not(windows))]
fn get_process_info(process_id: u32) -> (String, String) {
    let mut process_name = UNDEFINED.to_string();
    let mut process_cmd_line = UNDEFINED.to_string();

    let pid = Pid::from_u32(process_id);
    let mut sys = System::new();
    sys.refresh_processes();
    if let Some(p) = sys.process(pid) {
        match p.exe().to_str() {
            Some(name) => process_name = name.to_string(),
            None => process_name = UNDEFINED.to_string(),
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
            processName: EMPTY.to_string(),
            processFullPath: EMPTY.to_string(),
            processCmdLine: EMPTY.to_string(),
            runAsElevated: false,
            clientIp: EMPTY.to_string(),
        }
    }

    pub fn from_audit_entry(
        entry: &AuditEntry,
        client_ip: IpAddr,
        shared_state: Arc<Mutex<SharedState>>,
    ) -> std::io::Result<Self> {
        shared_state_wrapper::check_cancellation_token(shared_state.clone(), "from_audit_entry")?;
        let p = Process::from_pid(entry.process_id)?;
        let u = get_user(entry.logon_id, shared_state)?;
        Ok(Claims {
            userId: entry.logon_id,
            userName: u.user_name.to_string(),
            userGroups: u.user_groups.clone(),
            processId: p.pid,
            processName: p.name.to_string(),
            processFullPath: p.exe_full_name.to_string(),
            processCmdLine: p.command_line.to_string(),
            runAsElevated: entry.is_admin == 1,
            clientIp: client_ip.to_string(),
        })
    }
}

impl Clone for Claims {
    fn clone(&self) -> Self {
        Claims {
            userId: self.userId,
            userName: self.userName.to_string(),
            userGroups: self.userGroups.clone(),
            processId: self.processId,
            processName: self.processName.to_string(),
            processFullPath: self.processFullPath.to_string(),
            processCmdLine: self.processCmdLine.to_string(),
            runAsElevated: self.runAsElevated,
            clientIp: self.clientIp.to_string(),
        }
    }
}

impl Process {
    pub fn from_pid(pid: u32) -> std::io::Result<Self> {
        let (process_full_path, cmd);
        #[cfg(windows)]
        {
            let handler = windows::get_process_handler(pid)?;
            _ = windows::query_basic_process_info(handler)?;
            process_full_path =
                windows::get_process_full_name(handler).unwrap_or(UNDEFINED.to_string());
            cmd = windows::get_process_cmd(handler).unwrap_or(UNDEFINED.to_string());
        }
        #[cfg(not(windows))]
        {
            let process_info = get_process_info(pid);
            process_full_path = process_info.0;
            cmd = process_info.1;
        }

        let exe_path = PathBuf::from(process_full_path.to_string());
        Ok(Process {
            command_line: cmd,
            name: exe_path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string(),
            exe_full_name: process_full_path,
            pid,
        })
    }
}

impl User {
    pub fn from_logon_id(
        shared_state: Arc<Mutex<SharedState>>,
        logon_id: u64,
    ) -> std::io::Result<Self> {
        shared_state_wrapper::check_cancellation_token(shared_state.clone(), "from_logon_id")?;
        let user_name;
        let mut user_groups: Vec<String> = Vec::new();

        #[cfg(windows)]
        {
            let user = windows::get_user(shared_state.clone(), logon_id)?;
            user_name = user.0;
            for g in user.1 {
                user_groups.push(g.to_string());
            }
        }
        #[cfg(not(windows))]
        {
            match users::get_user_by_uid(logon_id as u32) {
                Some(u) => {
                    user_name = u.name().to_string_lossy().to_string();
                    let g: Option<Vec<users::Group>> =
                        users::get_user_groups(&user_name, u.primary_group_id());

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
    use super::Claims;
    use crate::{
        redirector::AuditEntry,
        shared_state::{self, proxy_wrapper},
    };
    use std::net::IpAddr;

    #[test]
    fn user_test() {
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
        let shared_state = shared_state::SharedState::new();

        let user = super::get_user(logon_id, shared_state.clone()).unwrap();
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
        let len = proxy_wrapper::get_users_count(shared_state.clone());
        _ = super::get_user(logon_id, shared_state.clone());
        _ = super::get_user(logon_id, shared_state.clone());
        _ = super::get_user(logon_id, shared_state.clone());
        _ = super::get_user(logon_id, shared_state.clone());
        assert_eq!(
            len,
            proxy_wrapper::get_users_count(shared_state.clone()),
            "users count should not change"
        )
    }

    #[test]
    fn entry_to_claims() {
        let mut entry = AuditEntry::empty();
        entry.logon_id = 999; // LocalSystem logon_id
        entry.process_id = std::process::id();
        entry.destination_ipv4 = 0x10813FA8;
        entry.destination_port = 80;
        entry.is_admin = 1;
        let shared_state = shared_state::SharedState::new();

        let claims =
            Claims::from_audit_entry(&entry, IpAddr::from([127, 0, 0, 1]), shared_state.clone())
                .unwrap();
        println!("{}", serde_json::to_string(&claims).unwrap());

        assert!(claims.runAsElevated, "runAsElevated must be true");
        assert_ne!(String::new(), claims.userName, "userName cannot be empty.");
        assert_ne!(
            String::new(),
            claims.processName,
            "processName cannot be empty."
        );
        assert_ne!(
            String::new(),
            claims.processFullPath,
            "processFullPath cannot be empty."
        );
        assert_ne!(
            claims.processName, claims.processFullPath,
            "processName and processFullPath should not be the same."
        );
        assert_ne!(
            String::new(),
            claims.processCmdLine,
            "processCmdLine cannot be empty."
        );
    }
}
