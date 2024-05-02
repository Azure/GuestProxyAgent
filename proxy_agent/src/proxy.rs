mod proxy_authentication;
pub mod proxy_connection;
pub mod proxy_listener;
mod proxy_pool;
pub mod proxy_summary;

#[cfg(windows)]
mod windows;

use crate::redirector::AuditEntry;
use once_cell::sync::Lazy;
use serde_derive::{Deserialize, Serialize};
use std::{collections::HashMap, net::IpAddr, path::PathBuf};

#[cfg(not(windows))]
use std::sync::{Arc, Mutex};
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

struct User {
    pub logon_id: u64,
    pub user_name: String,
    pub user_groups: Vec<String>,
}

#[cfg(not(windows))]
static mut CURRENT_SYSTEM: Lazy<Arc<Mutex<System>>> =
    Lazy::new(|| Arc::new(Mutex::new(System::new())));

static mut USERS: Lazy<HashMap<u64, User>> = Lazy::new(|| HashMap::new());
const UNDEFINED: &str = "undefined";
const EMPTY: &str = "empty";

fn get_user(logon_id: u64) -> User {
    unsafe {
        // cache the logon_id -> user_name
        if USERS.contains_key(&logon_id) {
            return USERS[&logon_id].clone();
        }

        let user = User::from_logon_id(logon_id);
        USERS.insert(logon_id, user.clone());
        user
    }
}

#[cfg(not(windows))]
fn get_process_info(process_id: u32) -> (String, String) {
    let mut process_name = UNDEFINED.to_string();
    let mut process_cmd_line = UNDEFINED.to_string();

    let pid = Pid::from_u32(process_id);
    unsafe {
        let cloned_sys = Arc::clone(&*CURRENT_SYSTEM);
        let mut sys = cloned_sys.lock().unwrap();
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

    pub fn from_audit_entry(entry: &AuditEntry, client_ip: IpAddr) -> Self {
        let p = Process::from_pid(entry.process_id);
        let u = get_user(entry.logon_id);
        Claims {
            userId: entry.logon_id,
            userName: u.user_name.to_string(),
            userGroups: u.user_groups.clone(),
            processId: p.pid,
            processName: p.name.to_string(),
            processFullPath: p.exe_full_name.to_string(),
            processCmdLine: p.command_line.to_string(),
            runAsElevated: entry.is_admin == 1,
            clientIp: client_ip.to_string(),
        }
    }

    pub fn clone(&self) -> Self {
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
    pub fn from_pid(pid: u32) -> Self {
        let (process_full_path, cmd);
        #[cfg(windows)]
        {
            let handler;
            match windows::get_process_handler(pid) {
                Ok(h) => handler = h,
                Err(e) => {
                    println!("Failed to get process handler: {}", e);
                    handler = 0;
                }
            }
            let base_info = windows::query_basic_process_info(handler);
            match base_info {
                Ok(_) => {
                    process_full_path =
                        windows::get_process_full_name(handler).unwrap_or(UNDEFINED.to_string());
                    cmd = windows::get_process_cmd(handler).unwrap_or(UNDEFINED.to_string());
                }
                Err(e) => {
                    process_full_path = UNDEFINED.to_string();
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

        let exe_path = PathBuf::from(process_full_path.to_string());
        Process {
            command_line: cmd,
            name: exe_path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string(),
            exe_full_name: process_full_path,
            pid,
        }
    }
}

impl User {
    pub fn clone(&self) -> Self {
        User {
            logon_id: self.logon_id,
            user_name: self.user_name.to_string(),
            user_groups: self.user_groups.clone(),
        }
    }

    pub fn from_logon_id(logon_id: u64) -> Self {
        let user_name;
        let mut user_groups: Vec<String> = Vec::new();

        #[cfg(windows)]
        {
            let user = windows::get_user(logon_id);
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
                    match g {
                        Some(groups) => {
                            for group in groups {
                                user_groups.push(group.name().to_string_lossy().to_string());
                            }
                        }
                        None => {}
                    }
                }
                None => user_name = UNDEFINED.to_string(),
            }
        }

        User {
            logon_id,
            user_name: user_name.to_string(),
            user_groups: user_groups.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::Claims;
    use crate::proxy::USERS;
    use crate::redirector::AuditEntry;

    #[test]
    fn user_test() {
        unsafe {
            let logon_id;
            #[cfg(windows)]
            {
                logon_id = 999u64;
            }
            #[cfg(not(windows))]
            {
                logon_id = 0u64;
            }

            let user = super::get_user(logon_id);
            println!("UserName: {}", user.user_name);
            println!("UserGroups: {}", user.user_groups.join(", "));
            assert_ne!(String::new(), user.user_name, "user_name cannot be empty.");
            #[cfg(windows)]
            {
                assert_eq!(0, user.user_groups.len(), "SYSTEM has no group.");
            }
            #[cfg(not(windows))]
            {
                assert!(
                    user.user_groups.len() > 0,
                    "user_groups should not be empty."
                );
            }

            // test the USERS.len will not change
            let len = USERS.len();
            _ = super::get_user(logon_id);
            _ = super::get_user(logon_id);
            _ = super::get_user(logon_id);
            _ = super::get_user(logon_id);
            assert_eq!(len, USERS.len(), "USERS.len() should not change")
        }
    }

    #[test]
    fn entry_to_claims() {
        let mut entry = AuditEntry::empty();
        entry.logon_id = 999; // LocalSystem logon_id
        entry.process_id = std::process::id();
        entry.destination_ipv4 = 0x10813FA8;
        entry.destination_port = 80;
        entry.is_admin = 1;

        let claims = Claims::from_audit_entry(&entry, IpAddr::from([127, 0, 0, 1]));
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
