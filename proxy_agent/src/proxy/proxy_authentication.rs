// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use super::authorization_rules::AuthorizationRules;
use super::proxy_connection::Connection;
use super::proxy_summary::ProxySummary;
use crate::common::http::response::Response;
use crate::key_keeper::key::AuthorizationItem;
use crate::proxy_agent_status;
use crate::{common::config, common::constants, proxy::Claims};
use once_cell::sync::Lazy;
use std::sync::Mutex;

static mut WIRESERVER_RULES: Lazy<Mutex<Option<AuthorizationRules>>> =
    Lazy::new(|| Mutex::new(None));
static mut IMDS_RULES: Lazy<Mutex<Option<AuthorizationRules>>> = Lazy::new(|| Mutex::new(None));

pub fn set_wireserver_rules(authorization_item: Option<AuthorizationItem>) {
    let rules = authorization_item.map(AuthorizationRules::from_authorization_item);
    unsafe {
        *WIRESERVER_RULES.lock().unwrap() = rules;
    }
}

pub fn set_imds_rules(authorization_item: Option<AuthorizationItem>) {
    let rules = authorization_item.map(AuthorizationRules::from_authorization_item);
    unsafe {
        *IMDS_RULES.lock().unwrap() = rules;
    }
}

#[cfg(windows)]
mod default {
    use crate::proxy::Claims;
    use proxy_agent_shared::misc_helpers;
    use std::path::PathBuf;

    const VM_APPLICATION_MANAGER_FILE_NAME: &str = "vm-application-manager";
    const WINDOWS_AZURE_GUEST_AGENT_FILE_NAME: &str = "windowsazureguestagent.exe";
    const WAAPPAGENT_FILE_NAME: &str = "waappagent.exe";
    const COLLECT_GUEST_LOG_FILE_NAME: &str = "collectguestlogs.exe";
    const SEC_AGENT_FILE_NAME: &str = "wasecagentprov.exe";
    const IMMEDIATE_RUNCOMMAND_SERVICE_FILE_NAME: &str = "immediateruncommandservice.exe";

    pub fn is_platform_process(claims: &Claims) -> bool {
        let process_name =
            misc_helpers::get_file_name(PathBuf::from(&claims.processName)).to_lowercase();
        if process_name == VM_APPLICATION_MANAGER_FILE_NAME
            || process_name == WINDOWS_AZURE_GUEST_AGENT_FILE_NAME
            || process_name == WAAPPAGENT_FILE_NAME
            || process_name == COLLECT_GUEST_LOG_FILE_NAME
            || process_name == SEC_AGENT_FILE_NAME
            || process_name == IMMEDIATE_RUNCOMMAND_SERVICE_FILE_NAME
        {
            return true;
        }

        false
    }
}

#[cfg(not(windows))]
mod default {
    use crate::proxy::Claims;
    use once_cell::sync::Lazy;
    use proxy_agent_shared::misc_helpers;
    use regex::Regex;
    use std::path::PathBuf;

    const VM_APPLICATION_MANAGER_FILE_NAME: &str = "vm-application-manager";
    const IMMEDIATE_RUNCOMMAND_SERVICE_FILE_NAME: &str = "immediate-run-command-handler";
    static LINUX_VM_AGENT_REGEX: Lazy<Regex> =
        Lazy::new(|| Regex::new(r".*python.*walinuxagent").unwrap());

    pub fn is_platform_process(claims: &Claims) -> bool {
        let process_name =
            misc_helpers::get_file_name(PathBuf::from(&claims.processName)).to_lowercase();
        if process_name == VM_APPLICATION_MANAGER_FILE_NAME
            || process_name == IMMEDIATE_RUNCOMMAND_SERVICE_FILE_NAME
        {
            return true;
        }

        let process_cmd_line = claims.processCmdLine.to_string().to_lowercase();
        if LINUX_VM_AGENT_REGEX.is_match(&process_cmd_line) {
            return true;
        }

        false
    }
}

pub trait Authenticate {
    // authenticate the connection
    fn authenticate(&self, connection_id: u128, request_url: String) -> bool;
    fn to_string(&self) -> String;
}

struct WireServer {
    claims: Claims,
}
impl Authenticate for WireServer {
    fn authenticate(&self, connection_id: u128, request_url: String) -> bool {
        if !self.claims.runAsElevated {
            return false;
        }
        if default::is_platform_process(&self.claims) {
            return true;
        }

        if config::get_wire_server_support() == 2 {
            let wireserver_rules = unsafe { WIRESERVER_RULES.lock().unwrap() };
            match &*wireserver_rules {
                Some(rules) => {
                    let allowed = rules.is_allowed(
                        connection_id,
                        request_url.to_string(),
                        self.claims.clone(),
                    );
                    if !allowed {
                        let summary = ProxySummary {
                            userId: self.claims.userId,
                            userName: self.claims.userName.to_string(),
                            userGroups: self.claims.userGroups.clone(),
                            clientIp: self.claims.clientIp.to_string(),
                            processFullPath: self.claims.processFullPath.to_string(),
                            processCmdLine: self.claims.processCmdLine.to_string(),
                            runAsElevated: self.claims.runAsElevated,
                            method: String::new(),
                            url: request_url.to_string(),
                            ip: constants::WIRE_SERVER_IP.to_string(),
                            port: constants::WIRE_SERVER_PORT,
                            responseStatus: Response::FORBIDDEN.to_string(),
                            elapsedTime: 0,
                        };
                        proxy_agent_status::add_connection_summary(summary, true);

                        if rules.mode.to_lowercase() == "audit" {
                            Connection::write_information(connection_id, format!("WireServer request {} denied in audit mode, continue forward the request", request_url));
                            return true;
                        }
                    }
                    return allowed;
                }
                None => {}
            }
        }

        true
    }

    fn to_string(&self) -> String {
        format!(
            "WireServer {{ runAsElevated: {}, processName: {} }}",
            self.claims.runAsElevated, self.claims.processName
        )
    }
}

struct Imds {
    #[allow(dead_code)]
    claims: Claims,
}
impl Authenticate for Imds {
    fn authenticate(&self, connection_id: u128, request_url: String) -> bool {
        if config::get_imds_support() == 2 {
            let imds_rules = unsafe { IMDS_RULES.lock().unwrap() };
            match &*imds_rules {
                Some(rules) => {
                    let allowed = rules.is_allowed(
                        connection_id,
                        request_url.to_string(),
                        self.claims.clone(),
                    );

                    if !allowed {
                        let summary = ProxySummary {
                            userId: self.claims.userId,
                            userName: self.claims.userName.to_string(),
                            userGroups: self.claims.userGroups.clone(),
                            clientIp: self.claims.clientIp.to_string(),
                            processFullPath: self.claims.processFullPath.to_string(),
                            processCmdLine: self.claims.processCmdLine.to_string(),
                            runAsElevated: self.claims.runAsElevated,
                            method: String::new(),
                            url: request_url.to_string(),
                            ip: constants::IMDS_IP.to_string(),
                            port: constants::IMDS_PORT,
                            responseStatus: Response::FORBIDDEN.to_string(),
                            elapsedTime: 0,
                        };
                        proxy_agent_status::add_connection_summary(summary, true);

                        if rules.mode.to_lowercase() == "audit" {
                            Connection::write_information(connection_id, format!("IMDS request {} denied in audit mode, continue forward the request", request_url));
                            return true;
                        }
                    }
                    return allowed;
                }
                None => {}
            }
        }

        true
    }

    fn to_string(&self) -> String {
        "IMDS".to_string()
    }
}

struct GAPlugin {
    claims: Claims,
}

impl Authenticate for GAPlugin {
    fn authenticate(&self, _connection_id: u128, _request_url: String) -> bool {
        if !self.claims.runAsElevated {
            return false;
        }
        if config::get_host_gaplugin_support() == 2 {
            // only allow VMAgent and VMApp extension talks to GAPlugin
            return default::is_platform_process(&self.claims);
        }

        true
    }

    fn to_string(&self) -> String {
        format!(
            "GAPlugin {{ runAsElevated: {}, processName: {} }}",
            self.claims.runAsElevated, self.claims.processName
        )
    }
}

struct ProxyAgent {}
impl Authenticate for ProxyAgent {
    fn authenticate(&self, _connection_id: u128, _request_url: String) -> bool {
        // Forbid the request send to this listener directly
        false
    }

    fn to_string(&self) -> String {
        "ProxyAgent".to_string()
    }
}

struct Default {}
impl Authenticate for Default {
    fn authenticate(&self, _connection_id: u128, _request_url: String) -> bool {
        true
    }

    fn to_string(&self) -> String {
        "Default".to_string()
    }
}

pub fn get_authenticate(ip: String, port: u16, claims: Claims) -> Box<dyn Authenticate> {
    if ip == constants::WIRE_SERVER_IP && port == constants::WIRE_SERVER_PORT {
        Box::new(WireServer { claims })
    } else if ip == constants::GA_PLUGIN_IP && port == constants::GA_PLUGIN_PORT {
        return Box::new(GAPlugin { claims });
    } else if ip == constants::IMDS_IP && port == constants::IMDS_PORT {
        return Box::new(Imds { claims });
    } else if ip == constants::PROXY_AGENT_IP && port == constants::PROXY_AGENT_PORT {
        return Box::new(ProxyAgent {});
    } else {
        Box::new(Default {})
    }
}

#[cfg(test)]
mod tests {
    use crate::key_keeper::key::AuthorizationItem;

    #[test]
    fn get_authenticate_test() {
        let claims = crate::proxy::Claims {
            userId: 0,
            userName: "test".to_string(),
            userGroups: vec!["test".to_string()],
            processId: std::process::id(),
            processName: "test".to_string(),
            processFullPath: "test".to_string(),
            processCmdLine: "test".to_string(),
            runAsElevated: true,
            clientIp: "127.0.0.1".to_string(),
        };
        let auth = super::get_authenticate(
            crate::common::constants::WIRE_SERVER_IP.to_string(),
            crate::common::constants::WIRE_SERVER_PORT,
            claims.clone(),
        );
        assert_eq!(
            auth.to_string(),
            "WireServer { runAsElevated: true, processName: test }"
        );
        assert!(
            auth.authenticate(1, "test".to_string()),
            "WireServer authentication must be true"
        );

        let auth = super::get_authenticate(
            crate::common::constants::GA_PLUGIN_IP.to_string(),
            crate::common::constants::GA_PLUGIN_PORT,
            claims.clone(),
        );
        assert_eq!(
            auth.to_string(),
            "GAPlugin { runAsElevated: true, processName: test }"
        );
        assert!(
            auth.authenticate(1, "test".to_string()),
            "GAPlugin authentication must be true since it has not enabled for builtin processes in the config yet"
        );

        let auth = super::get_authenticate(
            crate::common::constants::IMDS_IP.to_string(),
            crate::common::constants::IMDS_PORT,
            claims.clone(),
        );
        assert_eq!(auth.to_string(), "IMDS");
        assert!(
            auth.authenticate(1, "test".to_string()),
            "IMDS authentication must be true"
        );

        let auth = super::get_authenticate(
            crate::common::constants::PROXY_AGENT_IP.to_string(),
            crate::common::constants::PROXY_AGENT_PORT,
            claims.clone(),
        );
        assert_eq!(auth.to_string(), "ProxyAgent");
        assert!(
            !auth.authenticate(1, "test".to_string()),
            "ProxyAgent authentication must be false"
        );

        let auth = super::get_authenticate(
            crate::common::constants::PROXY_AGENT_IP.to_string(),
            crate::common::constants::PROXY_AGENT_PORT + 1,
            claims.clone(),
        );
        assert_eq!(auth.to_string(), "Default");
    }

    #[test]
    fn wireserver_authenticate_test() {
        let claims = crate::proxy::Claims {
            userId: 0,
            userName: "test".to_string(),
            userGroups: vec!["test".to_string()],
            processId: std::process::id(),
            processName: "test".to_string(),
            processFullPath: "test".to_string(),
            processCmdLine: "test".to_string(),
            runAsElevated: true,
            clientIp: "127.0.0.1".to_string(),
        };
        let auth = super::get_authenticate(
            crate::common::constants::WIRE_SERVER_IP.to_string(),
            crate::common::constants::WIRE_SERVER_PORT,
            claims.clone(),
        );
        let url = "http://localhost/test?";

        // validate disabled rules
        let disabled_rules = AuthorizationItem {
            defaultAccess: "deny".to_string(),
            mode: "disabled".to_string(),
            id: "id".to_string(),
            rules: None,
        };
        super::set_wireserver_rules(Some(disabled_rules));
        assert!(
            auth.authenticate(1, url.to_string()),
            "WireServer authentication must be true with diabled rules"
        );

        // validate audit rules
        let audit_deny_rules = AuthorizationItem {
            defaultAccess: "deny".to_string(),
            mode: "audit".to_string(),
            id: "id".to_string(),
            rules: None,
        };
        let audit_allow_rules = AuthorizationItem {
            defaultAccess: "allow".to_string(),
            mode: "audit".to_string(),
            id: "id".to_string(),
            rules: None,
        };
        super::set_wireserver_rules(Some(audit_allow_rules));
        assert!(
            auth.authenticate(1, url.to_string()),
            "WireServer authentication must be true with audit allow rules"
        );
        super::set_wireserver_rules(Some(audit_deny_rules));
        assert!(
            auth.authenticate(1, url.to_string()),
            "WireServer authentication must be true with audit deny rules"
        );

        // validate enforce rules
        let enforce_allow_rules = AuthorizationItem {
            defaultAccess: "allow".to_string(),
            mode: "enforce".to_string(),
            id: "id".to_string(),
            rules: None,
        };
        let enforce_deny_rules = AuthorizationItem {
            defaultAccess: "deny".to_string(),
            mode: "enforce".to_string(),
            id: "id".to_string(),
            rules: None,
        };
        super::set_wireserver_rules(Some(enforce_allow_rules));
        assert!(
            auth.authenticate(1, url.to_string()),
            "WireServer authentication must be true with enforce allow rules"
        );
        super::set_wireserver_rules(Some(enforce_deny_rules));
        assert!(
            !auth.authenticate(1, url.to_string()),
            "WireServer authentication must be false with enforce deny rules"
        );
    }

    #[test]
    fn imds_authenticate_test() {
        let claims = crate::proxy::Claims {
            userId: 0,
            userName: "test".to_string(),
            userGroups: vec!["test".to_string()],
            processId: std::process::id(),
            processName: "test".to_string(),
            processFullPath: "test".to_string(),
            processCmdLine: "test".to_string(),
            runAsElevated: true,
            clientIp: "127.0.0.1".to_string(),
        };
        let auth = super::get_authenticate(
            crate::common::constants::IMDS_IP.to_string(),
            crate::common::constants::IMDS_PORT,
            claims.clone(),
        );
        let url = "http://localhost/test?";

        // validate disabled rules
        let disabled_rules = AuthorizationItem {
            defaultAccess: "deny".to_string(),
            mode: "disabled".to_string(),
            id: "id".to_string(),
            rules: None,
        };
        super::set_imds_rules(Some(disabled_rules));
        assert!(
            auth.authenticate(1, url.to_string()),
            "IMDS authentication must be true with diabled rules"
        );

        // validate audit rules
        let audit_deny_rules = AuthorizationItem {
            defaultAccess: "deny".to_string(),
            mode: "audit".to_string(),
            id: "id".to_string(),
            rules: None,
        };
        let audit_allow_rules = AuthorizationItem {
            defaultAccess: "allow".to_string(),
            mode: "audit".to_string(),
            id: "id".to_string(),
            rules: None,
        };
        super::set_imds_rules(Some(audit_allow_rules));
        assert!(
            auth.authenticate(1, url.to_string()),
            "IMDS authentication must be true with audit allow rules"
        );
        super::set_imds_rules(Some(audit_deny_rules));
        assert!(
            auth.authenticate(1, url.to_string()),
            "IMDS authentication must be true with audit deny rules"
        );

        // validate enforce rules
        let enforce_allow_rules = AuthorizationItem {
            defaultAccess: "allow".to_string(),
            mode: "enforce".to_string(),
            id: "id".to_string(),
            rules: None,
        };
        let enforce_deny_rules = AuthorizationItem {
            defaultAccess: "deny".to_string(),
            mode: "enforce".to_string(),
            id: "id".to_string(),
            rules: None,
        };
        super::set_imds_rules(Some(enforce_allow_rules));
        assert!(
            auth.authenticate(1, url.to_string()),
            "IMDS authentication must be true with enforce allow rules"
        );
        super::set_imds_rules(Some(enforce_deny_rules));
        assert!(
            !auth.authenticate(1, url.to_string()),
            "IMDS authentication must be false with enforce deny rules"
        );
    }

    #[test]
    fn is_platform_process_test() {
        let mut claims = crate::proxy::Claims {
            userId: 0,
            userName: "test".to_string(),
            userGroups: vec!["test".to_string()],
            processId: std::process::id(),
            processName: "test".to_string(),
            processFullPath: "test".to_string(),
            processCmdLine: "test".to_string(),
            runAsElevated: true,
            clientIp: "127.0.0.1".to_string(),
        };

        #[cfg(windows)]
        {
            let windows_process_names = [
                "vm-application-manager",
                "windowsazureguestagent.exe",
                "waappagent.exe",
                "immediateruncommandservice.exe",
            ];
            for process in windows_process_names.iter() {
                claims.processName = process.to_string();
                assert!(
                    super::default::is_platform_process(&claims),
                    "{process} should be built-in process"
                );
            }
        }

        #[cfg(not(windows))]
        {
            let linux_process_names = ["vm-application-manager", "immediate-run-command-handler"];
            for process in linux_process_names.iter() {
                claims.processName = process.to_string();
                assert!(
                    super::default::is_platform_process(&claims),
                    "{process} should be built-in process"
                );
            }

            let linux_process_cmds =
                ["python3 -u bin/WALinuxAgent-2.9.1.1-py3.8.egg -run-exthandlers"];
            for process_cmd in linux_process_cmds.iter() {
                claims.processCmdLine = process_cmd.to_string();
                assert!(
                    super::default::is_platform_process(&claims),
                    "{process_cmd} should be built-in process"
                );
            }
        }
    }
}
