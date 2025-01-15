// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

//! This module contains the logic to authorize the connection based on the claims.
//! The claims are used to determine if the process is allowed to connect to the remote server.
//!
//! Example
//! ```rust
//! use proxy_agent::proxy_authorizer;
//! use proxy_agent::proxy::Claims;
//! use proxy_agent::shared_state::key_keeper_wrapper::KeyKeeperSharedState;
//! use proxy_agent::common::constants;
//! use std::str::FromStr;
//!
//! let key_keeper_shared_state = KeyKeeperSharedState::start_new();
//! let vm_metadata = proxy_authorizer::get_access_control_rules(constants::WIRE_SERVER_IP.to_string(), key_keeper_shared_state.clone()).await.unwrap();
//! let authorizer = proxy_authorizer::get_authorizer(constants::WIRE_SERVER_IP, constants::WIRE_SERVER_PORT, claims);
//! let url = hyper::Uri::from_str("http://localhost/test?").unwrap();
//! authorizer.authorize(logger, url, vm_metadata);
//!  

use proxy_agent_shared::logger_manager::LoggerLevel;

use super::authorization_rules::{AuthorizationMode, ComputedAuthorizationItem};
use super::proxy_connection::ConnectionLogger;
use crate::shared_state::key_keeper_wrapper::KeyKeeperSharedState;
use crate::{common::config, common::constants, common::result::Result, proxy::Claims};

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
            misc_helpers::get_file_name(&PathBuf::from(&claims.processName)).to_lowercase();
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
            misc_helpers::get_file_name(&PathBuf::from(&claims.processName)).to_lowercase();
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

#[derive(PartialEq)]
pub enum AuthorizeResult {
    Ok,
    OkWithAudit,
    Forbidden,
}

pub trait Authorizer {
    // authorize the connection
    fn authorize(
        &self,
        logger: ConnectionLogger,
        request_url: hyper::Uri,
        access_control_rules: Option<ComputedAuthorizationItem>,
    ) -> AuthorizeResult;
    fn to_string(&self) -> String;
    fn type_name(&self) -> String {
        std::any::type_name::<Self>().to_string()
    }
}

struct WireServer {
    claims: Claims,
}
impl Authorizer for WireServer {
    fn authorize(
        &self,
        logger: ConnectionLogger,
        request_url: hyper::Uri,
        access_control_rules: Option<ComputedAuthorizationItem>,
    ) -> AuthorizeResult {
        if !self.claims.runAsElevated {
            return AuthorizeResult::Forbidden;
        }

        if let Some(rules) = access_control_rules {
            if rules.is_allowed(logger.clone(), request_url.clone(), self.claims.clone()) {
                return AuthorizeResult::Ok;
            } else {
                if rules.mode == AuthorizationMode::Audit {
                    logger.write(
                            LoggerLevel::Information, format!("WireServer request {} denied in audit mode, continue forward the request", request_url));
                    return AuthorizeResult::OkWithAudit;
                }
                return AuthorizeResult::Forbidden;
            }
        }

        AuthorizeResult::Ok
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
impl Authorizer for Imds {
    fn authorize(
        &self,
        logger: ConnectionLogger,
        request_url: hyper::Uri,
        access_control_rules: Option<ComputedAuthorizationItem>,
    ) -> AuthorizeResult {
        if let Some(rules) = access_control_rules {
            if rules.is_allowed(logger.clone(), request_url.clone(), self.claims.clone()) {
                return AuthorizeResult::Ok;
            } else {
                if rules.mode == AuthorizationMode::Audit {
                    logger.write(
                        LoggerLevel::Information,
                        format!(
                            "IMDS request {} denied in audit mode, continue forward the request",
                            request_url
                        ),
                    );
                    return AuthorizeResult::OkWithAudit;
                }
                return AuthorizeResult::Forbidden;
            }
        }

        AuthorizeResult::Ok
    }

    fn to_string(&self) -> String {
        "IMDS".to_string()
    }
}

struct GAPlugin {
    claims: Claims,
}

impl Authorizer for GAPlugin {
    fn authorize(
        &self,
        _logger: ConnectionLogger,
        _request_url: hyper::Uri,
        _access_control_rules: Option<ComputedAuthorizationItem>,
    ) -> AuthorizeResult {
        if !self.claims.runAsElevated {
            return AuthorizeResult::Forbidden;
        }
        if config::get_host_gaplugin_support() == 2 {
            // only allow VMAgent and platform vm extensions talk to GAPlugin
            if default::is_platform_process(&self.claims) {
                return AuthorizeResult::Ok;
            } else {
                return AuthorizeResult::Forbidden;
            }
        }
        AuthorizeResult::Ok
    }

    fn to_string(&self) -> String {
        format!(
            "GAPlugin {{ runAsElevated: {}, processName: {} }}",
            self.claims.runAsElevated, self.claims.processName
        )
    }
}

struct ProxyAgent {}
impl Authorizer for ProxyAgent {
    fn authorize(
        &self,
        _logger: ConnectionLogger,
        _request_url: hyper::Uri,
        _access_control_rules: Option<ComputedAuthorizationItem>,
    ) -> AuthorizeResult {
        // Forbid the request send to this listener directly
        AuthorizeResult::Forbidden
    }

    fn to_string(&self) -> String {
        "ProxyAgent".to_string()
    }
}

struct Default {}
impl Authorizer for Default {
    fn authorize(
        &self,
        _logger: ConnectionLogger,
        _request_url: hyper::Uri,
        _access_control_rules: Option<ComputedAuthorizationItem>,
    ) -> AuthorizeResult {
        AuthorizeResult::Ok
    }

    fn to_string(&self) -> String {
        "Default".to_string()
    }
}

pub fn get_authorizer(ip: String, port: u16, claims: Claims) -> Box<dyn Authorizer> {
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

pub async fn get_access_control_rules(
    ip: String,
    key_keeper_shared_state: KeyKeeperSharedState,
) -> Result<Option<ComputedAuthorizationItem>> {
    match ip.as_str() {
        constants::WIRE_SERVER_IP => key_keeper_shared_state.get_wireserver_rules().await,
        constants::IMDS_IP => key_keeper_shared_state.get_imds_rules().await,
        _ => Ok(None),
    }
}

pub fn authorize(
    ip: String,
    port: u16,
    logger: ConnectionLogger,
    request_uri: hyper::Uri,
    claims: Claims,
    access_control_rules: Option<ComputedAuthorizationItem>,
) -> AuthorizeResult {
    let auth = get_authorizer(ip, port, claims);
    logger.write(
        LoggerLevel::Verbose,
        format!("Got auth: {}", auth.to_string()),
    );
    auth.authorize(logger, request_uri, access_control_rules)
}

#[cfg(test)]
mod tests {
    use crate::{
        key_keeper::key::AuthorizationItem,
        proxy::{proxy_authorizer::AuthorizeResult, proxy_connection::ConnectionLogger},
        shared_state::key_keeper_wrapper::KeyKeeperSharedState,
    };
    use std::str::FromStr;

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
            clientPort: 0, // doesn't matter for this test
        };
        let test_logger = ConnectionLogger {
            tcp_connection_id: 1,
            http_connection_id: 1,
        };
        let auth: Box<dyn super::Authorizer> = super::get_authorizer(
            crate::common::constants::WIRE_SERVER_IP.to_string(),
            crate::common::constants::WIRE_SERVER_PORT,
            claims.clone(),
        );
        let test_uri = hyper::Uri::from_str("test").unwrap();
        assert_eq!(
            auth.to_string(),
            "WireServer { runAsElevated: true, processName: test }"
        );
        assert!(
            AuthorizeResult::Ok == auth.authorize(test_logger.clone(), test_uri.clone(), None),
            "WireServer authentication must be Ok"
        );

        let auth = super::get_authorizer(
            crate::common::constants::GA_PLUGIN_IP.to_string(),
            crate::common::constants::GA_PLUGIN_PORT,
            claims.clone(),
        );
        assert_eq!(
            auth.to_string(),
            "GAPlugin { runAsElevated: true, processName: test }"
        );
        assert!(AuthorizeResult::Ok==
            auth.authorize(
                test_logger.clone(),
                test_uri.clone(),
                None
            ),          "GAPlugin authentication must be Ok since it has not enabled for builtin processes in the config yet"
        );

        let auth = super::get_authorizer(
            crate::common::constants::IMDS_IP.to_string(),
            crate::common::constants::IMDS_PORT,
            claims.clone(),
        );
        assert_eq!(auth.to_string(), "IMDS");
        assert!(
            AuthorizeResult::Ok == auth.authorize(test_logger.clone(), test_uri.clone(), None),
            "IMDS authentication must be Ok"
        );

        let auth = super::get_authorizer(
            crate::common::constants::PROXY_AGENT_IP.to_string(),
            crate::common::constants::PROXY_AGENT_PORT,
            claims.clone(),
        );
        assert_eq!(auth.to_string(), "ProxyAgent");
        assert!(
            AuthorizeResult::Forbidden
                == auth.authorize(test_logger.clone(), test_uri.clone(), None),
            "ProxyAgent authentication must be Forbidden"
        );

        let auth = super::get_authorizer(
            crate::common::constants::PROXY_AGENT_IP.to_string(),
            crate::common::constants::PROXY_AGENT_PORT + 1,
            claims.clone(),
        );
        assert_eq!(auth.to_string(), "Default");
    }

    #[tokio::test]
    async fn wireserver_authenticate_test() {
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
            clientPort: 0, // doesn't matter for this test
        };
        let test_logger = ConnectionLogger {
            tcp_connection_id: 1,
            http_connection_id: 1,
        };
        let auth = super::get_authorizer(
            crate::common::constants::WIRE_SERVER_IP.to_string(),
            crate::common::constants::WIRE_SERVER_PORT,
            claims.clone(),
        );
        let url = hyper::Uri::from_str("http://localhost/test?").unwrap();
        let key_keeper_shared_state = KeyKeeperSharedState::start_new();

        // validate disabled rules
        let disabled_rules = AuthorizationItem {
            defaultAccess: "deny".to_string(),
            mode: "disabled".to_string(),
            id: "id".to_string(),
            rules: None,
        };
        key_keeper_shared_state
            .set_wireserver_rules(Some(disabled_rules))
            .await
            .unwrap();
        let access_control_rules = key_keeper_shared_state
            .get_wireserver_rules()
            .await
            .unwrap();
        assert!(
            auth.authorize(test_logger.clone(), url.clone(), access_control_rules)
                == AuthorizeResult::Ok,
            "WireServer authentication must be Ok with disabled rules"
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
        key_keeper_shared_state
            .set_wireserver_rules(Some(audit_allow_rules))
            .await
            .unwrap();
        let access_control_rules = key_keeper_shared_state
            .get_wireserver_rules()
            .await
            .unwrap();
        assert!(
            auth.authorize(test_logger.clone(), url.clone(), access_control_rules)
                == AuthorizeResult::Ok,
            "WireServer authentication must be Ok with audit allow rules"
        );
        key_keeper_shared_state
            .set_wireserver_rules(Some(audit_deny_rules))
            .await
            .unwrap();
        let access_control_rules = key_keeper_shared_state
            .get_wireserver_rules()
            .await
            .unwrap();
        assert!(
            auth.authorize(test_logger.clone(), url.clone(), access_control_rules)
                == AuthorizeResult::OkWithAudit,
            "WireServer authentication must be OkWithAudit with audit deny rules"
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
        key_keeper_shared_state
            .set_wireserver_rules(Some(enforce_allow_rules))
            .await
            .unwrap();
        let access_control_rules = key_keeper_shared_state
            .get_wireserver_rules()
            .await
            .unwrap();
        assert!(
            auth.authorize(test_logger.clone(), url.clone(), access_control_rules)
                == AuthorizeResult::Ok,
            "WireServer authentication must be Ok with enforce allow rules"
        );
        key_keeper_shared_state
            .set_wireserver_rules(Some(enforce_deny_rules))
            .await
            .unwrap();
        let access_control_rules = key_keeper_shared_state
            .get_wireserver_rules()
            .await
            .unwrap();
        assert!(
            auth.authorize(test_logger.clone(), url.clone(), access_control_rules)
                == AuthorizeResult::Forbidden,
            "WireServer authentication must be Forbidden with enforce deny rules"
        );
    }

    #[tokio::test]
    async fn imds_authenticate_test() {
        let test_logger = ConnectionLogger {
            tcp_connection_id: 1,
            http_connection_id: 1,
        };
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
            clientPort: 0, // doesn't matter for this test
        };
        let auth = super::get_authorizer(
            crate::common::constants::IMDS_IP.to_string(),
            crate::common::constants::IMDS_PORT,
            claims.clone(),
        );
        let url = hyper::Uri::from_str("http://localhost/test?").unwrap();
        let key_keeper_shared_state = KeyKeeperSharedState::start_new();

        // validate disabled rules
        let disabled_rules = AuthorizationItem {
            defaultAccess: "deny".to_string(),
            mode: "disabled".to_string(),
            id: "id".to_string(),
            rules: None,
        };
        key_keeper_shared_state
            .set_imds_rules(Some(disabled_rules))
            .await
            .unwrap();
        let access_control_rules = key_keeper_shared_state.get_imds_rules().await.unwrap();
        assert!(
            auth.authorize(test_logger.clone(), url.clone(), access_control_rules,)
                == AuthorizeResult::Ok,
            "IMDS authentication must be Ok with disabled rules"
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
        key_keeper_shared_state
            .set_imds_rules(Some(audit_allow_rules))
            .await
            .unwrap();
        let access_control_rules = key_keeper_shared_state.get_imds_rules().await.unwrap();
        assert!(
            auth.authorize(test_logger.clone(), url.clone(), access_control_rules,)
                == AuthorizeResult::Ok,
            "IMDS authentication must be Ok with audit allow rules"
        );
        key_keeper_shared_state
            .set_imds_rules(Some(audit_deny_rules))
            .await
            .unwrap();
        let access_control_rules = key_keeper_shared_state.get_imds_rules().await.unwrap();
        assert!(
            auth.authorize(test_logger.clone(), url.clone(), access_control_rules,)
                == AuthorizeResult::OkWithAudit,
            "IMDS authentication must be OkWithAudit with audit deny rules"
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
        key_keeper_shared_state
            .set_imds_rules(Some(enforce_allow_rules))
            .await
            .unwrap();
        let access_control_rules = key_keeper_shared_state.get_imds_rules().await.unwrap();
        assert!(
            auth.authorize(test_logger.clone(), url.clone(), access_control_rules,)
                == AuthorizeResult::Ok,
            "IMDS authentication must be Ok with enforce allow rules"
        );
        key_keeper_shared_state
            .set_imds_rules(Some(enforce_deny_rules))
            .await
            .unwrap();
        let access_control_rules = key_keeper_shared_state.get_imds_rules().await.unwrap();
        assert!(
            auth.authorize(test_logger.clone(), url.clone(), access_control_rules,)
                == AuthorizeResult::Forbidden,
            "IMDS authentication must be Forbidden with enforce deny rules"
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
            clientPort: 0, // doesn't matter for this test
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
