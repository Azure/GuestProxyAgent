// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

//! This module contains the logic to authorize the connection based on the claims.
//! The claims are used to determine if the process is allowed to connect to the remote server.
//!
//! Example
//! ```rust
//! use proxy_agent::proxy_authorizer;
//! use proxy_agent::proxy::Claims;
//! use crate::shared_state::access_control_wrapper::AccessControlSharedState;
//! use proxy_agent::common::constants;
//! use std::str::FromStr;
//!
//! let access_control_shared_state  = AccessControlSharedState::start_new();
//! let vm_metadata = proxy_authorizer::get_access_control_rules(constants::WIRE_SERVER_IP.to_string(), constants::WIRE_SERVER_PORT, access_control_shared_state .clone()).await.unwrap();
//! let authorizer = proxy_authorizer::get_authorizer(constants::WIRE_SERVER_IP, constants::WIRE_SERVER_PORT, claims);
//! let url = hyper::Uri::from_str("http://localhost/test?").unwrap();
//! authorizer.authorize(logger, url, vm_metadata);
//!  

use super::authorization_rules::{AuthorizationMode, ComputedAuthorizationItem};
use super::proxy_connection::ConnectionLogger;
use crate::shared_state::access_control_wrapper::AccessControlSharedState;
use crate::{common::constants, common::result::Result, proxy::Claims};
use proxy_agent_shared::hyper_client;
use proxy_agent_shared::logger::LoggerLevel;

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
        logger: &mut ConnectionLogger,
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
        logger: &mut ConnectionLogger,
        request_url: hyper::Uri,
        access_control_rules: Option<ComputedAuthorizationItem>,
    ) -> AuthorizeResult {
        if !self.claims.runAsElevated {
            return AuthorizeResult::Forbidden;
        }

        if let Some(rules) = access_control_rules {
            if rules.is_allowed(logger, request_url.clone(), self.claims.clone()) {
                return AuthorizeResult::Ok;
            } else {
                if rules.mode == AuthorizationMode::Audit {
                    logger.write(
                            LoggerLevel::Info, format!("WireServer request {request_url} denied in audit mode, continue forward the request"));
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
            self.claims.runAsElevated,
            self.claims.processName.to_string_lossy()
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
        logger: &mut ConnectionLogger,
        request_url: hyper::Uri,
        access_control_rules: Option<ComputedAuthorizationItem>,
    ) -> AuthorizeResult {
        if let Some(rules) = access_control_rules {
            if rules.is_allowed(logger, request_url.clone(), self.claims.clone()) {
                return AuthorizeResult::Ok;
            } else {
                if rules.mode == AuthorizationMode::Audit {
                    logger.write(
                        LoggerLevel::Info,
                        format!(
                            "IMDS request {request_url} denied in audit mode, continue forward the request"
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
        logger: &mut ConnectionLogger,
        request_url: hyper::Uri,
        access_control_rules: Option<ComputedAuthorizationItem>,
    ) -> AuthorizeResult {
        if !self.claims.runAsElevated {
            return AuthorizeResult::Forbidden;
        }

        if let Some(rules) = access_control_rules {
            if rules.is_allowed(logger, request_url.clone(), self.claims.clone()) {
                return AuthorizeResult::Ok;
            } else {
                if rules.mode == AuthorizationMode::Audit {
                    logger.write(
                            LoggerLevel::Info, format!("HostGAPlugin request {request_url} denied in audit mode, continue forward the request"));
                    return AuthorizeResult::OkWithAudit;
                }
                return AuthorizeResult::Forbidden;
            }
        }

        AuthorizeResult::Ok
    }

    fn to_string(&self) -> String {
        format!(
            "GAPlugin {{ runAsElevated: {}, processName: {} }}",
            self.claims.runAsElevated,
            self.claims.processName.to_string_lossy()
        )
    }
}

struct ProxyAgent {}
impl Authorizer for ProxyAgent {
    fn authorize(
        &self,
        _logger: &mut ConnectionLogger,
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
        _logger: &mut ConnectionLogger,
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
        Box::new(GAPlugin { claims })
    } else if ip == constants::IMDS_IP && port == constants::IMDS_PORT {
        Box::new(Imds { claims })
    } else if ip == constants::PROXY_AGENT_IP && port == constants::PROXY_AGENT_PORT {
        Box::new(ProxyAgent {})
    } else {
        Box::new(Default {})
    }
}

pub async fn get_access_control_rules(
    ip: String,
    port: u16,
    access_control_shared_state: AccessControlSharedState,
) -> Result<Option<ComputedAuthorizationItem>> {
    match (ip.as_str(), port) {
        (constants::WIRE_SERVER_IP, constants::WIRE_SERVER_PORT) => {
            access_control_shared_state.get_wireserver_rules().await
        }
        (constants::GA_PLUGIN_IP, constants::GA_PLUGIN_PORT) => {
            access_control_shared_state.get_hostga_rules().await
        }
        (constants::IMDS_IP, constants::IMDS_PORT) => {
            access_control_shared_state.get_imds_rules().await
        }
        _ => Ok(None),
    }
}

pub fn authorize(
    ip: String,
    port: u16,
    logger: &mut ConnectionLogger,
    request_uri: hyper::Uri,
    request_method: hyper::Method,
    claims: Claims,
    access_control_rules: Option<ComputedAuthorizationItem>,
) -> AuthorizeResult {
    // If the request should skip signature and the claims indicate elevated privileges, allow the request.
    // This is a security measure to allow certain endpoints are exempt from enforcement regardless of the VM's configuration.
    if hyper_client::should_skip_sig(&request_method, &request_uri) && claims.runAsElevated {
        return AuthorizeResult::Ok;
    }

    let auth = get_authorizer(ip, port, claims);
    logger.write(
        LoggerLevel::Trace,
        format!("Got auth: {}", auth.to_string()),
    );
    auth.authorize(logger, request_uri, access_control_rules)
}

#[cfg(test)]
mod tests {
    use crate::{
        key_keeper::key::AuthorizationItem,
        proxy::{proxy_authorizer::AuthorizeResult, proxy_connection::ConnectionLogger},
        shared_state::access_control_wrapper::AccessControlSharedState,
    };
    use std::{ffi::OsString, path::PathBuf, str::FromStr};

    #[test]
    fn get_authenticate_test() {
        let claims = crate::proxy::Claims {
            userId: 0,
            userName: "test".to_string(),
            userGroups: vec!["test".to_string()],
            processId: std::process::id(),
            processName: OsString::from("test"),
            processFullPath: PathBuf::from("test"),
            processCmdLine: "test".to_string(),
            runAsElevated: true,
            clientIp: "127.0.0.1".to_string(),
            clientPort: 0, // doesn't matter for this test
        };
        let mut test_logger = ConnectionLogger::new(0, 0);
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
            AuthorizeResult::Ok == auth.authorize(&mut test_logger, test_uri.clone(), None),
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
        assert!(
            AuthorizeResult::Ok == auth.authorize(&mut test_logger, test_uri.clone(), None),
            "GAPlugin authentication must be Ok"
        );

        let auth = super::get_authorizer(
            crate::common::constants::IMDS_IP.to_string(),
            crate::common::constants::IMDS_PORT,
            claims.clone(),
        );
        assert_eq!(auth.to_string(), "IMDS");
        assert!(
            AuthorizeResult::Ok == auth.authorize(&mut test_logger, test_uri.clone(), None),
            "IMDS authentication must be Ok"
        );

        let auth = super::get_authorizer(
            crate::common::constants::PROXY_AGENT_IP.to_string(),
            crate::common::constants::PROXY_AGENT_PORT,
            claims.clone(),
        );
        assert_eq!(auth.to_string(), "ProxyAgent");
        assert!(
            AuthorizeResult::Forbidden == auth.authorize(&mut test_logger, test_uri.clone(), None),
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
            processName: OsString::from("test"),
            processFullPath: PathBuf::from("test"),
            processCmdLine: "test".to_string(),
            runAsElevated: true,
            clientIp: "127.0.0.1".to_string(),
            clientPort: 0, // doesn't matter for this test
        };
        let mut test_logger = ConnectionLogger::new(1, 1);
        let auth = super::get_authorizer(
            crate::common::constants::WIRE_SERVER_IP.to_string(),
            crate::common::constants::WIRE_SERVER_PORT,
            claims.clone(),
        );
        let url = hyper::Uri::from_str("http://localhost/test?").unwrap();
        let access_control_shared_state = AccessControlSharedState::start_new();

        // validate disabled rules
        let disabled_rules = AuthorizationItem {
            defaultAccess: "deny".to_string(),
            mode: "disabled".to_string(),
            id: "id".to_string(),
            rules: None,
        };
        access_control_shared_state
            .set_wireserver_rules(Some(disabled_rules))
            .await
            .unwrap();
        let access_control_rules = access_control_shared_state
            .get_wireserver_rules()
            .await
            .unwrap();
        assert!(
            auth.authorize(&mut test_logger, url.clone(), access_control_rules)
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
        access_control_shared_state
            .set_wireserver_rules(Some(audit_allow_rules))
            .await
            .unwrap();
        let access_control_rules = access_control_shared_state
            .get_wireserver_rules()
            .await
            .unwrap();
        assert!(
            auth.authorize(&mut test_logger, url.clone(), access_control_rules)
                == AuthorizeResult::Ok,
            "WireServer authentication must be Ok with audit allow rules"
        );
        access_control_shared_state
            .set_wireserver_rules(Some(audit_deny_rules))
            .await
            .unwrap();
        let access_control_rules = access_control_shared_state
            .get_wireserver_rules()
            .await
            .unwrap();
        assert!(
            auth.authorize(&mut test_logger, url.clone(), access_control_rules)
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
        access_control_shared_state
            .set_wireserver_rules(Some(enforce_allow_rules))
            .await
            .unwrap();
        let access_control_rules = access_control_shared_state
            .get_wireserver_rules()
            .await
            .unwrap();
        assert!(
            auth.authorize(&mut test_logger, url.clone(), access_control_rules)
                == AuthorizeResult::Ok,
            "WireServer authentication must be Ok with enforce allow rules"
        );
        access_control_shared_state
            .set_wireserver_rules(Some(enforce_deny_rules))
            .await
            .unwrap();
        let access_control_rules = access_control_shared_state
            .get_wireserver_rules()
            .await
            .unwrap();
        assert!(
            auth.authorize(&mut test_logger, url.clone(), access_control_rules)
                == AuthorizeResult::Forbidden,
            "WireServer authentication must be Forbidden with enforce deny rules"
        );
    }

    #[tokio::test]
    async fn imds_authenticate_test() {
        let mut test_logger = ConnectionLogger::new(1, 1);
        let claims = crate::proxy::Claims {
            userId: 0,
            userName: "test".to_string(),
            userGroups: vec!["test".to_string()],
            processId: std::process::id(),
            processName: OsString::from("test"),
            processFullPath: PathBuf::from("test"),
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
        let access_control_shared_state = AccessControlSharedState::start_new();

        // validate disabled rules
        let disabled_rules = AuthorizationItem {
            defaultAccess: "deny".to_string(),
            mode: "disabled".to_string(),
            id: "id".to_string(),
            rules: None,
        };
        access_control_shared_state
            .set_imds_rules(Some(disabled_rules))
            .await
            .unwrap();
        let access_control_rules = access_control_shared_state.get_imds_rules().await.unwrap();
        assert!(
            auth.authorize(&mut test_logger, url.clone(), access_control_rules,)
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
        access_control_shared_state
            .set_imds_rules(Some(audit_allow_rules))
            .await
            .unwrap();
        let access_control_rules = access_control_shared_state.get_imds_rules().await.unwrap();
        assert!(
            auth.authorize(&mut test_logger, url.clone(), access_control_rules,)
                == AuthorizeResult::Ok,
            "IMDS authentication must be Ok with audit allow rules"
        );
        access_control_shared_state
            .set_imds_rules(Some(audit_deny_rules))
            .await
            .unwrap();
        let access_control_rules = access_control_shared_state.get_imds_rules().await.unwrap();
        assert!(
            auth.authorize(&mut test_logger, url.clone(), access_control_rules,)
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
        access_control_shared_state
            .set_imds_rules(Some(enforce_allow_rules))
            .await
            .unwrap();
        let access_control_rules = access_control_shared_state.get_imds_rules().await.unwrap();
        assert!(
            auth.authorize(&mut test_logger, url.clone(), access_control_rules,)
                == AuthorizeResult::Ok,
            "IMDS authentication must be Ok with enforce allow rules"
        );
        access_control_shared_state
            .set_imds_rules(Some(enforce_deny_rules))
            .await
            .unwrap();
        let access_control_rules = access_control_shared_state.get_imds_rules().await.unwrap();
        assert!(
            auth.authorize(&mut test_logger, url.clone(), access_control_rules,)
                == AuthorizeResult::Forbidden,
            "IMDS authentication must be Forbidden with enforce deny rules"
        );
    }

    #[tokio::test]
    async fn hostga_authenticate_test() {
        let claims = crate::proxy::Claims {
            userId: 0,
            userName: "test".to_string(),
            userGroups: vec!["test".to_string()],
            processId: std::process::id(),
            processName: OsString::from("test"),
            processFullPath: PathBuf::from("test"),
            processCmdLine: "test".to_string(),
            runAsElevated: true,
            clientIp: "127.0.0.1".to_string(),
            clientPort: 0, // doesn't matter for this test
        };
        let mut test_logger = ConnectionLogger::new(1, 1);
        let auth = super::get_authorizer(
            crate::common::constants::GA_PLUGIN_IP.to_string(),
            crate::common::constants::GA_PLUGIN_PORT,
            claims.clone(),
        );
        let url = hyper::Uri::from_str("http://localhost/test?").unwrap();
        let access_control_shared_state = AccessControlSharedState::start_new();

        // validate disabled rules
        let disabled_rules = AuthorizationItem {
            defaultAccess: "deny".to_string(),
            mode: "disabled".to_string(),
            id: "id".to_string(),
            rules: None,
        };
        access_control_shared_state
            .set_hostga_rules(Some(disabled_rules))
            .await
            .unwrap();
        let access_control_rules = access_control_shared_state
            .get_hostga_rules()
            .await
            .unwrap();
        assert!(
            auth.authorize(&mut test_logger, url.clone(), access_control_rules)
                == AuthorizeResult::Ok,
            "HostGA authentication must be Ok with disabled rules"
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
        access_control_shared_state
            .set_hostga_rules(Some(audit_allow_rules))
            .await
            .unwrap();
        let access_control_rules = access_control_shared_state
            .get_hostga_rules()
            .await
            .unwrap();
        assert!(
            auth.authorize(&mut test_logger, url.clone(), access_control_rules)
                == AuthorizeResult::Ok,
            "HostGA authentication must be Ok with audit allow rules"
        );
        access_control_shared_state
            .set_hostga_rules(Some(audit_deny_rules))
            .await
            .unwrap();
        let access_control_rules = access_control_shared_state
            .get_hostga_rules()
            .await
            .unwrap();
        assert!(
            auth.authorize(&mut test_logger, url.clone(), access_control_rules)
                == AuthorizeResult::OkWithAudit,
            "HostGA authentication must be OkWithAudit with audit deny rules"
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
        access_control_shared_state
            .set_hostga_rules(Some(enforce_allow_rules))
            .await
            .unwrap();
        let access_control_rules = access_control_shared_state
            .get_hostga_rules()
            .await
            .unwrap();
        assert!(
            auth.authorize(&mut test_logger, url.clone(), access_control_rules)
                == AuthorizeResult::Ok,
            "HostGA authentication must be Ok with enforce allow rules"
        );
        access_control_shared_state
            .set_hostga_rules(Some(enforce_deny_rules))
            .await
            .unwrap();
        let access_control_rules = access_control_shared_state
            .get_hostga_rules()
            .await
            .unwrap();
        assert!(
            auth.authorize(&mut test_logger, url.clone(), access_control_rules)
                == AuthorizeResult::Forbidden,
            "HostGA authentication must be Forbidden with enforce deny rules"
        );
    }

    #[tokio::test]
    async fn authorize_skip_sig_test() {
        // Build claims for an elevated and a non-elevated process.
        let elevated_claims = crate::proxy::Claims {
            userId: 0,
            userName: "test".to_string(),
            userGroups: vec!["test".to_string()],
            processId: std::process::id(),
            processName: OsString::from("test"),
            processFullPath: PathBuf::from("test"),
            processCmdLine: "test".to_string(),
            runAsElevated: true,
            clientIp: "127.0.0.1".to_string(),
            clientPort: 0,
        };
        let mut non_elevated_claims = elevated_claims.clone();
        non_elevated_claims.runAsElevated = false;

        let mut test_logger = ConnectionLogger::new(2, 2);

        // Set up an enforce-deny rule for WireServer so the normal authorize path
        // would return Forbidden if the skip-sig early return did not take effect.
        let access_control_shared_state = AccessControlSharedState::start_new();
        let enforce_deny_rules = AuthorizationItem {
            defaultAccess: "deny".to_string(),
            mode: "enforce".to_string(),
            id: "id".to_string(),
            rules: None,
        };
        access_control_shared_state
            .set_wireserver_rules(Some(enforce_deny_rules))
            .await
            .unwrap();
        let wireserver_deny_rules = access_control_shared_state
            .get_wireserver_rules()
            .await
            .unwrap();

        // Skip-sig URIs (per hyper_client::should_skip_sig):
        //   o PUT  /vmAgentLog
        //   o POST /machine/?comp=telemetrydata
        let vm_agent_log_uri = hyper::Uri::from_str("/vmAgentLog").unwrap();
        let telemetry_uri = hyper::Uri::from_str("/machine/?comp=telemetrydata").unwrap();
        let non_skip_uri = hyper::Uri::from_str("http://localhost/test?").unwrap();

        // 1. Skip-sig URI + elevated claims => Ok even though rule is enforce-deny.
        assert!(
            super::authorize(
                crate::common::constants::WIRE_SERVER_IP.to_string(),
                crate::common::constants::WIRE_SERVER_PORT,
                &mut test_logger,
                vm_agent_log_uri.clone(),
                hyper::Method::PUT,
                elevated_claims.clone(),
                wireserver_deny_rules.clone(),
            ) == AuthorizeResult::Ok,
            "PUT /vmAgentLog with elevated claims must be Ok regardless of deny rules"
        );
        assert!(
            super::authorize(
                crate::common::constants::WIRE_SERVER_IP.to_string(),
                crate::common::constants::WIRE_SERVER_PORT,
                &mut test_logger,
                telemetry_uri.clone(),
                hyper::Method::POST,
                elevated_claims.clone(),
                wireserver_deny_rules.clone(),
            ) == AuthorizeResult::Ok,
            "POST /machine/?comp=telemetrydata with elevated claims must be Ok regardless of deny rules"
        );

        // 2. Skip-sig URI but the claims are NOT elevated => must fall through to the
        //    normal authorizer, which forbids WireServer access for non-elevated callers.
        assert!(
            super::authorize(
                crate::common::constants::WIRE_SERVER_IP.to_string(),
                crate::common::constants::WIRE_SERVER_PORT,
                &mut test_logger,
                vm_agent_log_uri.clone(),
                hyper::Method::PUT,
                non_elevated_claims.clone(),
                wireserver_deny_rules.clone(),
            ) == AuthorizeResult::Forbidden,
            "Skip-sig URI without elevated claims must fall through and be Forbidden"
        );

        // 3. Skip-sig URI methods that do not match the exempt method => still enforced.
        //    GET /vmAgentLog is not exempt, so the deny rule applies.
        assert!(
            super::authorize(
                crate::common::constants::WIRE_SERVER_IP.to_string(),
                crate::common::constants::WIRE_SERVER_PORT,
                &mut test_logger,
                vm_agent_log_uri.clone(),
                hyper::Method::GET,
                elevated_claims.clone(),
                wireserver_deny_rules.clone(),
            ) == AuthorizeResult::Forbidden,
            "GET /vmAgentLog is not skip-sig and must be Forbidden under enforce-deny"
        );

        // 4. Non-skip-sig URI with elevated claims => normal authorizer path is used.
        //    Under enforce-deny the request must be Forbidden.
        assert!(
            super::authorize(
                crate::common::constants::WIRE_SERVER_IP.to_string(),
                crate::common::constants::WIRE_SERVER_PORT,
                &mut test_logger,
                non_skip_uri.clone(),
                hyper::Method::GET,
                elevated_claims.clone(),
                wireserver_deny_rules.clone(),
            ) == AuthorizeResult::Forbidden,
            "Non skip-sig request must follow access control rules (Forbidden under enforce-deny)"
        );

        // 5. Skip-sig URI + elevated claims must also short-circuit for endpoints whose
        //    authorizer would otherwise reject everything (e.g. the ProxyAgent listener).
        assert!(
            super::authorize(
                crate::common::constants::PROXY_AGENT_IP.to_string(),
                crate::common::constants::PROXY_AGENT_PORT,
                &mut test_logger,
                telemetry_uri.clone(),
                hyper::Method::POST,
                elevated_claims.clone(),
                None,
            ) == AuthorizeResult::Ok,
            "Skip-sig + elevated claims must short-circuit even on the ProxyAgent listener"
        );
    }
}
