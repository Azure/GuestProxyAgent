// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

//! This module contains the KeyStatus and Key structs and the logic to latch the key from the wire server.
//! The KeyStatus struct contains the status of the key and the access control rule details from the wire server.
//! The Key struct contains the key details that are latched from the wire server.
//!
//! Example
//! ```rust
//! use proxy_agent::common::constants;
//! use proxy_agent::key_keeper::key::{Key, KeyStatus};
//! use hyper::Uri;
//!
//! let base_url: Uri = format!("http://{}:{}", constants::WIRE_SERVER_IP, constants::WIRE_SERVER_PORT).parse().unwrap();
//! let status = KeyStatus::get_status(base_url.clone()).await.unwrap();
//!
//! // acquire the key if the has not attest yet
//! let key = Key::acquire_key(base_url.clone()).await.unwrap();
//!
//! // attest the key
//! Key::attest_key(base_url.clone(), &key).await.unwrap();
//!
//! ```
use crate::proxy::{proxy_connection::ConnectionLogger, Claims};
use http::{Method, StatusCode};
use hyper::Uri;
use proxy_agent_shared::common::{
    constants,
    error::{Error, KeyErrorType},
    hyper_client, logger,
    result::Result,
};
use proxy_agent_shared::logger::LoggerLevel;
use serde_derive::{Deserialize, Serialize};
use std::ffi::OsString;
use std::fmt::{Display, Formatter};
use std::{collections::HashMap, path::PathBuf};

const AUDIT_MODE: &str = "audit";
const ENFORCE_MODE: &str = "enforce";
//const ALLOW_DEFAULT_ACCESS: &str = "allow";
//const DENY_DEFAULT_ACCESS: &str = "deny";

#[derive(Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct KeyStatus {
    // The authorization scheme;
    // defines what the scheme is along with what algorithms will be used.
    // Only Azure-HMAC-SHA256 exists in V1.
    authorizationScheme: String,
    // How the guest fetches the key. Either http or vtpm.
    keyDeliveryMethod: String,
    // An integer representing the incarnation of the key.
    #[serde(skip_serializing_if = "Option::is_none")]
    keyIncarnationId: Option<u32>,
    // Unique ID of the key
    pub keyGuid: Option<String>,
    // In AuthZ paradigms, specifies what keys are expected for validation. In AuthN paradigms,
    // specifies what keys are expected for telemetry purposes.
    // Exact values are TBD, but could include things like user id.
    requiredClaimsHeaderPairs: Option<Vec<String>>,
    // One of Disabled, Wireserver, WireserverAndImds. valid at version 1.0
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secureChannelState: Option<String>,
    // Indicates if the secure channel is enabled. valid at version 2.0
    pub secureChannelEnabled: Option<bool>,
    pub version: String,
    // Authorization rules for guest to evaluate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorizationRules: Option<AuthorizationRules>,
}

#[derive(Serialize, Deserialize, Clone)]
#[allow(non_snake_case)]
pub struct AuthorizationRules {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub imds: Option<AuthorizationItem>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wireserver: Option<AuthorizationItem>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostga: Option<AuthorizationItem>,
}

#[derive(Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct AuthorizationItem {
    // The default access: allow, deny
    pub defaultAccess: String,
    // disabled, audit, enforce
    pub mode: String,
    // reference: SIG artifact resource id / inline: hashOfRules
    pub id: String,
    // This is the RBAC settings of how user can specify which process/user can access to which privilege
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rules: Option<AccessControlRules>,
}

#[derive(Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct AccessControlRules {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub privileges: Option<Vec<Privilege>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub roles: Option<Vec<Role>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identities: Option<Vec<Identity>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub roleAssignments: Option<Vec<RoleAssignment>>,
}

impl Clone for AuthorizationItem {
    fn clone(&self) -> Self {
        let rules = self.rules.as_ref().map(|r| AccessControlRules {
            privileges: match r.privileges {
                Some(ref p) => {
                    let mut privileges: Vec<Privilege> = Vec::new();
                    for privilege in p {
                        privileges.push(privilege.clone());
                    }
                    Some(privileges)
                }
                None => None,
            },
            roles: match r.roles {
                Some(ref r) => {
                    let mut roles: Vec<Role> = Vec::new();
                    for role in r {
                        roles.push(role.clone());
                    }
                    Some(roles)
                }
                None => None,
            },
            identities: match r.identities {
                Some(ref i) => {
                    let mut identities: Vec<Identity> = Vec::new();
                    for identity in i {
                        identities.push(identity.clone());
                    }
                    Some(identities)
                }
                None => None,
            },
            roleAssignments: match r.roleAssignments {
                Some(ref r) => {
                    let mut role_assignments: Vec<RoleAssignment> = Vec::new();
                    for role_assignment in r {
                        role_assignments.push(role_assignment.clone());
                    }
                    Some(role_assignments)
                }
                None => None,
            },
        });
        AuthorizationItem {
            defaultAccess: self.defaultAccess.to_string(),
            mode: self.mode.to_string(),
            rules,
            id: self.id.to_string(),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct Privilege {
    pub name: String,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub queryParameters: Option<HashMap<String, String>>,
}

#[derive(Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct Role {
    pub name: String,
    pub privileges: Vec<String>,
}

#[derive(Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct Identity {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userName: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub groupName: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exePath: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub processName: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct RoleAssignment {
    pub role: String,
    pub identities: Vec<String>,
}

impl Clone for Privilege {
    fn clone(&self) -> Self {
        Privilege {
            name: self.name.to_string(),
            path: self.path.to_string(),
            queryParameters: self.queryParameters.clone(),
        }
    }
}

impl Privilege {
    pub fn is_match(&self, logger: &mut ConnectionLogger, request_url: &Uri) -> bool {
        logger.write(
            LoggerLevel::Trace,
            format!("Start to match privilege '{}'", self.name),
        );
        if request_url.path().to_lowercase().starts_with(&self.path) {
            logger.write(
                LoggerLevel::Trace,
                format!("Matched privilege path '{}'", self.path),
            );

            if let Some(query_parameters) = &self.queryParameters {
                logger.write(
                    LoggerLevel::Trace,
                    format!(
                        "Start to match query_parameters from privilege '{}'",
                        self.name
                    ),
                );

                for (key, value) in query_parameters {
                    match hyper_client::query_pairs(request_url)
                        .into_iter()
                        .find(|(k, _)| k.to_lowercase() == key.to_lowercase())
                    {
                        Some((_, v)) => {
                            if v.to_lowercase() == value.to_lowercase() {
                                logger.write(
                                    LoggerLevel::Trace,
                                    format!(
                                        "Matched query_parameters '{}:{}' from privilege '{}'",
                                        key, v, self.name
                                    ),
                                );
                            } else {
                                logger.write(
                                    LoggerLevel::Trace,
                                        format!("Not matched query_parameters value '{}' from privilege '{}'", key, self.name),
                                    );
                                return false;
                            }
                        }
                        None => {
                            logger.write(
                                LoggerLevel::Trace,
                                format!(
                                    "Not matched query_parameters key '{}' from privilege '{}'",
                                    key, self.name
                                ),
                            );
                            return false;
                        }
                    }
                }
            }
            return true;
        }
        false
    }
}

impl Clone for Role {
    fn clone(&self) -> Self {
        Role {
            name: self.name.to_string(),
            privileges: self.privileges.clone(),
        }
    }
}

impl Clone for Identity {
    fn clone(&self) -> Self {
        Identity {
            name: self.name.to_string(),
            userName: self.userName.clone(),
            groupName: self.groupName.clone(),
            exePath: self.exePath.clone(),
            processName: self.processName.clone(),
        }
    }
}

impl Identity {
    pub fn is_match(&self, logger: &mut ConnectionLogger, claims: &Claims) -> bool {
        logger.write(
            LoggerLevel::Trace,
            format!("Start to match identity '{}'", self.name),
        );
        if let Some(ref user_name) = self.userName {
            if *user_name == claims.userName {
                logger.write(
                    LoggerLevel::Trace,
                    format!(
                        "Matched user name '{}' from identity '{}'",
                        user_name, self.name
                    ),
                );
            } else {
                logger.write(
                    LoggerLevel::Trace,
                    format!(
                        "Not matched user name '{}' from identity '{}'",
                        user_name, self.name
                    ),
                );
                return false;
            }
        }
        if let Some(ref process_name) = self.processName {
            let process_name_os: OsString = process_name.into();
            if process_name_os == claims.processName {
                logger.write(
                    LoggerLevel::Trace,
                    format!(
                        "Matched process name '{}' from identity '{}'",
                        process_name, self.name
                    ),
                );
            } else {
                logger.write(
                    LoggerLevel::Trace,
                    format!(
                        "Not matched process name '{}' from identity '{}'",
                        process_name, self.name
                    ),
                );
                return false;
            }
        }
        if let Some(ref exe_path) = self.exePath {
            let process_path_buf: PathBuf = exe_path.into();
            if process_path_buf == claims.processFullPath {
                logger.write(
                    LoggerLevel::Trace,
                    format!(
                        "Matched process full path '{}' from identity '{}'",
                        exe_path, self.name
                    ),
                );
            } else {
                logger.write(
                    LoggerLevel::Trace,
                    format!(
                        "Not matched process full path '{}' from identity '{}'",
                        exe_path, self.name
                    ),
                );
                return false;
            }
        }
        if let Some(ref group_name) = self.groupName {
            let mut matched = false;
            for claims_user_group_name in &claims.userGroups {
                if claims_user_group_name == group_name {
                    logger.write(
                        LoggerLevel::Trace,
                        format!(
                            "Matched user group name '{}' from identity '{}'",
                            group_name, self.name
                        ),
                    );
                    matched = true;
                    break;
                }
            }
            if !matched {
                logger.write(
                    LoggerLevel::Trace,
                    format!(
                        "Not matched user group name '{}' from identity '{}'",
                        group_name, self.name
                    ),
                );
                return false;
            }
        }

        true
    }
}

impl Clone for RoleAssignment {
    fn clone(&self) -> Self {
        RoleAssignment {
            role: self.role.to_string(),
            identities: self.identities.clone(),
        }
    }
}

impl KeyStatus {
    fn validate(&self) -> Result<bool> {
        let mut validate_message = String::new();
        let mut validate_result = true;

        // validate authorizationScheme
        let authorization_scheme = self.authorizationScheme.to_string();
        if authorization_scheme != constants::AUTHORIZATION_SCHEME {
            validate_message.push_str("authorizationScheme must be 'Azure-HMAC-SHA256'; ");
        }

        // validate
        let key_delivery_method = self.keyDeliveryMethod.to_string();
        if key_delivery_method != constants::KEY_DELIVERY_METHOD_HTTP
            && key_delivery_method != constants::KEY_DELIVERY_METHOD_VTPM
        {
            validate_message.push_str(&format!(
                "keyDeliveryMethod '{key_delivery_method}' is invalid; "
            ));
        }

        if self.secureChannelEnabled.is_none() && self.secureChannelState.is_none() {
            validate_message.push_str(
                format!(
                    "Both secureChannelEnabled and secureChannelState are missing in version: {}",
                    self.version.as_str()
                )
                .as_str(),
            );
            validate_result = false;
        }

        // validate secureChannelState, it has to be Disabled, Wireserver or wireserverandImds
        match &self.secureChannelState {
            Some(s) => {
                let state = s.to_lowercase();
                if state != super::DISABLE_STATE
                    && state != super::MUST_SIG_WIRESERVER
                    && state != super::MUST_SIG_WIRESERVER_IMDS
                {
                    validate_message
                        .push_str(&format!("secureChannelState '{state}' is invalid; "));
                    validate_result = false;
                }
            }
            None => {
                if self.version == "1.0" {
                    validate_message.push_str("secureChannelState is missing in version: 1.0");
                    validate_result = false;
                }
            }
        }

        if self.secureChannelEnabled.is_none() && self.version == "2.0" {
            validate_message.push_str("secureChannelEnabled is missing in version: 2.0");
            validate_result = false;
        }

        if !validate_result {
            return Err(Error::Key(KeyErrorType::KeyStatusValidation(
                validate_message,
            )));
        }

        Ok(validate_result)
    }

    pub fn get_secure_channel_state(&self) -> String {
        if self.version == "2.0" {
            match &self.secureChannelEnabled {
                Some(s) => {
                    if *s {
                        // need read details from authorizationRules
                        let wireserver;
                        let imds;
                        let hostga;
                        match &self.authorizationRules {
                            Some(rules) => {
                                match &rules.wireserver {
                                    Some(item) => {
                                        let mode = item.mode.to_lowercase();
                                        if mode == ENFORCE_MODE {
                                            wireserver = "WireServer Enforce";
                                        } else if mode == AUDIT_MODE {
                                            wireserver = "WireServer Audit";
                                        } else {
                                            wireserver = "WireServer Disabled";
                                        }
                                    }
                                    None => wireserver = "WireServer Disabled",
                                };

                                match &rules.imds {
                                    Some(item) => {
                                        let mode = item.mode.to_lowercase();
                                        if mode == ENFORCE_MODE {
                                            imds = " IMDS Enforce";
                                        } else if mode == AUDIT_MODE {
                                            imds = " IMDS Audit";
                                        } else {
                                            imds = " IMDS Disabled";
                                        }
                                    }
                                    None => imds = " IMDS Disabled",
                                };

                                // short-term: HostGA uses wireserver mode
                                // long-term: TBD
                                match &rules.wireserver {
                                    Some(item) => {
                                        let mode = item.mode.to_lowercase();
                                        if mode == ENFORCE_MODE {
                                            hostga = "HostGA Enforce";
                                        } else if mode == AUDIT_MODE {
                                            hostga = "HostGA Audit";
                                        } else {
                                            hostga = "HostGA Disabled";
                                        }
                                    }
                                    None => hostga = "HostGA Disabled",
                                };
                            }
                            None => return super::DISABLE_STATE.to_string(),
                        }

                        format!("{wireserver} - {imds} - {hostga}")
                    } else {
                        super::DISABLE_STATE.to_string()
                    }
                }
                None => super::DISABLE_STATE.to_string(),
            }
        } else {
            // version 1.0
            match &self.secureChannelState {
                Some(s) => s.to_lowercase(),
                None => super::DISABLE_STATE.to_string(),
            }
        }
    }

    pub fn get_wireserver_rule_id(&self) -> String {
        match self.get_wireserver_rules() {
            Some(item) => item.id.to_string(),
            None => String::new(),
        }
    }

    pub fn get_imds_rule_id(&self) -> String {
        match self.get_imds_rules() {
            Some(item) => item.id.to_string(),
            None => String::new(),
        }
    }

    pub fn get_hostga_rule_id(&self) -> String {
        match self.get_hostga_rules() {
            Some(item) => item.id.to_string(),
            None => String::new(),
        }
    }

    pub fn get_wireserver_rules(&self) -> Option<AuthorizationItem> {
        match &self.authorizationRules {
            Some(rules) => rules.wireserver.clone(),
            None => None,
        }
    }

    pub fn get_imds_rules(&self) -> Option<AuthorizationItem> {
        match &self.authorizationRules {
            Some(rules) => rules.imds.clone(),
            None => None,
        }
    }

    pub fn get_hostga_rules(&self) -> Option<AuthorizationItem> {
        // short-term: HostGA has no rules
        // long-term: TBD
        match &self.authorizationRules {
            Some(rules) => rules.hostga.clone(),
            None => None,
        }
    }

    pub fn get_wire_server_mode(&self) -> String {
        if self.version == "2.0" {
            match &self.authorizationRules {
                Some(rules) => match &rules.wireserver {
                    Some(item) => item.mode.to_lowercase(),
                    None => "disabled".to_string(),
                },
                None => "disabled".to_string(),
            }
        } else {
            let state = match &self.secureChannelState {
                Some(s) => s.to_lowercase(),
                None => "disabled".to_string(),
            };
            if state == "wireserver" || state == "wireserverandimds" {
                ENFORCE_MODE.to_string()
            } else {
                AUDIT_MODE.to_string()
            }
        }
    }

    pub fn get_imds_mode(&self) -> String {
        if self.version == "2.0" {
            match &self.authorizationRules {
                Some(rules) => match &rules.imds {
                    Some(item) => item.mode.to_lowercase(),
                    None => "disabled".to_string(),
                },
                None => "disabled".to_string(),
            }
        } else {
            let state = match &self.secureChannelState {
                Some(s) => s.to_lowercase(),
                None => "disabled".to_string(),
            };
            if state == "wireserverandimds" {
                ENFORCE_MODE.to_string()
            } else {
                AUDIT_MODE.to_string()
            }
        }
    }

    pub fn get_hostga_mode(&self) -> String {
        // match self.get_hostga_rules() {
        //     Some(item) => item.mode.to_lowercase(),
        //     None => "disabled".to_string(),
        // }

        // short-term: HostGA uses wireserver mode
        self.get_wire_server_mode()
    }
}

impl Display for KeyStatus {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f,
            "authorizationScheme: {}, keyDeliveryMethod: {}, keyGuid: {}, secureChannelState: {}, version: {}",
            self.authorizationScheme,
            self.keyDeliveryMethod,
            match &self.keyGuid {
                Some(s) => s.to_string(),
                None => "None".to_string(),
            },
            self.get_secure_channel_state(),
            self.version)
    }
}

#[derive(Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct Key {
    // The authorization scheme;
    // defines what the scheme is along with what algorithms will be used.
    // Only Azure-HMAC-SHA256 exists in V1.
    authorizationScheme: String,
    // An integer representing the incarnation of the key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub incarnationId: Option<u32>,
    // Unique ID of the key
    pub guid: String,
    // An ISO 8601 UTC timestamp of when the key was provisioned by wire server
    issued: String,
    // Hex encoded 256-bit key. This key is used for generating HMAC signatures.
    pub key: String,
}

impl Key {
    // create a default empty Key
    pub fn empty() -> Self {
        Key {
            authorizationScheme: constants::AUTHORIZATION_SCHEME.to_string(),
            incarnationId: None,
            guid: "00000000-0000-0000-0000-000000000000".to_string(),
            issued: String::new(),
            key: String::new(),
        }
    }
}

impl Clone for Key {
    fn clone(&self) -> Self {
        Key {
            authorizationScheme: self.authorizationScheme.to_string(),
            guid: self.guid.to_string(),
            incarnationId: self.incarnationId,
            issued: self.issued.to_string(),
            key: self.key.to_string(),
        }
    }
}

enum KeyAction {
    Acquire,
    Attest,
}

impl Display for KeyAction {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match *self {
            KeyAction::Acquire => write!(f, "acquire"),
            KeyAction::Attest => write!(f, "attest"),
        }
    }
}

const STATUS_URL: &str = "/secure-channel/status";
const KEY_URL: &str = "/secure-channel/key";

pub async fn get_status(base_url: &Uri) -> Result<KeyStatus> {
    let (host, port) = hyper_client::host_port_from_uri(base_url)?;
    let url = format!("http://{host}:{port}{STATUS_URL}");
    let url: Uri = url.parse().map_err(|e| {
        Error::Key(KeyErrorType::ParseKeyUrl(
            base_url.to_string(),
            STATUS_URL.to_string(),
            e,
        ))
    })?;
    let mut headers = HashMap::new();
    headers.insert(constants::METADATA_HEADER.to_string(), "True ".to_string());
    let status: KeyStatus =
        hyper_client::get(&url, &headers, None, None, logger::write_warning).await?;
    status.validate()?;

    Ok(status)
}

pub async fn acquire_key(base_url: &Uri) -> Result<Key> {
    let (host, port) = hyper_client::host_port_from_uri(base_url)?;
    let url = format!("http://{host}:{port}{KEY_URL}");
    let url: Uri = url.parse().map_err(|e| {
        Error::Key(KeyErrorType::ParseKeyUrl(
            base_url.to_string(),
            KEY_URL.to_string(),
            e,
        ))
    })?;

    let (host, port) = hyper_client::host_port_from_uri(&url)?;
    let mut headers = HashMap::new();
    headers.insert(constants::METADATA_HEADER.to_string(), "True ".to_string());
    headers.insert("Content-Type".to_string(), "application/json".to_string());
    let body = r#"{"authorizationScheme": "Azure-HMAC-SHA256"}"#.to_string();
    let request = hyper_client::build_request(
        hyper::Method::POST,
        &url,
        &headers,
        Some(body.as_bytes()),
        None,
        None,
    )?;

    let response = hyper_client::send_request(&host, port, request, logger::write_warning)
        .await
        .map_err(|e| {
            Error::Key(KeyErrorType::SendKeyRequest(
                format!("{}", KeyAction::Acquire),
                e.to_string(),
            ))
        })?;

    if response.status() != StatusCode::OK {
        return Err(Error::Key(KeyErrorType::KeyResponse(
            format!("{}", KeyAction::Acquire),
            response.status(),
        )));
    }
    hyper_client::read_response_body(response).await
}

pub async fn attest_key(base_url: &Uri, key: &Key) -> Result<()> {
    // secure-channel/key/{key_guid}/key-attestation
    let (host, port) = hyper_client::host_port_from_uri(base_url)?;
    let url = format!(
        "http://{}:{}{}/{}/key-attestation",
        host, port, KEY_URL, key.guid
    );
    let url: Uri = url
        .parse()
        .map_err(|e| Error::Key(KeyErrorType::ParseKeyUrl(base_url.to_string(), url, e)))?;

    let mut headers = HashMap::new();
    headers.insert(constants::METADATA_HEADER.to_string(), "True ".to_string());
    let request = hyper_client::build_request(
        Method::POST,
        &url,
        &headers,
        None,
        Some(key.guid.to_string()),
        Some(key.key.to_string()),
    )?;

    let response = hyper_client::send_request(&host, port, request, logger::write_warning)
        .await
        .map_err(|e| {
            Error::Key(KeyErrorType::SendKeyRequest(
                format!("{}", KeyAction::Attest),
                e.to_string(),
            ))
        })?;

    if response.status() != StatusCode::OK {
        return Err(Error::Key(KeyErrorType::KeyResponse(
            format!("{}", KeyAction::Attest),
            response.status(),
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    #[cfg(not(windows))]
    use std::os::unix::ffi::OsStringExt;
    #[cfg(windows)]
    use std::os::windows::ffi::OsStringExt;
    use std::path::PathBuf;

    use super::Key;
    use super::KeyStatus;
    use crate::key_keeper::key::Identity;
    use crate::key_keeper::key::Privilege;
    use crate::proxy::proxy_connection::ConnectionLogger;
    use hyper::Uri;
    use proxy_agent_shared::common::constants;
    use serde_json::json;

    #[test]
    fn key_status_v1_test() {
        let status_response_v1 = r#"{
            "authorizationScheme": "Azure-HMAC-SHA256",
            "keyDeliveryMethod": "http",
            "keyGuid": null,
            "requiredClaimsHeaderPairs": null,
            "secureChannelState": "Wireserver",
            "version": "1.0"
        }"#;

        let status_v1: KeyStatus = serde_json::from_str(status_response_v1).unwrap();
        assert_eq!(
            constants::AUTHORIZATION_SCHEME,
            status_v1.authorizationScheme,
            "authorizationScheme mismatch"
        );
        assert_eq!(
            "http", status_v1.keyDeliveryMethod,
            "keyDeliveryMethod mismatch"
        );
        assert_eq!(None, status_v1.keyGuid, "keyGuid must be None");
        assert_eq!(
            None, status_v1.requiredClaimsHeaderPairs,
            "requiredClaimsHeaderPairs must be None"
        );
        assert_eq!(
            Some("Wireserver".to_string()),
            status_v1.secureChannelState,
            "secureChannelState mismatch"
        );
        assert!(
            status_v1.keyIncarnationId.is_none(),
            "keyIncarnationId must be None"
        );
        assert_eq!("1.0".to_string(), status_v1.version, "version 1.0 mismatch");
        assert!(
            status_v1.validate().unwrap(),
            "Key status validation must be true"
        );
        assert!(
            status_v1.secureChannelEnabled.is_none(),
            "secureChannelEnabled must be None in version 1.0"
        );
        assert_eq!(
            "",
            status_v1.get_imds_rule_id(),
            "IMDS rule id must be empty"
        );
        assert_eq!(
            "",
            status_v1.get_wireserver_rule_id(),
            "WireServer rule id must be empty"
        );
        assert_eq!(
            status_v1.get_wire_server_mode(),
            "enforce",
            "WireServer mode mismatch"
        );
        assert_eq!(status_v1.get_imds_mode(), "audit", "IMDS mode mismatch");
    }

    #[test]
    fn key_status_v2_test() {
        let status_response = r#"{
            "authorizationScheme": "Azure-HMAC-SHA256",
            "keyDeliveryMethod": "http",
            "keyGuid": null,
            "requiredClaimsHeaderPairs": null,
            "secureChannelEnabled": true,
            "version": "2.0",
            "authorizationRules": {
                "imds": {
                    "defaultAccess": "allow",
                    "mode": "enforce",
                    "id": "sigid",
                    "rules": {
                        "privileges": [
                            {
                                "name": "test",
                                "path": "/test"
                            },
                            {
                                "name": "test1",
                                "path": "/test1"
                            }
                        ],
                        "roles": [
                            {
                                "name": "test",
                                "privileges": [
                                    "test",
                                    "test1"
                                ]
                            }
                        ],
                        "identities": [
                            {
                                "name": "test",
                                "userName": "test",
                                "groupName": "test",
                                "exePath": "test",
                                "processName": "test"
                            }
                        ],
                        "roleAssignments": [
                            {
                                "role": "test",
                                "identities": [
                                    "test",
                                    "test1"
                                ]
                            }
                        ]
                    }
                },
                "wireserver": {
                    "defaultAccess": "deny",
                    "mode": "enforce",
                    "id": "sigid",
                    "rules": {
                        "privileges": [
                            {
                                "name": "test",
                                "path": "/test",
                                "queryParameters": {
                                    "key1": "value1",
                                    "key2": "value2"
                                }
                            },
                            {
                                "name": "test1",
                                "path": "/test1",
                                "queryParameters": {
                                    "key1": "value1",
                                    "key2": "value2"
                                }
                            }
                        ],
                        "roles": [
                            {
                                "name": "test",
                                "privileges": [
                                    "test",
                                    "test1"
                                ]
                            },
                            {
                                "name": "test1",
                                "privileges": [
                                    "test",
                                    "test1"
                                ]
                            }
                        ],
                        "identities": [
                            {
                                "name": "test",
                                "userName": "test",
                                "groupName": "test",
                                "exePath": "test",
                                "processName": "test"
                            },
                            {
                                "name": "test1",
                                "userName": "test1",
                                "groupName": "test1",
                                "exePath": "test1",
                                "processName": "test1"
                            }
                        ],
                        "roleAssignments": [
                            {
                                "role": "test",
                                "identities": [
                                    "test",
                                    "test1"
                                ]
                            },
                            {
                                "role": "test1",
                                "identities": [
                                    "test",
                                    "test1"
                                ]
                            }
                        ]
                    }
                },
                "hostga": {
                    "defaultAccess": "allow",
                    "mode": "enforce",
                    "id": "sigid",
                    "rules": {
                        "privileges": [
                            {
                                "name": "test",
                                "path": "/test",
                                "queryParameters": {
                                    "key1": "value1",
                                    "key2": "value2"
                                }
                            },
                            {
                                "name": "test2",
                                "path": "/test2",
                                "queryParameters": {
                                    "key1": "value3",
                                    "key2": "value4"
                                }
                            }
                        ],
                        "roles": [
                            {
                                "name": "test3",
                                "privileges": [
                                    "test1",
                                    "test2"
                                ]
                            },
                            {
                                "name": "test6",
                                "privileges": [
                                    "test4",
                                    "test5"
                                ]
                            }
                        ],
                        "identities": [
                            {
                                "name": "test",
                                "userName": "test",
                                "groupName": "test",
                                "exePath": "test",
                                "processName": "test"
                            },
                            {
                                "name": "test1",
                                "userName": "test1",
                                "groupName": "test1",
                                "exePath": "test1",
                                "processName": "test1"
                            }
                        ],
                        "roleAssignments": [
                            {
                                "role": "test4",
                                "identities": [
                                    "test",
                                    "test1"
                                ]
                            },
                            {
                                "role": "test5",
                                "identities": [
                                    "test",
                                    "test1"
                                ]
                            }
                        ]
                    }
                }
            }
        }"#;

        let status: KeyStatus = serde_json::from_str(status_response).unwrap();
        assert_eq!(
            constants::AUTHORIZATION_SCHEME,
            status.authorizationScheme,
            "authorizationScheme mismatch"
        );
        assert_eq!(
            "http", status.keyDeliveryMethod,
            "keyDeliveryMethod mismatch"
        );
        assert_eq!("2.0".to_string(), status.version, "version 2.0 mismatch");
        assert!(
            status.validate().unwrap(),
            "Key status validation must be true"
        );
        assert!(
            status.secureChannelEnabled.is_some(),
            "secureChannelEnabled must have value in version 2.0"
        );
        assert!(
            status.secureChannelState.is_none(),
            "secureChannelState must be None in version 2.0"
        );

        // validate IMDS rules
        let imds_rules = status.get_imds_rules().unwrap();
        assert_eq!("allow", imds_rules.defaultAccess, "defaultAccess mismatch");
        assert_eq!("sigid", status.get_imds_rule_id(), "IMDS rule id mismatch");
        assert_eq!("enforce", status.get_imds_mode(), "IMDS mode mismatch");

        // validate WireServer rules
        let wireserver_rules = status.get_wireserver_rules().unwrap();
        assert_eq!(
            "deny", wireserver_rules.defaultAccess,
            "defaultAccess mismatch"
        );
        assert_eq!(
            "sigid",
            status.get_wireserver_rule_id(),
            "WireServer rule id mismatch"
        );
        assert_eq!(
            "enforce",
            status.get_wire_server_mode(),
            "WireServer mode mismatch"
        );

        // validate WireServer rule details
        let first_privilege = &wireserver_rules
            .rules
            .as_ref()
            .unwrap()
            .privileges
            .as_ref()
            .unwrap()[0];
        assert_eq!("test", first_privilege.name, "privilege name mismatch");
        assert_eq!("/test", first_privilege.path, "privilege path mismatch");
        assert_eq!(
            "value1",
            first_privilege.queryParameters.as_ref().unwrap()["key1"],
            "privilege queryParameters mismatch"
        );
        assert_eq!(
            "value2",
            first_privilege.queryParameters.as_ref().unwrap()["key2"],
            "privilege queryParameters mismatch"
        );
        let second_privilege = &wireserver_rules
            .rules
            .as_ref()
            .unwrap()
            .privileges
            .as_ref()
            .unwrap()[1];
        assert_eq!(
            "test1", second_privilege.name,
            "second privilege name mismatch"
        );
        assert_eq!(
            "/test1", second_privilege.path,
            "second privilege path mismatch"
        );
        assert_eq!(
            "value1",
            second_privilege.queryParameters.as_ref().unwrap()["key1"],
            "second privilege queryParameters mismatch"
        );
        assert_eq!(
            "value2",
            second_privilege.queryParameters.as_ref().unwrap()["key2"],
            "second privilege queryParameters mismatch"
        );
        let first_role = &wireserver_rules
            .rules
            .as_ref()
            .unwrap()
            .roles
            .as_ref()
            .unwrap()[0];
        assert_eq!("test", first_role.name, "role name mismatch");
        assert_eq!("test", first_role.privileges[0], "role privilege mismatch");
        assert_eq!("test1", first_role.privileges[1], "role privilege mismatch");
        let first_identity = &wireserver_rules
            .rules
            .as_ref()
            .unwrap()
            .identities
            .as_ref()
            .unwrap()[0];
        assert_eq!("test", first_identity.name, "identity name mismatch");
        assert_eq!(
            "test",
            first_identity.userName.as_ref().unwrap(),
            "identity userName mismatch"
        );
        assert_eq!(
            "test",
            first_identity.groupName.as_ref().unwrap(),
            "identity groupName mismatch"
        );
        assert_eq!(
            "test",
            first_identity.exePath.as_ref().unwrap(),
            "identity exePath mismatch"
        );
        assert_eq!(
            "test",
            first_identity.processName.as_ref().unwrap(),
            "identity processName mismatch"
        );
        let first_role_assignment = &wireserver_rules
            .rules
            .as_ref()
            .unwrap()
            .roleAssignments
            .as_ref()
            .unwrap()[0];
        assert_eq!(
            "test", first_role_assignment.role,
            "roleAssignment role mismatch"
        );
        assert_eq!(
            "test", first_role_assignment.identities[0],
            "roleAssignment identities mismatch"
        );

        // Validate HostGA rules
        let hostga_rules = status.get_hostga_rules().unwrap();
        assert_eq!(
            "allow", hostga_rules.defaultAccess,
            "defaultAccess mismatch"
        );
        assert_eq!(
            "sigid",
            status.get_hostga_rule_id(),
            "HostGA rule id mismatch"
        );
        assert_eq!("enforce", status.get_hostga_mode(), "HostGA mode mismatch");

        // Validate HostGA rule details
        // Retrieve and validate second privilege for HostGA
        let privilege = &hostga_rules
            .rules
            .as_ref()
            .unwrap()
            .privileges
            .as_ref()
            .unwrap()[1];

        assert_eq!("test2", privilege.name, "privilege name mismatch");
        assert_eq!("/test2", privilege.path, "privilege path mismatch");

        assert_eq!(
            "value3",
            privilege.queryParameters.as_ref().unwrap()["key1"],
            "privilege queryParameters mismatch"
        );
        assert_eq!(
            "value4",
            privilege.queryParameters.as_ref().unwrap()["key2"],
            "privilege queryParameters mismatch"
        );

        // Retrieve and validate second role for HostGA
        let role = &hostga_rules.rules.as_ref().unwrap().roles.as_ref().unwrap()[1];
        assert_eq!("test6", role.name, "role name mismatch");
        assert_eq!("test4", role.privileges[0], "role privilege mismatch");
        assert_eq!("test5", role.privileges[1], "role privilege mismatch");

        // Retrieve and validate first identity for HostGA
        let identity = &hostga_rules
            .rules
            .as_ref()
            .unwrap()
            .identities
            .as_ref()
            .unwrap()[0];
        assert_eq!("test", identity.name, "identity name mismatch");
        assert_eq!(
            "test",
            identity.userName.as_ref().unwrap(),
            "identity userName mismatch"
        );
        assert_eq!(
            "test",
            identity.groupName.as_ref().unwrap(),
            "identity groupName mismatch"
        );
        assert_eq!(
            "test",
            identity.exePath.as_ref().unwrap(),
            "identity exePath mismatch"
        );
        assert_eq!(
            "test",
            identity.processName.as_ref().unwrap(),
            "identity processName mismatch"
        );

        // Retrieve and validate first role assignment for HostGA
        let role_assignment = &hostga_rules
            .rules
            .as_ref()
            .unwrap()
            .roleAssignments
            .as_ref()
            .unwrap()[0];
        assert_eq!(
            "test4", role_assignment.role,
            "roleAssignment role mismatch"
        );
        assert_eq!(
            "test", role_assignment.identities[0],
            "roleAssignment identities mismatch"
        );
    }

    #[test]
    fn key_test() {
        let key_response = r#"{
            "authorizationScheme": "Azure-HMAC-SHA256",        
            "guid": "9cf81e97-0316-4ad3-94a7-8ccbdee8ccbf",   
            "incarnationId": 1,     
            "issued": "2021-05-05T 12:00:00Z",        
            "key": "4A404E635266556A586E3272357538782F413F4428472B4B6250645367566B59"        
        }"#;

        let key: Key = serde_json::from_str(key_response).unwrap();
        assert_eq!(
            constants::AUTHORIZATION_SCHEME.to_string(),
            key.authorizationScheme,
            "authorizationScheme mismatch"
        );
        assert_eq!(
            "9cf81e97-0316-4ad3-94a7-8ccbdee8ccbf".to_string(),
            key.guid,
            "guid mismatch"
        );
        assert_eq!(Some(1), key.incarnationId, "incarnationId mismatch");
        assert_eq!(
            "2021-05-05T 12:00:00Z".to_string(),
            key.issued,
            "issued mismatch"
        );
        assert_eq!(
            "4A404E635266556A586E3272357538782F413F4428472B4B6250645367566B59".to_string(),
            key.key,
            "key mismatch"
        );
    }

    #[tokio::test]
    async fn test_privilege_is_match() {
        let mut logger = ConnectionLogger::new(1, 1);

        let privilege = r#"{
            "name": "test",
            "path": "/test",
            "queryParameters": {
                "key1": "value1",
                "key2": "value2"
            }
        }"#;
        let privilege: Privilege = serde_json::from_str(privilege).unwrap();
        let url: Uri = "http://localhost/test?key1=value1&key2=value2"
            .parse()
            .unwrap();
        assert!(
            privilege.is_match(&mut logger, &url),
            "privilege should be matched"
        );

        let url = "http://localhost/test?key1=value1&key2=value3"
            .parse()
            .unwrap();
        assert!(
            !privilege.is_match(&mut logger, &url),
            "privilege should not be matched"
        );

        let url = "http://localhost/test?key1=value1".parse().unwrap();
        assert!(
            !privilege.is_match(&mut logger, &url),
            "privilege should not be matched"
        );

        let privilege1 = r#"{
            "name": "test",
            "path": "/test"        
        }"#;
        let privilege1: Privilege = serde_json::from_str(privilege1).unwrap();
        let url = "http://localhost/test?key1=value1&key2=value2"
            .parse()
            .unwrap();
        assert!(
            privilege1.is_match(&mut logger, &url),
            "privilege should be matched"
        );

        let privilege2 = r#"{
            "name": "test",
            "path": "/test",
            "queryParameters": {
                "key1": "",
                "key2": ""
            }
        }"#;
        let privilege2: Privilege = serde_json::from_str(privilege2).unwrap();
        let url = "http://localhost/test?key1=value1&key2=value2"
            .parse()
            .unwrap();
        assert!(
            !privilege2.is_match(&mut logger, &url),
            "privilege should not be matched"
        );
    }

    #[tokio::test]
    async fn test_identity_is_match() {
        let mut logger = ConnectionLogger::new(1, 1);

        let mut claims = super::Claims {
            userName: "test".to_string(),
            userGroups: vec!["test".to_string()],
            processName: OsString::from("test"),
            processCmdLine: "test".to_string(),
            userId: 0,
            processId: 0,
            clientIp: "00.000.000".to_string(),
            clientPort: 0, // doesn't matter for this test
            runAsElevated: true,
            processFullPath: PathBuf::from("test"),
        };

        let identity = r#"{
            "name": "test",
            "userName": "test",
            "groupName": "test",
            "exePath": "test",
            "processName": "test"
        }"#;
        let identity: Identity = serde_json::from_str(identity).unwrap();
        assert!(
            identity.is_match(&mut logger, &claims),
            "identity should be matched"
        );

        let identity1 = r#"{
            "name": "test",
            "userName": "test1",
            "groupName": "test",
            "exePath": "test",
            "processName": "test"
        }"#;
        let identity1: Identity = serde_json::from_str(identity1).unwrap();
        assert!(
            !identity1.is_match(&mut logger, &claims),
            "identity should not be matched"
        );

        // test userName
        let identity2 = r#"{
            "name": "test",
            "userName": "test1"
        }"#;
        let identity2: Identity = serde_json::from_str(identity2).unwrap();
        assert!(
            !identity2.is_match(&mut logger, &claims),
            "identity should not be matched"
        );

        let identity2 = r#"{
            "name": "test",
            "userName": "test"
        }"#;
        let identity2: Identity = serde_json::from_str(identity2).unwrap();
        assert!(
            identity2.is_match(&mut logger, &claims),
            "identity should be matched"
        );

        // test processName
        let identity3 = r#"{
            "name": "test",
            "processName": "test1"
        }"#;
        let identity3: Identity = serde_json::from_str(identity3).unwrap();
        assert!(
            !identity3.is_match(&mut logger, &claims),
            "identity should not be matched"
        );
        let identity3 = r#"{
            "name": "test",
            "processName": "Test"
        }"#;
        let identity3: Identity = serde_json::from_str(identity3).unwrap();
        assert!(
            !identity3.is_match(&mut logger, &claims),
            "identity should not be matched"
        );
        let identity3 = r#"{
            "name": "test",
            "processName": "test"
        }"#;
        let identity3: Identity = serde_json::from_str(identity3).unwrap();
        assert!(
            identity3.is_match(&mut logger, &claims),
            "identity should be matched"
        );

        // test exePath
        let identity4 = r#"{
            "name": "test",
            "exePath": "test1"
        }"#;
        let identity4: Identity = serde_json::from_str(identity4).unwrap();
        assert!(
            !identity4.is_match(&mut logger, &claims),
            "identity should not be matched"
        );
        let identity4 = r#"{
            "name": "test",
            "exePath": "TEST"
        }"#;
        let identity4: Identity = serde_json::from_str(identity4).unwrap();
        assert!(
            !identity4.is_match(&mut logger, &claims),
            "identity should not be matched"
        );
        let identity4 = r#"{
            "name": "test",
            "exePath": "test"
        }"#;
        let identity4: Identity = serde_json::from_str(identity4).unwrap();
        assert!(
            identity4.is_match(&mut logger, &claims),
            "identity should be matched"
        );

        // test groupName
        let identity5 = r#"{
            "name": "test",
            "groupName": "test1"
        }"#;
        let identity5: Identity = serde_json::from_str(identity5).unwrap();
        assert!(
            !identity5.is_match(&mut logger, &claims),
            "identity should not be matched"
        );
        let identity5 = r#"{
            "name": "test",
            "groupName": "test"
        }"#;
        let identity5: Identity = serde_json::from_str(identity5).unwrap();
        assert!(
            identity5.is_match(&mut logger, &claims),
            "identity should be matched"
        );

        // Test with non-UTF8 valid process name
        #[cfg(windows)]
        {
            let invalid_utf16_bytes: Vec<u16> = vec![0xD800]; // Lone surrogate (0xD800)
            claims.processName = OsString::from_wide(invalid_utf16_bytes.as_slice());
        }

        #[cfg(not(windows))]
        {
            let invalid_utf8_bytes: Vec<u8> = vec![0x80]; // Invalid UTF-8
            claims.processName = OsString::from_vec(invalid_utf8_bytes);
        }

        let process_name_lossy = claims.processName.to_string_lossy().to_string();
        let replacement_char = "�";

        let identity6 = json!({
            "name": "test",
            "processName": replacement_char
        });
        let identity6: Identity = serde_json::from_value(identity6).unwrap();
        assert!(
            !identity6.is_match(&mut logger, &claims),
            "identity should not be matched"
        );

        assert_eq!(
            replacement_char, process_name_lossy,
            "process name after lossy conversion should be equal to replacement char"
        );
    }
}
