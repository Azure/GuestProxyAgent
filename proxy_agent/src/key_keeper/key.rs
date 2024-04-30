use crate::{
    common::{
        constants,
        http::{self, headers, http_request::HttpRequest, request::Request, response::Response},
    },
    proxy::{proxy_connection::Connection, Claims},
};
use proxy_agent_shared::misc_helpers;
use serde_derive::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    io::{Error, ErrorKind},
};
use url::Url;

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

#[derive(Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct AuthorizationRules {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub imds: Option<AuthorizationItem>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wireserver: Option<AuthorizationItem>,
}

#[derive(Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct AuthorizationItem {
    // The default access: allow, deny
    pub defaultAccess: String,
    // disabled, audit, enforce
    pub mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub privileges: Option<Vec<Privilege>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub roles: Option<Vec<Role>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identities: Option<Vec<Identity>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub roleAssignments: Option<Vec<RoleAssignment>>,
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

impl Privilege {
    pub fn clone(&self) -> Self {
        Privilege {
            name: self.name.to_string(),
            path: self.path.to_string(),
            queryParameters: self.queryParameters.clone(),
        }
    }

    pub fn is_match(&self, connection_id: u128, request_url: url::Url) -> bool {
        Connection::write_information(
            connection_id,
            format!("Start to match privilege '{}'", self.name.to_string()),
        );
        if request_url.path().to_lowercase().starts_with(&self.path) {
            Connection::write_information(
                connection_id,
                format!("Matched privilege path '{}'", self.path.to_string()),
            );

            match &self.queryParameters {
                Some(query_parameters) => {
                    Connection::write_information(
                        connection_id,
                        format!(
                            "Start to match query_parameters from privilege '{}'",
                            self.name.to_string()
                        ),
                    );

                    for (key, value) in query_parameters {
                        match request_url.query_pairs().find(|(k, _)| k == key) {
                            Some((_, v)) => {
                                if v.to_lowercase() == value.to_lowercase() {
                                    Connection::write_information(
                                        connection_id,
                                        format!(
                                            "Matched query_parameters '{}:{}' from privilege '{}'",
                                            key,
                                            v,
                                            self.name.to_string()
                                        ),
                                    );
                                } else {
                                    Connection::write_information(
                                        connection_id,
                                        format!("Not matched query_parameters value '{}' from privilege '{}'", key, self.name.to_string()),
                                    );
                                    return false;
                                }
                            }
                            None => {
                                Connection::write_information(
                                    connection_id,
                                    format!(
                                        "Not matched query_parameters key '{}' from privilege '{}'",
                                        key,
                                        self.name.to_string()
                                    ),
                                );
                                return false;
                            }
                        }
                    }
                }
                None => {}
            }
            return true;
        }
        return false;
    }
}

impl Identity {
    pub fn clone(&self) -> Self {
        Identity {
            name: self.name.to_string(),
            userName: self.userName.clone(),
            groupName: self.groupName.clone(),
            exePath: self.exePath.clone(),
            processName: self.processName.clone(),
        }
    }

    pub fn is_match(&self, connection_id: u128, claims: Claims) -> bool {
        Connection::write_information(
            connection_id,
            format!("Start to match identity '{}'", self.name.to_string()),
        );
        match self.userName {
            Some(ref user_name) => {
                if user_name.to_lowercase() == claims.userName.to_lowercase() {
                    Connection::write_information(
                        connection_id,
                        format!(
                            "Matched user name '{}' from identity '{}'",
                            user_name,
                            self.name.to_string()
                        ),
                    );
                } else {
                    Connection::write_information(
                        connection_id,
                        format!(
                            "Not matched user name '{}' from identity '{}'",
                            user_name,
                            self.name.to_string()
                        ),
                    );
                    return false;
                }
            }
            None => {}
        }
        match self.processName {
            Some(ref process_name) => {
                if process_name.to_lowercase() == claims.processName.to_lowercase() {
                    Connection::write_information(
                        connection_id,
                        format!(
                            "Matched process name '{}' from identity '{}'",
                            process_name,
                            self.name.to_string()
                        ),
                    );
                } else {
                    Connection::write_information(
                        connection_id,
                        format!(
                            "Not matched process name '{}' from identity '{}'",
                            process_name,
                            self.name.to_string()
                        ),
                    );
                    return false;
                }
            }
            None => {}
        }
        //TODO: need add exePath, groupName match

        return true;
    }
}

impl KeyStatus {
    fn validate(&self) -> std::io::Result<bool> {
        let mut validate_message = "key status validate failed: ".to_string();
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
                "keyDeliveryMethod '{}' is invalid; ",
                key_delivery_method
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
                        .push_str(&format!("secureChannelState '{}' is invalid; ", state));
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
            return Err(Error::new(ErrorKind::InvalidData, validate_message));
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
                            }
                            None => return super::DISABLE_STATE.to_string(),
                        }

                        return format!("{} - {}", wireserver, imds);
                    } else {
                        return super::DISABLE_STATE.to_string();
                    }
                }
                None => return super::DISABLE_STATE.to_string(),
            }
        } else {
            // version 1.0
            match &self.secureChannelState {
                Some(s) => return s.to_lowercase(),
                None => return super::DISABLE_STATE.to_string(),
            }
        }
    }

    pub fn to_string(&self) -> String {
        return format!(
            "authorizationScheme: {}, keyDeliveryMethod: {}, keyGuid: {}, secureChannelState: {}, version: {}",
            self.authorizationScheme,
            self.keyDeliveryMethod,
            match &self.keyGuid {
                Some(s) => s.to_string(),
                None => "None".to_string(),
            },
            self.get_secure_channel_state(),
            self.version.to_string());
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

    pub fn clone(&self) -> Self {
        Key {
            authorizationScheme: self.authorizationScheme.to_string(),
            guid: self.guid.to_string(),
            incarnationId: self.incarnationId.clone(),
            issued: self.issued.to_string(),
            key: self.key.to_string(),
        }
    }
}

const STATUS_URL: &str = "/secure-channel/status";
const KEY_URL: &str = "/secure-channel/key";

// base_url must end with '/'
pub fn get_status(base_url: Url) -> std::io::Result<KeyStatus> {
    let url = base_url.join(STATUS_URL).unwrap();
    let mut req = Request::new(STATUS_URL.to_string(), "GET".to_string());
    req.headers
        .add_header(constants::METADATA_HEADER.to_string(), "True ".to_string());
    req.headers.add_header(
        constants::DATE_HEADER.to_string(),
        misc_helpers::get_date_time_rfc1123_string(),
    );
    let mut http_request = HttpRequest::new(url, req);
    http_request
        .request
        .headers
        .add_header("Host".to_string(), http_request.get_host());

    let response = http::get_response_in_string(&mut http_request)?;
    if response.status != Response::OK {
        return Err(Error::new(
            ErrorKind::Other,
            format!("Host response {}", response.status),
        ));
    }

    let status: KeyStatus = serde_json::from_str(&response.get_body_as_string()?)?;
    status.validate()?;

    Ok(status)
}

// base_url must end with '/'
pub fn acquire_key(base_url: Url) -> std::io::Result<Key> {
    let url = base_url.join(KEY_URL).unwrap();
    let mut req = Request::new(KEY_URL.to_string(), "POST".to_string());
    req.headers
        .add_header(constants::METADATA_HEADER.to_string(), "True ".to_string());
    req.headers.add_header(
        constants::DATE_HEADER.to_string(),
        misc_helpers::get_date_time_rfc1123_string(),
    );
    req.headers
        .add_header("Content-Type".to_string(), "application/json".to_string());
    req.set_body_as_string(r#"{"authorizationScheme": "Azure-HMAC-SHA256"}"#.to_string());
    req.headers.add_header(
        headers::CONTENT_LENGTH_HEADER_NAME.to_string(),
        req.get_body_len().to_string(),
    );
    let mut http_request = HttpRequest::new(url, req);
    http_request
        .request
        .headers
        .add_header("Host".to_string(), http_request.get_host());

    let response = http::get_response_in_string(&mut http_request)?;
    if response.status != Response::OK {
        return Err(Error::new(
            ErrorKind::Other,
            format!("{} - {}", response.status, response.get_body_as_string()?),
        ));
    }

    let response_body = response.get_body_as_string()?;
    match serde_json::from_str(&response_body) {
        Ok(key) => Ok(key),
        Err(e) => {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!(
                    "Cannot parse the json response body {} with error {}",
                    response_body, e
                ),
            ));
        }
    }
}

// base_url must end with '/'
pub fn attest_key(base_url: Url, key: &Key) -> std::io::Result<()> {
    // secure-channel/key/{key_guid}/key-attestation
    let url = base_url
        .join(KEY_URL)
        .unwrap()
        .join(&key.guid)
        .unwrap()
        .join("key-attestation")
        .unwrap();
    let mut req = Request::new(
        format!("{}/{}/key-attestation", KEY_URL, key.guid.to_string()),
        "POST".to_string(),
    );
    req.headers.add_header(
        headers::CONTENT_LENGTH_HEADER_NAME.to_string(),
        0.to_string(),
    );
    let mut http_request =
        HttpRequest::new_proxy_agent_request(url, req, key.guid.to_string(), key.key.to_string())?;
    let mut response = http::get_response_in_string(&mut http_request)?;
    if response.status != Response::OK {
        return Err(Error::new(
            ErrorKind::Other,
            format!("{}", response.to_raw_string()),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::Key;
    use super::KeyStatus;
    use crate::common::constants;
    use crate::key_keeper::key::Identity;
    use crate::key_keeper::key::Privilege;
    use crate::proxy::proxy_connection::Connection;

    #[test]
    fn key_status_test() {
        let status_response = r#"{
            "authorizationScheme": "Azure-HMAC-SHA256",
            "keyDeliveryMethod": "http",
            "keyGuid": null,
            "requiredClaimsHeaderPairs": null,
            "secureChannelState": "Wireserver",
            "version": "1.0"
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
        assert_eq!(None, status.keyGuid, "keyGuid must be None");
        assert_eq!(
            None, status.requiredClaimsHeaderPairs,
            "requiredClaimsHeaderPairs must be None"
        );
        assert_eq!(
            Some("Wireserver".to_string()),
            status.secureChannelState,
            "secureChannelState mismatch"
        );
        assert!(
            status.keyIncarnationId.is_none(),
            "keyIncarnationId must be None"
        );
        assert_eq!("1.0".to_string(), status.version, "version 1.0 mismatch");

        assert!(
            status.validate().unwrap(),
            "Key status validation must be true"
        );
        assert!(
            status.secureChannelEnabled.is_none(),
            "secureChannelEnabled must be None in version 1.0"
        );

        let status_response = r#"{
            "authorizationScheme": "Azure-HMAC-SHA256",
            "keyDeliveryMethod": "http",
            "keyGuid": null,
            "requiredClaimsHeaderPairs": null,
            "secureChannelEnabled": true,
            "version": "2.0",
            "authorizationRules": {
                "imds": {
                    "defaultAccess": "deny",
                    "mode": "audit"
                },
                "wireserver": {
                    "defaultAccess": "deny",
                    "mode": "enforce"
                }
            }
        }"#;
        let status: KeyStatus = serde_json::from_str(status_response).unwrap();
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
        assert_eq!(
            "WireServer Enforce -  IMDS Audit",
            status.get_secure_channel_state(),
            "secureChannelState mismatch in version 2.0"
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

    #[test]
    fn test_privelege_is_match() {
        // initialize connection_logger 
        Connection::init_logger(std::path::PathBuf::new());

        let privilege = r#"{
            "name": "test",
            "path": "/test",
            "queryParameters": {
                "key1": "value1",
                "key2": "value2"
            }
        }"#;
        let privilege: Privilege = serde_json::from_str(privilege).unwrap();
        let url = url::Url::parse("http://localhost/test?key1=value1&key2=value2").unwrap();
        assert!(privilege.is_match(1, url.clone()), "privilege should be matched");

        let url = url::Url::parse("http://localhost/test?key1=value1&key2=value3").unwrap();
        assert!(!privilege.is_match(1, url.clone()), "privilege should not be matched");

        let url = url::Url::parse("http://localhost/test?key1=value1").unwrap();
        assert!(!privilege.is_match(1, url.clone()), "privilege should not be matched");
    }

    #[test]
    fn test_identity_is_match() {
        Connection::init_logger(std::path::PathBuf::new());

        let identity = r#"{
            "name": "test",
            "userName": "test",
            "groupName": "test",
            "exePath": "test",
            "processName": "test"
        }"#;
        let identity: Identity = serde_json::from_str(identity).unwrap();
        let claims = super::Claims {
            userName: "test".to_string(),
            processName: "test".to_string(),
            processCmdLine: "test".to_string(),
            userId: 0,
            processId: 0,
            clientIp: "00.000.000".to_string(),
            runAsElevated: true,
            processFullPath: "test".to_string(),
        };
        assert!(identity.is_match(1, claims.clone()), "identity should be matched");

        let identity1 = r#"{
            "name": "test",
            "userName": "test1",
            "groupName": "test",
            "exePath": "test",
            "processName": "test"
        }"#;
        let identity1: Identity = serde_json::from_str(identity1).unwrap();
        assert!(!identity1.is_match(1, claims.clone()), "identity should not be matched");

    }
}
