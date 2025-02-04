// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

//! This module contains the logic to authorize the request based on the authorization rules.
//! The authorization rules is from user inputted access control rules.
//!
//! Example
//! ```rust
//! use proxy_agent::authorization_rules;
//! use proxy_agent::proxy_connection::ConnectionLogger;
//!
//! // convert the authorization item to access control rules
//! let access_control_rules = AccessControlRules::from_authorization_item(authorization_item);
//!
//! // check if the request is allowed based on the access control rules
//! let is_allowed = access_control_rules.is_allowed(connection_id, request_url, claims);
//!
//! ```

use super::{proxy_connection::ConnectionLogger, Claims};
use crate::common::logger;
use crate::key_keeper::key::{AuthorizationItem, AuthorizationRules, Identity, Privilege, Role};
use proxy_agent_shared::logger_manager::LoggerLevel;
use proxy_agent_shared::misc_helpers;
use serde_derive::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::str::FromStr;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum AuthorizationMode {
    Disabled,
    Audit,
    Enforce,
}

impl std::fmt::Display for AuthorizationMode {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            AuthorizationMode::Disabled => write!(f, "disabled"),
            AuthorizationMode::Audit => write!(f, "audit"),
            AuthorizationMode::Enforce => write!(f, "enforce"),
        }
    }
}

impl std::str::FromStr for AuthorizationMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "disabled" => Ok(AuthorizationMode::Disabled),
            "audit" => Ok(AuthorizationMode::Audit),
            "enforce" => Ok(AuthorizationMode::Enforce),
            _ => Err(format!("Invalid AuthorizationMode: {}", s)),
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
#[allow(non_snake_case)]
pub struct ComputedAuthorizationItem {
    pub id: String,
    // The default access: allow -> true, deny-> false
    pub defaultAllowed: bool,
    // disabled, audit, enforce
    pub mode: AuthorizationMode,
    // all the defined unique privileges, distinct by name
    pub privileges: HashMap<String, Privilege>,
    // The identities assigned to this privilege
    // key - privilege name, value - the assigned identity names
    pub privilegeAssignments: HashMap<String, HashSet<String>>,
    // all the defined unique identities, distinct by name
    // key - identity name, value - identity object
    pub identities: HashMap<String, Identity>,
}

#[allow(dead_code)]
impl ComputedAuthorizationItem {
    pub fn from_authorization_item(
        authorization_item: AuthorizationItem,
    ) -> ComputedAuthorizationItem {
        let authorization_mode = match AuthorizationMode::from_str(&authorization_item.mode) {
            Ok(mode) => mode,
            Err(err) => {
                // This should not happen, log the error and set the mode to disabled
                logger::write_error(format!("Failed to parse authorization mode: {}", err));
                AuthorizationMode::Disabled
            }
        };

        // Initialize with empty dictionaries
        let mut privilege_dict: HashMap<String, Privilege> = HashMap::new();
        let mut identity_dict: HashMap<String, Identity> = HashMap::new();
        let mut privilege_assignments: HashMap<String, HashSet<String>> = HashMap::new();

        if let Some(input_rules) = authorization_item.rules {
            if let (Some(privileges), Some(identities), Some(roles), Some(role_assignments)) = (
                input_rules.privileges,
                input_rules.identities,
                input_rules.roles,
                input_rules.roleAssignments,
            ) {
                let role_dict = roles
                    .into_iter()
                    .map(|role| (role.name.clone(), role))
                    .collect::<HashMap<String, Role>>();
                identity_dict = identities
                    .into_iter()
                    .map(|identity| (identity.name.clone(), identity))
                    .collect::<HashMap<String, Identity>>();
                privilege_dict = privileges
                    .into_iter()
                    .map(|privilege| (privilege.name.clone(), privilege))
                    .collect::<HashMap<String, Privilege>>();

                for role_assignment in role_assignments {
                    match role_dict.get(&role_assignment.role) {
                        Some(role) => {
                            for privilege_name in &role.privileges {
                                if privilege_dict.contains_key(privilege_name) {
                                    let assignments =
                                        if privilege_assignments.contains_key(privilege_name) {
                                            privilege_assignments.get_mut(privilege_name).unwrap()
                                        } else {
                                            let assignments = HashSet::new();
                                            privilege_assignments
                                                .insert(privilege_name.clone(), assignments);
                                            privilege_assignments.get_mut(privilege_name).unwrap()
                                        };

                                    for identity_name in &role_assignment.identities {
                                        if !identity_dict.contains_key(identity_name) {
                                            // skip the identity if the identity is not defined
                                            continue;
                                        }
                                        assignments.insert(identity_name.clone());
                                    }
                                }
                            }
                        }
                        None => {
                            // skip the assignment if the role is not defined
                            logger::write_error(format!(
                                "Role '{}' is not defined, skip the role assignment.",
                                role_assignment.role
                            ));
                            continue;
                        }
                    }
                }
            }
        }

        ComputedAuthorizationItem {
            id: authorization_item.id,
            defaultAllowed: authorization_item.defaultAccess.to_lowercase() == "allow",
            mode: authorization_mode,
            identities: identity_dict,
            privileges: privilege_dict,
            privilegeAssignments: privilege_assignments,
        }
    }

    pub fn is_allowed(
        &self,
        logger: ConnectionLogger,
        request_url: hyper::Uri,
        claims: Claims,
    ) -> bool {
        if self.mode == AuthorizationMode::Disabled {
            logger.write(
                LoggerLevel::Verbose,
                "Access control is in disabled state, skip....".to_string(),
            );

            return true;
        }

        let mut any_privilege_matched = false;
        for privilege in self.privileges.values() {
            let privilege_name = &privilege.name;
            if privilege.is_match(&logger, &request_url) {
                any_privilege_matched = true;
                logger.write(
                    LoggerLevel::Verbose,
                    format!("Request matched privilege '{}'.", privilege_name),
                );

                if let Some(assignments) = self.privilegeAssignments.get(privilege_name) {
                    for assignment in assignments {
                        let identity_name = assignment.clone();
                        if let Some(identity) = self.identities.get(&identity_name) {
                            if identity.is_match(&logger, &claims) {
                                logger.write(
                                    LoggerLevel::Verbose,
                                    format!(
                                        "Request matched privilege '{}' and identity '{}'.",
                                        privilege_name, identity_name
                                    ),
                                );
                                return true;
                            }
                        }
                    }
                    logger.write(
                        LoggerLevel::Verbose,
                        format!(
                            "Request matched privilege '{}' but no identity matched.",
                            privilege_name
                        ),
                    );
                } else {
                    logger.write(
                        LoggerLevel::Verbose,
                        format!(
                            "Request matched privilege '{}' but no identity assigned.",
                            privilege_name
                        ),
                    );
                }
            } else {
                logger.write(
                    LoggerLevel::Verbose,
                    format!("Request does not match privilege '{}'.", privilege_name),
                );
            }
        }

        if any_privilege_matched {
            logger.write(
                LoggerLevel::Information,
                "Privilege matched at least once, but no identity matches, deny the access."
                    .to_string(),
            );
            return false;
        }

        logger.write(
            LoggerLevel::Verbose,
            format!(
                "No privilege matched, fall back to use the default access: {}.",
                self.defaultAllowed
            ),
        );
        self.defaultAllowed
    }
}

#[derive(Serialize, Deserialize, Clone)]
#[allow(non_snake_case)]
pub struct ComputedAuthorizationRules {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub imds: Option<ComputedAuthorizationItem>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wireserver: Option<ComputedAuthorizationItem>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostga: Option<ComputedAuthorizationItem>,
}

#[derive(Serialize, Deserialize, Clone)]
#[allow(non_snake_case)]
pub struct AuthorizationRulesForLogging {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inputRules: Option<AuthorizationRules>,
    pub computedRules: ComputedAuthorizationRules,
}

impl AuthorizationRulesForLogging {
    pub fn new(
        input_rules: Option<AuthorizationRules>,
        computed_rules: ComputedAuthorizationRules,
    ) -> AuthorizationRulesForLogging {
        AuthorizationRulesForLogging {
            inputRules: input_rules,
            computedRules: computed_rules,
        }
    }

    /// Write the authorization rules to a file for support purpose
    /// The file name is in the format of "AuthorizationRules_{timestamp}.json"
    /// The content is the json string of the AuthorizationRulesForLogging object
    /// The file is written to the path_dir specified by the input parameter
    pub fn write_all(&self, path_dir: &Path, max_file_count: usize) {
        // remove the old files
        let files = match misc_helpers::search_files(path_dir, r"^AuthorizationRules_.*\.json$") {
            Ok(files) => files,
            Err(e) => {
                // This should not happen, log the error and skip write the file
                logger::write_error(format!(
                    "Failed to search the old authorization rules files under dir {} with error: {}",
                    path_dir.display(),
                    e
                ));
                return;
            }
        };
        if files.len() >= max_file_count {
            let mut count = max_file_count;
            for file in &files {
                std::fs::remove_file(file).unwrap_or_else(|e| {
                    logger::write_error(format!(
                        "Failed to remove the old authorization rules file {} with error: {}",
                        file.display(),
                        e
                    ));
                });
                count += 1;

                if count > files.len() {
                    break;
                }
            }
        }

        // compute the file name
        let new_file_name = format!(
            "AuthorizationRules_{}-{}.json",
            misc_helpers::get_date_time_string_with_milliseconds(),
            misc_helpers::get_date_time_unix_nano()
        )
        .replace(':', ".");
        let full_file_path = path_dir.join(new_file_name);
        match misc_helpers::json_write_to_file(&self, &full_file_path) {
            Ok(_) => {
                logger::write_information(format!(
                    "Authorization rules are written to file: {}",
                    full_file_path.display()
                ));
            }
            Err(e) => {
                logger::write_error(format!(
                    "Failed to write the authorization rules to file {} with error: {}",
                    full_file_path.display(),
                    e
                ));
            }
        };
    }
}

#[cfg(test)]
mod tests {
    use super::{AuthorizationRulesForLogging, ComputedAuthorizationRules};
    use crate::common::logger;
    use crate::key_keeper::key::{
        AccessControlRules, AuthorizationItem, AuthorizationRules, Identity, Privilege, Role,
        RoleAssignment,
    };
    use crate::proxy::authorization_rules::{AuthorizationMode, ComputedAuthorizationItem};
    use crate::proxy::{proxy_connection::ConnectionLogger, Claims};
    use proxy_agent_shared::{logger_manager, misc_helpers};
    use std::ffi::OsString;
    use std::path::PathBuf;
    use std::str::FromStr;

    #[tokio::test]
    async fn test_authorization_rules() {
        let logger_key = "test_authorization_rules";
        let mut temp_test_path = std::env::temp_dir();
        temp_test_path.push(logger_key);
        ConnectionLogger::init_logger(temp_test_path.to_path_buf()).await;
        let test_logger = ConnectionLogger {
            tcp_connection_id: 0,
            http_connection_id: 0,
        };

        // Test Enforce Mode
        let access_control_rules = AccessControlRules {
            roles: Some(vec![Role {
                name: "test".to_string(),
                privileges: vec!["test".to_string(), "test1".to_string()],
            }]),
            privileges: Some(vec![Privilege {
                name: "test".to_string(),
                path: "/test".to_string(),
                queryParameters: None,
            }]),
            identities: Some(vec![Identity {
                name: "test".to_string(),
                exePath: Some("test".to_string()),
                groupName: Some("test".to_string()),
                processName: Some("test".to_string()),
                userName: Some("test".to_string()),
            }]),
            roleAssignments: Some(vec![RoleAssignment {
                role: "test".to_string(),
                identities: vec!["test".to_string()],
            }]),
        };
        let authorization_item: AuthorizationItem = AuthorizationItem {
            defaultAccess: "deny".to_string(),
            mode: "enforce".to_string(),
            rules: Some(access_control_rules),
            id: "0".to_string(),
        };
        let rules = ComputedAuthorizationItem::from_authorization_item(authorization_item);
        let _clone_rules = rules.clone();
        assert!(!rules.defaultAllowed);
        assert_eq!(rules.mode, AuthorizationMode::Enforce);
        assert!(!rules.privilegeAssignments.is_empty());
        assert!(!rules.identities.is_empty());
        assert!(!rules.privileges.is_empty());

        let mut claims = Claims {
            userId: 0,
            userName: "test".to_string(),
            userGroups: vec!["test".to_string()],
            processId: 0,
            processFullPath: PathBuf::from("test"),
            clientIp: "0".to_string(),
            clientPort: 0, // doesn't matter for this test
            processName: OsString::from("test"),
            processCmdLine: "test".to_string(),
            runAsElevated: true,
        };
        // assert the claim is allowed given the rules above
        let url = hyper::Uri::from_str("http://localhost/test/test").unwrap();
        assert!(rules.is_allowed(test_logger.clone(), url, claims.clone()));
        let relative_url = hyper::Uri::from_str("/test/test").unwrap();
        assert!(rules.is_allowed(test_logger.clone(), relative_url.clone(), claims.clone()));
        claims.userName = "test1".to_string();
        assert!(!rules.is_allowed(test_logger.clone(), relative_url, claims.clone()));

        // Test Audit Mode
        let access_control_rules = AccessControlRules {
            roles: Some(vec![Role {
                name: "test".to_string(),
                privileges: vec!["test".to_string(), "test1".to_string()],
            }]),
            privileges: Some(vec![Privilege {
                name: "test".to_string(),
                path: "/test".to_string(),
                queryParameters: None,
            }]),
            identities: Some(vec![Identity {
                name: "test".to_string(),
                exePath: Some("test".to_string()),
                groupName: Some("test".to_string()),
                processName: Some("test".to_string()),
                userName: Some("test".to_string()),
            }]),
            roleAssignments: Some(vec![RoleAssignment {
                role: "test".to_string(),
                identities: vec!["test".to_string()],
            }]),
        };
        let authorization_item: AuthorizationItem = AuthorizationItem {
            defaultAccess: "deny".to_string(),
            mode: "audit".to_string(),
            rules: Some(access_control_rules),
            id: "0".to_string(),
        };
        let rules = ComputedAuthorizationItem::from_authorization_item(authorization_item);
        assert!(!rules.defaultAllowed);
        assert_eq!(rules.mode, AuthorizationMode::Audit);
        assert!(!rules.privilegeAssignments.is_empty());
        assert!(!rules.identities.is_empty());
        assert!(!rules.privileges.is_empty());

        // Test Disabled Mode
        let access_control_rules = AccessControlRules {
            roles: Some(vec![Role {
                name: "test".to_string(),
                privileges: vec!["test".to_string(), "test1".to_string()],
            }]),
            privileges: Some(vec![Privilege {
                name: "test".to_string(),
                path: "/test".to_string(),
                queryParameters: None,
            }]),
            identities: Some(vec![Identity {
                name: "test".to_string(),
                exePath: Some("test".to_string()),
                groupName: Some("test".to_string()),
                processName: Some("test".to_string()),
                userName: Some("test".to_string()),
            }]),
            roleAssignments: Some(vec![RoleAssignment {
                role: "test".to_string(),
                identities: vec!["test".to_string()],
            }]),
        };
        let authorization_item: AuthorizationItem = AuthorizationItem {
            defaultAccess: "deny".to_string(),
            mode: "disabled".to_string(),
            rules: Some(access_control_rules),
            id: "0".to_string(),
        };
        let rules = ComputedAuthorizationItem::from_authorization_item(authorization_item);
        assert!(!rules.defaultAllowed);
        assert_eq!(rules.mode, AuthorizationMode::Disabled);
        assert!(!rules.privilegeAssignments.is_empty());
        assert!(!rules.identities.is_empty());
        assert!(!rules.privileges.is_empty());

        let url = hyper::Uri::from_str("http://localhost/test/test1").unwrap();
        assert!(rules.is_allowed(test_logger.clone(), url, claims.clone()));
        let relative_url = hyper::Uri::from_str("/test/test1").unwrap();
        assert!(rules.is_allowed(test_logger.clone(), relative_url, claims.clone()));

        // Test enforce mode, identity not match
        let access_control_rules = AccessControlRules {
            roles: Some(vec![Role {
                name: "test".to_string(),
                privileges: vec!["test".to_string(), "test1".to_string()],
            }]),
            privileges: Some(vec![Privilege {
                name: "test".to_string(),
                path: "/test".to_string(),
                queryParameters: None,
            }]),
            identities: Some(vec![Identity {
                name: "test1".to_string(),
                exePath: Some("test".to_string()),
                groupName: Some("test".to_string()),
                processName: Some("test".to_string()),
                userName: Some("test".to_string()),
            }]),
            roleAssignments: Some(vec![RoleAssignment {
                role: "test".to_string(),
                identities: vec!["test1".to_string()],
            }]),
        };
        let authorization_item: AuthorizationItem = AuthorizationItem {
            defaultAccess: "deny".to_string(),
            mode: "enforce".to_string(),
            rules: Some(access_control_rules),
            id: "0".to_string(),
        };
        let rules = ComputedAuthorizationItem::from_authorization_item(authorization_item);
        assert!(!rules.defaultAllowed);
        assert_eq!(rules.mode, AuthorizationMode::Enforce);
        assert!(!rules.privilegeAssignments.is_empty());
        assert!(!rules.identities.is_empty());
        assert!(!rules.privileges.is_empty());

        let url = hyper::Uri::from_str("http://localhost/test?").unwrap();
        assert!(!rules.is_allowed(test_logger.clone(), url, claims.clone()));
        let relativeurl = hyper::Uri::from_str("/test?").unwrap();
        assert!(!rules.is_allowed(test_logger.clone(), relativeurl, claims.clone()));
    }

    #[tokio::test]
    async fn test_authorization_rules_for_logging() {
        let mut temp_test_path = std::env::temp_dir();
        temp_test_path.push("test_authorization_rules_for_logging");
        let mut log_dir = temp_test_path.to_path_buf();
        log_dir.push("Logs");

        // clean up and ignore the clean up errors
        match std::fs::remove_dir_all(&temp_test_path) {
            Ok(_) => {}
            Err(e) => {
                print!("Failed to remove_dir_all with error {}.", e);
            }
        }
        misc_helpers::try_create_folder(&temp_test_path).unwrap();

        // init main logger
        logger_manager::init_logger(
            logger::AGENT_LOGGER_KEY.to_string(), // production code uses 'Agent_Log' to write.
            log_dir.clone(),
            "logger_key".to_string(),
            10 * 1024 * 1024,
            20,
        )
        .await;

        let access_control_rules = AccessControlRules {
            roles: Some(vec![Role {
                name: "test".to_string(),
                privileges: vec!["test".to_string(), "test1".to_string()],
            }]),
            privileges: Some(vec![Privilege {
                name: "test".to_string(),
                path: "/test".to_string(),
                queryParameters: None,
            }]),
            identities: Some(vec![Identity {
                name: "test".to_string(),
                exePath: Some("test".to_string()),
                groupName: Some("test".to_string()),
                processName: Some("test".to_string()),
                userName: Some("test".to_string()),
            }]),
            roleAssignments: Some(vec![RoleAssignment {
                role: "test".to_string(),
                identities: vec!["test".to_string()],
            }]),
        };
        let authorization_item: AuthorizationItem = AuthorizationItem {
            defaultAccess: "deny".to_string(),
            mode: "enforce".to_string(),
            rules: Some(access_control_rules),
            id: "0".to_string(),
        };
        let computed_authorization_item =
            ComputedAuthorizationItem::from_authorization_item(authorization_item.clone());

        let authorization_rules_for_logging = AuthorizationRulesForLogging::new(
            Some(AuthorizationRules {
                imds: Some(authorization_item.clone()),
                wireserver: Some(authorization_item.clone()),
                hostga: Some(authorization_item.clone()),
            }),
            ComputedAuthorizationRules {
                imds: Some(computed_authorization_item.clone()),
                wireserver: Some(computed_authorization_item.clone()),
                hostga: Some(computed_authorization_item.clone()),
            },
        );

        let max_file_count = 5;
        for _ in 0..10 {
            authorization_rules_for_logging.write_all(&temp_test_path, max_file_count);
            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        }

        let files =
            misc_helpers::search_files(&temp_test_path, r"^AuthorizationRules_.*\.json$").unwrap();
        assert_eq!(files.len(), max_file_count);

        // clean up and ignore the clean up errors
        _ = std::fs::remove_dir_all(&temp_test_path);
    }
}
