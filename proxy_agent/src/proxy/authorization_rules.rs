// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

//! This module contains the logic to authorize the request based on the authorization rules.
//! The authorization rules is from user inputted access control rules.
//!
//! Example
//! ```rust
//! use proxy_agent::authorization_rules;
//! use proxy_agent::proxy_connection::Connection;
//!
//! // convert the authorization item to access control rules
//! let access_control_rules = AccessControlRules::from_authorization_item(authorization_item);
//!
//! // check if the request is allowed based on the access control rules
//! let is_allowed = access_control_rules.is_allowed(connection_id, request_url, claims);
//!
//! ```

use super::{proxy_connection::Connection, Claims};
use crate::key_keeper::key::{AuthorizationItem, Identity, Keyable, Privilege};
use serde_derive::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Serialize, Deserialize, Clone)]
#[allow(non_snake_case)]
pub struct AuthorizationRules {
    // The default access: allow -> true, deny-> false
    pub defaultAllowed: bool,
    // disabled, audit, enforce
    pub mode: String,
    // all the defined unique privileges, distinct by name
    pub privileges: Option<HashMap<String, Privilege>>,
    // The identities assigned to this privilege
    // key - privilege name, value - the assigned identity names
    pub privilegeAssignments: Option<HashMap<String, HashSet<String>>>,
    // all the defined unique identities, distinct by name
    // key - identity name, value - identity object
    pub identities: Option<HashMap<String, Identity>>,
}

#[allow(dead_code)]
impl AuthorizationRules {
    pub fn from_authorization_item(authorization_item: AuthorizationItem) -> AuthorizationRules {
        let (identities, privileges, privilege_assignments) = match authorization_item.rules {
            Some(input_rules) => {
                let roles = AuthorizationRules::vec_to_dict(input_rules.roles);
                let identities = AuthorizationRules::vec_to_dict(input_rules.identities);
                let privileges = AuthorizationRules::vec_to_dict(input_rules.privileges);

                let privilege_assignments = match input_rules.roleAssignments {
                    Some(role_assignments) => {
                        let mut privilege_assignments: HashMap<String, HashSet<String>> =
                            HashMap::new();

                        for assignment in role_assignments {
                            match AuthorizationRules::get_from_dict(&roles, assignment.role.clone())
                            {
                                Some(role) => {
                                    for privilege_name in role.privileges {
                                        if AuthorizationRules::contains_key(
                                            &privileges,
                                            privilege_name.clone(),
                                        ) {
                                            let assignemnts = if privilege_assignments
                                                .contains_key(&privilege_name)
                                            {
                                                privilege_assignments
                                                    .get_mut(&privilege_name)
                                                    .unwrap()
                                            } else {
                                                let assignments = HashSet::new();
                                                privilege_assignments
                                                    .insert(privilege_name.clone(), assignments);
                                                privilege_assignments
                                                    .get_mut(&privilege_name)
                                                    .unwrap()
                                            };

                                            for identity in &assignment.identities {
                                                if !AuthorizationRules::contains_key(
                                                    &identities,
                                                    identity.clone(),
                                                ) {
                                                    // skip the identity if the identity is not defined
                                                    continue;
                                                }
                                                assignemnts.insert(identity.clone());
                                            }
                                        }
                                    }
                                }
                                None => {
                                    // skip the assignment if the role is not defined
                                    continue;
                                }
                            }
                        }
                        Some(privilege_assignments)
                    }
                    None => None,
                };
                (identities, privileges, privilege_assignments)
            }
            None => (None, None, None),
        };

        AuthorizationRules {
            defaultAllowed: authorization_item.defaultAccess.to_lowercase() == "allow",
            mode: authorization_item.mode.to_lowercase(),
            identities,
            privileges,
            privilegeAssignments: privilege_assignments,
        }
    }

    fn vec_to_dict<T>(vec: Option<Vec<T>>) -> Option<HashMap<String, T>>
    where
        T: Clone + Keyable,
    {
        match vec {
            Some(vec) => {
                let mut dict: HashMap<String, T> = HashMap::new();
                for v in vec {
                    dict.insert(v.get_key(), v.clone());
                }
                Some(dict)
            }
            None => None,
        }
    }

    fn contains_key<T>(dict: &Option<HashMap<String, T>>, key: String) -> bool {
        match dict {
            Some(dict) => dict.contains_key(&key),
            None => false,
        }
    }

    fn get_from_dict<T>(dict: &Option<HashMap<String, T>>, key: String) -> Option<T>
    where
        T: Clone,
    {
        match dict {
            Some(dict) => dict.get(&key).cloned(),
            None => None,
        }
    }

    pub fn is_allowed(&self, connection_id: u128, request_url: hyper::Uri, claims: Claims) -> bool {
        if self.mode.to_lowercase() == "disabled" {
            Connection::write_information(
                connection_id,
                "Access control is in disabled state, skip....".to_string(),
            );

            return true;
        }

        if let (Some(privileges), Some(identities), Some(privilege_assignments)) = (
            &self.privileges,
            &self.identities,
            &self.privilegeAssignments,
        ) {
            let mut privilege_matched = false;
            for privilege in privileges.values() {
                let privilege_name = privilege.name.clone();
                if privilege.is_match(connection_id, request_url.clone()) {
                    privilege_matched = true;
                    Connection::write_information(
                        connection_id,
                        format!("Reqeust matched privilege '{}'.", privilege_name),
                    );

                    if let Some(assignments) = privilege_assignments.get(&privilege_name) {
                        for assignemnt in assignments {
                            let identity_name = assignemnt.clone();
                            if let Some(identity) = identities.get(&identity_name) {
                                if identity.is_match(connection_id, claims.clone()) {
                                    Connection::write_information(
                                        connection_id,
                                        format!("Identity matched identity '{}'.", identity_name),
                                    );
                                    return true;
                                } else {
                                    Connection::write_information(
                                        connection_id,
                                        format!(
                                            "Identity does not match identity '{}'.",
                                            identity_name
                                        ),
                                    );
                                }
                            }
                        }
                    }
                } else {
                    Connection::write_information(
                        connection_id,
                        format!("Reqeust does not match privilege '{}'.", privilege_name),
                    );
                }
            }

            if privilege_matched {
                Connection::write_information(
                    connection_id,
                    "Privilege matched once, but no identity matches.".to_string(),
                );
                return false;
            }
        }

        Connection::write_information(
            connection_id,
            format!(
                "No privilege matched, fall back to use the default access: {}.",
                if self.defaultAllowed {
                    "allowed"
                } else {
                    "denied"
                }
            ),
        );
        self.defaultAllowed
    }
}

#[cfg(test)]
mod tests {
    use crate::key_keeper::key::{
        AccessControlRules, AuthorizationItem, Identity, Privilege, Role, RoleAssignment,
    };
    use crate::proxy::authorization_rules::AuthorizationRules;
    use crate::proxy::{proxy_connection::Connection, Claims};
    use std::str::FromStr;

    #[test]
    fn test_authorization_rules() {
        let logger_key = "test_authorization_rules";
        let mut temp_test_path = std::env::temp_dir();
        temp_test_path.push(logger_key);
        Connection::init_logger(temp_test_path.to_path_buf());

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
        let rules = AuthorizationRules::from_authorization_item(authorization_item);
        let _clone_rules = rules.clone();
        assert!(!rules.defaultAllowed);
        assert_eq!(rules.mode, "enforce");
        assert!(rules.privilegeAssignments.is_some());
        assert!(rules.identities.is_some());
        assert!(rules.privileges.is_some());

        let mut claims = Claims {
            userId: 0,
            userName: "test".to_string(),
            userGroups: vec!["test".to_string()],
            processId: 0,
            processFullPath: "test".to_string(),
            clientIp: "0".to_string(),
            processName: "test".to_string(),
            processCmdLine: "test".to_string(),
            runAsElevated: true,
        };
        // assert the claim is allowed given the rules above
        let url = hyper::Uri::from_str("http://localhost/test/test").unwrap();
        assert!(rules.is_allowed(0, url, claims.clone()));
        let relative_url = hyper::Uri::from_str("/test/test").unwrap();
        assert!(rules.is_allowed(0, relative_url.clone(), claims.clone()));
        claims.userName = "test1".to_string();
        assert!(!rules.is_allowed(0, relative_url, claims.clone()));

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
        let rules = AuthorizationRules::from_authorization_item(authorization_item);
        assert!(!rules.defaultAllowed);
        assert_eq!(rules.mode, "audit");
        assert!(rules.privilegeAssignments.is_some());
        assert!(rules.identities.is_some());
        assert!(rules.privileges.is_some());

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
        let rules = AuthorizationRules::from_authorization_item(authorization_item);
        assert!(!rules.defaultAllowed);
        assert_eq!(rules.mode, "disabled");
        assert!(rules.privilegeAssignments.is_some());
        assert!(rules.identities.is_some());
        assert!(rules.privileges.is_some());

        let url = hyper::Uri::from_str("http://localhost/test/test1").unwrap();
        assert!(rules.is_allowed(0, url, claims.clone()));
        let relative_url = hyper::Uri::from_str("/test/test1").unwrap();
        assert!(rules.is_allowed(0, relative_url, claims.clone()));

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
        let rules = AuthorizationRules::from_authorization_item(authorization_item);
        assert!(!rules.defaultAllowed);
        assert_eq!(rules.mode, "enforce");
        assert!(rules.privilegeAssignments.is_some());
        assert!(rules.identities.is_some());
        assert!(rules.privileges.is_some());

        let url = hyper::Uri::from_str("http://localhost/test?").unwrap();
        assert!(!rules.is_allowed(0, url, claims.clone()));
        let relativeurl = hyper::Uri::from_str("/test?").unwrap();
        assert!(!rules.is_allowed(0, relativeurl, claims.clone()));
    }
}
