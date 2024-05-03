use crate::key_keeper::key::{AuthorizationItem, Identity, Privilege};
use proxy_agent_shared::misc_helpers;
use serde_derive::{Deserialize, Serialize};

use super::{proxy_connection::Connection, Claims};

#[derive(Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct AuthorizationRules {
    // The default access: allow -> true, deny-> false
    pub defaultAllowed: bool,
    // disabled, audit, enforce
    pub mode: String,
    pub rules: Option<Vec<Rule>>,
}

#[derive(Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct Rule {
    pub roleName: String,
    pub privileges: Vec<Privilege>,
    pub identities: Vec<Identity>,
}

impl AuthorizationRules {
    pub fn new() -> AuthorizationRules {
        AuthorizationRules {
            defaultAllowed: false,
            mode: "disabled".to_string(),
            rules: None,
        }
    }
    pub fn from_authorization_item(authorization_item: AuthorizationItem) -> AuthorizationRules {
        let rules = match authorization_item.roleAssignments {
            Some(role_assignments) => {
                let mut rules = Vec::new();
                for role_assignment in role_assignments {
                    let role_name = role_assignment.role.to_string();

                    let mut privileges = Vec::new();
                    match &authorization_item.privileges {
                        Some(input_privileges) => match &authorization_item.roles {
                            Some(roles) => {
                                for role in roles {
                                    if role.name == role_name {
                                        for privilege_name in &role.privileges {
                                            for privilege in input_privileges {
                                                if privilege.name == privilege_name.to_string() {
                                                    privileges.push(privilege.clone());
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            None => {}
                        },
                        None => {}
                    }

                    let mut identities = Vec::new();
                    match &authorization_item.identities {
                        Some(input_identities) => {
                            for identity_name in role_assignment.identities {
                                for identity in input_identities {
                                    if identity.name == identity_name {
                                        identities.push(identity.clone());
                                    }
                                }
                            }
                        }
                        None => {}
                    }

                    rules.push(Rule {
                        roleName: role_name,
                        privileges: privileges,
                        identities: identities,
                    });
                }
                Some(rules)
            }
            None => None,
        };

        AuthorizationRules {
            defaultAllowed: authorization_item.defaultAccess.to_lowercase() == "allow",
            mode: authorization_item.mode.to_string(),
            rules: rules,
        }
    }

    pub fn clone(&self) -> AuthorizationRules {
        match misc_helpers::json_clone(self) {
            Ok(rules) => rules,
            Err(_) => AuthorizationRules::new(),
        }
    }

    pub fn is_allowed(&self, connection_id: u128, request_url: String, claims: Claims) -> bool {
        if self.mode.to_lowercase() == "disabled" {
            return true;
        }

        let url = request_url.to_lowercase();
        let url = match url::Url::parse(&url) {
            Ok(u) => u,
            Err(_) => {
                Connection::write_error(
                    connection_id,
                    format!("Failed to parse the request url: {}", request_url),
                );
                return false;
            }
        };

        if self.mode.to_lowercase() == "enforce" {
            if let Some(rules) = &self.rules {
                let mut role_privilege_matched = false;
                for rule in rules {
                    // is privilege match
                    for privilege in &rule.privileges {
                        if privilege.is_match(connection_id, url.clone()) {
                            role_privilege_matched = true;
                            for identity in &rule.identities {
                                if identity.is_match(connection_id, claims.clone()) {
                                    return true;
                                }
                            }
                        }
                    }
                }

                if role_privilege_matched {
                    // all the privilege matched, but no identity matched, block the request
                    return false;
                }
            }
        }

        if self.mode.to_lowercase() == "audit" {
            return true;
        }
        // no privilege matched, fall back to default access
        self.defaultAllowed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_keeper::key::{AuthorizationItem, Identity, Privilege, Role, RoleAssignment};
    use proxy_agent_shared::misc_helpers;

    #[test]
    fn authorizationRules_test() {
        let mut authorization_item = AuthorizationItem::new();
        authorization_item.defaultAccess = "deny".to_string();
        authorization_item.mode = "enforce".to_string();
        authorization_item.privileges = Some(vec![
            Privilege {
                name: "read".to_string(),
                path: "/".to_string(),
            },
            Privilege {
                name: "write".to_string(),
                path: "/".to_string(),
            },
        ]);
        authorization_item.roles = Some(vec![
            Role {
                name: "admin".to_string(),
                privileges: vec!["read".to_string(), "write".to_string()],
            },
            Role {
                name: "user".to_string(),
                privileges: vec!["read".to_string()],
            },
        ]);
        authorization_item.identities = Some(vec![
            Identity {
                name: "admin".to_string(),
                roles: vec!["admin".to_string()],
            },
            Identity {
                name: "user".to_string(),
                roles: vec!["user".to_string()],
            },
        ]);
        authorization_item.roleAssignments = Some(vec![
            RoleAssignment {
                role: "admin".to_string(),
                identities: vec!["admin".to_string()],
            },
            RoleAssignment {
                role: "user".to_string(),
                identities: vec!["user".to_string()],
            },
        ]);

        let rules = AuthorizationRules::from_authorization_item(authorization_item);
        let rules_clone = rules.clone();
        assert_eq!(rules.defaultAllowed, false);
        assert_eq!(rules.mode, "enforce");
        assert_eq!(rules.rules.is_some(), true);

        let claims = Claims {
            processName: "test".to_string(),
            processCmdLine: "test".to_string(),
            runAsElevated: true,
        };
        assert_eq!(
            rules.is_allowed(0, "http://localhost".to_string(), claims.clone()),
            false
        );

        let mut claims = Claims {
            processName: "test".to_string(),
            processCmdLine: "test".to_string(),
            runAsElevated: true,
        };
        claims.userName = "admin".to_string();
        assert_eq!(
            rules.is_allowed(0, "http://localhost".to_string(), claims.clone()),
            true
        );

        let mut claims = Claims {
            processName: "test".to_string(),
            processCmdLine: "test".to_string(),
            runAsElevated: true,
        };
        claims.userName = "user".to_string();
        assert_eq!(
            rules.is_allowed(0, "http://localhost".to_string(), claims.clone()),
            false
        );

        authorization_item.defaultAccess = "deny".to_string();
        authorization_item.mode = "audit".to_string();
        let rules = AuthorizationRules::from_authorization_item(authorization_item);
        assert_eq!(rules.defaultAllowed, false);
        assert_eq!(rules.mode, "audit");
        assert_eq!(rules.rules.is_some(), true);
        assert_eq!(
            rules.is_allowed(0, "http://localhost".to_string(), claims.clone()),
            true
        );

        authorization_item.defaultAccess = "allow".to_string();
        authorization_item.mode = "disabled".to_string();
        let rules = AuthorizationRules::from_authorization_item(authorization_item);
        assert_eq!(rules.defaultAllowed, true);
        assert_eq!(rules.mode, "disabled");
        assert_eq!(rules.rules.is_some(), false);
        assert_eq!(
            rules.is_allowed(0, "http://localhost".to_string(), claims.clone()),
            true
        );
    }
}
