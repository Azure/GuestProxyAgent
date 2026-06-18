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
use crate::proxy::canonical::{self, CanonError, CanonicalMode, CanonicalPattern};
use proxy_agent_shared::logger::LoggerLevel;
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
            _ => Err(format!("Invalid AuthorizationMode: {s}")),
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

    /// Innovation 2.1 shadow cache: each `Privilege` compiled through
    /// the canonical pipeline once at rule-load time so per-request
    /// shadow evaluation in [`ComputedAuthorizationItem::canonical_decision`]
    /// is a plain linear scan instead of re-parsing the rule path on
    /// every connection.
    ///
    /// Stored as `Vec<(name, pattern)>` rather than `HashMap` because:
    /// - The access pattern is "scan all" — `canonical_decision`
    ///   iterates every entry looking for matches; there is no
    ///   lookup-by-privilege-name path on the canonical side.
    /// - Iteration order is stable (insertion order), which makes
    ///   divergence logs and any future "first match wins" semantics
    ///   deterministic across processes — `HashMap` iteration is
    ///   randomized.
    /// - For typical rule counts (tens of entries) the per-entry
    ///   overhead is smaller than `HashMap`.
    ///
    /// Skipped from (de)serialization because:
    /// 1. The cache is a pure function of `privileges` — round-tripping
    ///    it through the AuthorizationRulesForLogging JSON would just
    ///    duplicate that data and risk drift if the canonical pipeline
    ///    is upgraded between writer and reader.
    /// 2. `CanonicalPattern` is not (and intentionally should not be)
    ///    `Serialize`/`Deserialize` — its shape is an internal contract
    ///    of the matcher.
    ///
    /// Privileges that fail to canonicalize at load time are dropped
    /// from this cache **and** a warning is logged. This is fail-closed
    /// for the canonical side: shadow / enforce mode will report a
    /// divergence (legacy may still match the un-canonicalizable rule)
    /// which is exactly the signal we want during rollout.
    #[serde(skip, default)]
    canonical_patterns: Vec<(String, CanonicalPattern)>,
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
                logger::write_error(format!("Failed to parse authorization mode: {err}"));
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
                    .map(|privilege| {
                        // case insensitive for path and query parameters key/values,
                        // to make it easier for users to write the rules without worrying about the case sensitivity.
                        // The name of the privilege is case sensitive, as it is used as the key in the privilege_dict and privilege_assignments.
                        let normalized = Privilege {
                            name: privilege.name,
                            path: privilege.path.to_lowercase(),
                            queryParameters: privilege.queryParameters.map(|qp| {
                                qp.into_iter()
                                    .map(|(k, v)| (k.to_lowercase(), v.to_lowercase()))
                                    .collect()
                            }),
                        };
                        (normalized.name.clone(), normalized)
                    })
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
            canonical_patterns: Self::compile_canonical_patterns(&privilege_dict),
            privileges: privilege_dict,
            privilegeAssignments: privilege_assignments,
        }
    }

    /// Compile every privilege through the canonical pipeline once.
    ///
    /// Errors are logged and the offending privilege is dropped from
    /// the cache (fail-closed on the canonical side; the legacy matcher
    /// retains its copy in `self.privileges`). This is exactly the
    /// shape of divergence shadow-mode is designed to surface.
    fn compile_canonical_patterns(
        privilege_dict: &HashMap<String, Privilege>,
    ) -> Vec<(String, CanonicalPattern)> {
        let mut out = Vec::with_capacity(privilege_dict.len());
        for (name, privilege) in privilege_dict {
            match CanonicalPattern::from_privilege(privilege) {
                Ok(pat) => out.push((name.clone(), pat)),
                Err(e) => {
                    // Don't fail rule-load; canonical mode will deny
                    // anything that needed this rule, which is the M3
                    // signal we want operators to see.
                    logger::write_warning(format!(
                        "Privilege '{name}' failed canonicalization ({code}); dropping from canonical cache (legacy matcher unaffected). path={path:?}",
                        name = name,
                        code = e.code(),
                        path = privilege.path,
                    ));
                }
            }
        }
        out
    }

    pub fn is_allowed(
        &self,
        logger: &mut ConnectionLogger,
        request_url: hyper::Uri,
        claims: Claims,
    ) -> bool {
        if self.mode == AuthorizationMode::Disabled {
            logger.write(
                LoggerLevel::Trace,
                "Access control is in disabled state, skip....".to_string(),
            );

            return true;
        }

        let decoded_path =
            percent_encoding::percent_decode_str(request_url.path()).decode_utf8_lossy();
        let lowered_request_path = decoded_path.to_lowercase();
        let mut any_privilege_matched = false;
        for privilege in self.privileges.values() {
            let privilege_name = &privilege.name;
            if privilege.is_match(logger, &request_url, &lowered_request_path) {
                any_privilege_matched = true;
                logger.write(
                    LoggerLevel::Trace,
                    format!("Request matched privilege '{privilege_name}'."),
                );

                if let Some(assignments) = self.privilegeAssignments.get(privilege_name) {
                    for assignment in assignments {
                        let identity_name = assignment.clone();
                        if let Some(identity) = self.identities.get(&identity_name) {
                            if identity.is_match(logger, &claims) {
                                logger.write(
                                    LoggerLevel::Trace,
                                    format!(
                                        "Request matched privilege '{privilege_name}' and identity '{identity_name}'."
                                    ),
                                );
                                return true;
                            }
                        }
                    }
                    logger.write(
                        LoggerLevel::Trace,
                        format!(
                            "Request matched privilege '{privilege_name}' but no identity matched."
                        ),
                    );
                } else {
                    logger.write(
                        LoggerLevel::Trace,
                        format!(
                            "Request matched privilege '{privilege_name}' but no identity assigned."
                        ),
                    );
                }
            } else {
                logger.write(
                    LoggerLevel::Trace,
                    format!("Request does not match privilege '{privilege_name}'."),
                );
            }
        }

        if any_privilege_matched {
            logger.write(
                LoggerLevel::Info,
                "Privilege matched at least once, but no identity matches, deny the access."
                    .to_string(),
            );
            return false;
        }

        logger.write(
            LoggerLevel::Trace,
            format!(
                "No privilege matched, fall back to use the default access: {}.",
                self.defaultAllowed
            ),
        );
        self.defaultAllowed
    }

    // ------------------------------------------------------------------
    // Innovation 2.1 M3 — shadow-mode integration.
    //
    // The two methods below add the canonical-pipeline evaluator and the
    // divergence comparator that `proxy_authorizer::authorize` invokes
    // when the rollout flag is `shadow` or `enforce`. With the default
    // flag (`off`) neither runs and the legacy path above is the
    // entirety of the authorization decision — the M3 exit criterion
    // "behavior unchanged for production traffic".
    // ------------------------------------------------------------------

    /// Canonical-pipeline mirror of [`is_allowed`].
    ///
    /// Runs the request through `canonical::canonicalize` and matches it
    /// against the precomputed [`CanonicalPattern`]s in
    /// `self.canonical_patterns`. The identity check is shared with the
    /// legacy path (same `Identity::is_match` semantics, same default
    /// fallback) — the only difference is *path matching*. This is what
    /// the comparator targets.
    ///
    /// **Fail-closed**: canonicalization errors collapse to
    /// [`CanonicalDecision::Error`], which the comparator surfaces in
    /// the divergence record and which the enforce-mode caller treats
    /// as deny.
    pub fn canonical_decision(
        &self,
        logger: &mut ConnectionLogger,
        request_uri: &hyper::Uri,
        request_method: &hyper::Method,
        claims: &Claims,
    ) -> CanonicalDecision {
        // Disabled mode short-circuits identically to legacy. We keep
        // the two implementations symmetric here so a divergence is
        // always attributable to path/query handling, never to the
        // disabled-skip.
        if self.mode == AuthorizationMode::Disabled {
            return CanonicalDecision::Allowed;
        }

        let canon = match canonical::canonicalize(request_uri, request_method) {
            Ok(c) => c,
            Err(e) => return CanonicalDecision::Error(e),
        };

        let mut any_pattern_matched = false;
        for (privilege_name, pattern) in &self.canonical_patterns {
            if !pattern.matches(&canon) {
                continue;
            }
            any_pattern_matched = true;
            logger.write(
                LoggerLevel::Trace,
                format!("[canonical] Request matched privilege '{privilege_name}'."),
            );

            if let Some(assignments) = self.privilegeAssignments.get(privilege_name) {
                for identity_name in assignments {
                    if let Some(identity) = self.identities.get(identity_name) {
                        if identity.is_match(logger, claims) {
                            return CanonicalDecision::Allowed;
                        }
                    }
                }
            }
        }

        if any_pattern_matched {
            // Same semantics as legacy: any privilege matched but no
            // identity matched -> deny (do NOT fall through to default).
            return CanonicalDecision::Denied;
        }
        if self.defaultAllowed {
            CanonicalDecision::Allowed
        } else {
            CanonicalDecision::Denied
        }
    }

    /// Compare the precomputed legacy decision with the canonical
    /// pipeline's verdict and emit a single divergence log line per
    /// request when they disagree.
    ///
    /// The shape of the emitted line is the M3 telemetry contract from
    /// `doc/plans/Innovation-2.1-canonical-request.md` §9.2 — see
    /// [`DivergenceRecord`]. We log it as a prefixed single-line
    /// `key=value` record so dev/test grep / structured log shippers can
    /// pick it up without a new telemetry pipeline (deferred to M4).
    ///
    /// Returns the canonical decision so an enforce-mode caller can use
    /// it directly. Off / shadow callers ignore the return value.
    pub fn shadow_compare(
        &self,
        logger: &mut ConnectionLogger,
        request_uri: &hyper::Uri,
        request_method: &hyper::Method,
        claims: &Claims,
        legacy_allowed: bool,
        mode: CanonicalMode,
    ) -> CanonicalDecision {
        debug_assert!(
            mode != CanonicalMode::Off,
            "shadow_compare invoked while canonical mode is Off; the proxy_authorizer guard should have skipped this call"
        );

        let canon = self.canonical_decision(logger, request_uri, request_method, claims);

        let canon_allowed = canon.allowed_or_fail_closed();
        if canon_allowed != legacy_allowed {
            let record = DivergenceRecord {
                rule_set_id: &self.id,
                mode,
                legacy_decision: legacy_allowed,
                canon_decision: &canon,
                request_uri,
            };
            // Warn level: M3 wants this visible in dev/test without a
            // separate telemetry pipeline. It's per-request only when
            // there *is* a divergence, so noise stays low. The plan
            // is to graduate this to a structured telemetry event in
            // M4 (§9.3).
            logger.write(LoggerLevel::Warn, record.to_log_line());
        }
        canon
    }
}

/// Outcome of [`ComputedAuthorizationItem::canonical_decision`].
///
/// Distinct from the legacy `bool` return so the shadow comparator can
/// distinguish "canonicalization rejected the request" from "matcher
/// said deny" in the divergence record. Both collapse to `false` under
/// [`CanonicalDecision::allowed_or_fail_closed`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CanonicalDecision {
    Allowed,
    Denied,
    /// The canonical pipeline rejected the request before any matcher
    /// ran. Always a deny in fail-closed evaluation.
    Error(CanonError),
}

impl CanonicalDecision {
    /// Project to a boolean using fail-closed semantics: errors become
    /// `false`. Used by the comparator to decide whether the canonical
    /// verdict diverges from the legacy bool.
    pub fn allowed_or_fail_closed(&self) -> bool {
        matches!(self, CanonicalDecision::Allowed)
    }
}

impl std::fmt::Display for CanonicalDecision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CanonicalDecision::Allowed => write!(f, "allow"),
            CanonicalDecision::Denied => write!(f, "deny"),
            CanonicalDecision::Error(e) => write!(f, "error:{}", e.code()),
        }
    }
}

/// Single divergence event between the legacy authorizer and the
/// canonical pipeline. Mapped to a one-line audit string by
/// [`DivergenceRecord::to_log_line`]; M4 will graduate this to a
/// structured telemetry event per design §9.3.
struct DivergenceRecord<'a> {
    rule_set_id: &'a str,
    mode: CanonicalMode,
    legacy_decision: bool,
    canon_decision: &'a CanonicalDecision,
    /// The full original `hyper::Uri`. We only log the path+query
    /// portion to keep authority/userinfo (already validated by the
    /// canonical pipeline) out of audit lines.
    request_uri: &'a hyper::Uri,
}

impl<'a> DivergenceRecord<'a> {
    fn to_log_line(&self) -> String {
        // `CANON_DIVERGENCE` is a stable prefix so structured log
        // shippers and ad-hoc grep can both find these. Field order is
        // also part of the contract — append-only.
        let path = self.request_uri.path();
        let query = self.request_uri.query().unwrap_or("");
        let path_and_query = if query.is_empty() {
            path.to_string()
        } else {
            format!("{path}?{query}")
        };
        format!(
            "CANON_DIVERGENCE mode={mode} rule_set={rsid} legacy={legacy} canon={canon} uri={uri:?}",
            mode = self.mode,
            rsid = self.rule_set_id,
            legacy = if self.legacy_decision { "allow" } else { "deny" },
            canon = self.canon_decision,
            uri = path_and_query,
        )
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

/// Remark: Regex::new is performance-sensitive, so we use LazyLock to compile it only once and reuse it for subsequent calls
static AUTHORIZATION_RULES_FILE_SEARCH_REGEX: std::sync::LazyLock<regex::Regex> =
    std::sync::LazyLock::new(|| regex::Regex::new(r"^AuthorizationRules_.*\.json$").unwrap());

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
        let files = match misc_helpers::search_files(
            path_dir,
            &AUTHORIZATION_RULES_FILE_SEARCH_REGEX,
        ) {
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
    use crate::key_keeper::key::{
        AccessControlRules, AuthorizationItem, AuthorizationRules, Identity, Privilege, Role,
        RoleAssignment,
    };
    use crate::proxy::authorization_rules::{
        AuthorizationMode, ComputedAuthorizationItem, AUTHORIZATION_RULES_FILE_SEARCH_REGEX,
    };
    use crate::proxy::{proxy_connection::ConnectionLogger, Claims};
    use proxy_agent_shared::misc_helpers;
    use std::ffi::OsString;
    use std::path::PathBuf;
    use std::str::FromStr;

    #[tokio::test]
    async fn test_authorization_rules() {
        let logger_key = "test_authorization_rules";
        let mut temp_test_path = std::env::temp_dir();
        temp_test_path.push(logger_key);
        let mut test_logger = ConnectionLogger::new(0, 0);

        // Test Enforce Mode
        let access_control_rules = AccessControlRules {
            roles: Some(vec![Role {
                name: "test".to_string(),
                privileges: vec!["test".to_string(), "test1".to_string()],
            }]),
            privileges: Some(vec![Privilege {
                name: "test".to_string(),
                path: "/TEST".to_string(), // test the case insensitivity of the path
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

        // test the case insensitivity of the path
        let url = hyper::Uri::from_str("http://localhost/tESt/test").unwrap();
        assert!(rules.is_allowed(&mut test_logger, url, claims.clone()));

        // test the case insensitivity of the path and the relative url
        let relative_url = hyper::Uri::from_str("/test/test").unwrap();
        assert!(rules.is_allowed(&mut test_logger, relative_url.clone(), claims.clone()));
        claims.userName = "test1".to_string();
        assert!(!rules.is_allowed(&mut test_logger, relative_url, claims.clone()));

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
        assert!(rules.is_allowed(&mut test_logger, url, claims.clone()));
        let relative_url = hyper::Uri::from_str("/test/test1").unwrap();
        assert!(rules.is_allowed(&mut test_logger, relative_url, claims.clone()));

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
        assert!(!rules.is_allowed(&mut test_logger, url, claims.clone()));
        let relativeurl = hyper::Uri::from_str("/test?").unwrap();
        assert!(!rules.is_allowed(&mut test_logger, relativeurl, claims.clone()));
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
                eprintln!("Failed to remove_dir_all with error {}.", e);
            }
        }
        misc_helpers::try_create_folder(&temp_test_path).unwrap();

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
            misc_helpers::search_files(&temp_test_path, &AUTHORIZATION_RULES_FILE_SEARCH_REGEX)
                .unwrap();
        assert_eq!(files.len(), max_file_count);

        // clean up and ignore the clean up errors
        _ = std::fs::remove_dir_all(&temp_test_path);
    }

    #[tokio::test]
    async fn test_percent_encoded_path_must_not_bypass_privilege() {
        let mut test_logger = ConnectionLogger::new(0, 0);

        // Simulate a privilege restricting /metadata/identity/oauth2/token
        let access_control_rules = AccessControlRules {
            roles: Some(vec![Role {
                name: "tokenRole".to_string(),
                privileges: vec!["tokenPrivilege".to_string()],
            }]),
            privileges: Some(vec![Privilege {
                name: "tokenPrivilege".to_string(),
                path: "/metadata/identity/oauth2/token".to_string(),
                queryParameters: None,
            }]),
            identities: Some(vec![Identity {
                name: "trustedUser".to_string(),
                userName: Some("trustyuser".to_string()),
                groupName: None,
                exePath: None,
                processName: None,
            }]),
            roleAssignments: Some(vec![RoleAssignment {
                role: "tokenRole".to_string(),
                identities: vec!["trustedUser".to_string()],
            }]),
        };
        let authorization_item = AuthorizationItem {
            defaultAccess: "allow".to_string(),
            mode: "enforce".to_string(),
            rules: Some(access_control_rules),
            id: "0".to_string(),
        };
        let rules = ComputedAuthorizationItem::from_authorization_item(authorization_item);

        let attacker_claims = Claims {
            userId: 9999,
            userName: "attacker".to_string(),
            userGroups: vec!["users".to_string()],
            processId: 1234,
            processFullPath: PathBuf::from("/usr/bin/curl"),
            clientIp: "127.0.0.1".to_string(),
            clientPort: 12345,
            processName: OsString::from("curl"),
            processCmdLine: "curl".to_string(),
            runAsElevated: false,
        };

        // Normal path is correctly denied for attacker
        let url = hyper::Uri::from_str("http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/").unwrap();
        assert!(
            !rules.is_allowed(&mut test_logger, url, attacker_claims.clone()),
            "Normal path must be denied for attacker"
        );

        // Percent-encoded %2F bypass: must also be denied
        let url_encoded = hyper::Uri::from_str("http://169.254.169.254/metadata/identity/oauth2%2Ftoken?api-version=2018-02-01&resource=https://management.azure.com/").unwrap();
        assert!(
            !rules.is_allowed(&mut test_logger, url_encoded, attacker_claims.clone()),
            "Percent-encoded path (%2F) must NOT bypass privilege matching"
        );

        // Mixed encoding: %2f (lowercase hex) must also be caught
        let url_lower_hex = hyper::Uri::from_str("http://169.254.169.254/metadata/identity/oauth2%2ftoken?api-version=2018-02-01&resource=https://management.azure.com/").unwrap();
        assert!(
            !rules.is_allowed(&mut test_logger, url_lower_hex, attacker_claims.clone()),
            "Percent-encoded path (%2f lowercase) must NOT bypass privilege matching"
        );

        // Trusted user should still be allowed through normal path
        let trusted_claims = Claims {
            userId: 1000,
            userName: "trustyuser".to_string(),
            userGroups: vec!["users".to_string()],
            processId: 5678,
            processFullPath: PathBuf::from("/usr/bin/curl"),
            clientIp: "127.0.0.1".to_string(),
            clientPort: 12345,
            processName: OsString::from("curl"),
            processCmdLine: "curl".to_string(),
            runAsElevated: false,
        };
        let url = hyper::Uri::from_str("http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/").unwrap();
        assert!(
            rules.is_allowed(&mut test_logger, url, trusted_claims.clone()),
            "Trusted user must be allowed through normal path"
        );

        // Trusted user should still be allowed through percent-encoded path (%2F)
        let url = hyper::Uri::from_str("http://169.254.169.254/metadata/identity/oauth2%2Ftoken?api-version=2018-02-01&resource=https://management.azure.com/").unwrap();
        assert!(
            rules.is_allowed(&mut test_logger, url, trusted_claims.clone()),
            "Trusted user must be allowed through percent-encoded path (%2F)"
        );

        // Trusted user should still be allowed through percent-encoded path (%2f) with lowercase hex
        let url = hyper::Uri::from_str("http://169.254.169.254/metadata/identity/oauth2%2ftoken?api-version=2018-02-01&resource=https://management.azure.com/").unwrap();
        assert!(
            rules.is_allowed(&mut test_logger, url, trusted_claims.clone()),
            "Trusted user must be allowed through percent-encoded path (%2f)"
        );
    }

    // ------------------------------------------------------------------
    // Innovation 2.1 M3 — shadow-mode integration tests.
    //
    // These tests verify the new canonical-pipeline evaluator and the
    // shadow comparator added in `ComputedAuthorizationItem`. They do
    // NOT exercise the proxy_authorizer wire-up directly (that needs
    // a live config getter); see `proxy_authorizer::tests` for the
    // outer plumbing.
    //
    // What we pin here:
    //   1. canonical_decision agrees with legacy on a path that does
    //      not exercise canonicalization differences.
    //   2. canonical_decision *disagrees* with legacy on the exact
    //      bypass class M2 was built to catch — substring vs
    //      segment prefix — so shadow telemetry has the signal it
    //      promises in §9.2.
    //   3. canonical_decision returns Error (fail-closed) when the
    //      pipeline rejects the URL, and Display surfaces a stable
    //      `error:<code>` token for the audit log.
    //   4. compile_canonical_patterns drops privileges that cannot be
    //      canonicalized, without taking down the rule load.
    //   5. shadow_compare returns the canonical decision so an
    //      enforce-mode caller can use it (M5/M6 hand-off).
    // ------------------------------------------------------------------

    use crate::proxy::authorization_rules::CanonicalDecision;
    use crate::proxy::canonical::{CanonError, CanonicalMode};

    /// Builds a single-privilege rule set: privilege path `/test` is
    /// granted to one identity named "trusted". Default-deny.
    fn build_test_rules(privilege_path: &str) -> ComputedAuthorizationItem {
        let access_control_rules = AccessControlRules {
            roles: Some(vec![Role {
                name: "r".to_string(),
                privileges: vec!["test".to_string()],
            }]),
            privileges: Some(vec![Privilege {
                name: "test".to_string(),
                path: privilege_path.to_string(),
                queryParameters: None,
            }]),
            identities: Some(vec![Identity {
                name: "trusted".to_string(),
                userName: Some("trusted-user".to_string()),
                groupName: None,
                exePath: None,
                processName: None,
            }]),
            roleAssignments: Some(vec![RoleAssignment {
                role: "r".to_string(),
                identities: vec!["trusted".to_string()],
            }]),
        };
        let authorization_item = AuthorizationItem {
            defaultAccess: "deny".to_string(),
            mode: "enforce".to_string(),
            rules: Some(access_control_rules),
            id: "test-rs".to_string(),
        };
        ComputedAuthorizationItem::from_authorization_item(authorization_item)
    }

    fn trusted_claims() -> Claims {
        Claims {
            userId: 0,
            userName: "trusted-user".to_string(),
            userGroups: vec![],
            processId: 0,
            processFullPath: PathBuf::from("p"),
            clientIp: "0".to_string(),
            clientPort: 0,
            processName: OsString::from("p"),
            processCmdLine: "p".to_string(),
            runAsElevated: true,
        }
    }

    #[test]
    fn canonical_decision_agrees_with_legacy_on_clean_paths() {
        // Sanity: when nothing in the URL exercises a canonical-vs-
        // substring difference, the two evaluators must agree. If this
        // ever flips, every shadow log line becomes noise and we lose
        // the M3 signal. So this is a regression net for both sides.
        let rules = build_test_rules("/test");
        let claims = trusted_claims();
        let mut log = ConnectionLogger::new(0, 0);

        let cases: &[(&str, bool)] = &[
            // (uri, expected_allowed)
            ("http://169.254.169.254/test/x", true),
            ("http://169.254.169.254/test", true),
            // not under /test -> default deny
            ("http://169.254.169.254/other", false),
        ];
        for (uri_str, expected) in cases {
            let uri = hyper::Uri::from_str(uri_str).unwrap();
            let legacy = rules.is_allowed(&mut log, uri.clone(), claims.clone());
            let canon = rules.canonical_decision(&mut log, &uri, &hyper::Method::GET, &claims);
            assert_eq!(legacy, *expected, "legacy verdict for {uri_str}");
            assert_eq!(
                canon.allowed_or_fail_closed(),
                *expected,
                "canonical verdict for {uri_str}"
            );
            assert_eq!(
                legacy,
                canon.allowed_or_fail_closed(),
                "shadow drift for {uri_str}"
            );
        }
    }

    #[test]
    fn canonical_decision_diverges_on_substring_vs_segment_prefix() {
        // THE M3 motivating divergence. Legacy `Privilege::is_match`
        // uses `starts_with` -> `/test-evil/x` is "under /test" by
        // substring. Canonical does segment-by-segment prefix
        // matching -> `/test-evil/x` is NOT under `/test`. Shadow mode
        // exists to report this exact class.
        let rules = build_test_rules("/test");
        let claims = trusted_claims();
        let mut log = ConnectionLogger::new(0, 0);

        let uri = hyper::Uri::from_str("http://169.254.169.254/test-evil/anything").unwrap();
        let legacy = rules.is_allowed(&mut log, uri.clone(), claims.clone());
        let canon = rules.canonical_decision(&mut log, &uri, &hyper::Method::GET, &claims);

        // Legacy is buggy here (allows the SSRF-shaped path).
        assert!(
            legacy,
            "legacy substring match should still allow /test-evil; if this fails, legacy was fixed and this test should be retired"
        );
        // Canonical correctly denies.
        assert_eq!(
            canon,
            CanonicalDecision::Denied,
            "canonical segment match must deny /test-evil"
        );
        // The shape we'll feed to telemetry:
        assert_ne!(
            legacy,
            canon.allowed_or_fail_closed(),
            "this is the divergence shadow mode must surface"
        );
    }

    #[test]
    fn canonical_decision_returns_error_for_userinfo_url() {
        // Userinfo in the authority -> canonical rejects at the
        // pipeline entry with UserinfoPresent. The decision must
        // collapse to fail-closed and Display must surface the stable
        // error code so audit logs can grep for it.
        let rules = build_test_rules("/test");
        let claims = trusted_claims();
        let mut log = ConnectionLogger::new(0, 0);

        // Build via hyper to avoid relying on whether `from_str`
        // accepts the userinfo form.
        let uri: hyper::Uri = match "http://attacker@169.254.169.254/test".parse() {
            Ok(u) => u,
            Err(_) => {
                // Hyper may refuse to parse this -> nothing to test.
                eprintln!("hyper refused to parse userinfo URL; skipping");
                return;
            }
        };
        let canon = rules.canonical_decision(&mut log, &uri, &hyper::Method::GET, &claims);
        assert_eq!(
            canon,
            CanonicalDecision::Error(CanonError::UserinfoPresent),
            "canonical must surface UserinfoPresent (got {canon:?})"
        );
        assert!(!canon.allowed_or_fail_closed(), "errors must fail-closed");
        // The audit-log token shape is part of the §9.2 telemetry
        // contract — keep it stable across refactors.
        assert_eq!(canon.to_string(), "error:CANON_USERINFO");
    }

    #[test]
    fn shadow_compare_returns_canonical_decision_for_enforce_handoff() {
        // shadow_compare's return value is the M5/M6 hand-off: the
        // enforce-mode caller will use it as the decision once the
        // shadow window proves zero divergences. We pin its
        // semantics here so a future enforce wiring doesn't get a
        // surprise.
        let rules = build_test_rules("/test");
        let claims = trusted_claims();
        let mut log = ConnectionLogger::new(0, 0);

        // Divergent case: legacy=true (substring), canon=Denied.
        let uri = hyper::Uri::from_str("http://169.254.169.254/test-evil/anything").unwrap();
        let legacy_allowed = true;
        let canon = rules.shadow_compare(
            &mut log,
            &uri,
            &hyper::Method::GET,
            &claims,
            legacy_allowed,
            CanonicalMode::Shadow,
        );
        assert_eq!(
            canon,
            CanonicalDecision::Denied,
            "shadow_compare must return the canonical verdict"
        );
    }

    #[test]
    fn compile_canonical_patterns_drops_uncanonicalizable_rules() {
        // A privilege whose path can't be canonicalized must NOT
        // brick the whole rule-load — the legacy matcher still has
        // its copy and the canonical cache simply skips it. This is
        // exactly the asymmetry shadow mode is designed to surface.
        //
        // We use an overlong %C0%AF (canonically `/`) which the
        // pipeline rejects with OverlongUtf8.
        let rules = build_test_rules("/x%C0%AFy");

        // Legacy still sees the privilege:
        assert_eq!(rules.privileges.len(), 1);
        // Canonical cache dropped it:
        assert_eq!(
            rules.canonical_patterns.len(),
            0,
            "uncanonicalizable privilege must be skipped from canonical cache"
        );
    }
}
