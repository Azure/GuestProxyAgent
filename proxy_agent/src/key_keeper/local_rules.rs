// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

use crate::common::error::Error;
use crate::common::logger;
use crate::common::result::Result;
use crate::key_keeper::key::{
    AccessControlRules, AuthorizationItem, Identity, Privilege, Role, RoleAssignment,
};
use base64::{engine::general_purpose, Engine as _};
use proxy_agent_shared::logger::LoggerLevel;
use proxy_agent_shared::misc_helpers;
use proxy_agent_shared::telemetry::event_logger;
use serde_derive::Deserialize;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

pub(crate) const LOCAL_RULE_FILE_PARSE_RETRY_COUNT: usize = 3;
pub(crate) const LOCAL_RULE_FILE_PARSE_RETRY_DELAY: Duration = Duration::from_millis(50);

#[derive(Clone, Copy)]
pub(crate) enum LocalRuleTarget {
    WireServer,
    Imds,
}

impl LocalRuleTarget {
    pub(crate) fn display_name(self) -> &'static str {
        match self {
            LocalRuleTarget::WireServer => "WireServer",
            LocalRuleTarget::Imds => "IMDS",
        }
    }

    pub(crate) fn file_name(self) -> &'static str {
        match self {
            LocalRuleTarget::WireServer => "WireServer_Rules.json",
            LocalRuleTarget::Imds => "IMDS_Rules.json",
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) enum LocalRuleFileState {
    #[default]
    Unknown,
    Error(String),
    Missing,
    Present(SystemTime),
}

#[derive(Clone, Default)]
pub(crate) struct LocalRuleMonitorState {
    pub(crate) use_local_file_rules: bool,
    pub(crate) file_state: LocalRuleFileState,
    pub(crate) parse_failed: bool,
    pub(crate) effective_rules: Option<AuthorizationItem>,
}

#[derive(Default)]
pub(crate) struct LocalRuleStateTracker {
    pub(crate) wireserver: LocalRuleMonitorState,
    pub(crate) imds: LocalRuleMonitorState,
}

#[derive(Default)]
pub(crate) struct RuleIdDescriptor {
    pub(crate) logical_id: String,
    pub(crate) use_local_file_rules: bool,
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct EncodedRuleId {
    #[serde(default)]
    id: String,
    #[serde(default)]
    useLocalFileRules: bool,
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
pub(crate) struct LocalAuthorizationRulesFile {
    #[serde(default)]
    pub(crate) defaultAccess: Option<String>,
    #[serde(default)]
    pub(crate) id: Option<String>,
    #[serde(default)]
    pub(crate) rules: Option<AccessControlRules>,
}

/// As the rules folder is a sibling folder of the key folder,
/// get the rules folder path based on the key folder path.
pub(crate) fn get_rules_dir_from_key_dir(key_dir: &Path) -> PathBuf {
    let folder_name = if cfg!(windows) { "Rules" } else { "rules" };
    match key_dir.parent() {
        Some(parent) => parent.join(folder_name),
        None => key_dir.join(folder_name),
    }
}

/// Get the state of the local rule file - whether it is present or missing, and if present, its last modified time.
pub(crate) fn get_local_rule_file_state(file_path: &Path) -> LocalRuleFileState {
    match fs::metadata(file_path) {
        Ok(metadata) => match metadata.modified() {
            Ok(modified) => LocalRuleFileState::Present(modified),
            Err(_) => LocalRuleFileState::Present(SystemTime::UNIX_EPOCH),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => LocalRuleFileState::Missing,
        Err(e) => LocalRuleFileState::Error(format!(
            "Unexpected error reading local rules file metadata: {e}"
        )),
    }
}

/// Parse the rule ID descriptor from the raw rule ID string.
/// The raw rule ID can be either a plain logical ID or
/// a base64-encoded JSON string containing the logical ID and whether to use local file rules.
pub(crate) fn parse_rule_id_descriptor(raw_rule_id: Option<&str>) -> RuleIdDescriptor {
    let raw_rule_id = raw_rule_id.unwrap_or_default().trim();
    if raw_rule_id.is_empty() {
        return RuleIdDescriptor::default();
    }

    if let Ok(decoded) = general_purpose::STANDARD.decode(raw_rule_id) {
        if let Ok(contract) = serde_json::from_slice::<EncodedRuleId>(&decoded) {
            return RuleIdDescriptor {
                logical_id: contract.id,
                use_local_file_rules: contract.useLocalFileRules,
            };
        }
    }

    // If parsing fails, treat the raw rule ID as the logical ID and do not use local file rules.
    RuleIdDescriptor {
        logical_id: raw_rule_id.to_string(),
        use_local_file_rules: false,
    }
}

pub(crate) fn normalize_authorization_item(
    authorization_item: Option<AuthorizationItem>,
    descriptor: &RuleIdDescriptor,
) -> Option<AuthorizationItem> {
    authorization_item.map(|mut item| {
        if !descriptor.logical_id.is_empty() {
            item.id = descriptor.logical_id.clone();
        }
        item
    })
}

pub(crate) fn merge_authorization_item(
    remote_rules: Option<AuthorizationItem>,
    local_rules: LocalAuthorizationRulesFile,
    descriptor: &RuleIdDescriptor,
) -> Option<AuthorizationItem> {
    let mut merged_item = remote_rules.unwrap_or(AuthorizationItem {
        defaultAccess: "deny".to_string(),
        mode: "disabled".to_string(),
        id: descriptor.logical_id.clone(),
        rules: None,
    });

    if !descriptor.logical_id.is_empty() {
        merged_item.id = descriptor.logical_id.clone();
    }

    if let Some(default_access) = local_rules.defaultAccess {
        merged_item.defaultAccess = default_access;
    }

    merged_item.rules = merge_access_control_rules(merged_item.rules, local_rules.rules);
    Some(merged_item)
}

fn merge_access_control_rules(
    remote_rules: Option<AccessControlRules>,
    local_rules: Option<AccessControlRules>,
) -> Option<AccessControlRules> {
    match (remote_rules, local_rules) {
        (None, None) => None,
        (Some(rules), None) | (None, Some(rules)) => Some(rules),
        (Some(remote), Some(local)) => Some(AccessControlRules {
            privileges: merge_rule_vectors(remote.privileges, local.privileges),
            roles: merge_rule_vectors(remote.roles, local.roles),
            identities: merge_rule_vectors(remote.identities, local.identities),
            roleAssignments: merge_rule_vectors(remote.roleAssignments, local.roleAssignments),
        }),
    }
}

fn merge_rule_vectors<T>(remote: Option<Vec<T>>, local: Option<Vec<T>>) -> Option<Vec<T>> {
    match (remote, local) {
        (None, None) => None,
        (Some(values), None) | (None, Some(values)) => Some(values),
        (Some(mut remote_values), Some(mut local_values)) => {
            remote_values.append(&mut local_values);
            Some(remote_values)
        }
    }
}

/// SPEC: Failed to parse file after retries - block all the proxied requests to corresponding host service,
/// In case of local rules file parse failure, build fail-closed rules which deny all access.
/// This ensures that if there is an issue with the local rules file,
/// we do not accidentally allow access due to fallback to remote rules which might be more permissive.
/// The fail-closed rules will keep the same logical ID as the remote rules (if any) for better traceability,
/// but will set defaultAccess to "deny" and remove all specific rules.
pub(crate) fn build_fail_closed_rules(
    remote_rules: Option<AuthorizationItem>,
    descriptor: &RuleIdDescriptor,
) -> Option<AuthorizationItem> {
    let mut rules = remote_rules.unwrap_or(AuthorizationItem {
        defaultAccess: "deny".to_string(),
        mode: "enforce".to_string(),
        id: descriptor.logical_id.clone(),
        rules: None,
    });

    if !descriptor.logical_id.is_empty() {
        rules.id = descriptor.logical_id.clone();
    }

    // block all the requests by setting defaultAccess to deny and removing all specific rules,
    // regardless of what the remote rules are.
    rules.defaultAccess = "deny".to_string();
    rules.rules = None;

    Some(rules)
}

fn validate_local_rules_file(local_rules: &LocalAuthorizationRulesFile) -> Result<()> {
    if let Some(default_access) = &local_rules.defaultAccess {
        if !matches!(default_access.trim(), "allow" | "deny") {
            return Err(Error::Invalid(format!(
                "local rules defaultAccess must be 'allow' or 'deny', got '{}'",
                default_access
            )));
        }
    }

    if let Some(id) = &local_rules.id {
        if id.trim().is_empty() {
            return Err(Error::Invalid(
                "local rules id cannot be empty when provided".to_string(),
            ));
        }
    }

    if let Some(rules) = &local_rules.rules {
        validate_access_control_rules(rules)?;
    }

    Ok(())
}

fn validate_access_control_rules(rules: &AccessControlRules) -> Result<()> {
    let privilege_names = validate_privileges(rules.privileges.as_ref())?;
    let role_names = validate_roles(rules.roles.as_ref(), &privilege_names)?;
    let identity_names = validate_identities(rules.identities.as_ref())?;
    validate_role_assignments(rules.roleAssignments.as_ref(), &role_names, &identity_names)?;
    Ok(())
}

fn validate_privileges(privileges: Option<&Vec<Privilege>>) -> Result<HashSet<String>> {
    let mut names = HashSet::new();
    if let Some(privileges) = privileges {
        for privilege in privileges {
            if privilege.name.trim().is_empty() {
                return Err(Error::Invalid("privilege name cannot be empty".to_string()));
            }
            if privilege.path.trim().is_empty() {
                return Err(Error::Invalid(format!(
                    "privilege '{}' path cannot be empty",
                    privilege.name
                )));
            }
            if !names.insert(privilege.name.clone()) {
                return Err(Error::Invalid(format!(
                    "duplicate privilege name '{}'",
                    privilege.name
                )));
            }
            if let Some(query_parameters) = &privilege.queryParameters {
                for (key, value) in query_parameters {
                    if key.trim().is_empty() || value.trim().is_empty() {
                        return Err(Error::Invalid(format!(
                            "privilege '{}' queryParameters cannot contain empty keys or values",
                            privilege.name
                        )));
                    }
                }
            }
        }
    }
    Ok(names)
}

fn validate_roles(
    roles: Option<&Vec<Role>>,
    privilege_names: &HashSet<String>,
) -> Result<HashSet<String>> {
    let mut names = HashSet::new();
    if let Some(roles) = roles {
        for role in roles {
            if role.name.trim().is_empty() {
                return Err(Error::Invalid("role name cannot be empty".to_string()));
            }
            if role.privileges.is_empty() {
                return Err(Error::Invalid(format!(
                    "role '{}' must reference at least one privilege",
                    role.name
                )));
            }
            if !names.insert(role.name.clone()) {
                return Err(Error::Invalid(format!(
                    "duplicate role name '{}'",
                    role.name
                )));
            }

            let mut referenced_privileges = HashSet::new();
            for privilege_name in &role.privileges {
                if privilege_name.trim().is_empty() {
                    return Err(Error::Invalid(format!(
                        "role '{}' contains an empty privilege reference",
                        role.name
                    )));
                }
                if !referenced_privileges.insert(privilege_name.clone()) {
                    return Err(Error::Invalid(format!(
                        "role '{}' contains duplicate privilege reference '{}'",
                        role.name, privilege_name
                    )));
                }
                if !privilege_names.contains(privilege_name) {
                    return Err(Error::Invalid(format!(
                        "role '{}' references unknown privilege '{}'",
                        role.name, privilege_name
                    )));
                }
            }
        }
    }
    Ok(names)
}

fn validate_identities(identities: Option<&Vec<Identity>>) -> Result<HashSet<String>> {
    let mut names = HashSet::new();
    if let Some(identities) = identities {
        for identity in identities {
            if identity.name.trim().is_empty() {
                return Err(Error::Invalid("identity name cannot be empty".to_string()));
            }
            if !names.insert(identity.name.clone()) {
                return Err(Error::Invalid(format!(
                    "duplicate identity name '{}'",
                    identity.name
                )));
            }

            let selectors = [
                identity.userName.as_deref(),
                identity.groupName.as_deref(),
                identity.exePath.as_deref(),
                identity.processName.as_deref(),
            ];
            let has_selector = selectors
                .into_iter()
                .flatten()
                .any(|value| !value.trim().is_empty());
            if !has_selector {
                return Err(Error::Invalid(format!(
                    "identity '{}' must specify at least one selector",
                    identity.name
                )));
            }
        }
    }
    Ok(names)
}

fn validate_role_assignments(
    role_assignments: Option<&Vec<RoleAssignment>>,
    role_names: &HashSet<String>,
    identity_names: &HashSet<String>,
) -> Result<()> {
    if let Some(role_assignments) = role_assignments {
        for role_assignment in role_assignments {
            if role_assignment.role.trim().is_empty() {
                return Err(Error::Invalid(
                    "roleAssignment role cannot be empty".to_string(),
                ));
            }
            if !role_names.contains(&role_assignment.role) {
                return Err(Error::Invalid(format!(
                    "roleAssignment references unknown role '{}'",
                    role_assignment.role
                )));
            }
            if role_assignment.identities.is_empty() {
                return Err(Error::Invalid(format!(
                    "roleAssignment for role '{}' must reference at least one identity",
                    role_assignment.role
                )));
            }

            let mut referenced_identities = HashSet::new();
            for identity_name in &role_assignment.identities {
                if identity_name.trim().is_empty() {
                    return Err(Error::Invalid(format!(
                        "roleAssignment for role '{}' contains an empty identity reference",
                        role_assignment.role
                    )));
                }
                if !referenced_identities.insert(identity_name.clone()) {
                    return Err(Error::Invalid(format!(
                        "roleAssignment for role '{}' contains duplicate identity reference '{}'",
                        role_assignment.role, identity_name
                    )));
                }
                if !identity_names.contains(identity_name) {
                    return Err(Error::Invalid(format!(
                        "roleAssignment for role '{}' references unknown identity '{}'",
                        role_assignment.role, identity_name
                    )));
                }
            }
        }
    }
    Ok(())
}

pub(crate) async fn read_local_rules_file(
    file_path: &Path,
    target: LocalRuleTarget,
) -> Result<LocalAuthorizationRulesFile> {
    let mut last_error = String::new();
    for attempt in 1..=LOCAL_RULE_FILE_PARSE_RETRY_COUNT {
        match misc_helpers::json_read_from_file::<LocalAuthorizationRulesFile>(file_path) {
            Ok(local_rules) => {
                validate_local_rules_file(&local_rules)?;

                let message = format!(
                    "Successfully parsed {} local rules file {} with id '{}' on attempt {}.",
                    target.display_name(),
                    file_path.display(),
                    local_rules.id.as_deref().unwrap_or("unknown"),
                    attempt
                );
                write_local_rules_event(
                    LoggerLevel::Info,
                    target,
                    "LocalRulesFileParseSuccess",
                    message,
                );

                return Ok(local_rules);
            }
            Err(e) => {
                last_error = e.to_string();
                logger::write_warning(format!(
                    "Failed to parse {} local rules file {} on attempt {}: {}",
                    target.display_name(),
                    file_path.display(),
                    attempt,
                    last_error
                ));
                if attempt < LOCAL_RULE_FILE_PARSE_RETRY_COUNT {
                    tokio::time::sleep(LOCAL_RULE_FILE_PARSE_RETRY_DELAY).await;
                }
            }
        }
    }

    Err(Error::Invalid(format!(
        "Failed to parse local rules file '{}' after {} attempts: {}",
        file_path.display(),
        LOCAL_RULE_FILE_PARSE_RETRY_COUNT,
        last_error
    )))
}

/// Resolve the effective authorization rules by considering both remote rules and local file rules based on the descriptor and current state.
pub(crate) async fn resolve_effective_rules(
    rules_dir: &Path,
    remote_rules: Option<AuthorizationItem>,
    target: LocalRuleTarget,
    tracker: &mut LocalRuleMonitorState,
    remote_rule_changed: bool,
) -> (Option<AuthorizationItem>, bool) {
    let descriptor = parse_rule_id_descriptor(remote_rules.as_ref().map(|item| item.id.as_str()));
    let normalized_remote_rules = normalize_authorization_item(remote_rules, &descriptor);
    let use_local_file_rules_changed =
        tracker.use_local_file_rules != descriptor.use_local_file_rules;
    let previous_parse_failed = tracker.parse_failed;

    if use_local_file_rules_changed {
        let action = if descriptor.use_local_file_rules {
            "enabled"
        } else {
            "disabled"
        };
        write_local_rules_event(
            LoggerLevel::Info,
            target,
            "LocalFileRulesStateChanged",
            format!("{} local file rules {action}.", target.display_name()),
        );
    }

    tracker.use_local_file_rules = descriptor.use_local_file_rules;
    if !descriptor.use_local_file_rules {
        // not using local file rules, return normalized remote rules directly.
        // also reset the tracker state as we are not monitoring local file changes in this case.
        tracker.file_state = LocalRuleFileState::Unknown;
        tracker.parse_failed = false;
        tracker.effective_rules = normalized_remote_rules.clone();
        return (
            normalized_remote_rules,
            use_local_file_rules_changed || previous_parse_failed,
        );
    }

    let local_rules_file = rules_dir.join(target.file_name());
    let current_file_state = get_local_rule_file_state(&local_rules_file);
    let file_state_changed = tracker.file_state != current_file_state;

    if file_state_changed {
        match (&tracker.file_state, &current_file_state) {
            (_, LocalRuleFileState::Present(_))
                if matches!(
                    tracker.file_state,
                    LocalRuleFileState::Unknown | LocalRuleFileState::Missing
                ) =>
            {
                write_local_rules_event(
                    LoggerLevel::Info,
                    target,
                    "LocalFileRulesStateChanged",
                    format!(
                        "{} local rules file found at {}.",
                        target.display_name(),
                        local_rules_file.display()
                    ),
                );
            }
            (LocalRuleFileState::Present(_), LocalRuleFileState::Present(_)) => {
                write_local_rules_event(
                    LoggerLevel::Info,
                    target,
                    "LocalFileRulesStateChanged",
                    format!(
                        "{} local rules file changed at {}.",
                        target.display_name(),
                        local_rules_file.display()
                    ),
                );
            }
            (_, LocalRuleFileState::Missing) => {
                write_local_rules_event(
                    LoggerLevel::Warn,
                    target,
                    "LocalFileRulesStateChanged",
                    format!(
                        "{} local rules file deleted or not found at {}.",
                        target.display_name(),
                        local_rules_file.display()
                    ),
                );
            }
            (_, LocalRuleFileState::Error(error)) => {
                write_local_rules_event(
                    LoggerLevel::Error,
                    target,
                    "LocalFileRulesStateChanged",
                    format!(
                        "{} local rules file metadata read failed at {}: {}",
                        target.display_name(),
                        local_rules_file.display(),
                        error
                    ),
                );
            }
            _ => {}
        }
    }

    tracker.file_state = current_file_state.clone();
    let needs_refresh = remote_rule_changed
        || use_local_file_rules_changed
        || file_state_changed
        || previous_parse_failed;

    if !needs_refresh {
        return (tracker.effective_rules.clone(), false);
    }

    // SPEC: No corresponding rule file found - treat it as no advanced configuration set yet, which means root-only to WS and all to IMDS.
    // This is to support new VM just provisioned and the customer payload has not downloaded & applied within the VM yet.
    if matches!(current_file_state, LocalRuleFileState::Missing) {
        tracker.parse_failed = false;
        tracker.effective_rules = None;
        return (
            None,
            use_local_file_rules_changed || file_state_changed || previous_parse_failed,
        );
    }

    if let LocalRuleFileState::Error(error) = &current_file_state {
        let message = format!(
            "Failed to read {} local rules file metadata {}: {}. Treat it as parse failure and apply fail-closed rules.",
            target.display_name(),
            local_rules_file.display(),
            error
        );
        write_local_rules_event(
            LoggerLevel::Error,
            target,
            "LocalRulesFileMetadataReadFailed",
            message,
        );

        let fail_closed_rules = build_fail_closed_rules(normalized_remote_rules, &descriptor);
        tracker.parse_failed = true;
        tracker.effective_rules = fail_closed_rules.clone();
        return (fail_closed_rules, true);
    }

    match read_local_rules_file(&local_rules_file, target).await {
        Ok(local_rules) => {
            let effective_rules =
                merge_authorization_item(normalized_remote_rules, local_rules, &descriptor);
            tracker.parse_failed = false;
            tracker.effective_rules = effective_rules.clone();
            (
                effective_rules,
                use_local_file_rules_changed || file_state_changed || previous_parse_failed,
            )
        }
        Err(e) => {
            let message = format!(
                "Failed to parse {} local rules file {}: {}. Apply fail-closed rules.",
                target.display_name(),
                local_rules_file.display(),
                e
            );
            write_local_rules_event(
                LoggerLevel::Error,
                target,
                "LocalRulesFileParseFailed",
                message,
            );

            let fail_closed_rules = build_fail_closed_rules(normalized_remote_rules, &descriptor);
            tracker.parse_failed = true;
            tracker.effective_rules = fail_closed_rules.clone();
            (fail_closed_rules, true)
        }
    }
}

pub(crate) fn write_local_rules_event(
    level: LoggerLevel,
    target: LocalRuleTarget,
    method_name: &str,
    message: String,
) {
    event_logger::write_event(
        level,
        message,
        method_name,
        target.display_name(),
        logger::AGENT_LOGGER_KEY,
    );
}

#[cfg(test)]
mod tests {
    use super::{
        get_rules_dir_from_key_dir, merge_authorization_item, parse_rule_id_descriptor,
        read_local_rules_file, resolve_effective_rules, validate_access_control_rules,
        validate_identities, validate_privileges, validate_role_assignments, validate_roles,
        LocalAuthorizationRulesFile, LocalRuleMonitorState, LocalRuleTarget, RuleIdDescriptor,
    };
    use crate::key_keeper::key::{
        AccessControlRules, AuthorizationItem, Identity, Privilege, Role, RoleAssignment,
    };
    use base64::{engine::general_purpose, Engine as _};
    use proxy_agent_shared::misc_helpers;
    use std::collections::HashSet;
    use std::env;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn create_temp_rules_dir(test_name: &str) -> PathBuf {
        let mut dir = env::temp_dir();
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        dir.push(format!("local_rules_{test_name}_{nonce}"));
        _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_file(path: &Path, content: &str) {
        fs::write(path, content).unwrap();
    }

    fn encoded_rule_id(logical_id: &str) -> String {
        general_purpose::STANDARD.encode(format!(
            r#"{{"id":"{logical_id}","useLocalFileRules":true}}"#
        ))
    }

    fn sample_privilege(name: &str) -> Privilege {
        Privilege {
            name: name.to_string(),
            path: format!("/{name}"),
            queryParameters: None,
        }
    }

    fn sample_role(name: &str, privileges: Vec<&str>) -> Role {
        Role {
            name: name.to_string(),
            privileges: privileges.into_iter().map(str::to_string).collect(),
        }
    }

    fn sample_identity(name: &str) -> Identity {
        Identity {
            name: name.to_string(),
            userName: Some(name.to_string()),
            groupName: None,
            exePath: None,
            processName: None,
        }
    }

    fn sample_role_assignment(role: &str, identities: Vec<&str>) -> RoleAssignment {
        RoleAssignment {
            role: role.to_string(),
            identities: identities.into_iter().map(str::to_string).collect(),
        }
    }

    fn sample_access_control_rules() -> AccessControlRules {
        AccessControlRules {
            privileges: Some(vec![sample_privilege("p1")]),
            roles: Some(vec![sample_role("r1", vec!["p1"])]),
            identities: Some(vec![sample_identity("i1")]),
            roleAssignments: Some(vec![sample_role_assignment("r1", vec!["i1"])]),
        }
    }

    fn string_set(values: &[&str]) -> HashSet<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    fn assert_validation_ok<T>(result: crate::common::result::Result<T>) -> T {
        result.unwrap()
    }

    fn assert_validation_err<T>(result: crate::common::result::Result<T>) {
        assert!(result.is_err());
    }

    fn assert_names_match(actual: HashSet<String>, expected: &[&str]) {
        assert_eq!(actual, string_set(expected));
    }

    fn write_wireserver_rules_file(rules_dir: &Path, content: &str) -> PathBuf {
        let rules_file = rules_dir.join(LocalRuleTarget::WireServer.file_name());
        write_file(&rules_file, content);
        rules_file
    }

    async fn run_read_wireserver_rules_file_case(
        test_name: &str,
        content: &str,
    ) -> crate::common::result::Result<LocalAuthorizationRulesFile> {
        ensure_test_config_in_exe_dir();
        let rules_dir = create_temp_rules_dir(test_name);
        let rules_file = write_wireserver_rules_file(&rules_dir, content);
        let result = read_local_rules_file(&rules_file, LocalRuleTarget::WireServer).await;
        _ = fs::remove_dir_all(&rules_dir);
        result
    }

    async fn run_resolve_wireserver_case(
        test_name: &str,
        local_file_content: Option<&str>,
        remote_default_access: &str,
        remote_rules: Option<AccessControlRules>,
        remote_rule_changed: bool,
    ) -> (Option<AuthorizationItem>, bool, LocalRuleMonitorState) {
        ensure_test_config_in_exe_dir();
        let rules_dir = create_temp_rules_dir(test_name);
        if let Some(content) = local_file_content {
            _ = write_wireserver_rules_file(&rules_dir, content);
        }

        let remote_rules = Some(AuthorizationItem {
            defaultAccess: remote_default_access.to_string(),
            mode: "enforce".to_string(),
            id: encoded_rule_id("decoded-id"),
            rules: remote_rules,
        });
        let mut tracker = LocalRuleMonitorState::default();

        let result = resolve_effective_rules(
            &rules_dir,
            remote_rules,
            LocalRuleTarget::WireServer,
            &mut tracker,
            remote_rule_changed,
        )
        .await;

        _ = fs::remove_dir_all(&rules_dir);
        (result.0, result.1, tracker)
    }

    fn ensure_test_config_in_exe_dir() {
        let mut config_target = misc_helpers::get_current_exe_dir();
        #[cfg(windows)]
        config_target.push("GuestProxyAgent.json");
        #[cfg(not(windows))]
        config_target.push("proxy-agent.json");

        if config_target.exists() {
            return;
        }

        let mut config_source = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        config_source.push("config");
        #[cfg(windows)]
        config_source.push("GuestProxyAgent.windows.json");
        #[cfg(not(windows))]
        config_source.push("GuestProxyAgent.linux.json");

        let config_content = fs::read_to_string(config_source).unwrap();
        fs::write(config_target, config_content).unwrap();
    }

    #[test]
    fn parse_rule_id_descriptor_test() {
        let legacy = parse_rule_id_descriptor(Some("legacy-id"));
        assert_eq!(legacy.logical_id, "legacy-id");
        assert!(!legacy.use_local_file_rules);

        let encoded = general_purpose::STANDARD
            .encode(r#"{"id":"sig-resource-id","useLocalFileRules":true}"#);
        let descriptor = parse_rule_id_descriptor(Some(&encoded));
        assert_eq!(descriptor.logical_id, "sig-resource-id");
        assert!(descriptor.use_local_file_rules);
    }

    #[test]
    fn get_rules_dir_from_key_dir_test() {
        #[cfg(windows)]
        assert_eq!(
            get_rules_dir_from_key_dir(Path::new("C:\\WindowsAzure\\ProxyAgent\\Keys")),
            PathBuf::from("C:\\WindowsAzure\\ProxyAgent\\Rules")
        );

        #[cfg(not(windows))]
        assert_eq!(
            get_rules_dir_from_key_dir(Path::new("/var/lib/azure-proxy-agent/keys")),
            PathBuf::from("/var/lib/azure-proxy-agent/rules")
        );
    }

    #[test]
    fn merge_authorization_item_test() {
        let remote_rules = AuthorizationItem {
            defaultAccess: "deny".to_string(),
            mode: "enforce".to_string(),
            id: "remote-id".to_string(),
            rules: Some(AccessControlRules {
                privileges: Some(vec![Privilege {
                    name: "remote-privilege".to_string(),
                    path: "/remote".to_string(),
                    queryParameters: None,
                }]),
                roles: Some(vec![Role {
                    name: "remote-role".to_string(),
                    privileges: vec!["remote-privilege".to_string()],
                }]),
                identities: Some(vec![Identity {
                    name: "remote-identity".to_string(),
                    userName: Some("root".to_string()),
                    groupName: None,
                    exePath: None,
                    processName: None,
                }]),
                roleAssignments: Some(vec![RoleAssignment {
                    role: "remote-role".to_string(),
                    identities: vec!["remote-identity".to_string()],
                }]),
            }),
        };
        let descriptor = RuleIdDescriptor {
            logical_id: "decoded-id".to_string(),
            use_local_file_rules: true,
        };
        let local_rules = LocalAuthorizationRulesFile {
            id: Some("local-id".to_string()),
            defaultAccess: Some("allow".to_string()),
            rules: Some(AccessControlRules {
                privileges: Some(vec![Privilege {
                    name: "local-privilege".to_string(),
                    path: "/local".to_string(),
                    queryParameters: None,
                }]),
                roles: Some(vec![Role {
                    name: "local-role".to_string(),
                    privileges: vec!["local-privilege".to_string()],
                }]),
                identities: Some(vec![Identity {
                    name: "local-identity".to_string(),
                    userName: Some("agent".to_string()),
                    groupName: None,
                    exePath: None,
                    processName: None,
                }]),
                roleAssignments: Some(vec![RoleAssignment {
                    role: "local-role".to_string(),
                    identities: vec!["local-identity".to_string()],
                }]),
            }),
        };

        let merged =
            merge_authorization_item(Some(remote_rules), local_rules, &descriptor).unwrap();
        assert_eq!(merged.id, "decoded-id");
        assert_eq!(merged.defaultAccess, "allow");
        let merged_rules = merged.rules.unwrap();
        assert_eq!(merged_rules.privileges.unwrap().len(), 2);
        assert_eq!(merged_rules.roles.unwrap().len(), 2);
        assert_eq!(merged_rules.identities.unwrap().len(), 2);
        assert_eq!(merged_rules.roleAssignments.unwrap().len(), 2);
    }

    #[test]
    fn validate_access_control_rules_success_test() {
        let rules = sample_access_control_rules();
        assert_validation_ok(validate_access_control_rules(&rules));
    }

    #[test]
    fn validate_access_control_rules_invalid_role_assignment_test() {
        let mut rules = sample_access_control_rules();
        rules.roleAssignments = Some(vec![sample_role_assignment("missing-role", vec!["i1"])]);

        assert_validation_err(validate_access_control_rules(&rules));
    }

    #[test]
    fn validate_privileges_success_test() {
        let privileges = vec![sample_privilege("p1"), sample_privilege("p2")];
        let privilege_names = assert_validation_ok(validate_privileges(Some(&privileges)));
        assert_names_match(privilege_names, &["p1", "p2"]);
    }

    #[test]
    fn validate_privileges_duplicate_name_test() {
        let privileges = vec![sample_privilege("p1"), sample_privilege("p1")];
        assert_validation_err(validate_privileges(Some(&privileges)));
    }

    #[test]
    fn validate_roles_success_test() {
        let privilege_names = string_set(&["p1", "p2"]);
        let roles = vec![sample_role("r1", vec!["p1", "p2"])];
        let role_names = assert_validation_ok(validate_roles(Some(&roles), &privilege_names));
        assert_names_match(role_names, &["r1"]);
    }

    #[test]
    fn validate_roles_unknown_privilege_test() {
        let privilege_names = string_set(&["p1"]);
        let roles = vec![sample_role("r1", vec!["missing-privilege"])];
        assert_validation_err(validate_roles(Some(&roles), &privilege_names));
    }

    #[test]
    fn validate_identities_success_test() {
        let identities = vec![sample_identity("i1"), sample_identity("i2")];
        let identity_names = assert_validation_ok(validate_identities(Some(&identities)));
        assert_names_match(identity_names, &["i1", "i2"]);
    }

    #[test]
    fn validate_identities_missing_selector_test() {
        let identities = vec![Identity {
            name: "i1".to_string(),
            userName: None,
            groupName: None,
            exePath: None,
            processName: None,
        }];
        assert_validation_err(validate_identities(Some(&identities)));
    }

    #[test]
    fn validate_role_assignments_success_test() {
        let role_names = string_set(&["r1"]);
        let identity_names = string_set(&["i1", "i2"]);
        let role_assignments = vec![sample_role_assignment("r1", vec!["i1", "i2"])];

        assert_validation_ok(validate_role_assignments(
            Some(&role_assignments),
            &role_names,
            &identity_names,
        ));
    }

    #[test]
    fn validate_role_assignments_unknown_identity_test() {
        let role_names = string_set(&["r1"]);
        let identity_names = string_set(&["i1"]);
        let role_assignments = vec![sample_role_assignment("r1", vec!["missing-identity"])];

        assert_validation_err(validate_role_assignments(
            Some(&role_assignments),
            &role_names,
            &identity_names,
        ));
    }

    #[tokio::test]
    async fn read_local_rules_file_success_test() {
        let parsed = run_read_wireserver_rules_file_case(
            "read_local_rules_file_success_test",
            r#"{
                "id": "local-read-id",
				"defaultAccess": "allow",
				"rules": {
					"privileges": [
						{ "name": "p1", "path": "/a" }
					]
				}
			}"#,
        )
        .await
        .unwrap();
        assert_eq!(parsed.id.as_deref(), Some("local-read-id"));
        assert_eq!(parsed.defaultAccess.as_deref(), Some("allow"));
        assert_eq!(parsed.rules.unwrap().privileges.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn read_local_rules_file_invalid_json_test() {
        let result = run_read_wireserver_rules_file_case(
            "read_local_rules_file_invalid_json_test",
            "{ invalid json ",
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn read_local_rules_file_invalid_default_access_test() {
        let result = run_read_wireserver_rules_file_case(
            "read_local_rules_file_invalid_default_access_test",
            r#"{
                "defaultAccess": "maybe",
                "rules": {
                    "privileges": [
                        { "name": "p1", "path": "/a" }
                    ]
                }
            }"#,
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn read_local_rules_file_invalid_role_reference_test() {
        let result = run_read_wireserver_rules_file_case(
            "read_local_rules_file_invalid_role_reference_test",
            r#"{
                "rules": {
                    "privileges": [
                        { "name": "p1", "path": "/a" }
                    ],
                    "roles": [
                        { "name": "r1", "privileges": ["missing-privilege"] }
                    ]
                }
            }"#,
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn resolve_effective_rules_local_file_present_merges_test() {
        let (effective_rules, changed, tracker) = run_resolve_wireserver_case(
            "resolve_effective_rules_local_file_present_merges_test",
            Some(
                r#"{
                "id": "local-effective-id",
				"defaultAccess": "allow",
				"rules": {
					"privileges": [
						{ "name": "local-priv", "path": "/local" }
					]
				}
			}"#,
            ),
            "deny",
            None,
            true,
        )
        .await;

        assert!(changed);
        let effective_rules = effective_rules.unwrap();
        assert_eq!(effective_rules.id, "decoded-id");
        assert_eq!(effective_rules.defaultAccess, "allow");
        assert!(effective_rules.rules.is_some());
        assert!(!tracker.parse_failed);
    }

    #[tokio::test]
    async fn resolve_effective_rules_local_file_missing_returns_none_test() {
        let (effective_rules, changed, tracker) = run_resolve_wireserver_case(
            "resolve_effective_rules_local_file_missing_returns_none_test",
            None,
            "deny",
            None,
            false,
        )
        .await;

        assert!(changed);
        assert!(effective_rules.is_none());
        assert!(!tracker.parse_failed);
    }

    #[tokio::test]
    async fn resolve_effective_rules_invalid_local_file_fail_closed_test() {
        let (effective_rules, changed, tracker) = run_resolve_wireserver_case(
            "resolve_effective_rules_invalid_local_file_fail_closed_test",
            Some("{ invalid json "),
            "allow",
            Some(AccessControlRules {
                privileges: Some(vec![Privilege {
                    name: "remote-privilege".to_string(),
                    path: "/remote".to_string(),
                    queryParameters: None,
                }]),
                roles: None,
                identities: None,
                roleAssignments: None,
            }),
            false,
        )
        .await;

        assert!(changed);
        let effective_rules = effective_rules.unwrap();
        assert_eq!(effective_rules.id, "decoded-id");
        assert_eq!(effective_rules.defaultAccess, "deny");
        assert!(effective_rules.rules.is_none());
        assert!(tracker.parse_failed);
    }
}
