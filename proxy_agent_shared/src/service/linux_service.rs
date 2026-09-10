// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use crate::error::CommandErrorType;
use crate::error::Error;
use crate::linux;
use crate::logger::logger_manager;
use crate::misc_helpers;
use crate::result::Result;
use std::fs;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

pub fn stop_service(service_name: &str) -> Result<()> {
    let output = misc_helpers::execute_command("systemctl", vec!["stop", service_name], -1)?;
    logger_manager::write_info(format!(
        "stop_service: {}  result: {}",
        service_name,
        output.message()
    ));
    Ok(())
}

/// Starts the specified service with `systemctl start` command.
/// If the command fails, an Error is returned.
pub fn start_service(service_name: &str) -> Result<()> {
    let output = misc_helpers::execute_command("systemctl", vec!["start", service_name], -1)?;
    if output.is_success() {
        logger_manager::write_info(format!("Service {service_name} started successfully"));
        Ok(())
    } else {
        let error_message = format!(
            "start_service: {service_name} failed with error: {}",
            output.message()
        );
        Err(Error::Command(
            CommandErrorType::CommandName("systemctl start".to_string()),
            error_message,
        ))
    }
}

pub fn install_or_update_service(service_name: &str) -> Result<()> {
    unmask_service(service_name)?;
    reload_systemd_daemon()?;
    enable_service(service_name)
}

fn unmask_service(service_name: &str) -> Result<()> {
    let output = misc_helpers::execute_command("systemctl", vec!["unmask", service_name], -1)?;
    logger_manager::write_info(format!(
        "unmask_service: {}  result: {}",
        service_name,
        output.message()
    ));
    Ok(())
}

pub fn uninstall_service(service_name: &str) -> Result<()> {
    disable_service(service_name)?;
    delete_service_config_file(service_name)
}

fn disable_service(service_name: &str) -> Result<()> {
    let output = misc_helpers::execute_command("systemctl", vec!["disable", service_name], -1)?;
    logger_manager::write_info(format!(
        "disable_service: {}  result: {}",
        service_name,
        output.message()
    ));
    Ok(())
}

fn reload_systemd_daemon() -> Result<()> {
    let output = misc_helpers::execute_command("systemctl", vec!["daemon-reload"], -1)?;
    logger_manager::write_info(format!(
        "reload_systemd_daemon result: {}",
        output.message()
    ));
    Ok(())
}

fn enable_service(service_name: &str) -> Result<()> {
    let output = misc_helpers::execute_command("systemctl", vec!["enable", service_name], -1)?;
    logger_manager::write_info(format!(
        "enable_service: {}  result: {}",
        service_name,
        output.message()
    ));
    Ok(())
}

fn delete_service_config_file(service_name: &str) -> Result<()> {
    let config_file_path =
        PathBuf::from(linux::SERVICE_CONFIG_FOLDER_PATH).join(format!("{service_name}.service"));
    match fs::remove_file(&config_file_path) {
        Ok(_) => {
            reload_systemd_daemon()?;
        }
        Err(e) => {
            let message = format!(
                "delete_service_config_file: {}  failed to delete service config file '{}': {}",
                service_name,
                misc_helpers::path_to_string(&config_file_path),
                e
            );
            logger_manager::write_info(message);
        }
    }
    Ok(())
}

/// Queries the executable path of the specified service.
/// It uses systemctl show command to get the ExecStart property.
/// If the command fails or the output cannot be parsed after all retries, an Error is returned.
pub fn query_service_executable_path(service_name: &str) -> Result<PathBuf> {
    const MAX_ATTEMPTS: u32 = 3;
    const RETRY_DELAY: Duration = Duration::from_secs(1);

    let mut last_error_message = String::new();
    for attempt in 1..=MAX_ATTEMPTS {
        if attempt > 1 {
            logger_manager::write_info(format!(
                "query_service_executable_path: attempt {attempt}/{MAX_ATTEMPTS} for {service_name}",
            ));
            thread::sleep(RETRY_DELAY);
        }

        let output = misc_helpers::execute_command(
            "systemctl",
            vec!["show", "--property=ExecStart", service_name],
            -1,
        )?;

        if !output.is_success() {
            last_error_message = format!(
                "query_service_executable_path: {service_name} failed with error: {}",
                output.message()
            );
            continue;
        }

        let stdout = output.stdout();
        logger_manager::write_info(format!(
            "query_service_executable_path: {service_name} result: {stdout}",
        ));

        // Parse ExecStart output
        // Format: ExecStart={ path=/path/to/executable ; argv[]=/path/to/executable [args] ; ... }
        // ExecStart={} means systemd has not yet loaded the unit (e.g. right after install);
        // we retry to give systemd time to process the unit file.
        if let Some(path_start) = stdout.find("path=") {
            let path_str = &stdout[path_start + 5..];
            if let Some(semicolon_pos) = path_str.find(" ;") {
                let executable_path = path_str[..semicolon_pos].trim();
                return Ok(PathBuf::from(executable_path));
            }
        }

        last_error_message = format!(
            "query_service_executable_path: {service_name} failed to parse ExecStart output: {stdout}"
        );
    }

    Err(Error::Command(
        CommandErrorType::CommandName("systemctl show --property=ExecStart".to_string()),
        last_error_message,
    ))
}

/// Check if the service is installed by verifying the existence of its unit file.
pub fn check_service_installed(service_name: &str) -> (bool, String) {
    let config_file_path =
        PathBuf::from(linux::SERVICE_CONFIG_FOLDER_PATH).join(format!("{service_name}.service"));

    if config_file_path.exists() && config_file_path.is_file() {
        let message =
            format!("check_service_installed: service: {service_name} successfully queried.");
        logger_manager::write_info(message.clone());
        (true, message)
    } else {
        let message = format!(
            "check_service_installed: service: {service_name} unit file not found at '{}'",
            misc_helpers::path_to_string(&config_file_path)
        );
        logger_manager::write_info(message.clone());
        (false, message)
    }
}

/// The subset of a service's runtime state derived from `systemctl is-active` output. A named
/// struct (rather than a bare tuple) so each field is self-documenting at every call site.
#[derive(Debug, PartialEq)]
struct ActiveState {
    is_running: bool,
    is_transitioning: bool,
    state_display: String,
}

/// Maps `systemctl is-active` output to an `ActiveState`. `activating` mirrors Windows
/// `StartPending`/`ContinuePending` (transitioning, not a failure); `deactivating` mirrors
/// `StopPending` (a confirmed down state). Pure function, unit-testable without `systemctl`.
fn map_is_active_output(output: &str) -> ActiveState {
    let (is_running, is_transitioning, state_display) = match output.trim() {
        "active" => (true, false, "Running"),
        "inactive" => (false, false, "Stopped"),
        "failed" => (false, false, "Failed"),
        "activating" => (false, true, "Activating"),
        "deactivating" => (false, false, "Deactivating"),
        other => {
            return ActiveState {
                is_running: false,
                is_transitioning: false,
                state_display: capitalize_first(other),
            }
        }
    };
    ActiveState {
        is_running,
        is_transitioning,
        state_display: state_display.to_string(),
    }
}

/// Maps the trimmed stdout of `systemctl is-enabled <service>` to a start-type display string,
/// using Windows-like vocabulary ("AutoStart"/"Disabled") so the reported message shape is
/// consistent across platforms. Pure function so it is unit-testable without shelling out.
fn map_is_enabled_output(output: &str) -> String {
    match output.trim() {
        "enabled" | "enabled-runtime" => "AutoStart".to_string(),
        "disabled" => "Disabled".to_string(),
        "masked" => "Disabled".to_string(),
        "static" => "OnDemand".to_string(),
        other => capitalize_first(other),
    }
}

fn capitalize_first(s: &str) -> String {
    if s.is_empty() {
        return "Unknown".to_string();
    }
    let mut chars = s.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => "Unknown".to_string(),
    }
}

/// Checks a service's runtime status (running state + start type) using `systemctl`,
/// in the cross-platform `ServiceRuntimeStatus` shape.
pub fn check_service_run_status(service_name: &str) -> crate::service::ServiceRuntimeStatus {
    let (is_installed, _) = check_service_installed(service_name);
    if !is_installed {
        return crate::service::ServiceRuntimeStatus {
            service_name: service_name.to_string(),
            is_installed: false,
            is_running: false,
            is_transitioning: false,
            state_display: "NotInstalled".to_string(),
            start_type_display: "NotInstalled".to_string(),
        };
    }

    let active_state =
        match misc_helpers::execute_command("systemctl", vec!["is-active", service_name], -1) {
            Ok(output) => map_is_active_output(&output.stdout()),
            Err(e) => {
                logger_manager::write_info(format!(
                    "check_service_run_status: failed to query is-active for {service_name}: {e}"
                ));
                ActiveState {
                    is_running: false,
                    is_transitioning: false,
                    state_display: "Unknown".to_string(),
                }
            }
        };

    let start_type_display =
        match misc_helpers::execute_command("systemctl", vec!["is-enabled", service_name], -1) {
            Ok(output) => map_is_enabled_output(&output.stdout()),
            Err(e) => {
                logger_manager::write_info(format!(
                    "check_service_run_status: failed to query is-enabled for {service_name}: {e}"
                ));
                "Unknown".to_string()
            }
        };

    crate::service::ServiceRuntimeStatus {
        service_name: service_name.to_string(),
        is_installed: true,
        is_running: active_state.is_running,
        is_transitioning: active_state.is_transitioning,
        state_display: active_state.state_display,
        start_type_display,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_is_active_output_test() {
        assert_eq!(
            map_is_active_output("active\n"),
            ActiveState {
                is_running: true,
                is_transitioning: false,
                state_display: "Running".to_string()
            }
        );
        assert_eq!(
            map_is_active_output("inactive\n"),
            ActiveState {
                is_running: false,
                is_transitioning: false,
                state_display: "Stopped".to_string()
            }
        );
        assert_eq!(
            map_is_active_output("failed\n"),
            ActiveState {
                is_running: false,
                is_transitioning: false,
                state_display: "Failed".to_string()
            }
        );
        // "activating" is transitioning toward Running - not a confirmed failure.
        assert_eq!(
            map_is_active_output("activating\n"),
            ActiveState {
                is_running: false,
                is_transitioning: true,
                state_display: "Activating".to_string()
            }
        );
        // "deactivating" is heading away from Running - treated as a confirmed down state,
        // consistent with Windows StopPending, since it's actionable to know immediately.
        assert_eq!(
            map_is_active_output("deactivating\n"),
            ActiveState {
                is_running: false,
                is_transitioning: false,
                state_display: "Deactivating".to_string()
            }
        );
        assert_eq!(
            map_is_active_output("unknown\n"),
            ActiveState {
                is_running: false,
                is_transitioning: false,
                state_display: "Unknown".to_string()
            }
        );
    }

    #[test]
    fn map_is_enabled_output_test() {
        assert_eq!(map_is_enabled_output("enabled\n"), "AutoStart".to_string());
        assert_eq!(map_is_enabled_output("disabled\n"), "Disabled".to_string());
        assert_eq!(map_is_enabled_output("masked\n"), "Disabled".to_string());
        assert_eq!(map_is_enabled_output("static\n"), "OnDemand".to_string());
        assert_eq!(
            map_is_enabled_output("some-other-state\n"),
            "Some-other-state".to_string()
        );
    }

    #[test]
    fn check_service_run_status_not_installed_test() {
        let status = check_service_run_status("gpa-test-service-that-does-not-exist");
        assert!(!status.is_installed);
        assert!(!status.is_running);
        assert!(!status.is_transitioning);
        assert_eq!(status.summary(), "NotInstalled");
    }
}
