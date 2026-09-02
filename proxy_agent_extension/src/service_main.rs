// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use crate::common;
use crate::constants;
use crate::logger;
use crate::structs::*;
use proxy_agent_shared::current_info;
use proxy_agent_shared::logger::LoggerLevel;
use proxy_agent_shared::proxy_agent_aggregate_status::{
    self, GuestProxyAgentAggregateStatus, GuestProxyAgentAggregateStatusSource,
    ProxyConnectionSummary,
};
use proxy_agent_shared::telemetry::event_logger;
use proxy_agent_shared::{misc_helpers, telemetry};
use service_state::ServiceState;
use std::io::Error;
use std::path::PathBuf;
use std::process::Command;
use std::process::Output;
use std::time::Duration;

pub mod service_state;
#[cfg(windows)]
pub mod windows_main;
#[cfg(windows)]
use proxy_agent_shared::service;

const MAX_STATE_COUNT: u32 = 120;

pub fn run() {
    let message = format!(
        "==============  GuestProxyAgentExtension Enabling Agent, Version: {}, OS Arch: {}, OS Version: {}",
        current_info::get_current_exe_version(),
        misc_helpers::get_processor_arch(),
        misc_helpers::get_long_os_version()
    );
    telemetry::event_logger::write_event(
        LoggerLevel::Info,
        message,
        "run",
        "service_main",
        &logger::get_logger_key(),
    );
    tokio::spawn({
        async {
            monitor_thread().await;
        }
    });
    tokio::spawn({
        async {
            heartbeat_thread().await;
        }
    });
}

async fn heartbeat_thread() {
    let exe_path = misc_helpers::get_current_exe_dir();
    let handler_environment = common::get_handler_environment(&exe_path);
    let heartbeat_file_path: PathBuf = handler_environment.heartbeatFile.to_string().into();
    let duration = Duration::from_secs(5 * 60);
    loop {
        let heartbeat_obj = HeartbeatObj {
            status: constants::HEARTBEAT_READY_STATUS.to_string(),
            code: constants::STATUS_CODE_OK.to_string(),
            formattedMessage: FormattedMessage {
                lang: constants::LANG_EN_US.to_string(),
                message: "Extension is running".to_string(),
            },
        };
        common::report_heartbeat(heartbeat_file_path.to_path_buf(), heartbeat_obj);
        tokio::time::sleep(duration).await;
    }
}

/// Describes the reason for running the setup tool install command.
#[derive(Debug, PartialEq)]
enum UpdateAction {
    /// Service file version differs from extension — a fresh update.
    VersionMismatch,
    /// Service files already match but the running process reports an older version —
    /// an interrupted update (e.g., VM force-restarted mid-eBPF-update).
    ResumeInterruptedUpdate,
}

/// Resolves the file version of the proxy agent bundled with the extension.
/// Returns `None` (and reports an error status) if the version cannot be read yet.
fn resolve_proxy_agent_file_version_in_extension(
    cached: &str,
    status: &mut StatusObj,
    status_state_obj: &mut common::StatusState,
) -> Option<String> {
    if !cached.is_empty() {
        return Some(cached.to_string());
    }
    let path = common::get_proxy_agent_exe_path();
    match misc_helpers::get_proxy_agent_version(&path) {
        Ok(version) => Some(version),
        Err(e) => {
            let error_message = format!(
                "Failed to get GuestProxyAgent version from file {} with error: {}",
                misc_helpers::path_to_string(&path),
                e
            );
            logger::write(error_message.clone());
            set_error(status, status_state_obj, error_message);
            None
        }
    }
}

/// Gets the file version of the currently installed GPA service executable.
fn get_proxy_agent_service_file_version() -> String {
    let path = common::get_proxy_agent_service_path();
    match misc_helpers::get_proxy_agent_version(&path) {
        Ok(version) => version,
        Err(e) => {
            logger::write(format!(
                "Failed to get GuestProxyAgent version from file {} with error: {}",
                misc_helpers::path_to_string(&path),
                e
            ));
            String::new()
        }
    }
}

/// Determines what update action (if any) is needed for the proxy agent service.
async fn determine_update_action(
    proxy_agent_in_extension_version: &str,
    proxy_agent_service_version: &str,
    http_ip: Option<String>,
    http_port: Option<u16>,
    status_file_path: Option<PathBuf>,
    logger_key: &str,
) -> Option<UpdateAction> {
    if proxy_agent_in_extension_version != proxy_agent_service_version {
        telemetry::event_logger::write_event(
            LoggerLevel::Info,
            format!(
                "Version mismatch between file versions. \
                 ProxyAgentService File Version: {proxy_agent_service_version}, \
                 ProxyAgent in Extension File Version: {proxy_agent_in_extension_version}"
            ),
            "monitor_thread",
            "service_main",
            logger_key,
        );
        Some(UpdateAction::VersionMismatch)
    } else if !check_version_in_proxy_agent_aggregate_status(
        proxy_agent_in_extension_version,
        http_ip,
        http_port,
        status_file_path,
    )
    .await
    {
        telemetry::event_logger::write_event(
            LoggerLevel::Info,
            format!(
                "Service file version matches extension version {proxy_agent_in_extension_version} but \
                 running service reports a different version. \
                 Re-running install to complete the interrupted update."
            ),
            "monitor_thread",
            "service_main",
            logger_key,
        );
        Some(UpdateAction::ResumeInterruptedUpdate)
    } else {
        None
    }
}

/// Runs the setup tool install command and reports the result.
fn run_setup_tool_install(
    status_folder: PathBuf,
    seq_no: &str,
    status: &mut StatusObj,
    status_state_obj: &mut common::StatusState,
) {
    let setup_tool = misc_helpers::path_to_string(&common::setup_tool_exe_path());
    let mut install_command = Command::new(&setup_tool);
    // Set the current directory to the directory of the current executable
    // for the setup tool to work properly
    install_command.current_dir(misc_helpers::get_current_exe_dir());
    install_command.arg("install");
    let output = install_command.output();
    report_proxy_agent_service_status(output, status_folder, seq_no, status, status_state_obj);
}

async fn monitor_thread() {
    let exe_path = misc_helpers::get_current_exe_dir();
    let handler_environment = common::get_handler_environment(&exe_path);
    let status_folder_path: PathBuf = handler_environment.statusFolder.to_string().into();
    let mut cache_seq_no = String::new();
    let mut proxy_agent_file_version_in_extension = String::new();
    let mut service_state = ServiceState::default();
    let mut status = StatusObj {
        name: constants::PLUGIN_NAME.to_string(),
        operation: constants::ENABLE_OPERATION.to_string(),
        configurationAppliedTime: misc_helpers::get_date_time_string(),
        code: constants::STATUS_CODE_OK,
        status: constants::SUCCESS_STATUS.to_string(),
        formattedMessage: FormattedMessage {
            lang: constants::LANG_EN_US.to_string(),
            message: "Started ProxyAgent Extension Monitoring thread.".to_string(),
        },
        substatus: Default::default(),
    };
    let mut status_state_obj = common::StatusState::new();
    let logger_key: &String = &logger::get_logger_key();
    let mut restored_in_error = false;
    let mut proxy_agent_update_reported: Option<telemetry::span::SimpleSpan> = None;
    let loop_interval = Duration::from_secs(15);
    // Decoupled cache/cadence for the eBPF (Windows only) and GuestProxyAgent service
    // (cross-platform) runtime status checks - these are (re)queried only every
    // SERVICE_STATUS_POLL_INTERVAL_SECS (~2 minutes), independent of loop_interval, while the
    // cached substatus is still re-appended to the status object (and written to the status
    // file) on every loop_interval tick.
    #[cfg(windows)]
    let mut last_ebpf_substatus: Option<SubStatus> = None;
    let mut last_gpa_service_substatus: Option<SubStatus> = None;
    let mut last_service_status_poll: Option<std::time::Instant> = None;
    // Last known timestamp (as reported by the GPA aggregate status itself) used to annotate
    // the immediate eBPF/GPA-service overrides below; kept from the previous iteration whenever
    // the current iteration's fetch fails outright.
    let mut last_known_status_timestamp = String::new();
    // Tracks whether the aggregate-status check (Step 3) was successful on the previous
    // iteration, so a fresh transition (success<->failure) can force an immediate recompute of
    // the cached eBPF/GPA service substatus below, instead of waiting out the full poll
    // interval - this avoids a stale cached Error substatus continuing to override a
    // just-recovered aggregate status (or vice versa) for up to the poll interval.
    let mut prev_aggregate_status_ok: Option<bool> = None;
    loop {
        let current_seq_no: String = common::get_current_seq_no(&exe_path);

        // Step 1: Resolve the extension-bundled proxy agent version (retry each iteration until available)
        match resolve_proxy_agent_file_version_in_extension(
            &proxy_agent_file_version_in_extension,
            &mut status,
            &mut status_state_obj,
        ) {
            Some(version) => proxy_agent_file_version_in_extension = version,
            None => {
                common::report_status(status_folder_path.to_path_buf(), &current_seq_no, &status);
                tokio::time::sleep(loop_interval).await;
                continue;
            }
        }

        // Step 2: On seq_no change, check whether the proxy agent service needs an update or
        //         whether a previous update was interrupted and needs to be resumed.
        if cache_seq_no != current_seq_no {
            telemetry::event_logger::write_event(
                LoggerLevel::Info,
                format!(
                    "Current seq_no: {current_seq_no} does not match cached seq no {cache_seq_no}"
                ),
                "monitor_thread",
                "service_main",
                logger_key,
            );
            cache_seq_no = current_seq_no.to_string();

            let proxy_agent_service_version = get_proxy_agent_service_file_version();
            if let Some(action) = determine_update_action(
                &proxy_agent_file_version_in_extension,
                &proxy_agent_service_version,
                Some(proxy_agent_shared::constants::WIRE_SERVER_IP.to_string()), // HTTP IP
                Some(proxy_agent_shared::constants::WIRE_SERVER_PORT),           // HTTP port
                None,
                logger_key,
            )
            .await
            {
                if matches!(action, UpdateAction::VersionMismatch) {
                    backup_proxy_agent(&misc_helpers::path_to_string(
                        &common::setup_tool_exe_path(),
                    ));

                    // reset this flag in case the previous restore was done due to an error,
                    // but now the version mismatch indicates a new update attempt rather than a resume of a previous interrupted update
                    restored_in_error = false;
                }
                let update_span = telemetry::span::SimpleSpan::new();
                proxy_agent_update_reported = Some(telemetry::span::SimpleSpan::new());
                run_setup_tool_install(
                    exe_path.join("status"),
                    &cache_seq_no,
                    &mut status,
                    &mut status_state_obj,
                );
                let span_message = match &action {
                    UpdateAction::VersionMismatch => "Update Proxy Agent command completed",
                    UpdateAction::ResumeInterruptedUpdate => {
                        "Retry install for interrupted update completed"
                    }
                };
                update_span.write_event(
                    span_message,
                    "install_proxy_agent",
                    "service_main",
                    logger_key,
                );
            }
        }

        // Step 3: Read and evaluate the proxy agent aggregate status
        if let Some(status_timestamp) = report_proxy_agent_aggregate_status(
            &proxy_agent_file_version_in_extension,
            &mut status,
            &mut status_state_obj,
            &mut service_state,
        )
        .await
        {
            last_known_status_timestamp = status_timestamp;
        }

        // Detect an aggregate-status success/failure transition since the previous iteration,
        // so Step 6 can force an immediate recompute of the cached eBPF/GPA service substatus
        // instead of waiting out the full poll interval. Without this, a stale cached Error
        // substatus could keep overriding a just-recovered aggregate status (or a stale cached
        // healthy substatus could keep masking a newly-broken service) for up to the poll
        // interval.
        let aggregate_status_ok = status.status == *constants::SUCCESS_STATUS;
        let force_service_status_recompute =
            should_force_recompute(prev_aggregate_status_ok, aggregate_status_ok);
        prev_aggregate_status_ok = Some(aggregate_status_ok);

        // Step 4: Restore (on error) or purge (on success) the backed-up proxy agent, once
        if !restored_in_error {
            restored_in_error = restore_purge_proxy_agent(&mut status);
        }

        // Step 5: Track time-to-success after an update
        if status.status == *constants::SUCCESS_STATUS {
            if let Some(span) = proxy_agent_update_reported.as_ref() {
                span.write_event(
                    "Proxy Agent Service is updated and reporting successful status",
                    "updated_proxy_agent",
                    "service_main",
                    logger_key,
                );
            }
            proxy_agent_update_reported = None;
        }

        // Step 6: Poll eBPF (Windows only) and GuestProxyAgent service (cross-platform) runtime
        // status on a decoupled ~2-minute cadence, independent of loop_interval (or immediately,
        // regardless of cadence, when the aggregate-status result just transitioned - see
        // `force_service_status_recompute` above). The cached substatus values are re-appended
        // every iteration so the status file (written every loop_interval) always reflects the
        // latest known state.
        if should_poll(
            last_service_status_poll,
            std::time::Instant::now(),
            Duration::from_secs(constants::SERVICE_STATUS_POLL_INTERVAL_SECS),
        ) || force_service_status_recompute
        {
            #[cfg(windows)]
            {
                last_ebpf_substatus = Some(compute_ebpf_substatus());
            }
            last_gpa_service_substatus = Some(compute_gpa_service_substatus());
            last_service_status_poll = Some(std::time::Instant::now());
        }
        #[cfg(windows)]
        if let Some(ebpf_substatus) = &last_ebpf_substatus {
            status.substatus.push(ebpf_substatus.clone());
        }
        if let Some(gpa_service_substatus) = &last_gpa_service_substatus {
            status.substatus.push(gpa_service_substatus.clone());
        }

        // Step 7: Apply immediate overrides when eBPF (Windows only, highest priority - an
        // unhealthy eBPF is frequently the root cause of the GuestProxyAgent service failing to
        // start) or the GuestProxyAgent service itself (both platforms) is reporting Error.
        // These bypass the debounce state machine and take priority over whatever status/message
        // Steps 3-5 produced (stale/version-mismatch/connectivity-error/success), because a
        // definitively-known local service failure is a complete, actionable, immediate answer
        // on its own - there is no reason to wait for slower generic detection to catch up.
        #[cfg(windows)]
        let overridden = match &last_ebpf_substatus {
            Some(ebpf_substatus) => apply_ebpf_status_override(
                &mut status,
                ebpf_substatus,
                &last_known_status_timestamp,
            ),
            None => false,
        };
        #[cfg(not(windows))]
        let overridden = false;
        if !overridden {
            if let Some(gpa_service_substatus) = &last_gpa_service_substatus {
                apply_gpa_service_status_override(
                    &mut status,
                    gpa_service_substatus,
                    &last_known_status_timestamp,
                );
            }
        }

        // Step 8: Write the final status file and sleep
        common::report_status(
            status_folder_path.to_path_buf(),
            &cache_seq_no.to_string(),
            &status,
        );

        tokio::time::sleep(loop_interval).await;
    }
}

/// Returns true when a poll is due: either no poll has happened yet, or at least `interval`
/// has elapsed since the last one. Pure/testable helper for the decoupled service-status cadence.
fn should_poll(
    last: Option<std::time::Instant>,
    now: std::time::Instant,
    interval: Duration,
) -> bool {
    match last {
        None => true,
        Some(last) => now.duration_since(last) >= interval,
    }
}

/// Returns true when `current` differs from the previously observed value, indicating the
/// aggregate-status success/failure state has just changed since the prior iteration. Returns
/// false on the very first call (when `prev` is `None`), since there is nothing yet to compare
/// against. Pure/testable helper used to force an immediate eBPF/GPA-service-status recompute
/// at meaningful transitions, without abandoning the steady-state decoupled polling cadence
/// the rest of the time.
fn should_force_recompute(prev: Option<bool>, current: bool) -> bool {
    prev.is_some_and(|previous| previous != current)
}

fn write_state_event(
    state_key: &str,
    state_value: &str,
    message: String,
    method_name: &str,
    module_name: &str,
    logger_key: &str,
    service_state: &mut ServiceState,
) {
    if service_state.update_service_state_entry(state_key, state_value, MAX_STATE_COUNT) {
        event_logger::write_event(
            LoggerLevel::Info,
            message,
            method_name,
            module_name,
            logger_key,
        );
    }
}

#[cfg(windows)]
fn build_ebpf_substatus(
    core: &proxy_agent_shared::service::ServiceStatusInfo,
    ext: &proxy_agent_shared::service::ServiceStatusInfo,
    svc: &proxy_agent_shared::service::ServiceStatusInfo,
) -> SubStatus {
    use proxy_agent_shared::service::classify_service_state;

    let (core_running, core_transitioning) = classify_service_state(core.state.as_ref());
    let (ext_running, ext_transitioning) = classify_service_state(ext.state.as_ref());
    let (svc_running, svc_transitioning) = classify_service_state(svc.state.as_ref());

    let all_running = core_running && ext_running && svc_running;
    // "Down" means confirmed not-running and not actively transitioning toward Running.
    let any_down = (!core_running && !core_transitioning)
        || (!ext_running && !ext_transitioning)
        || (!svc_running && !svc_transitioning);

    let (status, code) = if all_running {
        (
            constants::SUCCESS_STATUS.to_string(),
            constants::STATUS_CODE_OK,
        )
    } else if any_down {
        (
            constants::ERROR_STATUS.to_string(),
            constants::STATUS_CODE_NOT_OK,
        )
    } else {
        // None are confirmed down, but at least one is still starting up (StartPending /
        // ContinuePending) - a normal, usually brief condition during boot or a restart.
        // Report Transitioning instead of Error so the immediate top-level override
        // (`apply_ebpf_status_override`) does not fire on this benign condition.
        (
            constants::TRANSITIONING_STATUS.to_string(),
            constants::STATUS_CODE_OK,
        )
    };

    let message = format!(
        "EbpfCore: {}, NetEbpfExt: {}, eBPFSvc: {}",
        core.summary(),
        ext.summary(),
        svc.summary()
    );

    SubStatus {
        name: constants::EBPF_SUBSTATUS_NAME.to_string(),
        status,
        code,
        formattedMessage: FormattedMessage {
            lang: constants::LANG_EN_US.to_string(),
            message,
        },
    }
}

#[cfg(windows)]
fn compute_ebpf_substatus() -> SubStatus {
    let core_status = service::check_service_status(constants::EBPF_CORE);
    logger::write(format!("check_service_status: {}", core_status.message()));

    let ext_status = service::check_service_status(constants::EBPF_EXT);
    logger::write(format!("check_service_status: {}", ext_status.message()));

    let svc_status = service::check_service_status(constants::EBPF_SVC);
    logger::write(format!("check_service_status: {}", svc_status.message()));

    build_ebpf_substatus(&core_status, &ext_status, &svc_status)
}

/// Builds the cross-platform `ProxyAgentServiceStatus` substatus for the GuestProxyAgent
/// service itself (Windows SCM service or Linux systemd unit).
fn build_proxy_agent_service_substatus(
    info: &proxy_agent_shared::service::ServiceRuntimeStatus,
) -> SubStatus {
    let (status, code) = if info.is_running {
        (
            constants::SUCCESS_STATUS.to_string(),
            constants::STATUS_CODE_OK,
        )
    } else if info.is_transitioning {
        // Actively starting up (Windows StartPending/ContinuePending, or systemd
        // "activating") - a normal, usually brief condition during boot or a restart.
        // Report Transitioning instead of Error so the immediate top-level override
        // (`apply_gpa_service_status_override`) does not fire on this benign condition.
        (
            constants::TRANSITIONING_STATUS.to_string(),
            constants::STATUS_CODE_OK,
        )
    } else {
        (
            constants::ERROR_STATUS.to_string(),
            constants::STATUS_CODE_NOT_OK,
        )
    };

    SubStatus {
        name: constants::PROXY_AGENT_SERVICE_SUBSTATUS_NAME.to_string(),
        status,
        code,
        formattedMessage: FormattedMessage {
            lang: constants::LANG_EN_US.to_string(),
            message: format!(
                "{}: {}",
                constants::PROXY_AGENT_SERVICE_NAME,
                info.summary()
            ),
        },
    }
}

fn compute_gpa_service_substatus() -> SubStatus {
    let info =
        proxy_agent_shared::service::check_service_run_status(constants::PROXY_AGENT_SERVICE_NAME);
    logger::write(format!("check_service_run_status: {}", info.message()));
    build_proxy_agent_service_substatus(&info)
}

/// If `ebpf_substatus` reports Error, unconditionally overrides `status`'s top-level
/// status/code/message to surface the eBPF detail plus the last known status timestamp and the
/// current time. Bypasses the debounce state machine intentionally. Returns true if it applied
/// the override (used by the caller to give this priority over the GPA-service override).
#[cfg(windows)]
fn apply_ebpf_status_override(
    status: &mut StatusObj,
    ebpf_substatus: &SubStatus,
    last_known_status_timestamp: &str,
) -> bool {
    if ebpf_substatus.status != constants::ERROR_STATUS {
        return false;
    }
    status.status = constants::ERROR_STATUS.to_string();
    status.code = constants::STATUS_CODE_NOT_OK;
    status.formattedMessage.message = format!(
        "{}. Last status timestamp: {}, Current time: {}",
        ebpf_substatus.formattedMessage.message,
        last_known_status_timestamp,
        misc_helpers::get_current_utc_time()
    );
    true
}

/// If `gpa_service_substatus` reports Error, unconditionally overrides `status`'s top-level
/// status/code/message to surface the GuestProxyAgent service detail plus the last known status
/// timestamp and the current time. Bypasses the debounce state machine intentionally, mirroring
/// `apply_ebpf_status_override`. Cross-platform (Windows and Linux). Returns true if it applied
/// the override.
fn apply_gpa_service_status_override(
    status: &mut StatusObj,
    gpa_service_substatus: &SubStatus,
    last_known_status_timestamp: &str,
) -> bool {
    if gpa_service_substatus.status != constants::ERROR_STATUS {
        return false;
    }
    status.status = constants::ERROR_STATUS.to_string();
    status.code = constants::STATUS_CODE_NOT_OK;
    status.formattedMessage.message = format!(
        "{}. Last status timestamp: {}, Current time: {}",
        gpa_service_substatus.formattedMessage.message,
        last_known_status_timestamp,
        misc_helpers::get_current_utc_time()
    );
    true
}

fn backup_proxy_agent(setup_tool: &String) {
    match Command::new(setup_tool).arg("backup").output() {
        Ok(output) => {
            let event_level = if output.status.success() {
                LoggerLevel::Info
            } else {
                LoggerLevel::Warn
            };
            let message = format!(
                "Backup Proxy Agent command finished with stdoutput: {}, stderr: {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            telemetry::event_logger::write_event(
                event_level,
                message.clone(),
                "backup_proxy_agent",
                "service_main",
                &logger::get_logger_key(),
            );
        }
        Err(e) => {
            let message = format!("Error in running Backup Proxy Agent command: {e}");
            telemetry::event_logger::write_event(
                LoggerLevel::Warn,
                message.clone(),
                "backup_proxy_agent",
                "service_main",
                &logger::get_logger_key(),
            );
        }
    }
}

/// Checks if the proxy agent service is running a different version than the files present in the extension,
/// This can happen when a VM is force-restarted during a proxy agent service update, causing the new service to not start properly.
/// Return true if the versions match, return false if the versions do not match or if not able to read the service status version at all.
async fn check_version_in_proxy_agent_aggregate_status(
    proxy_agent_file_version_in_extension: &str,
    http_ip: Option<String>,
    http_port: Option<u16>,
    status_file_path: Option<PathBuf>,
) -> bool {
    match get_proxy_agent_aggregate_status(http_ip, http_port, status_file_path).await {
        Ok((aggregate_status, _)) => {
            let running_version = &aggregate_status.proxyAgentStatus.version;
            if running_version != proxy_agent_file_version_in_extension {
                logger::write(format!(
                    "Reported GPA service version {running_version} differs from installed file version {proxy_agent_file_version_in_extension}."
                ));
                false
            } else {
                true
            }
        }
        Err(e) => {
            // Cannot get aggregate status — service may not be running at all.
            // Treat this as an incomplete update so install is retried.
            logger::write(format!(
                "Cannot get aggregate status to verify running version: {e}.",
            ));
            false
        }
    }
}

/// Get the proxy agent aggregate status from a specific port or file.
/// If ip and port are provided, it will attempt to fetch the status from that port first and then specified status file.
/// or, it will attempt to read the status from the specified file directly.
async fn get_proxy_agent_aggregate_status(
    http_ip: Option<String>,
    http_port: Option<u16>,
    status_file_path: Option<PathBuf>,
) -> Result<
    (
        GuestProxyAgentAggregateStatus,
        GuestProxyAgentAggregateStatusSource,
    ),
    proxy_agent_shared::error::Error,
> {
    let aggregate_status_file_path = match status_file_path {
        Some(path) => path,
        None => proxy_agent_aggregate_status::get_proxy_agent_aggregate_status_folder()
            .join(proxy_agent_aggregate_status::PROXY_AGENT_AGGREGATE_STATUS_FILE_NAME),
    };

    if let (Some(http_ip), Some(http_port)) = (http_ip, http_port) {
        proxy_agent_aggregate_status::get_proxy_agent_aggregate_status(
            &http_ip,
            http_port,
            &aggregate_status_file_path,
        )
        .await
    } else {
        Ok((
            misc_helpers::json_read_from_file::<GuestProxyAgentAggregateStatus>(
                &aggregate_status_file_path,
            )?,
            GuestProxyAgentAggregateStatusSource::FILE,
        ))
    }
}

/// Reads and evaluates the proxy agent aggregate status, returning the raw status timestamp
/// (formatted) it observed when the fetch succeeded at all, or `None` when the fetch failed
/// outright (callers should keep whatever timestamp they last observed in that case).
async fn report_proxy_agent_aggregate_status(
    proxy_agent_file_version_in_extension: &String,
    status: &mut StatusObj,
    status_state_obj: &mut common::StatusState,
    service_state: &mut ServiceState,
) -> Option<String> {
    let proxy_agent_aggregate_status_top_level: GuestProxyAgentAggregateStatus;
    // Attempt to get the proxy agent aggregate status from the GPA Proxy Server.
    // If the GPA Proxy Server is not available, fall back to reading the status from the file.
    // We used the WS IP and Port to let this http request go through eBPF and redirect to GPA proxy server,
    // It utilizes the existing GPA claims as authorization signal
    match get_proxy_agent_aggregate_status(
        Some(proxy_agent_shared::constants::WIRE_SERVER_IP.to_string()),
        Some(proxy_agent_shared::constants::WIRE_SERVER_PORT),
        None,
    )
    .await
    {
        Ok((proxy_agent_aggregate_status, source)) => {
            write_state_event(
                constants::STATE_KEY_READ_PROXY_AGENT_AGGREGATE_STATUS,
                &format!(
                    "{success}|{source:?}",
                    success = constants::SUCCESS_STATUS,
                    source = source
                ),
                format!("Successfully get proxy agent aggregate status from {source:?}"),
                "report_proxy_agent_aggregate_status",
                "service_main",
                &logger::get_logger_key(),
                service_state,
            );
            proxy_agent_aggregate_status_top_level = proxy_agent_aggregate_status;
            let status_timestamp = proxy_agent_aggregate_status_top_level
                .get_status_timestamp()
                .ok()
                .map(|ts| ts.to_string());
            extension_substatus(
                proxy_agent_aggregate_status_top_level,
                proxy_agent_file_version_in_extension,
                status,
                status_state_obj,
                service_state,
            );
            status_timestamp
        }
        Err(e) => {
            let error_message = format!("{e}");
            write_state_event(
                constants::STATE_KEY_READ_PROXY_AGENT_AGGREGATE_STATUS,
                constants::ERROR_STATUS,
                error_message.to_string(),
                "report_proxy_agent_aggregate_status",
                "service_main",
                &logger::get_logger_key(),
                service_state,
            );
            set_error(status, status_state_obj, error_message.clone());
            status.substatus = {
                vec![
                    SubStatus {
                        name: constants::PLUGIN_CONNECTION_NAME.to_string(),
                        status: constants::TRANSITIONING_STATUS.to_string(),
                        code: constants::STATUS_CODE_NOT_OK,
                        formattedMessage: FormattedMessage {
                            lang: constants::LANG_EN_US.to_string(),
                            message: error_message.to_string(),
                        },
                    },
                    SubStatus {
                        name: constants::PLUGIN_STATUS_NAME.to_string(),
                        status: constants::TRANSITIONING_STATUS.to_string(),
                        code: constants::STATUS_CODE_NOT_OK,
                        formattedMessage: FormattedMessage {
                            lang: constants::LANG_EN_US.to_string(),
                            message: error_message.to_string(),
                        },
                    },
                    SubStatus {
                        name: constants::PLUGIN_FAILED_AUTH_NAME.to_string(),
                        status: constants::TRANSITIONING_STATUS.to_string(),
                        code: constants::STATUS_CODE_NOT_OK,
                        formattedMessage: FormattedMessage {
                            lang: constants::LANG_EN_US.to_string(),
                            message: error_message.to_string(),
                        },
                    },
                ]
            };
            None
        }
    }
}

/// Updates `status` to reflect a failure, atomically setting `status.status`,
/// `status.code`, `status.formattedMessage.message`, and `status.configurationAppliedTime`.
///
/// **Intentional behavior**: `code` is kept at `STATUS_CODE_OK` (0) while the state machine
/// is still `"Transitioning"` (fewer than 20 consecutive failures). It is only set to
/// `STATUS_CODE_NOT_OK` once `status` reaches `"Error"`. This couples `code` and `status`
/// so that CRP/VMSS operators do not see a hard-failure signal for what may be a transient
/// blip. Previously `code` was set to `STATUS_CODE_NOT_OK` immediately at some call sites
/// and left at 0 at others — this helper makes the behavior uniform and intentional.
fn set_error(status: &mut StatusObj, state: &mut common::StatusState, message: String) {
    status.status = state.update_state(false);
    status.code = if status.status == *constants::ERROR_STATUS {
        constants::STATUS_CODE_NOT_OK
    } else {
        constants::STATUS_CODE_OK
    };
    status.formattedMessage.message = message;
    status.configurationAppliedTime = misc_helpers::get_date_time_string();
}

/// Updates `status` to reflect a success, atomically setting `status.status`,
/// `status.code`, `status.formattedMessage.message`, and `status.configurationAppliedTime`.
fn set_success(status: &mut StatusObj, state: &mut common::StatusState, message: String) {
    status.status = state.update_state(true);
    status.code = constants::STATUS_CODE_OK;
    status.formattedMessage.message = message;
    status.configurationAppliedTime = misc_helpers::get_date_time_string();
}

fn report_error_status(
    status: &mut StatusObj,
    status_state_obj: &mut common::StatusState,
    service_state: &mut ServiceState,
    error_key: &str,
    error_message: String,
) {
    use proxy_agent_shared::logger::LoggerLevel;
    use proxy_agent_shared::telemetry::event_logger;

    set_error(status, status_state_obj, error_message.clone());
    if service_state.update_service_state_entry(error_key, constants::ERROR_STATUS, MAX_STATE_COUNT)
    {
        event_logger::write_event(
            LoggerLevel::Info,
            error_message.clone(),
            "extension_substatus",
            "service_main",
            &logger::get_logger_key(),
        );
    }
    status.substatus = {
        vec![
            SubStatus {
                name: constants::PLUGIN_CONNECTION_NAME.to_string(),
                status: constants::TRANSITIONING_STATUS.to_string(),
                code: constants::STATUS_CODE_NOT_OK,
                formattedMessage: FormattedMessage {
                    lang: constants::LANG_EN_US.to_string(),
                    message: error_message.to_string(),
                },
            },
            SubStatus {
                name: constants::PLUGIN_STATUS_NAME.to_string(),
                status: constants::TRANSITIONING_STATUS.to_string(),
                code: constants::STATUS_CODE_NOT_OK,
                formattedMessage: FormattedMessage {
                    lang: constants::LANG_EN_US.to_string(),
                    message: error_message.to_string(),
                },
            },
            SubStatus {
                name: constants::PLUGIN_FAILED_AUTH_NAME.to_string(),
                status: constants::TRANSITIONING_STATUS.to_string(),
                code: constants::STATUS_CODE_NOT_OK,
                formattedMessage: FormattedMessage {
                    lang: constants::LANG_EN_US.to_string(),
                    message: error_message.to_string(),
                },
            },
        ]
    };
}

fn extension_substatus(
    proxy_agent_aggregate_status_top_level: GuestProxyAgentAggregateStatus,
    proxy_agent_file_version_in_extension: &String,
    status: &mut StatusObj,
    status_state_obj: &mut common::StatusState,
    service_state: &mut ServiceState,
) {
    let proxy_agent_status_timestamp_result =
        proxy_agent_aggregate_status_top_level.get_status_timestamp();
    let proxy_agent_aggregate_status_obj = proxy_agent_aggregate_status_top_level.proxyAgentStatus;
    let proxy_agent_aggregate_status_file_version =
        proxy_agent_aggregate_status_obj.version.to_string();

    // Check for timestamp staleness or parse errors
    let timestamp_error = match proxy_agent_status_timestamp_result {
        Ok(status_timestamp) => {
            let current_time = misc_helpers::get_current_utc_time();
            let duration = current_time - status_timestamp;
            if duration > Duration::from_secs(constants::MAX_TIME_BEFORE_STALE_STATUS_SECS) {
                Some((constants::STATE_KEY_STALE_PROXY_AGENT_STATUS, format!("Proxy agent aggregate status file is stale. Status timestamp: {}, Current time: {}", status_timestamp, current_time)))
            } else {
                None
            }
        }
        Err(e) => Some((
            constants::STATE_KEY_PARSE_TIMESTAMP_ERROR,
            format!("Error in parsing timestamp from proxy agent aggregate status file: {e}"),
        )),
    };

    // Determine error for status reporting
    if let Some((error_key, error_message)) = timestamp_error {
        report_error_status(
            status,
            status_state_obj,
            service_state,
            error_key,
            error_message,
        );
        return;
    } else if proxy_agent_aggregate_status_file_version != *proxy_agent_file_version_in_extension {
        let version_mismatch_message = format!("Proxy agent aggregate status file version {proxy_agent_aggregate_status_file_version} does not match proxy agent file version in extension {proxy_agent_file_version_in_extension}");
        report_error_status(
            status,
            status_state_obj,
            service_state,
            constants::STATE_KEY_FILE_VERSION,
            version_mismatch_message,
        );
        return;
    }
    // Success Status and report to status file for CRP to read from
    let substatus_proxy_agent_message =
        match serde_json::to_string(&proxy_agent_aggregate_status_obj) {
            Ok(proxy_agent_aggregate_status) => proxy_agent_aggregate_status,
            Err(e) => {
                let error_message =
                    format!("Error in serializing proxy agent aggregate status: {e}");
                logger::write(error_message.to_string());
                error_message
            }
        };
    let mut substatus_proxy_agent_connection_message: String;
    if !proxy_agent_aggregate_status_top_level
        .proxyConnectionSummary
        .is_empty()
    {
        let proxy_agent_aggregate_connection_status_obj = get_top_proxy_connection_summary(
            proxy_agent_aggregate_status_top_level
                .proxyConnectionSummary
                .clone(),
            constants::MAX_CONNECTION_SUMMARY_LEN,
        );
        match serde_json::to_string(&proxy_agent_aggregate_connection_status_obj) {
            Ok(proxy_agent_aggregate_connection_status) => {
                substatus_proxy_agent_connection_message = proxy_agent_aggregate_connection_status;
            }
            Err(e) => {
                let error_message =
                    format!("Error in serializing proxy agent aggregate connection status: {e}");
                logger::write(error_message.to_string());
                substatus_proxy_agent_connection_message = error_message;
            }
        }
    } else {
        logger::write("proxy connection summary is empty".to_string());
        substatus_proxy_agent_connection_message = "proxy connection summary is empty".to_string();
    }
    let mut substatus_failed_auth_message: String;
    if !proxy_agent_aggregate_status_top_level
        .failedAuthenticateSummary
        .is_empty()
    {
        let proxy_agent_aggregate_failed_auth_status_obj = get_top_proxy_connection_summary(
            proxy_agent_aggregate_status_top_level
                .failedAuthenticateSummary
                .clone(),
            constants::MAX_FAILED_AUTH_SUMMARY_LEN,
        );
        match serde_json::to_string(&proxy_agent_aggregate_failed_auth_status_obj) {
            Ok(proxy_agent_aggregate_failed_auth_status) => {
                substatus_failed_auth_message = proxy_agent_aggregate_failed_auth_status;
            }
            Err(e) => {
                let error_message =
                    format!("Error in serializing proxy agent aggregate failed auth status: {e}");
                logger::write(error_message.to_string());
                substatus_failed_auth_message = error_message;
            }
        }
    } else {
        logger::write("proxy failed auth summary is empty".to_string());
        substatus_failed_auth_message = "proxy failed auth summary is empty".to_string();
    }

    trim_proxy_agent_status_file(
        &mut substatus_failed_auth_message,
        &mut substatus_proxy_agent_connection_message,
        constants::MAX_PROXYAGENT_CONNECTION_DATA_SIZE_IN_KB,
    );

    status.substatus = {
        vec![
            SubStatus {
                name: constants::PLUGIN_CONNECTION_NAME.to_string(),
                status: constants::SUCCESS_STATUS.to_string(),
                code: constants::STATUS_CODE_OK,
                formattedMessage: FormattedMessage {
                    lang: constants::LANG_EN_US.to_string(),
                    message: substatus_proxy_agent_connection_message.to_string(),
                },
            },
            SubStatus {
                name: constants::PLUGIN_STATUS_NAME.to_string(),
                status: constants::SUCCESS_STATUS.to_string(),
                code: constants::STATUS_CODE_OK,
                formattedMessage: FormattedMessage {
                    lang: constants::LANG_EN_US.to_string(),
                    message: substatus_proxy_agent_message.to_string(),
                },
            },
            SubStatus {
                name: constants::PLUGIN_FAILED_AUTH_NAME.to_string(),
                status: constants::SUCCESS_STATUS.to_string(),
                code: constants::STATUS_CODE_OK,
                formattedMessage: FormattedMessage {
                    lang: constants::LANG_EN_US.to_string(),
                    message: substatus_failed_auth_message.to_string(),
                },
            },
        ]
    };
    set_success(
        status,
        status_state_obj,
        "ProxyAgent extension is reporting successful status.".to_string(),
    );
    write_state_event(
        constants::STATE_KEY_FILE_VERSION,
        constants::SUCCESS_STATUS,
        substatus_proxy_agent_connection_message.to_string(),
        "extension_substatus",
        "service_main",
        &logger::get_logger_key(),
        service_state,
    );
}

fn trim_proxy_agent_status_file(
    substatus_failed_auth_message: &mut String,
    substatus_connection_summary_message: &mut String,
    max_size_in_kb: usize,
) {
    let allowed_bytes = max_size_in_kb * 1024;
    if substatus_connection_summary_message.len() + substatus_failed_auth_message.len()
        > allowed_bytes
    {
        let connection_message = "Substatus of proxy agent connection message and failed auth message size exceeds max size, dropping connection summary".to_string();
        logger::write(connection_message.clone());
        *substatus_connection_summary_message = connection_message;
        if substatus_failed_auth_message.len() > allowed_bytes {
            substatus_failed_auth_message.truncate(allowed_bytes);
        }
    }
}

fn get_top_proxy_connection_summary(
    mut summary: Vec<ProxyConnectionSummary>,
    max_count: usize,
) -> Vec<ProxyConnectionSummary> {
    summary.sort_by_key(|a| a.count);
    let len = summary.len();
    if len > max_count {
        summary = summary.split_off(len - max_count);
    }

    summary
}

fn restore_purge_proxy_agent(status: &mut StatusObj) -> bool {
    let setup_tool = misc_helpers::path_to_string(&common::setup_tool_exe_path());
    if status.status == *constants::ERROR_STATUS {
        let output = Command::new(&setup_tool).arg("restore").output();
        match output {
            Ok(output) => {
                let event_level = if output.status.success() {
                    LoggerLevel::Info
                } else {
                    LoggerLevel::Warn
                };
                telemetry::event_logger::write_event(
                    event_level,
                    format!(
                        "Restore Proxy Agent command finished with stdoutput: {}, stderr: {}",
                        String::from_utf8_lossy(&output.stdout),
                        String::from_utf8_lossy(&output.stderr)
                    ),
                    "restore_purge_proxy_agent",
                    "service_main",
                    &logger::get_logger_key(),
                );
            }
            Err(e) => {
                telemetry::event_logger::write_event(
                    LoggerLevel::Info,
                    format!("Error in running Restore Proxy Agent command: {e}"),
                    "restore_purge_proxy_agent",
                    "service_main",
                    &logger::get_logger_key(),
                );
            }
        }
        true
    } else if status.status == *constants::SUCCESS_STATUS {
        let output = Command::new(setup_tool).arg("purge").output();
        match output {
            Ok(output) => {
                let event_level = if output.status.success() {
                    LoggerLevel::Info
                } else {
                    LoggerLevel::Warn
                };
                telemetry::event_logger::write_event(
                    event_level,
                    format!(
                        "Purge Proxy Agent command finished with stdoutput: {}, stderr: {}",
                        String::from_utf8_lossy(&output.stdout),
                        String::from_utf8_lossy(&output.stderr)
                    ),
                    "restore_purge_proxy_agent",
                    "service_main",
                    &logger::get_logger_key(),
                );
            }
            Err(e) => {
                telemetry::event_logger::write_event(
                    LoggerLevel::Info,
                    format!("Error in running Purge Proxy Agent command: {e}"),
                    "restore_purge_proxy_agent",
                    "service_main",
                    &logger::get_logger_key(),
                );
            }
        }
        true
    } else {
        false
    }
}

fn report_proxy_agent_service_status(
    output: Result<Output, Error>,
    status_folder: PathBuf,
    seq_no: &str,
    status: &mut StatusObj,
    status_state_obj: &mut common::StatusState,
) {
    match output {
        Ok(output) => {
            let message =
                "Successfully Executed Setup Tool Install Command for Proxy Agent Version Upgrade"
                    .to_string();
            logger::write(format!(
                "{} with stdoutput: {}, stderr: {}",
                message.clone(),
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ));
            if output.status.success() {
                set_success(status, status_state_obj, message);
                status.substatus = Default::default();
                common::report_status(status_folder, seq_no, status);
            } else {
                let err_message = format!(
                    "Execute Install Command in Proxy Agent Setup Tool Output Status Not Success: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
                telemetry::event_logger::write_event(
                    LoggerLevel::Warn,
                    err_message.clone(),
                    "report_proxy_agent_service_status",
                    "service_main",
                    &logger::get_logger_key(),
                );
                set_error(status, status_state_obj, err_message.clone());
                // Override code with the actual process exit code
                status.code = output
                    .status
                    .code()
                    .unwrap_or(constants::STATUS_CODE_NOT_OK);
                status.substatus = Default::default();
                common::report_status(status_folder, seq_no, status);
            }
        }
        Err(e) => {
            let err_message = format!(
                "Failed to execute Install Proxy Agent Command Through Setup Tool with error: {e}"
            );
            telemetry::event_logger::write_event(
                LoggerLevel::Warn,
                err_message.clone(),
                "report_proxy_agent_service_status",
                "service_main",
                &logger::get_logger_key(),
            );
            // report proxyagent service update failed state
            set_error(status, status_state_obj, err_message.clone());
            status.substatus = Default::default();
            common::report_status(status_folder, seq_no, status);
        }
    }
}

// test report status
#[cfg(test)]
mod tests {
    use crate::constants;
    use crate::structs::*;
    use proxy_agent_shared::misc_helpers;
    use proxy_agent_shared::proxy_agent_aggregate_status::*;
    use std::path::PathBuf;

    /// Build a StatusObj with default plugin name, enable operation, and current timestamp.
    fn make_test_status_obj(status: &str, code: i32, message: &str) -> StatusObj {
        StatusObj {
            name: constants::PLUGIN_NAME.to_string(),
            operation: constants::ENABLE_OPERATION.to_string(),
            configurationAppliedTime: misc_helpers::get_date_time_string(),
            code,
            status: status.to_string(),
            formattedMessage: FormattedMessage {
                lang: constants::LANG_EN_US.to_string(),
                message: message.to_string(),
            },
            substatus: Default::default(),
        }
    }

    fn make_detail_status() -> ProxyAgentDetailStatus {
        ProxyAgentDetailStatus {
            status: ModuleState::RUNNING,
            message: "test".to_string(),
            states: None,
        }
    }

    fn make_test_proxy_agent_status(version: &str) -> ProxyAgentStatus {
        ProxyAgentStatus {
            version: version.to_string(),
            status: OverallState::SUCCESS,
            monitorStatus: make_detail_status(),
            keyLatchStatus: make_detail_status(),
            ebpfProgramStatus: make_detail_status(),
            proxyListenerStatus: make_detail_status(),
            telemetryLoggerStatus: make_detail_status(),
            proxyConnectionsCount: 1,
        }
    }

    fn make_test_connection_summary() -> ProxyConnectionSummary {
        ProxyConnectionSummary {
            userName: "test".to_string(),
            ip: "test".to_string(),
            port: 1,
            addressFamily: "IPv4".to_string(),
            processCmdLine: "test".to_string(),
            responseStatus: "test".to_string(),
            count: 1,
            processFullPath: Some("test".to_string()),
            userGroups: Some(vec!["test".to_string()]),
        }
    }

    fn make_test_aggregate_status(
        timestamp: String,
        version: &str,
    ) -> GuestProxyAgentAggregateStatus {
        let summary = make_test_connection_summary();
        GuestProxyAgentAggregateStatus {
            timestamp,
            proxyAgentStatus: make_test_proxy_agent_status(version),
            proxyConnectionSummary: vec![summary.clone()],
            failedAuthenticateSummary: vec![summary],
        }
    }

    #[test]
    #[cfg(windows)]
    fn report_proxy_agent_service_status() {
        use std::env;
        use std::fs;
        use std::io::Write;
        use std::path::PathBuf;
        use std::process::Command;

        // Create temp directory for status folder
        let mut temp_test_path = env::temp_dir();
        temp_test_path.push("test_status_file");

        //Clean up and ignore the clean up errors
        _ = fs::remove_dir_all(&temp_test_path);
        _ = misc_helpers::try_create_folder(&temp_test_path);
        let status_folder: PathBuf = temp_test_path.join("status");

        let mut test_good = temp_test_path.clone();
        test_good.push("test.ps1");
        let mut file = fs::File::create(&test_good).unwrap();
        file.write_all(b"\"Hello World\"").unwrap();

        let output = Command::new("powershell.exe").args(&test_good).output();

        //Set the config_seq_no value
        let seq_no = "0";
        let expected_status_file: &PathBuf = &temp_test_path.join("status").join("0.status");

        let mut status = make_test_status_obj(
            constants::SUCCESS_STATUS,
            constants::STATUS_CODE_OK,
            "Update Proxy Agent command output successfully",
        );
        let mut status_state_obj = super::common::StatusState::new();

        super::report_proxy_agent_service_status(
            output,
            status_folder,
            &seq_no,
            &mut status,
            &mut status_state_obj,
        );

        let handler_status =
            misc_helpers::json_read_from_file::<Vec<TopLevelStatus>>(&expected_status_file)
                .unwrap();
        assert_eq!(handler_status.len(), 1);
        assert_eq!(handler_status[0].status.code, 0);

        let status_folder_bad = temp_test_path.join("status_bad");
        let mut test_bad = temp_test_path.clone();
        test_bad.push("&?@(random)?.ps1");

        let output = Command::new("powershell.exe").args(&test_bad).output();

        let expected_status_file_bad: &PathBuf =
            &temp_test_path.join("status_bad").join("0.status");

        super::report_proxy_agent_service_status(
            output,
            status_folder_bad,
            &seq_no,
            &mut status,
            &mut status_state_obj,
        );
        let handler_status_bad =
            misc_helpers::json_read_from_file::<Vec<TopLevelStatus>>(expected_status_file_bad)
                .unwrap();
        assert_eq!(handler_status_bad.len(), 1);
        assert_eq!(handler_status_bad[0].status.code, 1);

        //Clean up and ignore the clean up errors
        _ = fs::remove_dir_all(&temp_test_path);
    }

    #[test]
    fn test_proxy_agent_service_success_status() {
        let toplevel_status =
            make_test_aggregate_status(misc_helpers::get_date_time_string(), "1.0.0");
        let result = toplevel_status.get_status_timestamp();
        assert!(
            result.is_ok(),
            "Status timestamp parse expected Ok result, got Err: {:?}",
            result.err()
        );

        let mut status = make_test_status_obj(
            constants::SUCCESS_STATUS,
            constants::STATUS_CODE_OK,
            "Update Proxy Agent command output successfully",
        );

        let mut status_state_obj = super::common::StatusState::new();

        let proxy_agent_file_version_in_extension: &String = &"1.0.0".to_string();
        let mut service_state = super::service_state::ServiceState::default();

        super::extension_substatus(
            toplevel_status,
            proxy_agent_file_version_in_extension,
            &mut status,
            &mut status_state_obj,
            &mut service_state,
        );
        assert_eq!(status.status, constants::SUCCESS_STATUS.to_string());
    }

    #[tokio::test]
    #[cfg(windows)]
    async fn test_compute_ebpf_substatus() {
        let mut status = make_test_status_obj(
            constants::SUCCESS_STATUS,
            constants::STATUS_CODE_OK,
            "Update Proxy Agent command output successfully",
        );
        status.substatus = vec![
            SubStatus {
                name: constants::PLUGIN_CONNECTION_NAME.to_string(),
                status: constants::SUCCESS_STATUS.to_string(),
                code: constants::STATUS_CODE_OK,
                formattedMessage: FormattedMessage {
                    lang: constants::LANG_EN_US.to_string(),
                    message: "test".to_string(),
                },
            },
            SubStatus {
                name: constants::PLUGIN_STATUS_NAME.to_string(),
                status: constants::SUCCESS_STATUS.to_string(),
                code: constants::STATUS_CODE_OK,
                formattedMessage: FormattedMessage {
                    lang: constants::LANG_EN_US.to_string(),
                    message: "test".to_string(),
                },
            },
            SubStatus {
                name: constants::PLUGIN_FAILED_AUTH_NAME.to_string(),
                status: constants::SUCCESS_STATUS.to_string(),
                code: constants::STATUS_CODE_OK,
                formattedMessage: FormattedMessage {
                    lang: constants::LANG_EN_US.to_string(),
                    message: "test".to_string(),
                },
            },
        ];

        status.substatus.push(super::compute_ebpf_substatus());
        assert_eq!(
            status.substatus[0].name,
            constants::PLUGIN_CONNECTION_NAME.to_string()
        );
        assert_eq!(
            status.substatus[1].name,
            constants::PLUGIN_STATUS_NAME.to_string()
        );
        assert_eq!(
            status.substatus[2].name,
            constants::PLUGIN_FAILED_AUTH_NAME.to_string()
        );
        assert_eq!(
            status.substatus[3].name,
            constants::EBPF_SUBSTATUS_NAME.to_string()
        );

        // Verify the eBPF substatus message includes all three services, and that status/code
        // are internally consistent (adaptive to whatever eBPF-for-Windows state the test
        // runner happens to have installed).
        let ebpf_substatus = &status.substatus[3];
        let ebpf_message = &ebpf_substatus.formattedMessage.message;
        assert!(
            ebpf_message.contains("EbpfCore:"),
            "Expected message to contain 'EbpfCore:', got: {ebpf_message}"
        );
        assert!(
            ebpf_message.contains("NetEbpfExt:"),
            "Expected message to contain 'NetEbpfExt:', got: {ebpf_message}"
        );
        assert!(
            ebpf_message.contains("eBPFSvc:"),
            "Expected message to contain 'eBPFSvc:', got: {ebpf_message}"
        );
        if ebpf_substatus.status == constants::SUCCESS_STATUS {
            assert_eq!(ebpf_substatus.code, constants::STATUS_CODE_OK);
        } else if ebpf_substatus.status == constants::TRANSITIONING_STATUS {
            // A service could legitimately be caught mid-start on the test runner; code stays
            // OK while Transitioning, consistent with the existing set_error/set_success
            // code/status coupling convention used elsewhere in this file.
            assert_eq!(ebpf_substatus.code, constants::STATUS_CODE_OK);
        } else {
            assert_eq!(ebpf_substatus.status, constants::ERROR_STATUS);
            assert_eq!(ebpf_substatus.code, constants::STATUS_CODE_NOT_OK);
        }
    }

    #[test]
    fn test_compute_gpa_service_substatus() {
        // Cross-platform (unlike compute_ebpf_substatus, not gated to Windows): exercises the
        // real check_service_run_status call (SCM on Windows, systemctl on Linux) against
        // whatever GuestProxyAgent service state the test runner happens to have, and verifies
        // the result is well-formed and internally consistent regardless of that state. This
        // backfills test coverage for a function introduced in the prior commit that previously
        // had no dedicated test (only its pure `build_proxy_agent_service_substatus` helper was
        // tested).
        let substatus = super::compute_gpa_service_substatus();
        assert_eq!(
            substatus.name,
            constants::PROXY_AGENT_SERVICE_SUBSTATUS_NAME
        );
        assert!(
            substatus
                .formattedMessage
                .message
                .starts_with(&format!("{}: ", constants::PROXY_AGENT_SERVICE_NAME)),
            "Expected message to start with '{}: ', got: {}",
            constants::PROXY_AGENT_SERVICE_NAME,
            substatus.formattedMessage.message
        );
        if substatus.status == constants::SUCCESS_STATUS {
            assert_eq!(substatus.code, constants::STATUS_CODE_OK);
        } else if substatus.status == constants::TRANSITIONING_STATUS {
            assert_eq!(substatus.code, constants::STATUS_CODE_OK);
        } else {
            assert_eq!(substatus.status, constants::ERROR_STATUS);
            assert_eq!(substatus.code, constants::STATUS_CODE_NOT_OK);
        }
    }

    #[test]
    #[cfg(windows)]
    fn test_build_ebpf_substatus() {
        use proxy_agent_shared::service::{ServiceState, ServiceStatusInfo};

        fn make_info(name: &str, state: Option<ServiceState>) -> ServiceStatusInfo {
            let start_type = if state.is_some() {
                "AutoStart".to_string()
            } else {
                "NotInstalled".to_string()
            };
            ServiceStatusInfo {
                service_name: name.to_string(),
                state,
                start_type,
            }
        }

        let running = || Some(ServiceState::Running);
        let stopped = || Some(ServiceState::Stopped);

        // 1. All three not installed
        let sub = super::build_ebpf_substatus(
            &make_info(constants::EBPF_CORE, None),
            &make_info(constants::EBPF_EXT, None),
            &make_info(constants::EBPF_SVC, None),
        );
        assert_eq!(sub.status, constants::ERROR_STATUS, "All not installed");
        assert_eq!(sub.code, constants::STATUS_CODE_NOT_OK);
        let msg = &sub.formattedMessage.message;
        assert!(
            msg.contains(constants::EBPF_CORE)
                && msg.contains(constants::EBPF_EXT)
                && msg.contains(constants::EBPF_SVC),
            "Expected all three service names in message, got: {msg}"
        );

        // 2. Core+Ext running, eBPFSvc not installed → still Error (all three required)
        let sub = super::build_ebpf_substatus(
            &make_info(constants::EBPF_CORE, running()),
            &make_info(constants::EBPF_EXT, running()),
            &make_info(constants::EBPF_SVC, None),
        );
        assert_eq!(
            sub.status,
            constants::ERROR_STATUS,
            "eBPFSvc not installed should still be Error even if Core+Ext are healthy"
        );
        assert_eq!(sub.code, constants::STATUS_CODE_NOT_OK);
        let msg = &sub.formattedMessage.message;
        assert!(
            msg.contains("eBPFSvc: NotInstalled"),
            "Expected eBPFSvc: NotInstalled in message, got: {msg}"
        );

        // 3. Core+Ext running, eBPFSvc stopped → Error
        let sub = super::build_ebpf_substatus(
            &make_info(constants::EBPF_CORE, running()),
            &make_info(constants::EBPF_EXT, running()),
            &make_info(constants::EBPF_SVC, stopped()),
        );
        assert_eq!(
            sub.status,
            constants::ERROR_STATUS,
            "eBPFSvc stopped should be Error even if Core+Ext are healthy"
        );
        assert_eq!(sub.code, constants::STATUS_CODE_NOT_OK);

        // 4. Core not installed, Ext+Svc running → Error
        let sub = super::build_ebpf_substatus(
            &make_info(constants::EBPF_CORE, None),
            &make_info(constants::EBPF_EXT, running()),
            &make_info(constants::EBPF_SVC, running()),
        );
        assert_eq!(sub.status, constants::ERROR_STATUS, "Core not installed");
        assert_eq!(sub.code, constants::STATUS_CODE_NOT_OK);
        let msg = &sub.formattedMessage.message;
        assert!(
            msg.contains(constants::EBPF_CORE),
            "Expected EbpfCore in message, got: {msg}"
        );
        assert!(
            msg.contains("Running"),
            "Expected Ext/Svc summary (Running) in message, got: {msg}"
        );

        // 5. Ext not installed, Core+Svc running → Error
        let sub = super::build_ebpf_substatus(
            &make_info(constants::EBPF_CORE, running()),
            &make_info(constants::EBPF_EXT, None),
            &make_info(constants::EBPF_SVC, running()),
        );
        assert_eq!(sub.status, constants::ERROR_STATUS, "Ext not installed");
        assert_eq!(sub.code, constants::STATUS_CODE_NOT_OK);

        // 6. All three running → Success
        let sub = super::build_ebpf_substatus(
            &make_info(constants::EBPF_CORE, running()),
            &make_info(constants::EBPF_EXT, running()),
            &make_info(constants::EBPF_SVC, running()),
        );
        assert_eq!(sub.status, constants::SUCCESS_STATUS, "All three running");
        assert_eq!(sub.code, constants::STATUS_CODE_OK);
        let msg = &sub.formattedMessage.message;
        assert!(
            msg.contains("EbpfCore:") && msg.contains("NetEbpfExt:") && msg.contains("eBPFSvc:"),
            "Expected all three driver labels in message, got: {msg}"
        );

        // 7. Core stopped, Ext+Svc running → Error
        let sub = super::build_ebpf_substatus(
            &make_info(constants::EBPF_CORE, stopped()),
            &make_info(constants::EBPF_EXT, running()),
            &make_info(constants::EBPF_SVC, running()),
        );
        assert_eq!(
            sub.status,
            constants::ERROR_STATUS,
            "Core stopped, Ext+Svc running"
        );
        assert_eq!(sub.code, constants::STATUS_CODE_NOT_OK);

        // 8. Core running, Ext stopped, Svc running → Error
        let sub = super::build_ebpf_substatus(
            &make_info(constants::EBPF_CORE, running()),
            &make_info(constants::EBPF_EXT, stopped()),
            &make_info(constants::EBPF_SVC, running()),
        );
        assert_eq!(
            sub.status,
            constants::ERROR_STATUS,
            "Core running, Ext stopped, Svc running"
        );
        assert_eq!(sub.code, constants::STATUS_CODE_NOT_OK);

        // 9. All three stopped → Error
        let sub = super::build_ebpf_substatus(
            &make_info(constants::EBPF_CORE, stopped()),
            &make_info(constants::EBPF_EXT, stopped()),
            &make_info(constants::EBPF_SVC, stopped()),
        );
        assert_eq!(sub.status, constants::ERROR_STATUS, "All three stopped");
        assert_eq!(sub.code, constants::STATUS_CODE_NOT_OK);

        // 10. Core starting up (StartPending), Ext+Svc running → Transitioning, not Error.
        // Regression test: a service mid-boot/mid-restart must not immediately flip the
        // top-level extension status to Error (see apply_ebpf_status_override, which only
        // fires on ERROR_STATUS).
        let sub = super::build_ebpf_substatus(
            &make_info(constants::EBPF_CORE, Some(ServiceState::StartPending)),
            &make_info(constants::EBPF_EXT, running()),
            &make_info(constants::EBPF_SVC, running()),
        );
        assert_eq!(
            sub.status,
            constants::TRANSITIONING_STATUS,
            "Core starting up should be Transitioning, not Error"
        );
        assert_eq!(sub.code, constants::STATUS_CODE_OK);

        // 11. Svc resuming (ContinuePending), Core+Ext running → Transitioning, not Error.
        let sub = super::build_ebpf_substatus(
            &make_info(constants::EBPF_CORE, running()),
            &make_info(constants::EBPF_EXT, running()),
            &make_info(constants::EBPF_SVC, Some(ServiceState::ContinuePending)),
        );
        assert_eq!(
            sub.status,
            constants::TRANSITIONING_STATUS,
            "Svc resuming should be Transitioning, not Error"
        );
        assert_eq!(sub.code, constants::STATUS_CODE_OK);

        // 12. Core starting up (StartPending) AND Ext confirmed stopped → Error wins over
        // Transitioning, since at least one service is confirmed down.
        let sub = super::build_ebpf_substatus(
            &make_info(constants::EBPF_CORE, Some(ServiceState::StartPending)),
            &make_info(constants::EBPF_EXT, stopped()),
            &make_info(constants::EBPF_SVC, running()),
        );
        assert_eq!(
            sub.status,
            constants::ERROR_STATUS,
            "A confirmed-down service should still report Error even if another is transitioning"
        );
        assert_eq!(sub.code, constants::STATUS_CODE_NOT_OK);
    }

    #[test]
    fn test_build_proxy_agent_service_substatus() {
        use proxy_agent_shared::service::ServiceRuntimeStatus;

        // Running → Success
        let info = ServiceRuntimeStatus {
            service_name: constants::PROXY_AGENT_SERVICE_NAME.to_string(),
            is_installed: true,
            is_running: true,
            is_transitioning: false,
            state_display: "Running".to_string(),
            start_type_display: "AutoStart".to_string(),
        };
        let sub = super::build_proxy_agent_service_substatus(&info);
        assert_eq!(sub.name, constants::PROXY_AGENT_SERVICE_SUBSTATUS_NAME);
        assert_eq!(sub.status, constants::SUCCESS_STATUS);
        assert_eq!(sub.code, constants::STATUS_CODE_OK);
        assert_eq!(
            sub.formattedMessage.message,
            format!(
                "{}: Running, AutoStart",
                constants::PROXY_AGENT_SERVICE_NAME
            )
        );

        // Stopped → Error
        let info = ServiceRuntimeStatus {
            service_name: constants::PROXY_AGENT_SERVICE_NAME.to_string(),
            is_installed: true,
            is_running: false,
            is_transitioning: false,
            state_display: "Stopped".to_string(),
            start_type_display: "AutoStart".to_string(),
        };
        let sub = super::build_proxy_agent_service_substatus(&info);
        assert_eq!(sub.status, constants::ERROR_STATUS);
        assert_eq!(sub.code, constants::STATUS_CODE_NOT_OK);
        assert_eq!(
            sub.formattedMessage.message,
            format!(
                "{}: Stopped, AutoStart",
                constants::PROXY_AGENT_SERVICE_NAME
            )
        );

        // Disabled (installed but not running, start type Disabled) → Error
        let info = ServiceRuntimeStatus {
            service_name: constants::PROXY_AGENT_SERVICE_NAME.to_string(),
            is_installed: true,
            is_running: false,
            is_transitioning: false,
            state_display: "Stopped".to_string(),
            start_type_display: "Disabled".to_string(),
        };
        let sub = super::build_proxy_agent_service_substatus(&info);
        assert_eq!(sub.status, constants::ERROR_STATUS);
        assert_eq!(sub.code, constants::STATUS_CODE_NOT_OK);

        // Not installed → Error, "NotInstalled" summary
        let info = ServiceRuntimeStatus {
            service_name: constants::PROXY_AGENT_SERVICE_NAME.to_string(),
            is_installed: false,
            is_running: false,
            is_transitioning: false,
            state_display: "NotInstalled".to_string(),
            start_type_display: "NotInstalled".to_string(),
        };
        let sub = super::build_proxy_agent_service_substatus(&info);
        assert_eq!(sub.status, constants::ERROR_STATUS);
        assert_eq!(sub.code, constants::STATUS_CODE_NOT_OK);
        assert_eq!(
            sub.formattedMessage.message,
            format!("{}: NotInstalled", constants::PROXY_AGENT_SERVICE_NAME)
        );

        // Starting up (StartPending on Windows / "activating" on Linux) → Transitioning, not
        // Error. Regression test: a service mid-boot/mid-restart must not immediately flip the
        // top-level extension status to Error (see apply_gpa_service_status_override, which
        // only fires on ERROR_STATUS).
        let info = ServiceRuntimeStatus {
            service_name: constants::PROXY_AGENT_SERVICE_NAME.to_string(),
            is_installed: true,
            is_running: false,
            is_transitioning: true,
            state_display: "StartPending".to_string(),
            start_type_display: "AutoStart".to_string(),
        };
        let sub = super::build_proxy_agent_service_substatus(&info);
        assert_eq!(
            sub.status,
            constants::TRANSITIONING_STATUS,
            "A service starting up should be Transitioning, not Error"
        );
        assert_eq!(sub.code, constants::STATUS_CODE_OK);
        assert_eq!(
            sub.formattedMessage.message,
            format!(
                "{}: StartPending, AutoStart",
                constants::PROXY_AGENT_SERVICE_NAME
            )
        );
    }

    #[test]
    #[cfg(windows)]
    fn test_apply_ebpf_status_override() {
        let make_ebpf_sub = |status: &str, message: &str| SubStatus {
            name: constants::EBPF_SUBSTATUS_NAME.to_string(),
            status: status.to_string(),
            code: if status == constants::ERROR_STATUS {
                constants::STATUS_CODE_NOT_OK
            } else {
                constants::STATUS_CODE_OK
            },
            formattedMessage: FormattedMessage {
                lang: constants::LANG_EN_US.to_string(),
                message: message.to_string(),
            },
        };

        // eBPF Error overrides an otherwise-Success status
        let mut status = make_test_status_obj(
            constants::SUCCESS_STATUS,
            constants::STATUS_CODE_OK,
            "ProxyAgent extension is reporting successful status.",
        );
        let ebpf_sub = make_ebpf_sub(
            constants::ERROR_STATUS,
            "EbpfCore: Running, AutoStart, NetEbpfExt: Stopped, AutoStart, eBPFSvc: Running, AutoStart",
        );
        let overridden = super::apply_ebpf_status_override(
            &mut status,
            &ebpf_sub,
            "2026-08-21 8:13:38.104 +00:00:00",
        );
        assert!(overridden);
        assert_eq!(status.status, constants::ERROR_STATUS);
        assert_eq!(status.code, constants::STATUS_CODE_NOT_OK);
        assert!(status
            .formattedMessage
            .message
            .contains("NetEbpfExt: Stopped"));
        assert!(status
            .formattedMessage
            .message
            .contains("Last status timestamp: 2026-08-21 8:13:38.104 +00:00:00"));
        assert!(status.formattedMessage.message.contains("Current time:"));

        // eBPF Error overrides an already-Error stale message too
        let mut status = make_test_status_obj(
            constants::ERROR_STATUS,
            constants::STATUS_CODE_NOT_OK,
            "Proxy agent aggregate status file is stale. Status timestamp: ..., Current time: ...",
        );
        let overridden = super::apply_ebpf_status_override(
            &mut status,
            &ebpf_sub,
            "2026-08-21 8:13:38.104 +00:00:00",
        );
        assert!(overridden);
        assert!(!status.formattedMessage.message.contains("stale"));
        assert!(status
            .formattedMessage
            .message
            .contains("NetEbpfExt: Stopped"));

        // eBPF healthy leaves the existing message untouched
        let mut status = make_test_status_obj(
            constants::SUCCESS_STATUS,
            constants::STATUS_CODE_OK,
            "ProxyAgent extension is reporting successful status.",
        );
        let healthy_ebpf_sub = make_ebpf_sub(
            constants::SUCCESS_STATUS,
            "EbpfCore: Running, AutoStart, NetEbpfExt: Running, AutoStart, eBPFSvc: Running, AutoStart",
        );
        let overridden =
            super::apply_ebpf_status_override(&mut status, &healthy_ebpf_sub, "irrelevant");
        assert!(!overridden);
        assert_eq!(status.status, constants::SUCCESS_STATUS);
        assert_eq!(
            status.formattedMessage.message,
            "ProxyAgent extension is reporting successful status."
        );

        // eBPF Transitioning (e.g. a service mid-boot/mid-restart) must NOT trigger the
        // override - regression test for the reviewer finding that this override previously
        // fired immediately on any non-Running state, including benign transitional ones.
        let mut status = make_test_status_obj(
            constants::SUCCESS_STATUS,
            constants::STATUS_CODE_OK,
            "ProxyAgent extension is reporting successful status.",
        );
        let transitioning_ebpf_sub = make_ebpf_sub(
            constants::TRANSITIONING_STATUS,
            "EbpfCore: Running, AutoStart, NetEbpfExt: StartPending, AutoStart, eBPFSvc: Running, AutoStart",
        );
        let overridden =
            super::apply_ebpf_status_override(&mut status, &transitioning_ebpf_sub, "irrelevant");
        assert!(
            !overridden,
            "Transitioning eBPF substatus must not trigger the immediate override"
        );
        assert_eq!(status.status, constants::SUCCESS_STATUS);
        assert_eq!(
            status.formattedMessage.message,
            "ProxyAgent extension is reporting successful status."
        );
    }

    #[test]
    fn test_apply_gpa_service_status_override() {
        let make_gpa_sub = |status: &str, message: &str| SubStatus {
            name: constants::PROXY_AGENT_SERVICE_SUBSTATUS_NAME.to_string(),
            status: status.to_string(),
            code: if status == constants::ERROR_STATUS {
                constants::STATUS_CODE_NOT_OK
            } else {
                constants::STATUS_CODE_OK
            },
            formattedMessage: FormattedMessage {
                lang: constants::LANG_EN_US.to_string(),
                message: message.to_string(),
            },
        };

        // GPA-service Error overrides an otherwise-Success status immediately (no gating on
        // top-level already being Error)
        let mut status = make_test_status_obj(
            constants::SUCCESS_STATUS,
            constants::STATUS_CODE_OK,
            "ProxyAgent extension is reporting successful status.",
        );
        let gpa_sub = make_gpa_sub(
            constants::ERROR_STATUS,
            &format!(
                "{}: Stopped, AutoStart",
                constants::PROXY_AGENT_SERVICE_NAME
            ),
        );
        let overridden = super::apply_gpa_service_status_override(
            &mut status,
            &gpa_sub,
            "2026-08-21 8:13:38.104 +00:00:00",
        );
        assert!(overridden);
        assert_eq!(status.status, constants::ERROR_STATUS);
        assert_eq!(status.code, constants::STATUS_CODE_NOT_OK);
        assert!(status
            .formattedMessage
            .message
            .contains("Stopped, AutoStart"));
        assert!(status
            .formattedMessage
            .message
            .contains("Last status timestamp: 2026-08-21 8:13:38.104 +00:00:00"));
        assert!(status.formattedMessage.message.contains("Current time:"));

        // GPA-service healthy leaves the existing message untouched
        let mut status = make_test_status_obj(
            constants::SUCCESS_STATUS,
            constants::STATUS_CODE_OK,
            "ProxyAgent extension is reporting successful status.",
        );
        let healthy_gpa_sub = make_gpa_sub(
            constants::SUCCESS_STATUS,
            &format!(
                "{}: Running, AutoStart",
                constants::PROXY_AGENT_SERVICE_NAME
            ),
        );
        let overridden =
            super::apply_gpa_service_status_override(&mut status, &healthy_gpa_sub, "irrelevant");
        assert!(!overridden);
        assert_eq!(
            status.formattedMessage.message,
            "ProxyAgent extension is reporting successful status."
        );

        // GPA-service Transitioning (e.g. mid-boot/mid-restart) must NOT trigger the override -
        // regression test for the reviewer finding that this override previously fired
        // immediately on any non-Running state, including benign transitional ones.
        let mut status = make_test_status_obj(
            constants::SUCCESS_STATUS,
            constants::STATUS_CODE_OK,
            "ProxyAgent extension is reporting successful status.",
        );
        let transitioning_gpa_sub = make_gpa_sub(
            constants::TRANSITIONING_STATUS,
            &format!(
                "{}: StartPending, AutoStart",
                constants::PROXY_AGENT_SERVICE_NAME
            ),
        );
        let overridden = super::apply_gpa_service_status_override(
            &mut status,
            &transitioning_gpa_sub,
            "irrelevant",
        );
        assert!(
            !overridden,
            "Transitioning GPA-service substatus must not trigger the immediate override"
        );
        assert_eq!(status.status, constants::SUCCESS_STATUS);
        assert_eq!(
            status.formattedMessage.message,
            "ProxyAgent extension is reporting successful status."
        );
    }

    #[test]
    fn test_should_poll() {
        use std::time::{Duration, Instant};

        let interval = Duration::from_secs(120);
        let now = Instant::now();

        // Never polled before -> should poll
        assert!(super::should_poll(None, now, interval));

        // Polled recently -> should not poll yet
        assert!(!super::should_poll(Some(now), now, interval));

        // Polled long enough ago -> should poll again
        let long_ago = now - Duration::from_secs(121);
        assert!(super::should_poll(Some(long_ago), now, interval));

        // Exactly at the interval boundary -> should poll (>=)
        let exactly_at_interval = now - interval;
        assert!(super::should_poll(Some(exactly_at_interval), now, interval));
    }

    #[test]
    fn test_should_force_recompute() {
        // First observation ever (no previous value) -> never force, nothing to compare against
        assert!(!super::should_force_recompute(None, true));
        assert!(!super::should_force_recompute(None, false));

        // No change since previous iteration -> don't force
        assert!(!super::should_force_recompute(Some(true), true));
        assert!(!super::should_force_recompute(Some(false), false));

        // Aggregate status just recovered (was failing, now succeeding) -> force recompute so
        // a stale cached Error substatus doesn't keep overriding the fresh success.
        assert!(super::should_force_recompute(Some(false), true));

        // Aggregate status just broke (was succeeding, now failing) -> force recompute so a
        // stale cached healthy substatus doesn't keep masking the new failure.
        assert!(super::should_force_recompute(Some(true), false));
    }

    #[tokio::test]
    async fn get_top_proxy_connection_summary_tests() {
        let mut summary = Vec::new();
        let mut proxy_connection_summary_obj = make_test_connection_summary();
        summary.push(proxy_connection_summary_obj.clone());
        proxy_connection_summary_obj.count = 5;
        summary.push(proxy_connection_summary_obj.clone());
        proxy_connection_summary_obj.count = 2;
        summary.push(proxy_connection_summary_obj.clone());
        proxy_connection_summary_obj.count = 4;
        summary.push(proxy_connection_summary_obj.clone());
        proxy_connection_summary_obj.count = 2;
        summary.push(proxy_connection_summary_obj.clone());
        let max_len = 3;
        let result = super::get_top_proxy_connection_summary(summary, max_len);
        assert_eq!(result.len(), max_len);
        assert_eq!(result[0].count, 2); // lowest count
        assert_eq!(result[1].count, 4); // 2nd highest count
        assert_eq!(result[2].count, 5); // 3rd highest count
    }

    #[test]
    fn test_trim_proxy_agent_status_file_cases() {
        // Case 1: total size is under max_size, should not modify the strings
        let mut connection_summary = "b".repeat(1024 * 2); // 2 KB
        let mut failed_auth_summary = "a".repeat(1024); // 1 KB
        let max_size = 4; // 4 KB
        let orig_conn = connection_summary.clone();
        let orig_auth = failed_auth_summary.clone();
        super::trim_proxy_agent_status_file(
            &mut failed_auth_summary,
            &mut connection_summary,
            max_size,
        );
        assert_eq!(connection_summary, orig_conn);
        assert_eq!(failed_auth_summary, orig_auth);

        // Case 2: total size exceeds max_size, should drop connection summary and keep failed_auth_summary the same
        let mut connection_summary = "b".repeat(1024 * 3); // 3 KB
        let mut failed_auth_summary = "a".repeat(1024 * 3); // 3 KB
        let max_size = 5; // 5 KB
        super::trim_proxy_agent_status_file(
            &mut failed_auth_summary,
            &mut connection_summary,
            max_size,
        );
        assert!(connection_summary.contains("Substatus of proxy agent connection message and failed auth message size exceeds max size"));
        assert_eq!(failed_auth_summary, "a".repeat(1024 * 3));

        // Case 3: failed_auth_summary alone exceeds max_size, should drop connection summary and trim failed_auth_summary
        let mut connection_summary = "b".repeat(1024 * 1); // 1 KB
        let mut failed_auth_summary = "a".repeat(1024 * 10); // 10 KB
        let max_size = 2; // 2 KB
        super::trim_proxy_agent_status_file(
            &mut failed_auth_summary,
            &mut connection_summary,
            max_size,
        );
        assert!(connection_summary.contains("Substatus of proxy agent connection message and failed auth message size exceeds max size"));
        assert_eq!(failed_auth_summary, "a".repeat(2048));

        // Case 4: total size exactly equals max_size, should not modify the strings
        let mut connection_summary = "b".repeat(1024 * 2); // 2 KB
        let mut failed_auth_summary = "a".repeat(1024 * 2); // 2 KB
        let max_size = 4; // 4 KB
        let orig_conn = connection_summary.clone();
        let orig_auth = failed_auth_summary.clone();
        super::trim_proxy_agent_status_file(
            &mut failed_auth_summary,
            &mut connection_summary,
            max_size,
        );
        assert_eq!(connection_summary, orig_conn);
        assert_eq!(failed_auth_summary, orig_auth);
    }

    #[test]
    fn test_stale_status_timestamp_greater_than_5_minutes() {
        // Create a timestamp that is 10 minutes old (greater than 5 minutes)
        // Use a fixed old timestamp format to simulate staleness
        let stale_timestamp = "2024-01-01T00:00:00Z".to_string();
        let toplevel_status = make_test_aggregate_status(stale_timestamp, "1.0.0");

        let mut status = make_test_status_obj(
            constants::SUCCESS_STATUS,
            constants::STATUS_CODE_OK,
            "Update Proxy Agent command output successfully",
        );

        let mut status_state_obj = super::common::StatusState::new();
        let proxy_agent_file_version_in_extension: &String = &"1.0.0".to_string();
        let mut service_state = super::service_state::ServiceState::default();

        super::extension_substatus(
            toplevel_status,
            proxy_agent_file_version_in_extension,
            &mut status,
            &mut status_state_obj,
            &mut service_state,
        );

        // Verify that status is not successful due to stale timestamp
        assert_ne!(status.status, constants::SUCCESS_STATUS.to_string());
        assert_eq!(status.substatus.len(), 3);
        assert_eq!(
            status.substatus[0].status,
            constants::TRANSITIONING_STATUS.to_string()
        );
        assert_eq!(status.substatus[0].code, constants::STATUS_CODE_NOT_OK);
        assert!(status.substatus[0]
            .formattedMessage
            .message
            .contains("stale"));
    }

    #[test]
    fn test_fresh_status_timestamp_within_5_minutes() {
        // Create a fresh timestamp (current time)
        let toplevel_status =
            make_test_aggregate_status(misc_helpers::get_date_time_string(), "1.0.0");

        let mut status = make_test_status_obj(
            constants::SUCCESS_STATUS,
            constants::STATUS_CODE_OK,
            "Update Proxy Agent command output successfully",
        );

        let mut status_state_obj = super::common::StatusState::new();
        let proxy_agent_file_version_in_extension: &String = &"1.0.0".to_string();
        let mut service_state = super::service_state::ServiceState::default();

        super::extension_substatus(
            toplevel_status,
            proxy_agent_file_version_in_extension,
            &mut status,
            &mut status_state_obj,
            &mut service_state,
        );

        // Verify that status is successful with fresh timestamp
        assert_eq!(status.status, constants::SUCCESS_STATUS.to_string());
        assert_eq!(status.substatus.len(), 3);
        assert_eq!(
            status.substatus[0].status,
            constants::SUCCESS_STATUS.to_string()
        );
        assert_eq!(status.substatus[0].code, constants::STATUS_CODE_OK);
    }

    #[test]
    fn test_resolve_version_returns_cached_when_non_empty() {
        let mut status =
            make_test_status_obj(constants::SUCCESS_STATUS, constants::STATUS_CODE_OK, "test");
        let mut status_state_obj = super::common::StatusState::new();

        let result = super::resolve_proxy_agent_file_version_in_extension(
            "1.0.39",
            &mut status,
            &mut status_state_obj,
        );

        assert_eq!(result, Some("1.0.39".to_string()));
        // Status should remain unchanged when cached version is returned
        assert_eq!(status.status, constants::SUCCESS_STATUS.to_string());
        assert_eq!(status.code, constants::STATUS_CODE_OK);
        assert_eq!(status.formattedMessage.message, "test");
    }

    #[test]
    fn test_resolve_version_returns_none_when_file_not_found() {
        let mut status =
            make_test_status_obj(constants::SUCCESS_STATUS, constants::STATUS_CODE_OK, "test");
        let mut status_state_obj = super::common::StatusState::new();

        // Empty cache forces file read; the proxy agent exe doesn't exist in test env
        let result = super::resolve_proxy_agent_file_version_in_extension(
            "",
            &mut status,
            &mut status_state_obj,
        );

        assert_eq!(result, None);
        // After set_error with a single failure, StatusState is Transitioning,
        // so code stays STATUS_CODE_OK (0). It flips to STATUS_CODE_NOT_OK only
        // once the state machine reaches ERROR_STATUS (after 20 consecutive failures).
        assert_eq!(status.code, constants::STATUS_CODE_OK);
        assert!(status
            .formattedMessage
            .message
            .contains("Failed to get GuestProxyAgent version"));
        // StatusState starts at Transitioning; one failure keeps it there
        assert_eq!(status.status, constants::TRANSITIONING_STATUS.to_string());
    }

    #[tokio::test]
    async fn test_determine_update_action() {
        use std::env;
        use std::fs;

        let temp_dir = env::temp_dir().join("test_check_version_status");
        _ = fs::remove_dir_all(&temp_dir);
        _ = misc_helpers::try_create_folder(&temp_dir);
        let status_file = temp_dir.join("status.json");

        let version_39 = "1.0.39";
        let version_30 = "1.0.30";

        // Matching versions should return VersionMismatch
        let result = super::determine_update_action(
            version_39,
            version_30,
            None,
            None,
            None,
            "test_logger_key",
        )
        .await;
        assert_eq!(
            result,
            Some(super::UpdateAction::VersionMismatch),
            "Expected VersionMismatch when versions differ"
        );

        // Matching versions should return ResumeInterruptedUpdate when the aggregate status file doesn't exist
        let result = super::determine_update_action(
            version_39,
            version_39,
            None,
            None, // do not query from gpa server
            Some(PathBuf::from("nonexistent_path")),
            "test_logger_key",
        )
        .await;
        assert_eq!(
            result,
            Some(super::UpdateAction::ResumeInterruptedUpdate),
            "Expected ResumeInterruptedUpdate when status file does not exist"
        );

        // Matching versions should return ResumeInterruptedUpdate when the aggregate status file does exist but with different version
        // Write a valid aggregate status file with version "1.0.30"
        let aggregate_status =
            make_test_aggregate_status(misc_helpers::get_date_time_string(), version_30);
        misc_helpers::json_write_to_file(&aggregate_status, &status_file).unwrap();
        let result = super::determine_update_action(
            version_39,
            version_39,
            None,
            None, // do not query from gpa server
            Some(status_file.clone()),
            "test_logger_key",
        )
        .await;
        assert_eq!(
            result,
            Some(super::UpdateAction::ResumeInterruptedUpdate),
            "Expected ResumeInterruptedUpdate when status file exists but version differs"
        );

        // Matching versions should return None when the aggregate status file does exist and version matches
        // Write a valid aggregate status file with version "1.0.39"
        let aggregate_status =
            make_test_aggregate_status(misc_helpers::get_date_time_string(), version_39);
        misc_helpers::json_write_to_file(&aggregate_status, &status_file).unwrap();
        let result = super::determine_update_action(
            version_39,
            version_39,
            None,
            None, // do not query from gpa server
            Some(status_file.clone()),
            "test_logger_key",
        )
        .await;
        assert_eq!(
            result, None,
            "Expected None when status file exists and version matches"
        );

        // Clean up
        _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_restore_purge_returns_true_for_error_status() {
        let mut status = make_test_status_obj(
            constants::ERROR_STATUS,
            constants::STATUS_CODE_NOT_OK,
            "test error",
        );

        // restore_purge_proxy_agent should return true when status is ERROR
        // (the restore command will fail since setup tool doesn't exist, but that's OK in unit test)
        let result = super::restore_purge_proxy_agent(&mut status);
        assert!(result);
    }

    #[test]
    fn test_restore_purge_returns_true_for_success_status() {
        let mut status = make_test_status_obj(
            constants::SUCCESS_STATUS,
            constants::STATUS_CODE_OK,
            "test success",
        );

        // restore_purge_proxy_agent should return true when status is SUCCESS
        // (the purge command will fail since setup tool doesn't exist, but that's OK in unit test)
        let result = super::restore_purge_proxy_agent(&mut status);
        assert!(result);
    }

    #[test]
    fn test_restore_purge_returns_false_for_transitioning_status() {
        let mut status = make_test_status_obj(
            constants::TRANSITIONING_STATUS,
            constants::STATUS_CODE_OK,
            "test transitioning",
        );

        // restore_purge_proxy_agent should return false when status is TRANSITIONING
        let result = super::restore_purge_proxy_agent(&mut status);
        assert!(!result);
    }

    // --- Tests for set_error / set_success helpers ---

    #[test]
    fn test_set_error_updates_message_while_transitioning() {
        // A single failure: StatusState starts at Transitioning and stays there.
        // The key fix: formattedMessage.message must be updated (no longer stale).
        let mut status = make_test_status_obj(
            constants::SUCCESS_STATUS,
            constants::STATUS_CODE_OK,
            "Started ProxyAgent Extension Monitoring thread.",
        );
        let mut state = super::common::StatusState::new();

        super::set_error(
            &mut status,
            &mut state,
            "aggregate status file unreadable".to_string(),
        );

        assert_eq!(status.status, constants::TRANSITIONING_STATUS);
        assert_eq!(
            status.formattedMessage.message,
            "aggregate status file unreadable"
        );
        // code stays 0 (OK) while still Transitioning
        assert_eq!(status.code, constants::STATUS_CODE_OK);
    }

    #[test]
    fn test_set_error_sets_code_not_ok_when_reaches_error_state() {
        // After 20 consecutive failures the state machine transitions to Error.
        // code must flip to STATUS_CODE_NOT_OK at that point.
        let mut status = make_test_status_obj(
            constants::SUCCESS_STATUS,
            constants::STATUS_CODE_OK,
            "Started ProxyAgent Extension Monitoring thread.",
        );
        let mut state = super::common::StatusState::new();
        let error_msg = "aggregate status file unreadable".to_string();

        for _ in 0..20 {
            super::set_error(&mut status, &mut state, error_msg.clone());
        }

        assert_eq!(status.status, constants::ERROR_STATUS);
        assert_eq!(status.formattedMessage.message, error_msg);
        assert_eq!(status.code, constants::STATUS_CODE_NOT_OK);
    }

    #[test]
    fn test_set_success_resets_message_and_code() {
        // After a failure (Transitioning), a success call must reset the message.
        let mut status = make_test_status_obj(
            constants::TRANSITIONING_STATUS,
            constants::STATUS_CODE_NOT_OK,
            "Started ProxyAgent Extension Monitoring thread.",
        );
        let mut state = super::common::StatusState::new();
        // Drive one failure first so the state is in Transitioning
        super::set_error(&mut status, &mut state, "some error".to_string());

        super::set_success(
            &mut status,
            &mut state,
            "ProxyAgent extension is reporting successful status.".to_string(),
        );

        assert_eq!(status.status, constants::SUCCESS_STATUS);
        assert_eq!(
            status.formattedMessage.message,
            "ProxyAgent extension is reporting successful status."
        );
        assert_eq!(status.code, constants::STATUS_CODE_OK);
    }

    #[test]
    fn test_report_error_status_updates_formatted_message() {
        // Regression test for the original bug:
        // report_error_status must update formattedMessage.message with the real error.
        let mut status = make_test_status_obj(
            constants::SUCCESS_STATUS,
            constants::STATUS_CODE_OK,
            "Started ProxyAgent Extension Monitoring thread.",
        );
        let mut state = super::common::StatusState::new();
        let mut service_state = super::service_state::ServiceState::default();
        let error_message = "aggregate status file unreadable".to_string();

        super::report_error_status(
            &mut status,
            &mut state,
            &mut service_state,
            constants::STATE_KEY_READ_PROXY_AGENT_AGGREGATE_STATUS,
            error_message.clone(),
        );

        assert_eq!(status.formattedMessage.message, error_message);
        assert_ne!(
            status.formattedMessage.message, "Started ProxyAgent Extension Monitoring thread.",
            "formattedMessage must not be the stale startup string"
        );
    }

    #[test]
    fn test_stale_status_updates_formatted_message() {
        // After the fix, extension_substatus on a stale timestamp must update
        // the top-level formattedMessage.message, not leave it as the startup string.
        let stale_timestamp = "2024-01-01T00:00:00Z".to_string();
        let toplevel_status = make_test_aggregate_status(stale_timestamp, "1.0.0");

        let mut status = make_test_status_obj(
            constants::SUCCESS_STATUS,
            constants::STATUS_CODE_OK,
            "Started ProxyAgent Extension Monitoring thread.",
        );
        let mut status_state_obj = super::common::StatusState::new();
        let proxy_agent_file_version_in_extension: &String = &"1.0.0".to_string();
        let mut service_state = super::service_state::ServiceState::default();

        super::extension_substatus(
            toplevel_status,
            proxy_agent_file_version_in_extension,
            &mut status,
            &mut status_state_obj,
            &mut service_state,
        );

        assert_ne!(status.status, constants::SUCCESS_STATUS);
        assert!(
            status.formattedMessage.message.contains("stale"),
            "formattedMessage.message should describe the stale status, got: {}",
            status.formattedMessage.message
        );
        assert_ne!(
            status.formattedMessage.message, "Started ProxyAgent Extension Monitoring thread.",
            "formattedMessage must not be the stale startup string"
        );
    }
}
