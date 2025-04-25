// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use crate::common;
use crate::constants;
use crate::logger;
use crate::result::Result;
use crate::service_main;
use std::ffi::OsString;
use std::time::Duration;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{
    self, ServiceControlHandlerResult, ServiceStatusHandle,
};

// The private global variable to store the windows service status handle.
// It is used to set the windows service status to Running and Stopped.
// Its event handler does not support async + await, which it is not allow to get it via async mpsc.
static SERVICE_STATUS_HANDLE: tokio::sync::OnceCell<ServiceStatusHandle> =
    tokio::sync::OnceCell::const_new();

pub async fn run_service(_args: Vec<OsString>) -> Result<()> {
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop => {
                common::stop_event_logger();
                if let Some(status_handle) = SERVICE_STATUS_HANDLE.get() {
                    let stop_state = ServiceStatus {
                        service_type: ServiceType::OWN_PROCESS,
                        current_state: ServiceState::Stopped,
                        controls_accepted: ServiceControlAccept::STOP,
                        exit_code: ServiceExitCode::Win32(0),
                        checkpoint: 0,
                        wait_hint: Duration::default(),
                        process_id: None,
                    };
                    if let Err(e) = status_handle.set_service_status(stop_state) {
                        logger::write(format!("Failed to set service status to Stopped: {}", e));
                    }
                } else {
                    // workaround to stop the service by exiting the process
                    logger::write("Force exit the process to stop the service.".to_string());
                    std::process::exit(0);
                }
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    // start service
    service_main::run();

    // set the service state to Running
    let status_handle = service_control_handler::register(constants::PLUGIN_NAME, event_handler)?;
    let running_state = ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    };
    status_handle.set_service_status(running_state)?;

    // set the windows service status handle
    SERVICE_STATUS_HANDLE.set(status_handle).unwrap();

    Ok(())
}
