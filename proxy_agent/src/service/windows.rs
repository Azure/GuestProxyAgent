// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

use crate::common::{constants, logger};
use crate::{service, shared_state};
use std::ffi::OsString;
use std::time::Duration;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{
    self, ServiceControlHandlerResult, ServiceStatusHandle,
};

static mut SERVICE_STATUS_HANDLE: Option<ServiceStatusHandle> = None;

pub fn run_service(_args: Vec<OsString>) -> windows_service::Result<()> {
    let shared_state = shared_state::new_shared_state();
    let cloned_shared_state = shared_state.clone();
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop => {
                service::stop_service(cloned_shared_state.clone());
                unsafe {
                    match SERVICE_STATUS_HANDLE {
                        Some(status_handle) => {
                            let stop_state = ServiceStatus {
                                service_type: ServiceType::OWN_PROCESS,
                                current_state: ServiceState::Stopped,
                                controls_accepted: ServiceControlAccept::STOP,
                                exit_code: ServiceExitCode::Win32(0),
                                checkpoint: 0,
                                wait_hint: Duration::default(),
                                process_id: None,
                            };
                            _ = status_handle.set_service_status(stop_state);
                        }
                        _ => {
                            // workaround to stop the service by exiting the process
                            logger::write_warning(
                                "Force exit the process to stop the service.".to_string(),
                            );
                            std::process::exit(0);
                        }
                    };
                }
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    // start service
    service::start_service(shared_state.clone());

    // set the service state to Running
    let status_handle =
        service_control_handler::register(constants::PROXY_AGENT_SERVICE_NAME, event_handler)?;
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

    unsafe {
        SERVICE_STATUS_HANDLE = Some(status_handle);
    }

    Ok(())
}
