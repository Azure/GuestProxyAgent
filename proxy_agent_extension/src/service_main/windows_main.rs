// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use crate::common;
use crate::constants;
use crate::logger;
use crate::result::Result;
use crate::service_main;
use std::ffi::OsStr;
use std::ffi::OsString;
use std::os::windows::ffi::OsStrExt;
use std::path::PathBuf;
use std::ptr::null_mut;
use std::time::Duration;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{
    self, ServiceControlHandlerResult, ServiceStatusHandle,
};
use windows_sys::Win32::Storage::FileSystem::{
    GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW, VS_FIXEDFILEINFO,
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

#[cfg(windows)]
pub fn get_file_version(file: PathBuf) -> Result<String> {
    logger::write(format!("get_file_version: {:?}", file.to_path_buf()));
    let file = file
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let size = unsafe { GetFileVersionInfoSizeW(file.as_ptr(), null_mut()) };
    if size == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut buffer = vec![0u8; size as usize];
    let buffer_ptr = buffer.as_mut_ptr() as *mut _;
    let result = unsafe { GetFileVersionInfoW(file.as_ptr(), 0, size, buffer_ptr) };
    if result == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut version = null_mut();
    let mut version_len = 0;
    let result = unsafe {
        VerQueryValueW(
            buffer_ptr,
            OsStr::new("\\")
                .encode_wide()
                .chain(Some(0))
                .collect::<Vec<_>>()
                .as_ptr() as *const _,
            &mut version,
            &mut version_len,
        )
    };
    if result == 0 {
        return Err(std::io::Error::last_os_error().into());
    }

    let version_info = unsafe { &*(version as *const VS_FIXEDFILEINFO) };
    let major = version_info.dwFileVersionMS >> 16;
    let minor = version_info.dwFileVersionMS & 0xffff;
    let build = version_info.dwFileVersionLS >> 16;
    let revision = version_info.dwFileVersionLS & 0xffff;
    let mut version_info_str = format!("{}.{}.{}", major, minor, build,);
    if revision > 0 {
        version_info_str = format!("{}.{}", version_info_str, revision);
    }

    Ok(version_info_str)
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_get_file_version() {
        let exe_path = std::env::current_exe().unwrap();
        let version = super::get_file_version(exe_path).unwrap();
        assert!(version.contains('.'), "version should contain .");
    }
}
