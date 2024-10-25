// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

use crate::error::Error;
use crate::result::Result;
use crate::version::Version;
use std::ffi::OsStr;
use std::mem::MaybeUninit;
use windows_service::service::{ServiceAccess, ServiceState};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_sys::Win32::System::SystemInformation::SYSTEM_INFO;
use winreg::enums::*;
use winreg::RegKey;

fn read_reg_int(key_name: &str, value_name: &str, default_value: Option<u32>) -> Option<u32> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    match hklm.open_subkey(key_name) {
        Ok(key) => match key.get_value(value_name) {
            Ok(val) => return Some(val),
            Err(e) => {
                print!("{}", e);
            }
        },
        Err(e) => {
            print!("{}", e);
        }
    }

    default_value
}

fn read_reg_string(key_name: &str, value_name: &str, default_value: String) -> String {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);

    if let Ok(key) = hklm.open_subkey(key_name) {
        if let Ok(val) = key.get_value(value_name) {
            return val;
        }
    }

    default_value
}

const OS_VERSION_REGISTRY_KEY: &str = "Software\\Microsoft\\Windows NT\\CurrentVersion";
const PRODUCT_NAME_VAL_STRING: &str = "ProductName";
const CURRENT_MAJOR_VERSION_NUMBER_STRING: &str = "CurrentMajorVersionNumber";
const CURRENT_MINOR_VERSION_NUMBER_STRING: &str = "CurrentMinorVersionNumber";
const CURRENT_BUILD_NUMBER_STRING: &str = "CurrentBuildNumber";
const UBRSTRING: &str = "UBR";

pub fn get_os_version() -> Result<Version> {
    let major;
    match read_reg_int(
        OS_VERSION_REGISTRY_KEY,
        CURRENT_MAJOR_VERSION_NUMBER_STRING,
        None,
    ) {
        Some(m) => major = m,
        None => {
            let major_str = read_reg_string(
                OS_VERSION_REGISTRY_KEY,
                CURRENT_MAJOR_VERSION_NUMBER_STRING,
                "".to_string(),
            );
            match major_str.parse::<u32>() {
                Ok(u) => major = u,
                Err(_) => {
                    return Err(Error::ParseVersion(format!(
                        "Cannot read Major build from {}",
                        CURRENT_MAJOR_VERSION_NUMBER_STRING
                    )));
                }
            }
        }
    }

    let minor;
    match read_reg_int(
        OS_VERSION_REGISTRY_KEY,
        CURRENT_MINOR_VERSION_NUMBER_STRING,
        None,
    ) {
        Some(m) => minor = m,
        None => {
            let major_str = read_reg_string(
                OS_VERSION_REGISTRY_KEY,
                CURRENT_MINOR_VERSION_NUMBER_STRING,
                "".to_string(),
            );
            match major_str.parse::<u32>() {
                Ok(u) => minor = u,
                Err(_) => {
                    return Err(Error::ParseVersion(format!(
                        "Cannot read Minor build from {}",
                        CURRENT_MINOR_VERSION_NUMBER_STRING
                    )));
                }
            }
        }
    }
    let build;
    let build_str = read_reg_string(
        OS_VERSION_REGISTRY_KEY,
        CURRENT_BUILD_NUMBER_STRING,
        "".to_string(),
    );
    if build_str.is_empty() {
        build = read_reg_int(OS_VERSION_REGISTRY_KEY, CURRENT_BUILD_NUMBER_STRING, None);
    } else {
        match build_str.parse::<u32>() {
            Ok(u) => build = Some(u),
            Err(_) => build = None,
        }
    }

    let revision_str = read_reg_string(OS_VERSION_REGISTRY_KEY, UBRSTRING, "".to_string());
    let revision;
    if revision_str.is_empty() {
        revision = read_reg_int(OS_VERSION_REGISTRY_KEY, UBRSTRING, None);
    } else {
        match revision_str.parse::<u32>() {
            Ok(u) => revision = Some(u),
            Err(_) => revision = None,
        }
    }

    Ok(Version::from_major_minor_build_revision(
        major, minor, build, revision,
    ))
}

pub fn get_os_name() -> String {
    let os_name = read_reg_string(
        OS_VERSION_REGISTRY_KEY,
        PRODUCT_NAME_VAL_STRING,
        "".to_string(),
    );

    // Win11 CurrentVersion Registry Shows Wrong ProductName Key
    // https://docs.microsoft.com/en-us/answers/questions/555857/windows-11-product-name-in-registry.html
    if let Ok(ver) = get_os_version() {
        if let Some(build) = ver.build {
            if build >= 22000 {
                return os_name.replace("Windows 10 ", "Windows 11 ");
            }
        }
    }

    os_name
}

pub fn get_long_os_version() -> String {
    match get_os_version() {
        Ok(ver) => format!("Windows:{}-{}", get_os_name(), ver),
        Err(_) => format!("Windows:{}-{}", get_os_name(), ""),
    }
}

pub fn get_processor_arch() -> String {
    unsafe {
        let mut data = MaybeUninit::<SYSTEM_INFO>::uninit();
        windows_sys::Win32::System::SystemInformation::GetSystemInfo(data.as_mut_ptr());

        // Ref: https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/ns-sysinfoapi-system_info
        match data
            .assume_init()
            .Anonymous
            .Anonymous
            .wProcessorArchitecture
        {
            windows_sys::Win32::System::Diagnostics::Debug::PROCESSOR_ARCHITECTURE_INTEL => "x86", // 0
            windows_sys::Win32::System::Diagnostics::Debug::PROCESSOR_ARCHITECTURE_ARM => "ARM", // 5
            windows_sys::Win32::System::Diagnostics::Debug::PROCESSOR_ARCHITECTURE_IA64 => "IA64", // 6
            windows_sys::Win32::System::Diagnostics::Debug::PROCESSOR_ARCHITECTURE_AMD64 => "AMD64", // 9
            12 => "ARM64", // 12 - ARM64 is missed here
            _ => "unknown",
        }
        .to_owned()
    }
}

pub fn ensure_service_running(service_name: &str) -> (bool, String) {
    let mut message = String::new();
    let service_manager =
        match ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT) {
            Ok(manager) => manager,
            Err(e) => {
                message = format!(
                    "ensure_service_running:: Failed to connect to service manager with error {e}."
                );
                return (false, message);
            }
        };

    let service = match service_manager.open_service(
        service_name,
        ServiceAccess::QUERY_STATUS | ServiceAccess::START,
    ) {
        Ok(s) => s,
        Err(e) => {
            message = format!(
                "ensure_service_running:: Failed to open service {service_name} with error {e}."
            );
            return (false, message);
        }
    };

    match service.query_status() {
        Ok(status) => {
            if status.current_state == ServiceState::Stopped {
                match service.start(&[OsStr::new("Started by GuestProxyAgent")]) {
                    Ok(()) => {
                        message =format!(
                                "ensure_service_running:: service {service_name} started by GuestProxyAgent successfully."
                            );
                    }
                    Err(e) => {
                        message =format!(
                                "ensure_service_running:: Failed to start service {service_name} with error {e}."
                            );
                        return (false, message);
                    }
                }
            }
        }
        Err(e) => {
            message =format!(
                    "ensure_service_running:: Failed to query service state for {service_name} with error {e}."
                );
            return (false, message);
        }
    }

    (true, message)
}

#[cfg(test)]
mod tests {

    #[test]
    fn get_os_version_tests() {
        let os_name = super::get_os_name();
        assert_ne!("", os_name, "os name cannot be empty");
        let os_version = super::get_os_version().unwrap();

        assert_ne!(None, os_version.build, "os version.build cannot be None.");
        assert_ne!(
            None, os_version.revision,
            "os version.revision cannot be None."
        );

        let long_os_version = super::get_long_os_version();
        assert_eq!(
            format!("Windows:{}-{}", os_name, os_version),
            long_os_version,
            "long_os_version mismatch"
        )
    }

    #[test]
    fn get_processor_arch_test() {
        let processor_arch = super::get_processor_arch();
        assert_ne!(
            "unknown", processor_arch,
            "processor arch cannot be 'unknown'"
        );
    }
}
