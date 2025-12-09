// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

use crate::error::{Error, ParseVersionErrorType};
use crate::result::Result;
use crate::version::Version;
use std::ffi::OsStr;
use std::mem::MaybeUninit;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use windows_service::service::{ServiceAccess, ServiceState};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_sys::Win32::Foundation::{CloseHandle, FALSE, HANDLE};
use windows_sys::Win32::Security::Cryptography::{
    //bcrypt.dll functions
    BCryptCreateHash,
    BCryptDestroyHash,
    BCryptFinishHash,
    BCryptHashData,
    BCRYPT_HMAC_SHA256_ALG_HANDLE,
};
use windows_sys::Win32::Storage::FileSystem::{
    GetFileVersionInfoSizeW, // version.dll
    GetFileVersionInfoW,
    VerQueryValueW,
    VS_FIXEDFILEINFO,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectCpuRateControlInformation,
    SetInformationJobObject, JOBOBJECT_CPU_RATE_CONTROL_INFORMATION,
    JOBOBJECT_CPU_RATE_CONTROL_INFORMATION_0, JOB_OBJECT_CPU_RATE_CONTROL_ENABLE,
    JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP,
};
use windows_sys::Win32::System::SystemInformation::{
    GetSystemInfo,        // kernel32.dll
    GlobalMemoryStatusEx, // kernel32.dll
    MEMORYSTATUSEX,
    SYSTEM_INFO,
};
use windows_sys::Win32::System::Threading::{
    OpenProcess, PROCESS_ACCESS_RIGHTS, PROCESS_SET_QUOTA,
};
use winreg::enums::*;
use winreg::RegKey;

fn read_reg_int(key_name: &str, value_name: &str, default_value: Option<u32>) -> Option<u32> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    match hklm.open_subkey(key_name) {
        Ok(key) => match key.get_value(value_name) {
            Ok(val) => return Some(val),
            Err(e) => {
                print!("{e}");
            }
        },
        Err(e) => {
            print!("{e}");
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

pub fn set_reg_string(key_name: &str, value_name: &str, value: String) -> Result<()> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let (key, _) = hklm.create_subkey(key_name)?;
    key.set_value(value_name, &value)?;
    Ok(())
}

pub fn remove_reg_key(key_name: &str) -> Result<()> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    hklm.delete_subkey_all(key_name)?;
    Ok(())
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
                    return Err(Error::ParseVersion(ParseVersionErrorType::MajorBuild(
                        format!("{major_str} ({CURRENT_MAJOR_VERSION_NUMBER_STRING})"),
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
                    return Err(Error::ParseVersion(ParseVersionErrorType::MinorBuild(
                        format!("{major_str} ({CURRENT_MINOR_VERSION_NUMBER_STRING})"),
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
            windows_sys::Win32::System::SystemInformation::PROCESSOR_ARCHITECTURE_INTEL => "x86", // 0
            windows_sys::Win32::System::SystemInformation::PROCESSOR_ARCHITECTURE_ARM => "ARM", // 5
            windows_sys::Win32::System::SystemInformation::PROCESSOR_ARCHITECTURE_IA64 => "IA64", // 6
            windows_sys::Win32::System::SystemInformation::PROCESSOR_ARCHITECTURE_AMD64 => "AMD64", // 9
            windows_sys::Win32::System::SystemInformation::PROCESSOR_ARCHITECTURE_ARM64 => "ARM64", // 12
            _ => "unknown",
        }
        .to_owned()
    }
}

pub fn get_processor_count() -> usize {
    let mut data = MaybeUninit::<SYSTEM_INFO>::uninit();
    unsafe { GetSystemInfo(data.as_mut_ptr()) };

    let data = unsafe { data.assume_init() };
    data.dwNumberOfProcessors as usize
}

pub fn get_memory_in_mb() -> Result<u64> {
    let mut data = MaybeUninit::<MEMORYSTATUSEX>::uninit();
    let data = data.as_mut_ptr();
    unsafe {
        (*data).dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
        if GlobalMemoryStatusEx(data) == 0 {
            return Err(Error::WindowsApi(
                "GlobalMemoryStatusEx".to_string(),
                std::io::Error::last_os_error(),
            ));
        }
        let memory_in_mb = (*data).ullTotalPhys / 1024 / 1024;
        Ok(memory_in_mb)
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

pub fn get_file_product_version(file_path: &Path) -> Result<Version> {
    if !file_path.exists() {
        return Err(Error::ParseVersion(ParseVersionErrorType::InvalidString(
            format!("File path does not exist: {}", file_path.display()),
        )));
    }
    if !file_path.is_file() {
        return Err(Error::ParseVersion(ParseVersionErrorType::InvalidString(
            format!("File path is not a file: {}", file_path.display()),
        )));
    }
    if !file_path.is_absolute() {
        return Err(Error::ParseVersion(ParseVersionErrorType::InvalidString(
            format!("File path is not absolute: {}", file_path.display()),
        )));
    }

    let file_path = file_path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<u16>>();
    let size = unsafe { GetFileVersionInfoSizeW(file_path.as_ptr(), std::ptr::null_mut()) };
    if size == 0 {
        return Err(Error::WindowsApi(
            "GetFileVersionInfoSizeW".to_string(),
            std::io::Error::last_os_error(),
        ));
    }

    let mut buffer = vec![0u8; size as usize];
    if unsafe { GetFileVersionInfoW(file_path.as_ptr(), 0, size, buffer.as_mut_ptr() as *mut _) }
        == 0
    {
        return Err(Error::WindowsApi(
            "GetFileVersionInfoW".to_string(),
            std::io::Error::last_os_error(),
        ));
    }

    // get VS_FIXEDFILEINFO
    let mut fixed_file_info = MaybeUninit::<*mut VS_FIXEDFILEINFO>::uninit();
    let mut fixed_file_info_size = 0;
    let result = unsafe {
        VerQueryValueW(
            buffer.as_mut_ptr() as *mut _,
            "\\".encode_utf16()
                .chain(Some(0))
                .collect::<Vec<u16>>()
                .as_ptr(),
            fixed_file_info.as_mut_ptr() as *mut _,
            &mut fixed_file_info_size,
        )
    };
    if result == 0 {
        return Err(Error::WindowsApi(
            "VerQueryValueW".to_string(),
            std::io::Error::last_os_error(),
        ));
    }
    if fixed_file_info_size != std::mem::size_of::<VS_FIXEDFILEINFO>() as u32 {
        return Err(Error::ParseVersion(ParseVersionErrorType::InvalidString(
            format!("Invalid VS_FIXEDFILEINFO size '{fixed_file_info_size}' returned"),
        )));
    }

    // get the product version from VS_FIXEDFILEINFO
    let fixed_file_info = unsafe { *fixed_file_info.assume_init() };
    let major = fixed_file_info.dwProductVersionMS >> 16;
    let minor = fixed_file_info.dwProductVersionMS & 0xFFFF;
    let build = fixed_file_info.dwProductVersionLS >> 16;
    let revision = fixed_file_info.dwProductVersionLS & 0xFFFF;
    let version =
        Version::from_major_minor_build_revision(major, minor, Some(build), Some(revision));
    Ok(version)
}

pub fn compute_signature(hex_encoded_key: &str, input_to_sign: &[u8]) -> Result<String> {
    match hex::decode(hex_encoded_key) {
        Ok(key) => {
            // Create HMAC hash object
            let mut h_hash = std::ptr::null_mut();
            let status = unsafe {
                BCryptCreateHash(
                    BCRYPT_HMAC_SHA256_ALG_HANDLE,
                    &mut h_hash,
                    std::ptr::null_mut(),
                    0,
                    key.as_ptr() as *mut u8,
                    key.len() as u32,
                    0,
                )
            };
            if status != 0 {
                return Err(Error::ComputeSignature(
                    "BCryptCreateHash".to_string(),
                    status,
                ));
            }

            // Message to sign
            let status = unsafe {
                BCryptHashData(
                    h_hash,
                    input_to_sign.as_ptr() as *mut u8,
                    input_to_sign.len() as u32,
                    0,
                )
            };
            if status != 0 {
                return Err(Error::ComputeSignature(
                    "BCryptHashData".to_string(),
                    status,
                ));
            }
            // Finalize HMAC
            let mut signature = vec![0u8; 32]; // SHA256 output size
            let status = unsafe {
                BCryptFinishHash(h_hash, signature.as_mut_ptr(), signature.len() as u32, 0)
            };
            if status != 0 {
                return Err(Error::ComputeSignature(
                    "BCryptFinishHash".to_string(),
                    status,
                ));
            }
            // Clean up
            let status = unsafe { BCryptDestroyHash(h_hash) };
            if status != 0 {
                return Err(Error::ComputeSignature(
                    "BCryptDestroyHash".to_string(),
                    status,
                ));
            }
            Ok(hex::encode(signature))
        }
        Err(e) => Err(Error::Hex(hex_encoded_key.to_string(), e)),
    }
}

/// Set CPU quota for a process
/// # Arguments
/// * `process_id` - Process ID
/// * `percent` - CPU quota percentage (0-100)
pub fn set_cpu_quota(process_id: u32, percent: u16) -> Result<()> {
    // create job object
    let job_object = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
    if job_object == 0 {
        return Err(Error::WindowsApi(
            "CreateJobObjectW".to_string(),
            std::io::Error::last_os_error(),
        ));
    }

    // Configure the CPU cap first
    let mut cpu = JOBOBJECT_CPU_RATE_CONTROL_INFORMATION {
        ControlFlags: JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP,
        Anonymous: JOBOBJECT_CPU_RATE_CONTROL_INFORMATION_0 {
            CpuRate: (percent as u32) * 100,
        },
    };
    let ok = unsafe {
        SetInformationJobObject(
            job_object,
            JobObjectCpuRateControlInformation,
            &mut cpu as *mut _ as *mut _,
            std::mem::size_of::<JOBOBJECT_CPU_RATE_CONTROL_INFORMATION>() as u32,
        )
    };
    if ok == 0 {
        return Err(Error::WindowsApi(
            "SetInformationJobObject".to_string(),
            std::io::Error::last_os_error(),
        ));
    }

    // Open the target process with sufficient rights
    let process_handle = get_process_handler(process_id, PROCESS_SET_QUOTA)?;

    // Assign the process to the job object
    let ok = unsafe { AssignProcessToJobObject(job_object, process_handle) };
    let err = std::io::Error::last_os_error();
    _ = close_process_handler(process_handle);
    if ok == 0 {
        return Err(Error::WindowsApi(
            "AssignProcessToJobObject".to_string(),
            err,
        ));
    }

    Ok(())
}

/// Get process handler by pid
/// # Arguments
/// * `pid` - Process ID
/// # Returns
/// * `Result<HANDLE>` - Process handler
/// # Errors
/// * `Error::Invalid` - If the pid is 0
/// * `Error::WindowsApi` - If the OpenProcess call fails
/// # Safety
/// This function is safe to call as it does not dereference any raw pointers.
/// However, the caller is responsible for closing the process handler using `close_process_handler`
/// when it is no longer needed to avoid resource leaks.
pub fn get_process_handler(pid: u32, options: PROCESS_ACCESS_RIGHTS) -> Result<HANDLE> {
    if pid == 0 {
        return Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Process ID cannot be 0",
        )));
    }
    // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
    let handler = unsafe { OpenProcess(options, FALSE, pid) };
    if handler == 0 {
        return Err(Error::WindowsApi(
            "OpenProcess".to_string(),
            std::io::Error::last_os_error(),
        ));
    }
    Ok(handler)
}

/// Close process handler
/// # Arguments
/// * `handler` - Process handler
/// # Returns
/// * `Result<()>` - Ok if successful, Err if failed
pub fn close_process_handler(handler: HANDLE) -> Result<()> {
    if handler != 0 {
        // https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle
        if 0 != unsafe { CloseHandle(handler) } {
            return Err(Error::WindowsApi(
                "CloseHandle".to_string(),
                std::io::Error::last_os_error(),
            ));
        }
    }
    Ok(())
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

    #[test]
    fn get_file_product_version_test() {
        let system_path = std::env::var("SystemRoot").unwrap_or("C:\\Windows".to_string());
        let file_path = std::path::Path::new(&system_path)
            .join("System32")
            .join("kernel32.dll");
        let version = match super::get_file_product_version(&file_path) {
            Ok(v) => v,
            Err(e) => {
                println!("Failed to get file product version: {}", e);
                assert!(false, "Failed to get file product version");
                return;
            }
        };
        println!("kernel32.dll File product version: {}", version);
        assert_eq!(version.major, 10, "major version mismatch");
    }

    #[test]
    fn reg_set_test() {
        let key_name = "Software\\TestKey";
        let value_name = "TestValue";
        let value = "TestValueData".to_string();

        // Set the registry value
        super::set_reg_string(key_name, value_name, value.clone()).unwrap();

        // Read the registry value
        let read_value = super::read_reg_string(key_name, value_name, "".to_string());
        assert_eq!(value, read_value, "Registry value mismatch");

        // Clean up
        super::remove_reg_key(key_name).unwrap();
    }

    #[test]
    fn get_process_test() {
        let pid = std::process::id();
        let handler = super::get_process_handler(pid, super::PROCESS_SET_QUOTA).unwrap();
        assert_ne!(0, handler, "process handler cannot be 0");
        super::close_process_handler(handler).unwrap();
    }
}
