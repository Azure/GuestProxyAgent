// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

use crate::common::{
    error::{Error, WindowsApiErrorType},
    logger,
    result::Result,
};
use libloading::{Library, Symbol};
use once_cell::sync::Lazy;
use std::mem::MaybeUninit;
use std::ptr::null_mut;
use std::{collections::HashMap, ffi::OsString, os::windows::ffi::OsStringExt, path::PathBuf};
use windows_sys::Wdk::System::Threading::{
    NtQueryInformationProcess, // ntdll.dll
    PROCESSINFOCLASS,
};
use windows_sys::Win32::Foundation::{BOOL, HANDLE, LUID, NTSTATUS, UNICODE_STRING};
use windows_sys::Win32::Security::Authentication::Identity;
use windows_sys::Win32::Security::Authentication::Identity::{
    LSA_UNICODE_STRING, SECURITY_LOGON_SESSION_DATA,
};
use windows_sys::Win32::System::ProcessStatus::{
    K32GetModuleBaseNameW,   // kernel32.dll
    K32GetModuleFileNameExW, // kernel32.dll
};
use windows_sys::Win32::System::Threading::PROCESS_BASIC_INFORMATION;
use windows_sys::Win32::System::Threading::{
    OpenProcess, //kernel32.dll
};

const LG_INCLUDE_INDIRECT: u32 = 1u32;
const MAX_PREFERRED_LENGTH: u32 = 4294967295u32;
#[repr(C)]
struct LocalgroupUsersInfo0 {
    pub lgrui0_name: windows_sys::core::PWSTR,
}
static NETAPI32_DLL: Lazy<Library> = Lazy::new(load_netapi32_dll);
fn load_netapi32_dll() -> Library {
    let dll_name = "netapi32.dll\0";
    match unsafe { Library::new(dll_name) } {
        Ok(lib) => lib,
        Err(e) => {
            logger::write_error(format!("Loading {dll_name} failed with error: {e}."));
            panic!("Loading {dll_name} failed with error: {e}");
        }
    }
}

type NetUserGetLocalGroups = unsafe extern "system" fn(
    servername: windows_sys::core::PWSTR,
    username: windows_sys::core::PWSTR,
    level: u32,
    flags: u32,
    bufptr: *mut *mut u8,
    prefmaxlen: u32,
    entriesread: *mut u32,
    totalentries: *mut u32,
) -> u32;

#[allow(clippy::too_many_arguments)]
fn net_user_get_local_groups(
    servername: windows_sys::core::PWSTR,
    username: windows_sys::core::PWSTR,
    level: u32,
    flags: u32,
    bufptr: *mut *mut LocalgroupUsersInfo0,
    prefmaxlen: u32,
    entriesread: *mut u32,
    totalentries: *mut u32,
) -> Result<u32> {
    unsafe {
        let fun_name = "NetUserGetLocalGroups\0";
        let net_user_get_local_groups: Symbol<NetUserGetLocalGroups> = NETAPI32_DLL
            .get(fun_name.as_bytes())
            .map_err(|e| Error::WindowsApi(WindowsApiErrorType::LoadNetUserGetLocalGroups(e)))?;
        let status = net_user_get_local_groups(
            servername,
            username,
            level,
            flags,
            bufptr as *mut *mut u8,
            prefmaxlen,
            entriesread,
            totalentries,
        );
        Ok(status)
    }
}

static BUILTIN_USERS: Lazy<HashMap<u64, &str>> = Lazy::new(load_users);
fn load_users() -> HashMap<u64, &'static str> {
    let mut users = HashMap::new();
    users.insert(0x3e4, "NETWORK SERVICE");
    users.insert(0x3e5, "LOCAL SERVICE");
    users.insert(0x3e6, "SYSTEM");
    users.insert(0x3e7, "SYSTEM");
    users.insert(0x3e8, "IIS_IUSRS");
    users.insert(0x3e9, "IUSR");
    users
}

/*
    Get user name and user group names
*/
pub fn get_user(logon_id: u64) -> Result<(String, Vec<String>)> {
    let mut user_name;
    let luid = LUID {
        LowPart: (logon_id & 0xFFFFFFFF) as u32, // get lower part of 32 bits
        HighPart: (logon_id >> 32) as i32,
    };

    let mut data = MaybeUninit::<*mut SECURITY_LOGON_SESSION_DATA>::uninit();
    let status = unsafe { Identity::LsaGetLogonSessionData(&luid, data.as_mut_ptr()) };
    if status != 0 {
        let e = std::io::Error::from_raw_os_error(status as i32);
        return Err(Error::WindowsApi(
            WindowsApiErrorType::LsaGetLogonSessionData(format!("failed with os error: {e}")),
        ));
    }

    let session_data = unsafe { *data.assume_init() };
    if session_data.UserName.Length != 0 {
        user_name = from_unicode_string(&session_data.UserName);
    } else {
        // When calling LsaGetLogonSessionData and receiving a successful return code,
        // but finding that SECURITY_LOGON_SESSION_DATA->UserName.Length is 0,
        // it typically means that the logon session exists but does not have an associated username.
        logger::write_warning(format!(
            "LsaGetLogonSessionData with logon id '{logon_id}' success, but user name is empty."
        ));
        // return OK with UNDEFINED user name and empty groups
        return Ok((super::UNDEFINED.to_string(), Vec::new()));
    }
    let mut domain_user_name = user_name.clone();
    if session_data.LogonDomain.Length != 0 {
        domain_user_name = format!(
            "{}\\{}",
            from_unicode_string(&session_data.LogonDomain),
            domain_user_name
        );
    }

    // call NetUserGetLocalGroups to get local user group names
    let mut user_groups = Vec::new();
    let mut group_count = 0;
    let mut total_group_count = 0;
    let mut group_info = null_mut();
    let status = net_user_get_local_groups(
        null_mut(),
        to_pwstr(domain_user_name.as_str()).as_mut_ptr(),
        0,
        LG_INCLUDE_INDIRECT,
        &mut group_info,
        MAX_PREFERRED_LENGTH,
        &mut group_count,
        &mut total_group_count,
    )?;
    if status == 0 {
        let group_info = unsafe {
            std::slice::from_raw_parts(
                group_info as *const u8 as *const LocalgroupUsersInfo0,
                group_count as usize,
            )
        };
        for group in group_info {
            let group_name = from_pwstr(group.lgrui0_name);
            user_groups.push(group_name);
        }
    } else {
        let e = std::io::Error::from_raw_os_error(status as i32);
        logger::write_warning(format!(
            "NetUserGetLocalGroups '{domain_user_name}' failed ({status}) with os error: {e}"
        ));
    }

    // update user name if it's a built-in user
    if BUILTIN_USERS.contains_key(&logon_id) {
        user_name = BUILTIN_USERS[&logon_id].to_string();
    }

    Ok((user_name, user_groups))
}

fn from_unicode_string(unicode_string: &LSA_UNICODE_STRING) -> String {
    let mut v = vec![0u16; unicode_string.Length as usize];
    unsafe {
        std::ptr::copy_nonoverlapping(
            unicode_string.Buffer,
            v.as_mut_ptr(),
            unicode_string.Length as usize,
        );
    }

    let mut rstr = String::new();
    for val in v.iter() {
        let c: u8 = (*val & 0xFF) as u8;
        if c == 0 {
            break;
        }
        rstr.push(c as char);
    }

    rstr
}

fn from_pwstr(wide_string: *mut u16) -> String {
    let mut rstr = String::new();
    let mut i = 0;
    loop {
        let c: u8 = unsafe { (*wide_string.offset(i) & 0xFF) as u8 };
        if c == 0 {
            break;
        }
        rstr.push(c as char);
        i += 1;
    }
    rstr
}

fn to_pwstr(s: &str) -> Vec<u16> {
    let mut v: Vec<u16> = s.encode_utf16().collect();
    v.push(0);
    v
}

/*
    Get process information
*/
const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
const PROCESS_VM_READ: u32 = 0x0010;
const FALSE: BOOL = 0;
const MAX_PATH: usize = 260;
const STATUS_BUFFER_OVERFLOW: NTSTATUS = -2147483643;
const STATUS_BUFFER_TOO_SMALL: NTSTATUS = -1073741789;
const STATUS_INFO_LENGTH_MISMATCH: NTSTATUS = -1073741820;

const PROCESS_BASIC_INFORMATION_CLASS: PROCESSINFOCLASS = 0;
const PROCESS_COMMAND_LINE_INFORMATION_CLASS: PROCESSINFOCLASS = 60;

pub fn query_basic_process_info(handler: isize) -> Result<PROCESS_BASIC_INFORMATION> {
    unsafe {
        let mut process_basic_information = std::mem::zeroed::<PROCESS_BASIC_INFORMATION>();
        let mut return_length = 0;
        let status: NTSTATUS = NtQueryInformationProcess(
            handler,
            PROCESS_BASIC_INFORMATION_CLASS,
            &mut process_basic_information as *mut _ as *mut _,
            std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            &mut return_length,
        );

        if status != 0 {
            return Err(Error::WindowsApi(WindowsApiErrorType::WindowsOsError(
                std::io::Error::from_raw_os_error(status),
            )));
        }
        Ok(process_basic_information)
    }
}
pub fn get_process_handler(pid: u32) -> Result<HANDLE> {
    if pid == 0 {
        return Err(Error::Invalid("pid 0".to_string()));
    }
    let options = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ;

    unsafe {
        let handler = OpenProcess(options, FALSE, pid);
        if handler == 0 {
            return Err(Error::WindowsApi(WindowsApiErrorType::WindowsOsError(
                std::io::Error::last_os_error(),
            )));
        }
        Ok(handler)
    }
}

pub fn get_process_cmd(handler: isize) -> Result<String> {
    unsafe {
        let mut return_length = 0;
        let status: NTSTATUS = NtQueryInformationProcess(
            handler,
            PROCESS_COMMAND_LINE_INFORMATION_CLASS,
            null_mut(),
            0,
            &mut return_length as *mut _,
        );

        if status != STATUS_BUFFER_OVERFLOW
            && status != STATUS_BUFFER_TOO_SMALL
            && status != STATUS_INFO_LENGTH_MISMATCH
        {
            return Err(Error::WindowsApi(WindowsApiErrorType::WindowsOsError(
                std::io::Error::from_raw_os_error(status),
            )));
        }
        println!("return_length: {return_length}");

        let buf_len = (return_length as usize) / 2;
        let mut buffer: Vec<u16> = vec![0; buf_len + 1];
        buffer.resize(buf_len + 1, 0); // set everything to 0

        let status: NTSTATUS = NtQueryInformationProcess(
            handler,
            PROCESS_COMMAND_LINE_INFORMATION_CLASS,
            buffer.as_mut_ptr() as *mut _,
            return_length,
            &mut return_length as *mut _,
        );
        if status < 0 {
            eprintln!("NtQueryInformationProcess failed with status: {status}");
            return Err(Error::WindowsApi(WindowsApiErrorType::WindowsOsError(
                std::io::Error::from_raw_os_error(status),
            )));
        }
        buffer.set_len(buf_len);
        buffer.push(0);

        let cmd_buffer = *(buffer.as_ptr() as *const UNICODE_STRING);

        let cmd = String::from_utf16_lossy(std::slice::from_raw_parts(
            cmd_buffer.Buffer,
            (cmd_buffer.Length / 2) as usize,
        ));

        Ok(cmd)
    }
}

#[allow(dead_code)]
pub fn get_process_name(handler: isize) -> Result<PathBuf> {
    unsafe {
        let mut buffer = [0u16; MAX_PATH + 1];
        let size = K32GetModuleBaseNameW(handler, 0, buffer.as_mut_ptr(), buffer.len() as u32);
        if size == 0 {
            return Err(Error::WindowsApi(WindowsApiErrorType::WindowsOsError(
                std::io::Error::last_os_error(),
            )));
        }
        Ok(PathBuf::from(OsString::from_wide(&buffer[..size as usize])))
    }
}

pub fn get_process_full_name(handler: isize) -> Result<PathBuf> {
    unsafe {
        let mut buffer = [0u16; MAX_PATH + 1];
        let size = K32GetModuleFileNameExW(handler, 0, buffer.as_mut_ptr(), buffer.len() as u32);
        if size == 0 {
            return Err(Error::WindowsApi(WindowsApiErrorType::WindowsOsError(
                std::io::Error::last_os_error(),
            )));
        }
        Ok(PathBuf::from(OsString::from_wide(&buffer[..size as usize])))
    }
}

#[cfg(test)]
mod tests {
    use std::mem::MaybeUninit;
    use windows_sys::Win32::Foundation::LUID;
    use windows_sys::Win32::Security::Authentication::Identity;

    #[tokio::test]
    async fn get_user_test() {
        unsafe {
            let mut data = MaybeUninit::<*mut LUID>::uninit();
            let mut count: u32 = 10;
            let status = Identity::LsaEnumerateLogonSessions(&mut count, data.as_mut_ptr());
            println!(
                "Identity::LsaEnumerateLogonSessions return value: {}",
                status
            );
            for i in 0..count {
                let uid: LUID = *data.assume_init().offset(i as isize);
                println!("LUID: {:?} - {:?}", uid.HighPart, uid.LowPart);
                let logon_id: u64 = (uid.HighPart as u64) << 32 | uid.LowPart as u64;
                println!("LogonId: {}", logon_id);
                let user = super::get_user(logon_id).unwrap();
                let user_name = user.0;
                let user_groups = user.1;
                println!("UserName: {}", user_name);
                println!("UserGroups: {}", user_groups.join(", "));
                assert_ne!(String::new(), user_name, "user_name cannot be empty.");
            }
            // Couldn't find any user with group in our internal test environment
            // assert!(
            //     false,
            //     "test failed after enumerated all logon session accounts."
            // );
        }
    }

    #[test]
    fn get_process_test() {
        let pid = std::process::id();
        let handler = super::get_process_handler(pid).unwrap();
        let name = super::get_process_name(handler).unwrap();
        let full_name = super::get_process_full_name(handler).unwrap();
        let cmd = super::get_process_cmd(handler).unwrap();

        let base_info = super::query_basic_process_info(handler);
        assert!(base_info.is_ok(), "base_info must be ok");

        assert!(
            !name.as_os_str().is_empty(),
            "process name should not be empty"
        );
        assert!(
            !full_name.as_os_str().is_empty(),
            "process full name should not be empty"
        );
        assert!(!cmd.is_empty(), "process cmd should not be empty");
    }
}
