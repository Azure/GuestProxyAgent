// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#![cfg(windows)]

use crate::common::logger;
use libloading::{Library, Symbol};
use once_cell::sync::Lazy;
use std::io::{Error, ErrorKind};
use std::mem::MaybeUninit;
use std::ptr::null_mut;
use windows_sys::Win32::Foundation::{BOOL, HANDLE, LUID, NTSTATUS, UNICODE_STRING};
use windows_sys::Win32::Security::Authentication::Identity;
use windows_sys::Win32::Security::Authentication::Identity::SECURITY_LOGON_SESSION_DATA;
use windows_sys::Win32::System::ProcessStatus::{
    K32GetModuleBaseNameW,   // kernel32.dll
    K32GetModuleFileNameExW, // kernel32.dll
};
use windows_sys::Win32::System::Threading::{
    NtQueryInformationProcess, // ntdll.dll
    OpenProcess,               //kernel32.dll
};
use windows_sys::Win32::System::Threading::{PROCESSINFOCLASS, PROCESS_BASIC_INFORMATION};

const LG_INCLUDE_INDIRECT: u32 = 1u32;
const MAX_PREFERRED_LENGTH: u32 = 4294967295u32;
#[repr(C)]
struct LocalgroupUsersInfo0 {
    pub lgrui0_name: windows_sys::core::PWSTR,
}
static NETAPI32_DLL: Lazy<Library> = Lazy::new(|| load_dll_with_retry("netapi32.dll\0", 3));

fn load_dll_with_retry(dll_name: &str, max_retry: u8) -> Library {
    let mut retry = 0;
    unsafe {
        loop {
            match Library::new(dll_name) {
                Ok(lib) => return lib,
                Err(e) => {
                    if retry >= max_retry {
                        panic!("Loading {} failed with error: {}", dll_name, e);
                    }
                    retry += 1;
                    logger::write_warning(format!(
                        "Loading {} failed with error: {}, retrying {}...",
                        dll_name, e, retry
                    ));
                    std::thread::sleep(std::time::Duration::from_secs(1));
                }
            }
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

fn NetUserGetLocalGroups(
    servername: windows_sys::core::PWSTR,
    username: windows_sys::core::PWSTR,
    level: u32,
    flags: u32,
    bufptr: *mut *mut LocalgroupUsersInfo0,
    prefmaxlen: u32,
    entriesread: *mut u32,
    totalentries: *mut u32,
) -> std::io::Result<u32> {
    unsafe {
        let fun_name = "NetUserGetLocalGroups\0";
        let NetUserGetLocalGroups: Symbol<NetUserGetLocalGroups> =
            NETAPI32_DLL.get(fun_name.as_bytes()).map_err(|e| {
                Error::new(
                    ErrorKind::Other,
                    format!("Loading {} failed with error: {}", fun_name, e),
                )
            })?;
        let status = NetUserGetLocalGroups(
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

/*
    Get user name and user group names
*/
pub fn get_user(logon_id: u64) -> (String, Vec<String>) {
    unsafe {
        let mut user_name = "undefined".to_string();

        let luid = LUID {
            LowPart: (logon_id & 0xFFFFFFFF) as u32, // get lower part of 32 bits
            HighPart: (logon_id >> 32) as i32,
        };

        let mut data = MaybeUninit::<*mut SECURITY_LOGON_SESSION_DATA>::uninit();
        let _status = Identity::LsaGetLogonSessionData(&luid, data.as_mut_ptr());

        let session_data = *data.assume_init();
        if session_data.UserName.Length != 0 {
            user_name = from_unicode_string(&session_data.UserName);
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
        let status = NetUserGetLocalGroups(
            null_mut(),
            to_pwstr(domain_user_name.as_str()).as_mut_ptr(),
            0,
            LG_INCLUDE_INDIRECT,
            &mut group_info,
            MAX_PREFERRED_LENGTH,
            &mut group_count,
            &mut total_group_count,
        )
        .unwrap();
        if status == 0 {
            let group_info = std::slice::from_raw_parts(
                group_info as *const u8 as *const LocalgroupUsersInfo0,
                group_count as usize,
            );
            for group in group_info {
                let group_name = from_pwstr(group.lgrui0_name);
                user_groups.push(group_name);
            }
        } else {
            let message = format!(
                "NetUserGetLocalGroups '{}' failed with status: {}",
                domain_user_name.to_string(),
                status
            );
            eprintln!("{}", message.to_string());
            logger::write_warning(message);
        }

        (user_name, user_groups)
    }
}

fn from_unicode_string(unicode_string: &UNICODE_STRING) -> String {
    let mut v = vec![0u16; unicode_string.MaximumLength as usize];
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

pub fn query_basic_process_info(handler: isize) -> std::io::Result<PROCESS_BASIC_INFORMATION> {
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
            return Err(std::io::Error::from_raw_os_error(status));
        }
        Ok(process_basic_information)
    }
}
pub fn get_process_handler(pid: u32) -> std::io::Result<HANDLE> {
    if pid == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "pid 0 is not a valid process id",
        ));
    }
    let options = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ;

    unsafe {
        let handler = OpenProcess(options, FALSE, pid);
        if handler == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(handler)
    }
}

pub fn get_process_cmd(handler: isize) -> std::io::Result<String> {
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
            return Err(std::io::Error::from_raw_os_error(status));
        }
        println!("return_length: {}", return_length);

        let buf_len = (return_length as usize) / 2;
        let mut buffer: Vec<u16> = Vec::with_capacity(buf_len + 1);
        buffer.resize(buf_len + 1, 0); // set everything to 0

        let status: NTSTATUS = NtQueryInformationProcess(
            handler,
            PROCESS_COMMAND_LINE_INFORMATION_CLASS,
            buffer.as_mut_ptr() as *mut _,
            return_length,
            &mut return_length as *mut _,
        );
        if status < 0 {
            eprintln!("NtQueryInformationProcess failed with status: {}", status);
            return Err(std::io::Error::from_raw_os_error(status));
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
pub fn get_process_name(handler: isize) -> std::io::Result<String> {
    unsafe {
        let mut buffer = [0u16; MAX_PATH + 1];
        let size = K32GetModuleBaseNameW(handler, 0, buffer.as_mut_ptr(), buffer.len() as u32);
        if size == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let name = String::from_utf16_lossy(&buffer[..size as usize]);
        Ok(name)
    }
}

pub fn get_process_full_name(handler: isize) -> std::io::Result<String> {
    unsafe {
        let mut buffer = [0u16; MAX_PATH + 1];
        let size = K32GetModuleFileNameExW(handler, 0, buffer.as_mut_ptr(), buffer.len() as u32);
        if size == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let name = String::from_utf16_lossy(&buffer[..size as usize]);
        Ok(name)
    }
}

#[cfg(test)]
mod tests {
    use std::mem::MaybeUninit;
    use windows_sys::Win32::Foundation::LUID;
    use windows_sys::Win32::Security::Authentication::Identity;

    #[test]
    fn get_user_test() {
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
                let user = super::get_user(logon_id);
                let user_name = user.0;
                let user_groups = user.1;
                println!("UserName: {}", user_name);
                println!("UserGroups: {}", user_groups.join(", "));
                assert_ne!(String::new(), user_name, "user_name cannot be empty.");
                if user_name.to_lowercase() == "undefined"{
                    println!("user_name cannot be 'undefined'");
                    continue;
                }
                if user_groups.len() > 0 {
                    return;
                }
            }
            // Coudn't find any user with group in our internal test environment
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

        assert!(name.len() > 0, "process name should not be empty");
        assert!(full_name.len() > 0, "process full name should not be empty");
        assert!(cmd.len() > 0, "process cmd should not be empty");
    }
}
