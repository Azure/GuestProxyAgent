#![cfg(windows)]

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

/*
    Get user name
*/
pub fn get_user_name(logon_id: u64) -> String {
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

        user_name
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
    fn get_user_name_test() {
        unsafe {
            let mut data = MaybeUninit::<*mut LUID>::uninit();
            let mut count: u32 = 1;
            let _status = Identity::LsaEnumerateLogonSessions(&mut count, data.as_mut_ptr());
            // get the first LUID
            let uid = *data.assume_init();
            let logon_id: u64 = (uid.HighPart as u64) << 32 | uid.LowPart as u64;
            let user_name = super::get_user_name(logon_id);
            println!("UserName: {}", user_name);
            assert_ne!(String::new(), user_name, "user_name cannot be empty.");
            assert_ne!("undefined", user_name, "user_name cannot be 'undefined'")
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
