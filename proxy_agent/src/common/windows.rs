// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

use std::io::{Error, ErrorKind};
use std::mem::MaybeUninit;
use windows_sys::Win32::Networking::WinSock;
use windows_sys::Win32::System::SystemInformation::{
    GetSystemInfo,        // kernel32.dll
    GlobalMemoryStatusEx, // kernel32.dll
    MEMORYSTATUSEX,
    SYSTEM_INFO,
};

pub fn get_processor_count() -> usize {
    let mut data = MaybeUninit::<SYSTEM_INFO>::uninit();
    unsafe { GetSystemInfo(data.as_mut_ptr()) };

    let data = unsafe { data.assume_init() };
    data.dwNumberOfProcessors as usize
}

pub fn get_memory_in_mb() -> Result<u64, String> {
    let mut data = MaybeUninit::<MEMORYSTATUSEX>::uninit();
    let data = data.as_mut_ptr();
    unsafe {
        (*data).dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
        if GlobalMemoryStatusEx(data) == 0 {
            return Err("GlobalMemoryStatusEx failed".to_string());
        }
        let memory_in_mb = (*data).ullTotalPhys / 1024 / 1024;
        Ok(memory_in_mb)
    }
}

pub fn check_winsock_last_error(caller: &str) -> std::io::Result<()> {
    let error = unsafe { WinSock::WSAGetLastError() };
    let message = format!("{caller} : {error}");
    if error != 0 {
        return Err(Error::new(ErrorKind::InvalidInput, message));
    }

    Ok(())
}

#[cfg(test)]
mod tests {

    #[test]
    fn get_processor_count_test() {
        let count = super::get_processor_count();
        println!("Processor count: {}", count);
        assert_ne!(0, count, "Processor count cannot be 0.");
    }

    #[test]
    fn get_memory_in_mb_test() {
        let memory = super::get_memory_in_mb();
        match memory {
            Ok(memory) => println!("Memory in MB: {}", memory),
            Err(e) => assert_ne!(0, memory, "Memory cannot be 0."),
        }
    }
}
