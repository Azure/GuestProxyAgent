// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

use crate::common::{
    error::{Error, WindowsApiErrorType},
    result::Result,
};
use std::mem::MaybeUninit;
use std::path::Path;
use windows_sys::Win32::Security::Cryptography::{
    // crypt32.dll
    // msasn1.dll (ASN.1 library) is also used by crypt32.dll
    CryptProtectData,
    CryptUnprotectData,
    CRYPT_INTEGER_BLOB,
};
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

pub fn get_memory_in_mb() -> Result<u64> {
    let mut data = MaybeUninit::<MEMORYSTATUSEX>::uninit();
    let data = data.as_mut_ptr();
    unsafe {
        (*data).dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
        if GlobalMemoryStatusEx(data) == 0 {
            return Err(Error::WindowsApi(
                WindowsApiErrorType::GlobalMemoryStatusEx(std::io::Error::last_os_error()),
            ));
        }
        let memory_in_mb = (*data).ullTotalPhys / 1024 / 1024;
        Ok(memory_in_mb)
    }
}

pub fn store_key_data(encrypted_file_path: &Path, key_data: String) -> Result<()> {
    let data = key_data.as_bytes();
    let data_in = CRYPT_INTEGER_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_ptr() as *mut u8,
    };
    let mut data_out = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    let result = unsafe {
        CryptProtectData(
            &data_in,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
            &mut data_out,
        )
    };
    if result == 0 {
        return Err(Error::WindowsApi(WindowsApiErrorType::CryptProtectData(
            std::io::Error::last_os_error(),
        )));
    }

    let encrypted_data =
        unsafe { std::slice::from_raw_parts(data_out.pbData, data_out.cbData as usize).to_vec() };
    unsafe {
        windows_sys::Win32::Foundation::LocalFree(data_out.pbData as *mut ::core::ffi::c_void)
    };
    std::fs::write(encrypted_file_path, encrypted_data).map_err(|e| {
        Error::Io(
            format!(
                "store_encrypt_key write file '{}' failed",
                encrypted_file_path.display()
            ),
            e,
        )
    })?;

    Ok(())
}

pub fn fetch_key_data(encrypted_file_path: &Path) -> Result<String> {
    let encrypted_data = std::fs::read(encrypted_file_path).map_err(|e| {
        Error::Io(
            format!(
                "fetch_encrypted_key read file '{}' failed",
                encrypted_file_path.display()
            ),
            e,
        )
    })?;
    let data_in = CRYPT_INTEGER_BLOB {
        cbData: encrypted_data.len() as u32,
        pbData: encrypted_data.as_ptr() as *mut u8,
    };
    let mut data_out = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };

    let result = unsafe {
        CryptUnprotectData(
            &data_in,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
            &mut data_out,
        )
    };
    if result == 0 {
        return Err(Error::WindowsApi(WindowsApiErrorType::CryptUnprotectData(
            std::io::Error::last_os_error(),
        )));
    }
    let decrypted_data = unsafe {
        std::slice::from_raw_parts(data_out.pbData as *const u8, data_out.cbData as usize).to_vec()
    };
    unsafe {
        windows_sys::Win32::Foundation::LocalFree(data_out.pbData as *mut ::core::ffi::c_void)
    };
    let key_data = String::from_utf8_lossy(&decrypted_data).to_string();

    Ok(key_data)
}

#[cfg(test)]
mod tests {
    use std::{env, fs};

    use proxy_agent_shared::misc_helpers;

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
            Ok(memory) => {
                assert_ne!(0, memory, "Memory cannot be 0.");
            }
            Err(e) => assert!(false, "{}", format!("Failed to get memory: {}", e)),
        }
    }

    #[test]
    fn store_fetch_data_test() {
        let mut temp_test_path = env::temp_dir();
        temp_test_path.push("store_fetch_data_test");

        // clean up and ignore the clean up errors
        _ = fs::remove_dir_all(&temp_test_path);
        misc_helpers::try_create_folder(&temp_test_path).unwrap();

        let key_data = "test data".to_string();
        let encrypted_file_path = temp_test_path.join("test_data.encrypted");
        super::store_key_data(&encrypted_file_path, key_data.clone()).unwrap();

        let fetched_key_data = super::fetch_key_data(&encrypted_file_path).unwrap();
        assert_eq!(key_data, fetched_key_data);

        // clean up and ignore the clean up errors
        _ = fs::remove_dir_all(&temp_test_path);
    }
}
