// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use super::result::Result;
use super::{error::Error, logger};
use once_cell::sync::Lazy;
use proxy_agent_shared::misc_helpers;
use proxy_agent_shared::telemetry::span::SimpleSpan;

#[cfg(not(windows))]
use sysinfo::{CpuRefreshKind, MemoryRefreshKind, RefreshKind, System};

#[cfg(windows)]
use super::windows;

static CURRENT_SYS_INFO: Lazy<(u64, usize)> = Lazy::new(|| {
    #[cfg(windows)]
    {
        let ram_in_mb = match windows::get_memory_in_mb() {
            Ok(ram) => ram,
            Err(e) => {
                logger::write_error(format!("get_memory_in_mb failed: {}", e));
                0
            }
        };
        let cpu_count = windows::get_processor_count();
        (ram_in_mb, cpu_count)
    }
    #[cfg(not(windows))]
    {
        let sys = System::new_with_specifics(
            RefreshKind::new()
                .with_memory(MemoryRefreshKind::everything())
                .with_cpu(CpuRefreshKind::everything()),
        );
        let ram = sys.total_memory();
        let ram_in_mb = ram / 1024 / 1024;
        let cpu_count = sys.cpus().len();
        (ram_in_mb, cpu_count)
    }
});

static CURRENT_OS_INFO: Lazy<(String, String)> = Lazy::new(|| {
    //arch
    let arch = misc_helpers::get_processor_arch();
    // os
    let os = misc_helpers::get_long_os_version();
    (arch, os)
});

pub fn get_ram_in_mb() -> u64 {
    CURRENT_SYS_INFO.0
}

pub fn get_cpu_count() -> usize {
    CURRENT_SYS_INFO.1
}

pub fn get_cpu_arch() -> String {
    CURRENT_OS_INFO.0.to_string()
}

pub fn get_long_os_version() -> String {
    CURRENT_OS_INFO.1.to_string()
}

pub fn compute_signature(hex_encoded_key: &str, input_to_sign: &[u8]) -> Result<String> {
    match hex::decode(hex_encoded_key) {
        Ok(key) => {
            let mut mac = hmac_sha256::HMAC::new(key);
            mac.update(input_to_sign);
            let result = mac.finalize();
            Ok(hex::encode(result))
        }
        Err(e) => Err(Error::Hex(hex_encoded_key.to_string(), e)),
    }
}

// replace xml escape characters
pub fn xml_escape(s: String) -> String {
    s.replace('&', "&amp;")
        .replace('\'', "&apos;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

static START: Lazy<SimpleSpan> = Lazy::new(SimpleSpan::new);

pub fn get_elapsed_time_in_millisec() -> u128 {
    START.get_elapsed_time_in_millisec()
}

pub fn write_startup_event(
    task: &str,
    method_name: &str,
    module_name: &str,
    logger_key: &str,
) -> String {
    let message = START.write_event(task, method_name, module_name, logger_key);
    #[cfg(not(windows))]
    logger::write_serial_console_log(message.clone());
    message
}

#[cfg(test)]
mod tests {
    #[test]
    fn get_system_info_tests() {
        let ram = super::get_ram_in_mb();
        assert!(ram > 100, "total ram must great than 100MB");
        let cpu_count = super::get_cpu_count();
        assert!(
            cpu_count >= 1,
            "total cpu count must great than or equal to 1"
        );
        let cpu_arch = super::get_cpu_arch();
        assert_ne!("unknown", cpu_arch, "cpu arch cannot be 'unknown'");
    }
    #[test]
    fn compute_signature_test() {
        let hex_encoded_key = "4A404E635266556A586E3272357538782F413F4428472B4B6250645367566B59";
        let message = "Hello world";
        let result = super::compute_signature(hex_encoded_key, message.as_bytes()).unwrap();
        println!("compute_signature: {result}");
        let invalid_hex_encoded_key =
            "YA404E635266556A586E3272357538782F413F4428472B4B6250645367566B59";
        let result = super::compute_signature(invalid_hex_encoded_key, message.as_bytes());
        assert!(result.is_err(), "invalid key should fail.");

        let e = result.unwrap_err();
        let error = e.to_string();
        assert!(
            error.contains(invalid_hex_encoded_key),
            "Error does not contains the invalid key"
        )
    }
}
