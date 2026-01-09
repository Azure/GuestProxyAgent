// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

use crate::misc_helpers;
use once_cell::sync::Lazy;

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
                crate::logger::logger_manager::write_err(format!("get_memory_in_mb failed: {e}"));
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
}
