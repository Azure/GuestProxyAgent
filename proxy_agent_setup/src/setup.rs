// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use proxy_agent_shared::misc_helpers;
use std::path::PathBuf;

pub fn proxy_agent_folder_in_setup() -> PathBuf {
    let path: PathBuf = misc_helpers::get_current_exe_dir();
    path.join("ProxyAgent")
}

pub fn proxy_agent_exe_in_setup() -> PathBuf {
    proxy_agent_exe_path(proxy_agent_folder_in_setup())
}

pub fn proxy_agent_exe_path(proxy_agent_package_dir: PathBuf) -> PathBuf {
    #[cfg(windows)]
    {
        proxy_agent_package_dir.join("GuestProxyAgent.exe")
    }
    #[cfg(not(windows))]
    {
        proxy_agent_package_dir.join("GuestProxyAgent")
    }
}

fn ebpf_folder() -> PathBuf {
    let path: PathBuf = misc_helpers::get_current_exe_dir();
    path.join("eBPF-For-Windows")
}

pub fn ebpf_setup_script_file() -> PathBuf {
    ebpf_folder().join("setup.ps1")
}

