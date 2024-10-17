// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use crate::logger;
use proxy_agent_shared::misc_helpers;
use std::path::{Path, PathBuf};

#[cfg(windows)]
use proxy_agent_shared::service;

pub fn proxy_agent_running_folder(_ervice_name: &str) -> PathBuf {
    let path;
    #[cfg(windows)]
    {
        path = match service::query_service_executable_path(_ervice_name).parent() {
            Some(p) => p.to_path_buf(),
            None => PathBuf::from("C:\\WindowsAzure\\ProxyAgent\\Package"),
        };
    }
    #[cfg(not(windows))]
    {
        path = PathBuf::from(proxy_agent_shared::linux::EXE_FOLDER_PATH);
    }
    path
}

pub fn proxy_agent_parent_folder() -> PathBuf {
    #[cfg(windows)]
    {
        PathBuf::from("C:\\WindowsAzure\\ProxyAgent")
    }
    #[cfg(not(windows))]
    {
        panic!("Not implemented")
    }
}

pub fn proxy_agent_version_target_folder(proxy_agent_exe: &Path) -> PathBuf {
    let proxy_agent_version = misc_helpers::get_proxy_agent_version(proxy_agent_exe);
    logger::write(format!("Proxy agent version: {}", &proxy_agent_version));
    #[cfg(windows)]
    {
        let path = proxy_agent_parent_folder();

        path.join(format!("Package_{}", proxy_agent_version))
    }
    #[cfg(not(windows))]
    {
        PathBuf::from(proxy_agent_shared::linux::EXE_FOLDER_PATH)
    }
}
