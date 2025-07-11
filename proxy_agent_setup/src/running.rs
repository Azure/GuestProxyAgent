// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use crate::logger;
use proxy_agent_shared::misc_helpers;
use std::path::{Path, PathBuf};

#[cfg(windows)]
use proxy_agent_shared::service;

pub fn proxy_agent_running_folder(_service_name: &str) -> PathBuf {
    let path;
    #[cfg(windows)]
    {
        path = match service::query_service_executable_path(_service_name).parent() {
            Some(p) => p.to_path_buf(),
            None => proxy_agent_parent_folder().join("Package"),
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
        let path = misc_helpers::resolve_env_variables("%SYSTEMDRIVE%\\WindowsAzure\\ProxyAgent")
            .unwrap_or("C:\\WindowsAzure\\ProxyAgent".to_string());
        PathBuf::from(path)
    }
    #[cfg(not(windows))]
    {
        panic!("Not implemented")
    }
}

pub fn proxy_agent_version_target_folder(proxy_agent_exe: &Path) -> PathBuf {
    let proxy_agent_version = match misc_helpers::get_proxy_agent_version(proxy_agent_exe) {
        Ok(v) => v,
        Err(e) => {
            // This should not happen, if failed to get version, we should not proceed
            logger::write(format!("Failed to get proxy agent version with error: {e}"));
            panic!("Failed to get proxy agent version with error: {e}");
        }
    };
    logger::write(format!("Proxy agent version: {}", &proxy_agent_version));
    #[cfg(windows)]
    {
        let path = proxy_agent_parent_folder();
        path.join(format!("Package_{proxy_agent_version}"))
    }
    #[cfg(not(windows))]
    {
        PathBuf::from(proxy_agent_shared::linux::EXE_FOLDER_PATH)
    }
}
