// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use crate::running;
use std::path::PathBuf;

pub fn proxy_agent_backup_folder() -> PathBuf {
    let path = running::proxy_agent_parent_folder();
    path.join("Backup")
}

pub fn proxy_agent_backup_package_folder() -> PathBuf {
    proxy_agent_backup_folder().join("Package")
}
