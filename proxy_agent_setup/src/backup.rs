// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use crate::setup;
use std::path::PathBuf;

pub fn proxy_agent_backup_folder() -> PathBuf {
    let path = setup::proxy_agent_folder_in_setup();
    path.join("Backup")
}

pub fn proxy_agent_backup_package_folder() -> PathBuf {
    proxy_agent_backup_folder().join("Package")
}
