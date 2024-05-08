// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#[cfg(windows)]
mod windows_acl;

#[cfg(not(windows))]
mod linux_acl;

use std::path::PathBuf;

pub fn acl_directory(dir_to_acl: PathBuf) -> std::io::Result<()> {
    if !dir_to_acl.exists() || !dir_to_acl.is_dir() {
        return Ok(());
    }

    #[cfg(windows)]
    {
        windows_acl::acl_directory(dir_to_acl)?;
    }

    #[cfg(not(windows))]
    {
        linux_acl::acl_directory(dir_to_acl)?;
    }

    Ok(())
}
