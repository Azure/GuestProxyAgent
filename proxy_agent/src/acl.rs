// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

//! This module contains the logic to set the ACL on the directory.
//! The ACL is set on the directory to allow the elevated accounts only to access the directory.
//! Example
//! ```rust
//! use proxy_agent::acl;
//! use std::path::PathBuf;
//!
//! // Set the ACL on the directory
//! let dir_to_acl = PathBuf::from("path_to_directory");
//! acl::acl_directory(dir_to_acl);
//! ```

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
