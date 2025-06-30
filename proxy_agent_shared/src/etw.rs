// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
//! This module provides functionality for ETW (Event Tracing for Windows) logging.

pub mod etw_writter;

/// This module provides functionality to read ETW events.
/// Test quality only so far.
#[cfg(test)]
mod etw_reader;

use std::ffi::OsStr;
use std::iter::once;
use std::os::windows::ffi::OsStrExt;

/// Converts a string to a wide character vector (u16).
/// This is used to convert Rust strings to the format required by Windows API functions.
pub fn to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(once(0)).collect()
}