// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

//! Windows eventing support: real-time ETW tracing plus the Windows Event Log
//! (`Evt*`) reader, writer, and subscriber.

pub mod evt_listener;
pub mod evt_query;
pub mod evt_writer;
pub mod models;

use std::ffi::OsStr;
use std::iter::once;
use std::os::windows::ffi::OsStrExt;

/// Converts a string to a wide character vector (u16).
/// This is used to convert Rust strings to the format required by Windows API functions.
pub fn to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(once(0)).collect()
}
