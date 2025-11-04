// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
pub mod cli;
pub mod config;
pub mod constants;
pub mod error;
pub mod helpers;
pub mod logger;
pub mod result;

#[cfg(windows)]
pub mod windows;

#[cfg(windows)]
pub use windows::store_key_data;

#[cfg(windows)]
pub use windows::fetch_key_data;
