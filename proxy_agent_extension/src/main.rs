// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#![allow(non_snake_case)]
#![deny(warnings)]

pub mod common;
pub mod constants;
pub mod handler_main;
pub mod logger;
pub mod service_main;
pub mod structs;

#[cfg(not(windows))]
pub mod linux;

#[cfg(windows)]
pub mod windows;

use proxy_agent_shared::misc_helpers;
use std::env;

#[cfg(windows)]
use std::ffi::OsString;
#[cfg(windows)]
use windows_service::{define_windows_service, service_dispatcher};
#[cfg(windows)]
define_windows_service!(ffi_service_main, proxy_agent_extension_windows_service_main);

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() > 1 {
        let config_seq_no = match env::var("ConfigSequenceNumber") {
            Ok(seq_no) => seq_no,
            Err(_e) => "no seq no".to_string(),
        };
        handler_main::program_start(args, Some(config_seq_no));
    } else {
        let exe_path = misc_helpers::get_current_exe_dir();
        let log_folder = common::get_handler_environment(exe_path)
            .logFolder
            .to_string();
        logger::init_logger(log_folder, constants::SERVICE_LOG_FILE);
        common::start_event_logger(constants::SERVICE_LOG_FILE);
        #[cfg(windows)]
        {
            _ = service_dispatcher::start(constants::PLUGIN_NAME, ffi_service_main);
        }
        #[cfg(not(windows))]
        {
            linux::start_service_wait();
        }
    }
}

#[cfg(windows)]
fn proxy_agent_extension_windows_service_main(args: Vec<OsString>) {
    _ = service_main::windows_main::run_service(args);
}
