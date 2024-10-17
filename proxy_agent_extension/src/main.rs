// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#![allow(non_snake_case)]

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

use clap::{Parser, Subcommand};
use proxy_agent_shared::misc_helpers;
use std::env;

#[cfg(windows)]
use std::ffi::OsString;
#[cfg(windows)]
use windows_service::{define_windows_service, service_dispatcher};
#[cfg(windows)]
define_windows_service!(ffi_service_main, proxy_agent_extension_windows_service_main);

#[derive(Parser)]
#[command()]
struct Cli {
    /// GPA VM Extension commands
    #[command(subcommand)]
    command: Option<ExensionCommand>,
}

#[derive(Subcommand, Debug)]
pub enum ExensionCommand {
    /// enable the GPA VM Extension
    Enable,
    /// disable the GPA VM Extension
    Disable,
    /// uninstall the GPA VM Extension
    Uninstall,
    /// install the GPA VM Extension
    Install,
    /// update the GPA VM Extension
    Update,
    /// reset the GPA VM Extension state
    Reset,
}

fn main() {
    let cli = Cli::parse();

    if let Some(command) = cli.command {
        // extension commands
        let config_seq_no =
            env::var("ConfigSequenceNumber").unwrap_or_else(|_e| "no seq no".to_string());
        handler_main::program_start(command, Some(config_seq_no));
    } else {
        // no arguments, start it as a service
        let exe_path = misc_helpers::get_current_exe_dir();
        let log_folder = common::get_handler_environment(&exe_path)
            .logFolder
            .to_string();
        logger::init_logger(log_folder, constants::SERVICE_LOG_FILE);
        common::start_event_logger(constants::SERVICE_LOG_FILE);
        #[cfg(windows)]
        {
            if let Err(e) = service_dispatcher::start(constants::PLUGIN_NAME, ffi_service_main) {
                logger::write(format!("Failed to start the service: {}", e));
            }
        }
        #[cfg(not(windows))]
        {
            linux::start_service_wait();
        }
    }
}

#[cfg(windows)]
fn proxy_agent_extension_windows_service_main(args: Vec<OsString>) {
    if let Err(e) = service_main::windows_main::run_service(args) {
        logger::write(format!("Failed to start the service: {}", e));
    }
}
