// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#![allow(non_snake_case)]

pub mod common;
pub mod constants;
pub mod error;
pub mod handler_main;
pub mod logger;
pub mod result;
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
// define_windows_service does not accept async function in fffi_service_main,
// also it does not allow to pass tokio runtime or handle as arguments to the function.
// we have to use the global variable to set the tokio runtime handle.
#[cfg(windows)]
static ASYNC_RUNTIME_HANDLE: tokio::sync::OnceCell<tokio::runtime::Handle> =
    tokio::sync::OnceCell::const_new();

const CONFIG_SEQ_NO_ENV_VAR: &str = "ConfigSequenceNumber";

#[derive(Parser)]
#[command()]
struct Cli {
    /// GPA VM Extension commands
    #[command(subcommand)]
    command: Option<ExtensionCommand>,
}

#[derive(Subcommand, Debug)]
pub enum ExtensionCommand {
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

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    // set the tokio runtime handle
    #[cfg(windows)]
    ASYNC_RUNTIME_HANDLE
        .set(tokio::runtime::Handle::current())
        .unwrap();

    let cli = Cli::parse();

    if let Some(command) = cli.command {
        // extension commands
        let config_seq_no =
            env::var(CONFIG_SEQ_NO_ENV_VAR).unwrap_or_else(|_e| "no seq no".to_string());
        handler_main::program_start(command, config_seq_no).await;
    } else {
        // no arguments, start it as a service
        let exe_path = misc_helpers::get_current_exe_dir();
        let log_folder = common::get_handler_environment(&exe_path)
            .logFolder
            .to_string();
        logger::init_logger(log_folder, constants::SERVICE_LOG_FILE);
        common::start_event_logger().await;
        #[cfg(windows)]
        {
            if let Err(e) = service_dispatcher::start(constants::PLUGIN_NAME, ffi_service_main) {
                logger::write(format!("Failed to start the service: {e}"));
            }
        }
        #[cfg(not(windows))]
        {
            linux::start_service_wait().await;
        }
    }
}

#[cfg(windows)]
fn proxy_agent_extension_windows_service_main(args: Vec<OsString>) {
    // Pass the tokio runtime handle here to launch the windows service.
    let handle = ASYNC_RUNTIME_HANDLE
        .get()
        .expect("You must provide the Tokio runtime handle before this function is called");
    handle.block_on(async {
        if let Err(e) = service_main::windows_main::run_service(args).await {
            logger::write(format!("Failed to start the service: {e}"));
        }
    });
}
