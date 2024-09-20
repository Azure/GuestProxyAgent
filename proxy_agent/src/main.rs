// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

pub mod acl;
pub mod common;
pub mod host_clients;
pub mod key_keeper;
pub mod provision;
pub mod proxy;
pub mod proxy_agent_status;
pub mod redirector;
pub mod service;
pub mod shared_state;
pub mod telemetry;

#[cfg(test)]
pub mod test_mock;

use clap::{Parser, Subcommand};
use common::constants;
use common::helpers;
use shared_state::SharedState;
use std::{process, time::Duration};

#[cfg(windows)]
use common::logger;
#[cfg(windows)]
use service::windows;
#[cfg(windows)]
use std::ffi::OsString;
#[cfg(windows)]
use windows_service::{define_windows_service, service_dispatcher};
#[cfg(windows)]
define_windows_service!(ffi_service_main, proxy_agent_windows_service_main);
// define_windows_service does not accept async function in fffi_service_main,
// also it does not allow to pass tokio runtime or handle as arguments to the function.
// we have to use the global variable to set the tokio runtime handle.
#[cfg(windows)]
static ASYNC_RUNTIME_HANDLE: tokio::sync::OnceCell<tokio::runtime::Handle> =
    tokio::sync::OnceCell::const_new();

/// azure-proxy-agent console - launch a long run process of GPA in console mode.
/// azure-proxy-agent --version - print the version of the GPA.
/// azure-proxy-agent --status [--wait <seconds>] - get the provision status of the GPA service.
/// azure-proxy-agent - start the GPA as an OS service.
///                     The GPA service will be started as an OS service in the background.
#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    /// get the provision status of the GPA service
    #[arg(short, long)]
    status: bool,

    /// wait for the provision status to finish
    #[arg(short, long, requires = "status")]
    wait: Option<u64>,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// launch a long run process of GPA in console mode
    Console,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    // set the tokio runtime handle
    #[cfg(windows)]
    ASYNC_RUNTIME_HANDLE
        .set(tokio::runtime::Handle::current())
        .unwrap();

    // start the Instant to calculate the elapsed time
    _ = helpers::get_elapsed_time_in_millisec();

    let cli = Cli::parse();
    if cli.status {
        // --wait parameter to wait for the provision status until the given time in seconds
        // it is an optional, if not provided then it will query the provision state once by waiting for 0 seconds.
        let wait_time = cli.wait.unwrap_or(0);
        let (provision_finished, error_message) = provision::get_provision_status_wait(
            constants::PROXY_AGENT_PORT,
            Some(Duration::from_secs(wait_time)),
        )
        .await;
        if !provision_finished {
            // exit code 1 means provision not finished yet.
            process::exit(1);
        } else {
            // provision finished
            if !error_message.is_empty() {
                // if there is any error message then print it and exit with exit code 2.
                println!("{}", error_message);
                process::exit(2);
            }
            // no error message then exit with 0.
            return;
        }
    }

    if let Some(Commands::Console) = cli.command {
        // console mode - start GPA as long running process
        let shared_state = SharedState::new();
        service::start_service(shared_state.clone());
        println!("Press Enter to end it.");
        let mut temp = String::new();
        _ = std::io::stdin().read_line(&mut temp);
        service::stop_service(shared_state.clone());
    } else {
        // no argument provided, start the GPA as an OS service
        #[cfg(windows)]
        {
            _ = service_dispatcher::start(constants::PROXY_AGENT_SERVICE_NAME, ffi_service_main);
        }

        #[cfg(not(windows))]
        {
            service::start_service_wait().await;
        }
    }
}

/// This function is the entry point of the GPA windows service.
#[cfg(windows)]
fn proxy_agent_windows_service_main(_args: Vec<OsString>) {
    // start the Instant to calculate the elapsed time
    _ = helpers::get_elapsed_time_in_millisec();

    // Pass the tokio runtime handle here to launch the windows service.
    let handle = ASYNC_RUNTIME_HANDLE
        .get()
        .expect("You must provide the Tokio runtime handle before this function is called");
    handle.block_on(async {
        if let Err(e) = windows::run_service() {
            logger::write_error(format!("Error in running the service: {}", e));
        }
    });
}
