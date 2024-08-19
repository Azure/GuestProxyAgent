// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

pub mod acl;
pub mod common;
pub mod host_clients;
pub mod key_keeper;
pub mod monitor;
pub mod provision;
pub mod proxy;
pub mod proxy_agent_status;
pub mod redirector;
pub mod service;
pub mod shared_state;
pub mod telemetry;
pub mod test_mock;

use common::helpers;
use proxy_agent_shared::misc_helpers;
use shared_state::SharedState;
use std::{process, time::Duration};

#[cfg(windows)]
use common::constants;
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

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    // start the Instant to calculate the elapsed time
    _ = helpers::get_elapsed_time_in_millisec();

    // set the tokio runtime handle
    #[cfg(windows)]
    ASYNC_RUNTIME_HANDLE
        .set(tokio::runtime::Handle::current())
        .unwrap();

    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 {
        if args[1].to_lowercase() == "console" {
            let shared_state = SharedState::new();
            service::start_service(shared_state.clone());
            println!("Press Enter to end it.");
            let mut temp = String::new();
            _ = std::io::stdin().read_line(&mut temp);
            service::stop_service(shared_state.clone());
        } else if args[1].to_lowercase() == "--version" {
            println!("{}", misc_helpers::get_current_version());
        } else if args[1].to_lowercase() == "--status" {
            let mut wait_time: u64 = 0;
            if args.len() >= 4 && args[2].to_lowercase() == "--wait" {
                wait_time = args[3].parse::<u64>().unwrap_or(0);
            }
            let status =
                provision::get_provision_status_wait(None, Some(Duration::from_secs(wait_time)))
                    .await;
            if !status.0 {
                // exit code 1 means provision not finished yet.
                process::exit(1);
            } else {
                // provision finished
                if !status.1.is_empty() {
                    // exit code 2 means provision finished but failed.
                    println!("{}", status.1);
                    process::exit(2);
                }
                // provision finished and success
                return;
            }
        } else {
            println!("Invalid argument: {}", args[1]);
        }
    } else {
        #[cfg(windows)]
        {
            //
            let main = std::thread::spawn(|| {
                _ = service_dispatcher::start(
                    constants::PROXY_AGENT_SERVICE_NAME,
                    ffi_service_main,
                );
            });

            main.join().unwrap();
        }

        #[cfg(not(windows))]
        {
            service::start_service_wait().await;
        }
    }
}

#[cfg(windows)]
fn proxy_agent_windows_service_main(_args: Vec<OsString>) {
    // start the Instant to calculate the elapsed time
    _ = helpers::get_elapsed_time_in_millisec();

    let handle = ASYNC_RUNTIME_HANDLE
        .get()
        .expect("You must provide the Tokio runtime handle before this function is called");
    _ = handle.block_on(windows::run_service());
}
