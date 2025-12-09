// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

pub mod acl;
pub mod common;
pub mod key_keeper;
pub mod provision;
pub mod proxy;
pub mod proxy_agent_status;
pub mod redirector;
pub mod service;
pub mod shared_state;

use common::cli::{Commands, CLI};
use common::constants;
use common::helpers;
use provision::provision_query::ProvisionQuery;
use proxy_agent_shared::misc_helpers;
use shared_state::SharedState;
use std::{process, time::Duration};

#[cfg(windows)]
use common::logger;
#[cfg(windows)]
use service::windows_main;
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
    // set the tokio runtime handle
    #[cfg(windows)]
    ASYNC_RUNTIME_HANDLE
        .set(tokio::runtime::Handle::current())
        .unwrap();

    // start the Instant to calculate the elapsed time
    let _time = helpers::get_elapsed_time_in_millisec();

    if CLI.version {
        println!("{}", misc_helpers::get_current_version());
        return;
    }

    if CLI.status {
        // --wait parameter to wait for the provision status until the given time in seconds
        // it is an optional, if not provided then it will query the provision state once by waiting for 0 seconds.
        let wait_time = CLI.wait.unwrap_or(0);
        let state = ProvisionQuery::new(
            constants::PROXY_AGENT_PORT,
            Some(Duration::from_secs(wait_time)),
        )
        .get_provision_status_wait()
        .await;
        if !state.finished {
            // exit code 1 means provision not finished yet.
            process::exit(1);
        } else {
            // provision finished
            if !state.errorMessage.is_empty() {
                // if there is any error message then print it and exit with exit code 2.
                println!("{}", state.errorMessage);
                process::exit(2);
            }
            // no error message then exit with 0.
            return;
        }
    }

    if let Some(Commands::Console) = CLI.command {
        // console mode - start GPA as long running process
        let shared_state = SharedState::start_all();
        service::start_service(shared_state.clone()).await;
        println!("Press Enter to end it.");
        let mut temp = String::new();
        let _read = std::io::stdin().read_line(&mut temp);
        service::stop_service(shared_state.clone());
    } else {
        // no argument provided, start the GPA as an OS service
        #[cfg(windows)]
        {
            match service_dispatcher::start(constants::PROXY_AGENT_SERVICE_NAME, ffi_service_main) {
                Ok(_) => {}
                Err(e) => {
                    logger::write_error(format!("Error in starting the service dispatcher: {e}"));
                }
            }
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
    let _time = helpers::get_elapsed_time_in_millisec();

    // Pass the tokio runtime handle here to launch the windows service.
    let handle = ASYNC_RUNTIME_HANDLE
        .get()
        .expect("You must provide the Tokio runtime handle before this function is called");
    handle.block_on(async {
        if let Err(e) = windows_main::run_service().await {
            logger::write_error(format!("Error in running the service: {e}"));
        }
    });
}
