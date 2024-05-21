// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#![allow(non_snake_case)]

pub mod common;
pub mod constants;
pub mod handler_main;
pub mod service_main;
pub mod structs;

#[cfg(not(windows))]
pub mod linux;

#[cfg(windows)]
pub mod windows;

use std::env;

use tracing_subscriber::prelude::*;

#[cfg(windows)]
use std::ffi::OsString;
#[cfg(windows)]
use windows_service::{define_windows_service, service_dispatcher};
#[cfg(windows)]
define_windows_service!(ffi_service_main, proxy_agent_extension_windows_service_main);

fn main() {
    // TODO: If Windows doesn't do log management, pull in a tracing rolling logger impl
    let format = tracing_subscriber::fmt::format()
        .with_level(true)
        .with_thread_names(true);
    // Configurable via environment variable for now
    // https://docs.rs/tracing-subscriber/0.3.18/tracing_subscriber/filter/struct.EnvFilter.html#directives
    let stderr_layer = tracing_subscriber::fmt::layer()
        .event_format(format)
        .with_writer(std::io::stderr)
        .with_filter(tracing_subscriber::EnvFilter::from_env(
            "GUEST_PROXY_AGENT_LOG",
        ));
    let registry = tracing_subscriber::registry().with(stderr_layer);
    tracing::subscriber::set_global_default(registry).expect("Unable to configure logging!");

    let args: Vec<String> = env::args().collect();
    if args.len() > 1 {
        let config_seq_no =
            env::var("ConfigSequenceNumber").unwrap_or_else(|_e| "no seq no".to_string());
        handler_main::program_start(args, Some(config_seq_no));
    } else {
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
