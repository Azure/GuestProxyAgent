// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

use once_cell::sync::Lazy;
use proxy_agent_shared::{current_info, telemetry::span::SimpleSpan};

static START: Lazy<SimpleSpan> = Lazy::new(SimpleSpan::new);

pub fn get_elapsed_time_in_millisec() -> u128 {
    START.get_elapsed_time_in_millisec()
}

pub fn write_startup_event(
    task: &str,
    method_name: &str,
    module_name: &str,
    logger_key: &str,
) -> String {
    let message = START.write_event(task, method_name, module_name, logger_key);
    #[cfg(not(windows))]
    crate::common::logger::write_serial_console_log(message.clone(), None);
    message
}

/// Determine the number of worker threads for the tokio runtime
/// Limit the number of worker threads to a maximum of 10 and minimum of 2  
static TOKIO_RUNTIME_WORKER_THREADS: Lazy<usize> = Lazy::new(|| {
    let cpu_count = current_info::get_cpu_count();
    cpu_count.clamp(2, 10)
});

pub fn get_worker_threads() -> usize {
    *TOKIO_RUNTIME_WORKER_THREADS
}
