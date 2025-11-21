// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

use once_cell::sync::Lazy;
use proxy_agent_shared::telemetry::span::SimpleSpan;

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
    logger::write_serial_console_log(message.clone());
    message
}
