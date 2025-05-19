// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

use crate::misc_helpers;

pub mod logger_manager;
pub mod rolling_logger;

pub type LoggerLevel = log::Level;

pub fn get_log_header(level: LoggerLevel) -> String {
    format!(
        "{} [{}]    ",
        misc_helpers::get_date_time_string_with_milliseconds(),
        level
    )[..34]
        .to_string()
}

pub fn get_caller_info(module_to_skip: &str) -> (String, String) {
    // unit test, the callstack end with address `proxy_agent_shared::logger::get_caller_info::h7bc59e9a5e48ecd1
    #[cfg(test)]
    let function_last_index = 1;
    #[cfg(not(test))]
    let function_last_index = 0;

    let bt = backtrace::Backtrace::new();
    for frame in bt.frames().iter() {
        for symbol in frame.symbols() {
            if let Some(name) = symbol.name() {
                let name_str = name.to_string();
                println!("name_str: {}", name_str);
                // Skip internal frames, current function frame and `module_to_skip` to find the first relevant caller
                if !name_str.contains("backtrace::")
                    && !name_str.contains("proxy_agent_shared::logger::get_caller_info")
                    && !name_str.contains(module_to_skip)
                {
                    let seg = name_str.split("::").collect::<Vec<_>>();
                    let seg_len = seg.len();
                    let caller_name = seg
                        .get(seg_len - 1 - function_last_index)
                        .unwrap_or(&"unknown")
                        .to_string();
                    // Get the module name from the first to second last segment
                    let module_name = seg
                        .into_iter()
                        .map(String::from)
                        .collect::<Vec<_>>()
                        .into_iter()
                        .take(seg_len - 1 - function_last_index)
                        .collect::<Vec<_>>()
                        .join("::");
                    return (module_name, caller_name);
                }
            }
        }
    }
    ("unknown".to_string(), "unknown".to_string())
}

#[cfg(test)]
mod tests {
    use log::Level;
    use std::str::FromStr;

    #[test]
    fn logger_level_test() {
        let info_level = Level::Info;
        assert_eq!(Level::from_str("Info").unwrap(), Level::Info);

        let trace_level = Level::from_str("Trace").unwrap();
        assert_eq!(trace_level, Level::Trace);
        assert!(
            info_level < trace_level,
            "Info level should be lower than Trace level"
        );

        assert!(
            Level::from_str("Trace").unwrap() >= trace_level,
            "Trace level should be greater than or equal to Trace level"
        );
    }

    #[test]
    fn invoke_get_caller_info_test() {
        test_get_caller_info_test("invoke_get_caller_info_test");
    }

    fn test_get_caller_info_test(expected_caller_name: &str) {
        let (module_name, caller_name) = super::get_caller_info("test_get_caller_info_test");
        println!("Module Name: {}", module_name);
        println!("Caller Name: {}", caller_name);
        // Check if the module name and caller name are as expected
        assert_eq!(module_name, "proxy_agent_shared::logger::tests");
        assert_eq!(caller_name, expected_caller_name);
    }
}
