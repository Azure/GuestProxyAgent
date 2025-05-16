// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

use crate::misc_helpers;

pub mod logger_manager;
pub mod rolling_logger;

pub type LoggerLevel = log::Level;

const HEADER_LENGTH: usize = 34;
pub fn get_log_header(level: LoggerLevel) -> String {
    get_log_header_with_length(
        level,
        misc_helpers::get_date_time_string_with_milliseconds(),
        HEADER_LENGTH,
    )
}

fn get_log_header_with_length(
    level: LoggerLevel,
    date_time_string: String,
    length: usize,
) -> String {
    let header = format!("{} [{}]    ", date_time_string, level)
        .chars()
        .take(length)
        .collect::<String>();

    // padding if the header is shorter than HEADER_LENGTH
    if header.len() < length {
        let padding = " ".repeat(length - header.len());
        return format!("{}{}", header, padding);
    }
    header
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
    fn get_log_header_with_length_test() {
        let header = super::get_log_header_with_length(
            Level::Info,
            "2023-10-01 12:00:00.000".to_string(),
            34,
        );
        assert_eq!(header, "2023-10-01 12:00:00.000 [INFO]    ");
        let header = super::get_log_header_with_length(
            Level::Error,
            "2023-10-01 12:00:00.000".to_string(),
            34,
        );
        assert_eq!(header, "2023-10-01 12:00:00.000 [ERROR]   ");
        let header = super::get_log_header_with_length(
            Level::Warn,
            "2023-10-01 12:00:00.00".to_string(),
            34,
        );
        assert_eq!(header, "2023-10-01 12:00:00.00 [WARN]     ");
    }
}
