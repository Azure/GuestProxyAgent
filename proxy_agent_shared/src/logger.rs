// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

pub mod logger_manager;
pub mod rolling_logger;

pub type LoggerLevel = log::Level;

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
}
