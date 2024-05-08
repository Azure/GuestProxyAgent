// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use super::event_logger;
use serde_derive::{Deserialize, Serialize};
use std::time::Instant;

pub struct SimpleSpan {
    start: Instant,
}

#[derive(Serialize, Deserialize)]
struct ElapsedMessage {
    elapsed: u128,
    message: String,
}

impl ElapsedMessage {
    fn new(elapsed: u128, message: String) -> Self {
        ElapsedMessage { elapsed, message }
    }

    fn to_json_string(&self) -> String {
        format!(
            "{{\"elapsed\":{}, \"message\":\"{}\"}}",
            self.elapsed, self.message
        )
    }

    fn to_string(&self) -> String {
        format!("{} - {}", self.message, self.elapsed)
    }
}

impl SimpleSpan {
    pub fn new() -> Self {
        SimpleSpan {
            start: Instant::now(),
        }
    }

    pub fn start_new(&mut self) {
        self.start = Instant::now();
    }

    pub fn get_elapsed_time_in_millisec(&self) -> u128 {
        self.start.elapsed().as_millis()
    }

    pub fn get_elapsed_json_message(&self, message: &str) -> String {
        let elapsed_massage =
            ElapsedMessage::new(self.get_elapsed_time_in_millisec(), message.to_string());
        elapsed_massage.to_json_string()
    }

    pub fn write_event(
        &self,
        message: &str,
        method_name: &str,
        module_name: &str,
        logger_key: &str,
    ) -> String {
        let elapsed_massage =
            ElapsedMessage::new(self.get_elapsed_time_in_millisec(), message.to_string());
        event_logger::write_event(
            event_logger::INFO_LEVEL,
            elapsed_massage.to_json_string(),
            method_name,
            module_name,
            logger_key,
        );
        elapsed_massage.to_string()
    }
}

#[cfg(test)]
mod tests {
    use std::thread::sleep;
    use std::time::Duration;

    #[test]
    fn span_test() {
        let mut span = super::SimpleSpan::new();
        sleep(Duration::from_millis(1));
        let elapsed = span.get_elapsed_time_in_millisec();
        assert!(elapsed > 0);
        let duration = Duration::from_millis(100);
        sleep(duration);
        let message: String = span.get_elapsed_json_message("test");
        let elapsed_message: super::ElapsedMessage = serde_json::from_str(&message).unwrap();
        assert_eq!(elapsed_message.message, "test");
        assert!(elapsed_message.elapsed > duration.as_millis());

        span.start_new();
        sleep(Duration::from_millis(1));
        let elapsed = span.get_elapsed_time_in_millisec();
        assert!(elapsed > 0);
        assert!(elapsed < duration.as_millis());
    }
}
