use super::event_logger;
use std::time::Instant;

pub struct SimpleSpan {
    start: Instant,
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

    pub fn get_elapsed_message(&self, message: &str) -> String {
        format!(
            "{{\"elapsed\":{}, \"task\":\"{}\"}}",
            self.get_elapsed_time_in_millisec(),
            message
        )
    }

    pub fn write_event(
        &self,
        message: &str,
        method_name: &str,
        module_name: &str,
        logger_key: &str,
    ) -> String {
        let message = self.get_elapsed_message(&message);
        event_logger::write_event(
            event_logger::INFO_LEVEL,
            message.to_string(),
            method_name,
            module_name,
            logger_key,
        );
        message
    }
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;
    use serde::Serialize;
    use std::thread::sleep;
    use std::time::Duration;

    #[derive(Serialize, Deserialize)]
    struct ElapsedMessage {
        elapsed: u128,
        task: String,
    }

    #[test]
    fn span_test() {
        let mut span = super::SimpleSpan::new();
        sleep(Duration::from_millis(1));
        let elapsed = span.get_elapsed_time_in_millisec();
        assert!(elapsed > 0);
        let duration = Duration::from_millis(100);
        sleep(duration);
        let message: String = span.get_elapsed_message("test");
        let elapsed_message: ElapsedMessage = serde_json::from_str(&message).unwrap();
        assert_eq!(elapsed_message.task, "test");
        assert!(elapsed_message.elapsed > duration.as_millis());

        span.start_new();
        sleep(Duration::from_millis(1));
        let elapsed = span.get_elapsed_time_in_millisec();
        assert!(elapsed > 0);
        assert!(elapsed < duration.as_millis());
    }
}
