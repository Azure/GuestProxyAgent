// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use proxy_agent_shared::{
    logger::{logger_manager, LoggerLevel},
    telemetry::event_logger,
};

use super::config;

pub const AGENT_LOGGER_KEY: &str = "Agent_Logger";

pub fn write(message: String) {
    log(LoggerLevel::Trace, message);
}

pub fn write_information(message: String) {
    log(LoggerLevel::Info, message);
}

pub fn write_warning(message: String) {
    log(LoggerLevel::Warn, message);
}

pub fn write_error(message: String) {
    log(LoggerLevel::Error, message);
}

fn log(log_level: LoggerLevel, message: String) {
    if let Some(log_for_event) = config::get_file_log_level_for_events() {
        if log_for_event >= log_level {
            // write to event
            event_logger::write_event_only(
                log_level,
                message.to_string(),
                "CommonLogger",
                "ProxyAgent",
            );
        }
    }

    logger_manager::log(AGENT_LOGGER_KEY.to_string(), log_level, message);
}

#[cfg(not(windows))]
pub fn write_serial_console_log(message: String, serial_console_log_path: Option<String>) {
    use proxy_agent_shared::{current_info, misc_helpers};
    use std::os::unix::fs::OpenOptionsExt;
    use std::time::Duration;

    let message = format!(
        "{} {}_{}({}) - {}\n",
        misc_helpers::get_date_time_string_with_milliseconds(),
        env!("CARGO_PKG_NAME"),
        current_info::get_current_exe_version(),
        std::process::id(),
        message
    );

    let serial_console_path = serial_console_log_path.unwrap_or_else(|| "/dev/console".to_string());
    match std::fs::OpenOptions::new()
        .write(true)
        // O_NONBLOCK makes a stalled console return `WouldBlock` instead of blocking the write;
        // the write helper retries it with a bounded timeout.
        // O_CLOEXEC prevents a child process from retaining this /dev/console descriptor after it executes an external program.
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(serial_console_path)
    {
        Ok(mut serial_console) => {
            if let Err(e) = write_all_with_timeout(
                &mut serial_console,
                message.as_bytes(),
                Duration::from_secs(2),
            ) {
                write_warning(format!(
                    "write_serial_console_log::Failed to write to serial console: {e}"
                ));
            }
        }
        Err(e) => {
            write_warning(format!(
                "write_serial_console_log::Failed to open serial console: {e}"
            ));
        }
    }
}

#[cfg(not(windows))]
fn write_all_with_timeout(
    file: &mut std::fs::File,
    mut buffer: &[u8],
    timeout: std::time::Duration,
) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::fd::AsRawFd;

    let deadline = std::time::Instant::now() + timeout;
    while !buffer.is_empty() {
        match file.write(buffer) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "failed to write serial console message",
                ));
            }
            Ok(written) => buffer = &buffer[written..],
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                let remaining = deadline.saturating_duration_since(std::time::Instant::now());
                if remaining.is_zero() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "serial console write timed out",
                    ));
                }

                let timeout_ms = remaining.as_millis().min(libc::c_int::MAX as u128) as libc::c_int;
                let mut poll_fd = libc::pollfd {
                    fd: file.as_raw_fd(),
                    events: libc::POLLOUT,
                    revents: 0,
                };
                // SAFETY: poll_fd points to one valid pollfd for the duration of this call.
                let result = unsafe { libc::poll(&mut poll_fd, 1, timeout_ms) };
                if result == 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "serial console write timed out",
                    ));
                }
                if result < 0 {
                    let poll_error = std::io::Error::last_os_error();
                    if poll_error.kind() != std::io::ErrorKind::Interrupted {
                        return Err(poll_error);
                    }
                }
            }
            Err(e) => return Err(e),
        }
    }

    Ok(())
}

#[cfg(all(test, not(windows)))]
mod tests {
    use super::{write_all_with_timeout, write_serial_console_log};
    use std::io::Write;
    use std::os::fd::FromRawFd;
    use std::time::Duration;

    #[test]
    fn write_serial_console_log_writes_to_supplied_path() {
        let log_path = std::env::temp_dir().join(format!(
            "azure-proxy-agent-console-{}-{}.log",
            std::process::id(),
            proxy_agent_shared::misc_helpers::get_date_time_unix_nano()
        ));
        std::fs::File::create(&log_path).expect("create serial console test log");

        write_serial_console_log(
            "serial console test message".to_string(),
            Some(log_path.to_string_lossy().into_owned()),
        );

        let contents = std::fs::read_to_string(&log_path).expect("read serial console test log");
        std::fs::remove_file(log_path).expect("remove serial console test log");
        assert!(contents.ends_with(" - serial console test message\n"));
    }

    #[test]
    fn write_all_with_timeout_times_out_when_file_is_not_writable() {
        let mut pipe_fds = [0; 2];
        // SAFETY: pipe_fds points to storage for the two descriptors returned by pipe2.
        assert_eq!(
            unsafe { libc::pipe2(pipe_fds.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) },
            0
        );
        // SAFETY: pipe2 returned two owned descriptors that are each converted exactly once.
        let _read_end = unsafe { std::fs::File::from_raw_fd(pipe_fds[0]) };
        // SAFETY: pipe2 returned two owned descriptors that are each converted exactly once.
        let mut write_end = unsafe { std::fs::File::from_raw_fd(pipe_fds[1]) };
        let fill_buffer = [0_u8; 4096];
        loop {
            match write_end.write(&fill_buffer) {
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => panic!("failed to fill nonblocking pipe: {error}"),
            }
        }

        let error = write_all_with_timeout(&mut write_end, b"blocked", Duration::from_millis(200))
            .expect_err("full pipe should time out");

        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    }
}
