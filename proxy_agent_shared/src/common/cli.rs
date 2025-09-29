// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

use clap::{Parser, Subcommand};
use once_cell::sync::Lazy;

/// azure-proxy-agent console - launch a long run process of GPA in console mode.
/// azure-proxy-agent --version - print the version of the GPA.
/// azure-proxy-agent --status [--wait <seconds>] - get the provision status of the GPA service.
/// azure-proxy-agent - start the GPA as an OS service.
///                     The GPA service will be started as an OS service in the background.
#[derive(Parser)]
#[command()]
pub struct Cli {
    /// get the provision status of the GPA service
    #[arg(short, long)]
    pub status: bool,

    /// wait for the provision status to finish
    #[arg(short, long, requires = "status")]
    pub wait: Option<u64>,

    /// print the version of the GPA
    #[arg(short, long)]
    pub version: bool,

    #[cfg(test)]
    #[arg(short, long)]
    test_threads: Option<usize>,

    #[cfg(test)]
    #[arg(short, long)]
    nocapture: bool,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// launch a long run process of GPA in console mode
    Console,
}

impl Cli {
    pub fn is_console_mode(&self) -> bool {
        self.command.is_some()
    }
}

pub static CLI: Lazy<Cli> = Lazy::new(Cli::parse);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_version_flag() {
        let cli = Cli::try_parse_from(["command", "--version"]).unwrap();
        assert!(cli.version);
        assert!(!cli.status);
        assert!(cli.wait.is_none());
        assert!(cli.command.is_none());
    }

    #[test]
    fn test_parse_status_with_wait() {
        let cli = Cli::try_parse_from(["command", "--status", "--wait", "10"]).unwrap();
        assert!(cli.status);
        assert_eq!(cli.wait, Some(10));
        assert!(!cli.version);
        assert!(cli.command.is_none());
    }

    #[test]
    fn test_parse_console_command() {
        let cli = Cli::try_parse_from(["command", "console"]).unwrap();
        assert!(cli.is_console_mode());
        match cli.command {
            Some(Commands::Console) => {}
            _ => panic!("Expected Commands::Console"),
        }
    }

    #[test]
    fn test_parse_status_without_wait() {
        let cli = Cli::try_parse_from(["command", "--status"]).unwrap();
        assert!(cli.status);
        assert!(cli.wait.is_none());
        assert!(!cli.version);
    }

    #[test]
    fn test_conflicting_wait_without_status_fails() {
        let result = Cli::try_parse_from(["command", "--wait", "5"]);
        assert!(result.is_err(), "wait without --status should fail");
    }

    #[test]
    fn test_no_args_defaults() {
        let cli = Cli::try_parse_from(["command"]).unwrap();
        assert!(!cli.status);
        assert!(!cli.version);
        assert!(cli.wait.is_none());
        assert!(cli.command.is_none());
        assert!(!cli.is_console_mode());
    }

    #[cfg(test)]
    #[test]
    fn test_test_only_flags() {
        let cli =
            Cli::try_parse_from(["command", "--status", "--test-threads", "4", "--nocapture"])
                .unwrap();
        assert!(cli.status);
        assert_eq!(cli.test_threads, Some(4));
        assert!(cli.nocapture);
    }
}
