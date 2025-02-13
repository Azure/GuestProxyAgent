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
