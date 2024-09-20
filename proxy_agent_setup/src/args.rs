// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use clap::{Parser, Subcommand, ValueEnum};
use std::fmt::{Display, Formatter};

#[derive(Parser)]
#[command(version, about, long_about = None)]
pub(crate) struct Cli {
    /// GPA VM Extension commands
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub(crate) enum Command {
    /// backup the GPA service
    Backup,
    /// restore the GPA service
    Restore {
        #[arg(default_value_t = true)]
        delete_backup: bool,
    },
    /// uninstall the GPA service
    Uninstall {
        #[arg(default_value_t = UninstallMode::Service)]
        uninstall_mode: UninstallMode,
    },
    /// install the GPA VM service
    Install,
    /// purge the backup GPA service files
    Purge,
}

#[derive(ValueEnum, Clone, Debug, PartialEq)]
pub(crate) enum UninstallMode {
    Service,
    Package,
}

impl Display for Cli {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.command)
    }
}

impl Display for Command {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Command::Backup => write!(f, "backup"),
            Command::Restore { delete_backup } => {
                write!(f, "restore delete_backup={}", delete_backup)
            }
            Command::Uninstall { uninstall_mode } => write!(f, "uninstall {}", uninstall_mode),
            Command::Install => write!(f, "install"),
            Command::Purge => write!(f, "purge"),
        }
    }
}

impl Display for UninstallMode {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            UninstallMode::Service => write!(f, "service"),
            UninstallMode::Package => write!(f, "package"),
        }
    }
}
