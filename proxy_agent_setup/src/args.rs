// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
pub struct Args {
    pub action: String,         // install, uninstall, or help
    pub uninstall_mode: String, // optional parameter for uninstall: service or package
}

impl Args {
    pub const INSTALL: &'static str = "install";
    pub const UNINSTALL: &'static str = "uninstall";
    pub const BACKUP: &'static str = "backup";
    pub const RESTORE: &'static str = "restore";
    pub const PURGE: &'static str = "purge";
    pub const HELP: &'static str = "help";
    pub const UNINSTALL_SERVICE: &'static str = "service";
    pub const DELETE_PACKAGE: &'static str = "package";

    pub fn parse(args: Vec<String>) -> Self {
        if args.len() < 2 {
            Args::print_help();
            std::process::exit(1);
        }
        let action = match args[1].clone().to_lowercase().as_str() {
            Args::INSTALL => Args::INSTALL,
            Args::UNINSTALL => Args::UNINSTALL,
            Args::BACKUP => Args::BACKUP,
            Args::RESTORE => Args::RESTORE,
            Args::PURGE => Args::PURGE,
            Args::HELP => {
                Args::print_help();
                std::process::exit(0);
            }
            _ => {
                Args::print_help();
                std::process::exit(1);
            }
        };

        if args.len() > 2
            && args[2].to_lowercase() != Args::UNINSTALL_SERVICE
            && args[2].to_lowercase() != Args::DELETE_PACKAGE
        {
            Args::print_help();
            std::process::exit(1);
        }

        let uninstall_mode = if args.len() > 2 {
            args[2].to_lowercase()
        } else {
            Args::DELETE_PACKAGE.to_string()
        };

        let args = Args {
            action: action.to_string(),
            uninstall_mode: uninstall_mode,
        };

        args
    }

    fn print_help() {
        println!("Usage: proxy_agent_setup <action> [service]");
        println!("  action: install, uninstall, backup, restore, purge, or help");
        println!("  service: optional parameter for uninstall or restore: service or package. Default is package.");
    }

    pub fn to_string(&self) -> String {
        format!(
            "{} {}",
            self.action, self.uninstall_mode
        )
    }
}
