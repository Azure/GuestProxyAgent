// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use crate::common;
use crate::constants;
use crate::logger;
use crate::structs;
use crate::ExtensionCommand;
use once_cell::sync::Lazy;
use proxy_agent_shared::misc_helpers;
use proxy_agent_shared::version::Version;
use std::fs::{self};
use std::path::{Path, PathBuf};
use std::process;
use std::process::Command;
use std::str;
use std::time::Duration;

#[cfg(windows)]
use crate::windows::service_ext;
#[cfg(windows)]
use proxy_agent_shared::windows;

#[cfg(not(windows))]
use nix::sys::signal::{kill, SIGKILL};
#[cfg(not(windows))]
use nix::unistd::Pid as NixPid;
#[cfg(not(windows))]
use proxy_agent_shared::linux;
#[cfg(not(windows))]
use sysinfo::{ProcessRefreshKind, RefreshKind, System, UpdateKind};

static HANDLER_ENVIRONMENT: Lazy<structs::HandlerEnvironment> = Lazy::new(|| {
    let exe_path = misc_helpers::get_current_exe_dir();
    common::get_handler_environment(&exe_path)
});

pub async fn program_start(command: ExtensionCommand, config_seq_no: String) {
    //Set up Logger instance
    let log_folder = HANDLER_ENVIRONMENT.logFolder.to_string();
    logger::init_logger(log_folder, constants::HANDLER_LOG_FILE);

    logger::write(format!(
        "GuestProxyAgentExtension Version: {}, OS Arch: {}, OS Version: {}",
        misc_helpers::get_current_version(),
        misc_helpers::get_processor_arch(),
        misc_helpers::get_long_os_version()
    ));

    if !check_os_version_supported() {
        report_os_not_supported(config_seq_no);
        process::exit(constants::EXIT_CODE_NOT_SUPPORTED_OS_VERSION);
    }

    handle_command(command, config_seq_no).await;
}

#[cfg(windows)]
fn check_windows_os_version(version: Version) -> bool {
    match version.build {
        Some(build) => {
            logger::write(format!("OS build version: {build}"));
            build >= constants::MIN_SUPPORTED_OS_BUILD
        }
        None => false,
    }
}

fn check_os_version_supported() -> bool {
    #[cfg(windows)]
    {
        match windows::get_os_version() {
            Ok(version) => check_windows_os_version(version),
            Err(e) => {
                logger::write(format!("Error in getting OS version: {e}"));
                false
            }
        }
    }
    #[cfg(not(windows))]
    {
        match Version::from_string(linux::get_os_version()) {
            Ok(version) => check_linux_os_supported(version),
            Err(e) => {
                logger::write(format!("Error in getting OS version: {e}"));
                false
            }
        }
    }
}

#[cfg(not(windows))]
fn check_linux_os_supported(version: Version) -> bool {
    let linux_type = linux::get_os_type().to_lowercase();
    if linux_type.contains("ubuntu") {
        version.major >= constants::linux::MIN_SUPPORTED_UBUNTU_OS_VERSION_MAJOR
    } else if linux_type.contains("mariner") {
        return version.major >= constants::linux::MIN_SUPPORTED_MARINER_OS_VERSION_MAJOR;
    } else if linux_type.contains("azure linux") {
        return version.major >= constants::linux::MIN_SUPPORTED_AZURE_LINUX_OS_VERSION_MAJOR;
    } else if linux_type.contains(constants::linux::RED_HAT_OS_NAME) {
        return version.major >= constants::linux::MIN_RED_HAT_OS_VERSION_MAJOR;
    } else if linux_type.contains(constants::linux::ROCKY_OS_NAME) {
        return version.major >= constants::linux::MIN_ROCKY_OS_VERSION_MAJOR;
    } else if linux_type.contains(constants::linux::SUSE_OS_NAME) {
        // SUSE 15 SP4+ is supported
        return version.major > constants::linux::MIN_SUSE_OS_VERSION_MAJOR
            || (version.major == constants::linux::MIN_SUSE_OS_VERSION_MAJOR
                && version.minor >= constants::linux::MIN_SUSE_OS_VERSION_MINOR);
    } else {
        return false;
    }
}

fn report_os_not_supported(config_seq_no: String) {
    // report to status folder if the os version is not supported
    let status_folder = HANDLER_ENVIRONMENT.statusFolder.to_string();
    let status_folder_path: PathBuf = Path::new(&status_folder).to_path_buf();
    let message = format!(
        "OS version not supported: {}",
        misc_helpers::get_long_os_version()
    );
    let status_obj = structs::StatusObj {
        name: constants::PLUGIN_NAME.to_string(),
        operation: "CheckOSVersionSupport".to_string(),
        configurationAppliedTime: misc_helpers::get_date_time_string(),
        status: constants::ERROR_STATUS.to_string(),
        code: constants::EXIT_CODE_NOT_SUPPORTED_OS_VERSION,
        formattedMessage: structs::FormattedMessage {
            lang: constants::LANG_EN_US.to_string(),
            message: message.to_string(),
        },
        substatus: Default::default(),
    };
    logger::write(message);
    common::report_status(status_folder_path, &config_seq_no, &status_obj);
}

fn get_update_tag_file() -> PathBuf {
    let exe_parent = get_exe_parent();
    let update_tag_file = exe_parent.join(constants::UPDATE_TAG_FILE);
    update_tag_file.to_path_buf()
}

fn update_tag_file_exists() -> bool {
    let update_tag_file = get_update_tag_file();
    if update_tag_file.exists() {
        logger::write(format!("update tag file exists: {update_tag_file:?}"));
        true
    } else {
        logger::write(format!(
            "update tag file does not exist: {update_tag_file:?}"
        ));
        false
    }
}

fn get_exe_parent() -> PathBuf {
    let exe_path = misc_helpers::get_current_exe_dir();

    let exe_parent = match exe_path.parent() {
        Some(parent) => parent,
        None => {
            logger::write("exe parent is None".to_string());
            Path::new("")
        }
    };
    logger::write(format!("exe parent: {exe_parent:?}"));
    exe_parent.to_path_buf()
}

async fn handle_command(command: ExtensionCommand, config_seq_no: String) {
    logger::write(format!("entering handle command: {command:?}"));
    let status_folder = HANDLER_ENVIRONMENT.statusFolder.to_string();
    let status_folder_path: PathBuf = PathBuf::from(&status_folder);
    match command {
        ExtensionCommand::Install => install_handler(),
        ExtensionCommand::Uninstall => uninstall_handler(),
        ExtensionCommand::Enable => enable_handler(status_folder_path, config_seq_no).await,
        ExtensionCommand::Disable => disable_handler().await,
        ExtensionCommand::Reset => reset_handler(),
        ExtensionCommand::Update => update_handler().await,
    }
}

fn install_handler() {
    logger::write("Installing Handler".to_string());
    #[cfg(windows)]
    {
        service_ext::install_extension_service();
    }
}

fn uninstall_handler() {
    logger::write("Uninstalling Handler".to_string());
    if !update_tag_file_exists() {
        let setup_tool = misc_helpers::path_to_string(&common::setup_tool_exe_path());
        match Command::new(setup_tool).arg("uninstall").output() {
            Ok(output) => {
                match str::from_utf8(&output.stdout) {
                    Ok(output_string) => {
                        logger::write(format!(
                            "uninstalling GuestProxyAgent, output: {output_string}"
                        ));
                    }
                    Err(e) => {
                        logger::write(format!("error in uninstalling GuestProxyAgent: {e:?}"));
                    }
                }
                match str::from_utf8(&output.stderr) {
                    Ok(output_string) => {
                        logger::write(format!(
                            "output stderr for uninstall GuestProxyAgent: {output_string}"
                        ));
                    }
                    Err(e) => {
                        logger::write(format!("error in uninstalling GuestProxyAgent: {e:?}"));
                    }
                }
            }
            Err(e) => {
                logger::write(format!("error in uninstalling GuestProxyAgent: {e:?}"));
            }
        }
    }
}

async fn enable_handler(status_folder: PathBuf, config_seq_no: String) {
    let exe_path = misc_helpers::get_current_exe_dir();
    match common::update_current_seq_no(&config_seq_no, &exe_path) {
        Ok(should_report_status) => {
            if should_report_status {
                common::report_status_enable_command(
                    status_folder.to_path_buf(),
                    &config_seq_no,
                    None,
                );
            }
        }
        Err(e) => {
            logger::write(format!("error in updating current seq no: {e:?}"));
            process::exit(constants::EXIT_CODE_WRITE_CURRENT_SEQ_NO_ERROR);
        }
    }

    #[cfg(windows)]
    {
        service_ext::start_extension_service().await;
    }
    #[cfg(not(windows))]
    {
        let process_running = get_linux_extension_long_running_process().is_some();
        let mut count = 0;
        loop {
            if process_running {
                logger::write("ProxyAgentExt process running".to_string());
                break;
            }
            if count > constants::SERVICE_START_RETRY_COUNT {
                common::report_status_enable_command(
                    status_folder.to_path_buf(),
                    &config_seq_no,
                    Some(constants::ERROR_STATUS.to_string()),
                );
                process::exit(constants::EXIT_CODE_SERVICE_START_ERR);
            } else {
                // start the process GuestProxyAgentVMExtension if process not started
                let exe_path = misc_helpers::get_current_exe_dir();
                let service_exe_path = exe_path.join(constants::EXTENSION_PROCESS_NAME);
                match Command::new(service_exe_path).spawn() {
                    Ok(child) => {
                        let pid = child.id();
                        logger::write(format!(
                            "ProxyAgentExt started with pid: {pid}, do not start new one."
                        ));
                        break;
                    }
                    Err(e) => {
                        logger::write(format!("error in starting ProxyAgentExt: {e:?}"));
                    }
                }
            }
            count += 1;
            tokio::time::sleep(Duration::from_secs(15)).await;
        }
    }
    if update_tag_file_exists() {
        let update_tag_file = get_update_tag_file();
        match fs::remove_file(&update_tag_file) {
            Ok(_) => logger::write(format!(
                "update tag file removed: {:?}",
                update_tag_file.to_path_buf()
            )),
            Err(e) => logger::write(format!("error in removing update tag file: {e:?}")),
        }
    }
}

#[cfg(not(windows))]
fn get_linux_extension_long_running_process() -> Option<i32> {
    // check if the process GuestProxyAgentVMExtension running AND without parameters
    let system = System::new_with_specifics(
        RefreshKind::new().with_processes(
            ProcessRefreshKind::new()
                .with_cmd(UpdateKind::Always)
                .with_exe(UpdateKind::Always),
        ),
    );

    for p in system.processes_by_exact_name(constants::EXTENSION_PROCESS_NAME) {
        let cmd = p.cmd();
        logger::write(format!("cmd: {cmd:?}"));
        if cmd.len() == 1 {
            logger::write(format!("ProxyAgentExt running with pid: {}", p.pid()));
            return Some(p.pid().as_u32() as i32);
        }
    }
    None
}

async fn disable_handler() {
    logger::write("Disabling Handler".to_string());
    #[cfg(windows)]
    {
        service_ext::stop_extension_service().await;
    }
    #[cfg(not(windows))]
    {
        match get_linux_extension_long_running_process() {
            Some(pid) => {
                let p = NixPid::from_raw(pid);
                match kill(p, SIGKILL) {
                    Ok(_) => {
                        logger::write(format!("ProxyAgentExt process with pid: {pid} killed"));
                    }
                    Err(e) => {
                        logger::write(format!("error in killing ProxyAgentExt process: {e:?}"));
                    }
                }
            }
            None => {
                logger::write("ProxyAgentExt not running".to_string());
            }
        }
    }
}

fn reset_handler() {
    let exe_path = misc_helpers::get_current_exe_dir();
    let update_tag_file = get_update_tag_file();
    let seq_no_file = exe_path.join(constants::CURRENT_SEQ_NO_FILE);
    match fs::remove_file(&update_tag_file) {
        Ok(_) => logger::write(format!(
            "update tag file removed: {:?}",
            update_tag_file.to_path_buf()
        )),
        Err(e) => logger::write(format!("error in removing update tag file: {e:?}")),
    }
    match fs::remove_file(&seq_no_file) {
        Ok(_) => logger::write(format!(
            "seq no file removed: {:?}",
            seq_no_file.to_path_buf()
        )),
        Err(e) => logger::write(format!("error in removing seq no file: {e:?}")),
    }
}

async fn update_handler() {
    #[cfg(windows)]
    {
        let version = match std::env::var("VERSION") {
            Ok(ver) => ver,
            Err(e) => {
                logger::write(format!("error in getting VERSION from env::var: {e:?}"));
                process::exit(constants::EXIT_CODE_UPDATE_TO_VERSION_ENV_VAR_NOTFOUND);
            }
        };

        let extension_dir = get_exe_parent();
        let extension_dir = extension_dir.join(version);
        service_ext::update_extension_service(extension_dir);
    }

    let update_tag_file = get_update_tag_file();
    let mut count = 0;
    loop {
        if count > constants::SERVICE_START_RETRY_COUNT {
            logger::write(format!(
                "service start retry count exceeded: {}",
                constants::SERVICE_START_RETRY_COUNT
            ));
            break;
        } else {
            match fs::write(&update_tag_file, misc_helpers::get_date_time_string()) {
                Ok(_) => {
                    logger::write(format!(
                        "update tag file created: {:?}",
                        update_tag_file.to_path_buf()
                    ));
                    break;
                }
                Err(e) => {
                    logger::write(format!("error in creating update tag file: {e:?}"));
                }
            }
        }
        count += 1;
        tokio::time::sleep(Duration::from_secs(15)).await;
    }
}

#[cfg(test)]
mod tests {

    #[cfg(windows)]
    use crate::handler_main;
    #[cfg(windows)]
    use proxy_agent_shared::version::Version;

    #[test]
    fn test_check_os_supported() {
        #[cfg(windows)]
        {
            let version = Version {
                major: 10,
                minor: 0,
                build: Some(17765),
                revision: None,
            };
            assert!(handler_main::check_windows_os_version(version));

            let version = Version {
                major: 10,
                minor: 0,
                build: Some(17762),
                revision: None,
            };

            assert!(!handler_main::check_windows_os_version(version));

            let version = Version {
                major: 10,
                minor: 0,
                build: None,
                revision: None,
            };
            assert!(!handler_main::check_windows_os_version(version));
        }
    }
}
