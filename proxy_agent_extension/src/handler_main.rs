// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use crate::common;
use crate::constants;
use crate::logger;
use crate::structs;
use once_cell::sync::Lazy;
use proxy_agent_shared::misc_helpers;
use proxy_agent_shared::version::Version;
use std::fs::{self};
use std::path::{Path, PathBuf};
use std::process;
use std::process::Command;
use std::str;
use std::thread;
use std::time::Duration;

#[cfg(windows)]
use crate::windows::service_ext;
#[cfg(windows)]
use proxy_agent_shared::windows;

#[cfg(not(windows))]
use proxy_agent_shared::linux;
#[cfg(not(windows))]
use sysinfo::{Pid, ProcessExt, System, SystemExt};

static HANDLER_ENVIRONMENT: Lazy<structs::HandlerEnvironment> = Lazy::new(|| {
    let exe_path = misc_helpers::get_current_exe_dir();
    common::get_handler_environment(exe_path)
});

pub fn program_start(args: Vec<String>, config_seq_no: Option<String>) {
    if args.len() < 2 {
        eprintln!("input args length invalid {}", args.len());
        process::exit(constants::INVALID_INPUT_ARGS_LENGTH);
    }

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

    handle_command(&args[1], &config_seq_no);
}

#[cfg(windows)]
fn check_windows_os_version(version: Version) -> bool {
    match version.build {
        Some(build) => {
            logger::write(format!("OS build version: {}", build));
            return build >= constants::MIN_SUPPORTED_OS_BUILD;
        }
        None => return false,
    }
}

fn check_os_version_supported() -> bool {
    #[cfg(windows)]
    {
        match windows::get_os_version() {
            Ok(version) => {
                return check_windows_os_version(version);
            }
            Err(e) => {
                logger::write(format!("Error in getting OS version: {e}"));
                return false;
            }
        }
    }
    #[cfg(not(windows))]
    {
        match Version::from_string(linux::get_os_version()) {
            Ok(version) => {
                return check_linux_os_supported(version);
            }
            Err(e) => {
                logger::write(format!("Error in getting OS version: {e}"));
                return false;
            }
        }
    }
}

#[cfg(not(windows))]
fn check_linux_os_supported(version: Version) -> bool {
    let linux_type = linux::get_os_type().to_lowercase();
    if linux_type.contains("ubuntu") {
        return version.major >= constants::MIN_SUPPORTED_UBUNTU_OS_BUILD;
    } else if linux_type.contains("mariner") {
        return version.major >= constants::MIN_SUPPORTED_MARINER_OS_BUILD;
    } else {
        return false;
    }
}

fn report_os_not_supported(config_seq_no: Option<String>) {
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
        code: constants::NOT_SUPPORTED_OS_VERSION,
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
    return update_tag_file.to_path_buf();
}

fn update_tag_file_exists() -> bool {
    let update_tag_file = get_update_tag_file();
    if update_tag_file.exists() {
        logger::write(format!("update tag file exists: {:?}", update_tag_file));
        return true;
    } else {
        logger::write(format!(
            "update tag file does not exist: {:?}",
            update_tag_file
        ));
        return false;
    }
}

fn get_exe_parent() -> PathBuf {
    let exe_path = misc_helpers::get_current_exe_dir();
    let exe_parent;
    match exe_path.parent() {
        Some(parent) => exe_parent = parent,
        None => {
            logger::write(format!("exe parent is None"));
            exe_parent = Path::new("");
        }
    }
    logger::write(format!("exe parent: {:?}", exe_parent));
    return exe_parent.to_path_buf();
}

fn handle_command(cmd: &str, config_seq_no: &Option<String>) {
    logger::write(format!("entering handle command: {cmd}"));
    let status_folder = HANDLER_ENVIRONMENT.statusFolder.to_string();
    let status_folder_path: PathBuf = Path::new(&status_folder).to_path_buf();
    match cmd {
        "install" => install_handler(),
        "uninstall" => unistall_handler(),
        "enable" => enable_handler(status_folder_path, config_seq_no),
        "disable" => disable_handler(),
        "reset" => reset_handler(),
        "update" => update_handler(),
        _ => {}
    }
}

fn install_handler() {
    logger::write("Installing Handler".to_string());
    #[cfg(windows)]
    {
        service_ext::install_extension_service();
    }
}

fn unistall_handler() {
    logger::write("Uninstalling Handler".to_string());
    if !update_tag_file_exists() {
        let setup_tool = misc_helpers::path_to_string(common::setup_tool_exe_path());
        match Command::new(setup_tool).arg("uninstall").output() {
            Ok(output) => {
                match str::from_utf8(&output.stdout) {
                    Ok(output_string) => {
                        logger::write(format!(
                            "uninstalling GuestProxyAgent, output: {}",
                            output_string
                        ));
                    }
                    Err(e) => {
                        logger::write(format!("error in uninstalling GuestProxyAgent: {:?}", e));
                    }
                }
                match str::from_utf8(&output.stderr) {
                    Ok(output_string) => {
                        logger::write(format!(
                            "output stderr for uninstall GuestProxyAgent: {}",
                            output_string
                        ));
                    }
                    Err(e) => {
                        logger::write(format!("error in uninstalling GuestProxyAgent: {:?}", e));
                    }
                }
            }
            Err(e) => {
                logger::write(format!("error in uninstalling GuestProxyAgent: {:?}", e));
            }
        }
    }
}

fn enable_handler(status_folder: PathBuf, config_seq_no: &Option<String>) {
    let exe_path = misc_helpers::get_current_exe_dir();
    let should_report_status =
        match common::update_current_seq_no(config_seq_no, exe_path.to_path_buf()) {
            Ok(should_report_status) => should_report_status,
            Err(e) => {
                eprintln!("Error in updating current seq no: {e}");
                process::exit(constants::EXIT_CODE_NO_CONFIG_SEQ_NO);
            }
        };

    if should_report_status {
        common::report_status_enable_command(status_folder.to_path_buf(), config_seq_no, None);
    }

    #[cfg(windows)]
    {
        service_ext::start_extension_service();
    }
    #[cfg(not(windows))]
    {
        let process_running;
        match get_linux_extension_long_running_process() {
            Some(_) => {
                process_running = true;
            }
            None => {
                process_running = false;
            }
        }
        let mut count = 0;
        loop {
            if process_running {
                logger::write("ProxyAgentExt process running".to_string());
                break;
            }
            if count > constants::SERVICE_START_RETRY_COUNT {
                common::report_status_enable_command(
                    status_folder.to_path_buf(),
                    config_seq_no,
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
                            "ProxyAgentExt started with pid: {}, do not start new one.",
                            pid
                        ));
                        break;
                    }
                    Err(e) => {
                        logger::write(format!("error in starting ProxyAgentExt: {:?}", e));
                    }
                }
            }
            count += 1;
            thread::sleep(Duration::from_secs(15));
        }
    }
    if update_tag_file_exists() {
        let update_tag_file = get_update_tag_file();
        match fs::remove_file(update_tag_file.to_path_buf()) {
            Ok(_) => logger::write(format!(
                "update tag file removed: {:?}",
                update_tag_file.to_path_buf()
            )),
            Err(e) => logger::write(format!("error in removing update tag file: {:?}", e)),
        }
    }
}

#[cfg(not(windows))]
fn get_linux_extension_long_running_process() -> Option<Pid> {
    // check if the process GuestProxyAgentVMExtension running AND without parameters
    let mut system = System::new();
    system.refresh_processes();
    for p in system.processes_by_name(constants::EXTENSION_PROCESS_NAME) {
        let cmd = p.cmd();
        logger::write(format!("cmd: {:?}", cmd));
        if cmd.len() == 1 {
            logger::write(format!("ProxyAgentExt running with pid: {}", p.pid()));
            return Some(p.pid());
        }
    }
    return None;
}

fn disable_handler() {
    logger::write("Disabling Handler".to_string());
    #[cfg(windows)]
    {
        service_ext::stop_extension_service();
    }
    #[cfg(not(windows))]
    {
        match get_linux_extension_long_running_process() {
            Some(pid) => {
                let output =
                    misc_helpers::execute_command("kill", vec!["-9", &pid.to_string()], -1);
                logger::write(format!(
                    "kill ProxyAgentExt: result: '{}'-'{}'-'{}'.",
                    output.0, output.1, output.2
                ));
            }
            None => {
                logger::write(format!("ProxyAgentExt not running"));
            }
        }
    }
}

fn reset_handler() {
    let exe_path = misc_helpers::get_current_exe_dir();
    let update_tag_file = get_update_tag_file();
    let seq_no_file = exe_path.join(constants::CURRENT_SEQ_NO_FILE);
    match fs::remove_file(update_tag_file.to_path_buf()) {
        Ok(_) => logger::write(format!(
            "update tag file removed: {:?}",
            update_tag_file.to_path_buf()
        )),
        Err(e) => logger::write(format!("error in removing update tag file: {:?}", e)),
    }
    match fs::remove_file(seq_no_file.to_path_buf()) {
        Ok(_) => logger::write(format!(
            "seq no file removed: {:?}",
            seq_no_file.to_path_buf()
        )),
        Err(e) => logger::write(format!("error in removing seq no file: {:?}", e)),
    }
}

fn update_handler() {
    #[cfg(windows)]
    {
        let version = match std::env::var("VERSION") {
            Ok(ver) => ver,
            Err(e) => {
                logger::write(format!("error in getting VERSION from env::var: {:?}", e));
                process::exit(constants::EXIT_CODE_UPDATE_TO_VERSION_ENV_VAR_NOTFOUND);
            }
        };

        let extension_dir = get_exe_parent();
        let extesion_dir = extension_dir.join(version);
        service_ext::update_extension_service(extesion_dir);
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
            match fs::write(
                update_tag_file.to_path_buf(),
                misc_helpers::get_date_time_string(),
            ) {
                Ok(_) => {
                    logger::write(format!(
                        "update tag file created: {:?}",
                        update_tag_file.to_path_buf()
                    ));
                    break;
                }
                Err(e) => {
                    logger::write(format!("error in creating update tag file: {:?}", e));
                }
            }
        }
        count += 1;
        thread::sleep(Duration::from_secs(15));
    }
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::fs::{self};

    #[cfg(windows)]
    use crate::handler_main;
    #[cfg(windows)]
    use proxy_agent_shared::version::Version;

    #[test]
    fn test_check_os_supported() {
        let mut temp_test_path = env::temp_dir();
        temp_test_path.push("test_check_os_supported");

        let log_folder: String = temp_test_path.to_str().unwrap().to_string();
        super::logger::init_logger(log_folder, "log.txt");

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
        _ = fs::remove_dir_all(&temp_test_path);
    }
}
