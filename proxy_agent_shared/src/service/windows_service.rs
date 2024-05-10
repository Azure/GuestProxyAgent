// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use crate::logger_manager;
use std::ffi::OsString;
use std::io;
use std::path::PathBuf;
use std::str;
use std::thread;
use windows_service::service::ServiceDependency;
use windows_service::service::{
    Service, ServiceAccess, ServiceConfig, ServiceErrorControl, ServiceInfo, ServiceStartType,
    ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

pub fn start_service_with_retry(
    service_name: &str,
    retry_count: u32,
    duration: std::time::Duration,
) {
    for i in 0..retry_count {
        logger_manager::write_info(format!("Starting service {} attempt {}", service_name, i));

        match start_service_once(service_name) {
            Ok(service) => {
                if service.current_state == ServiceState::Running {
                    logger_manager::write_info(format!(
                        "Service {} is at Running state",
                        service_name
                    ));
                    return;
                }

                logger_manager::write_info(
                    format!(
                        "Service {} failed to start with current state {:?}",
                        service_name, service.current_state
                    )
                    .to_string(),
                );
            }
            Err(e) => {
                logger_manager::write_info(
                    format!(
                        "Extension service {} start failed with error: {}",
                        service_name, e
                    )
                    .to_string(),
                );
            }
        }

        thread::sleep(duration);
    }
}

fn start_service_once(service_name: &str) -> windows_service::Result<ServiceStatus> {
    // Start service if it already isn't running
    query_service_status(service_name).and_then(|service| {
        if service.current_state == ServiceState::Running {
            logger_manager::write_info(format!(
                "Extension service '{}' is already running",
                service_name
            ));
            Ok(service)
        } else {
            let service_manager: ServiceManager =
                ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
            let service = service_manager.open_service(
                service_name,
                ServiceAccess::START | ServiceAccess::QUERY_STATUS,
            )?;
            service.start(&[""])?;
            logger_manager::write_info(format!("Staring Extension service '{}'", service_name));
            logger_manager::write_info(
                "Wait for 1 second before querying service status".to_string(),
            );
            thread::sleep(std::time::Duration::from_secs(1));
            service.query_status()
        }
    })
}

pub fn stop_and_delete_service(service_name: &str) -> windows_service::Result<()> {
    stop_service(service_name)?;
    delete_service(service_name)
}

pub fn stop_service(service_name: &str) -> windows_service::Result<ServiceStatus> {
    // Stop service if it already isn't stopped
    query_service_status(service_name).and_then(|service| {
        if service.current_state == ServiceState::Running {
            let service_manager: ServiceManager =
                ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
            let service = service_manager.open_service(
                service_name,
                ServiceAccess::STOP | ServiceAccess::QUERY_STATUS,
            )?;
            match service.stop() {
                Ok(service) => {
                    logger_manager::write_info(format!(
                        "Stopped service {} successfully with current status {:?}",
                        service_name, service.current_state
                    ));
                    thread::sleep(std::time::Duration::from_secs(1));
                }
                Err(e) => {
                    logger_manager::write_info(format!(
                        "Stopped service {} failed, error: {:?}",
                        service_name, e
                    ));
                }
            }
            service.query_status()
        } else {
            Ok(service)
        }
    })
}

fn delete_service(service_name: &str) -> windows_service::Result<()> {
    // Delete the service
    let service_manager: ServiceManager =
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = service_manager.open_service(service_name, ServiceAccess::DELETE)?;
    service.delete()
}

pub fn install_or_update_service(
    service_name: &str,
    service_display_name: &str,
    service_dependencies: Vec<&str>,
    service_exe_path: PathBuf,
) -> std::io::Result<()> {
    // if query_service returns Ok, then the service needs to be updated otherwise create a service
    match query_service_status(service_name) {
        Ok(_service) => {
            match update_service(
                service_name,
                service_display_name,
                service_dependencies,
                service_exe_path,
            ) {
                Ok(_service) => {
                    return Ok(());
                }
                Err(e) => {
                    return Err(io::Error::new(io::ErrorKind::Other, e));
                }
            };
        }
        Err(_e) => {
            match create_service(
                service_name,
                service_display_name,
                service_dependencies,
                service_exe_path,
            ) {
                Ok(_service) => {
                    return Ok(());
                }
                Err(e) => {
                    return Err(io::Error::new(io::ErrorKind::Other, e));
                }
            };
        }
    };
}

fn query_service_status(service_name: &str) -> windows_service::Result<ServiceStatus> {
    let service_manager =
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = service_manager.open_service(service_name, ServiceAccess::QUERY_STATUS)?;
    service.query_status()
}

#[allow(dead_code)]
pub fn query_service_config(service_name: &str) -> windows_service::Result<ServiceConfig> {
    let service_manager =
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = service_manager.open_service(service_name, ServiceAccess::QUERY_CONFIG)?;
    service.query_config()
}

pub fn update_service(
    service_name: &str,
    service_display_name: &str,
    service_dependencies: Vec<&str>,
    service_exe_path: PathBuf,
) -> windows_service::Result<()> {
    // update the service with the new executable path
    let service_manager =
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;

    let service = service_manager.open_service(service_name, ServiceAccess::CHANGE_CONFIG)?;

    let mut vec_service_dependencies: Vec<ServiceDependency> = Vec::new();
    for src_dep in service_dependencies {
        vec_service_dependencies.push(ServiceDependency::Service(OsString::from(src_dep)));
    }
    let service_info = ServiceInfo {
        name: OsString::from(service_name),
        display_name: OsString::from(service_display_name),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: service_exe_path,
        launch_arguments: vec![], //TODO: add arguments
        dependencies: vec_service_dependencies,
        account_name: None, // run as System
        account_password: None,
    };

    service.change_config(&service_info)
}

fn create_service(
    service_name: &str,
    service_display_name: &str,
    service_dependencies: Vec<&str>,
    exe_path: PathBuf,
) -> windows_service::Result<Service> {
    let _manager_access = ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE;

    let service_manager =
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CREATE_SERVICE)?;

    let mut vec_service_dependencies: Vec<ServiceDependency> = Vec::new();
    for src_dep in service_dependencies {
        vec_service_dependencies.push(ServiceDependency::Service(OsString::from(src_dep)));
    }
    let service_info = ServiceInfo {
        name: OsString::from(service_name),
        display_name: OsString::from(service_display_name),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe_path,
        launch_arguments: vec![],
        dependencies: vec_service_dependencies,
        account_name: None, // run as System
        account_password: None,
    };
    service_manager.create_service(&service_info, ServiceAccess::QUERY_STATUS)
}

#[cfg(test)]
mod tests {
    use crate::logger_manager;
    use std::env;
    use std::{path::PathBuf, process::Command};

    #[test]
    fn test_install_service() {
        const TEST_SERVICE_NAME: &str = "test_nt_service";
        let mut temp_test_path = env::temp_dir();
        temp_test_path.push("test_install_service");

        let log_folder: PathBuf = temp_test_path.to_path_buf();
        let log_key: &str = "test_install_service";
        let log_name: String = "test_install_service.log".to_string();
        let log_size: u64 = 20 * 1024 * 1024;
        let log_count: u16 = 30;
        logger_manager::init_logger(
            log_key.to_string(),
            log_folder,
            log_name,
            log_size,
            log_count,
        );

        // Delete Service if it exists
        _ = super::stop_and_delete_service(TEST_SERVICE_NAME);

        // Install Service
        let service_exe_path: PathBuf = PathBuf::from("notepad.exe");
        super::install_or_update_service(
            TEST_SERVICE_NAME,
            TEST_SERVICE_NAME,
            vec![],
            service_exe_path.to_path_buf(),
        )
        .unwrap();
        // check the exe path
        let config = super::query_service_config(TEST_SERVICE_NAME).unwrap();
        assert_eq!(config.executable_path, service_exe_path.to_path_buf());

        // Update Service
        let updated_service_exe_path: PathBuf = PathBuf::from("calc.exe");
        super::install_or_update_service(
            TEST_SERVICE_NAME,
            TEST_SERVICE_NAME,
            vec![],
            updated_service_exe_path.to_path_buf(),
        )
        .unwrap();
        // check exe path has been updated
        let config = super::query_service_config(TEST_SERVICE_NAME).unwrap();
        assert_eq!(
            config.executable_path,
            updated_service_exe_path.to_path_buf()
        );

        //Check if service is running
        let output = Command::new("sc")
            .args(&["query", TEST_SERVICE_NAME])
            .output()
            .expect("Failed to execute command");

        let output_str = String::from_utf8_lossy(&output.stdout);
        print!("SC query output: {}", output_str);

        // Check if the output contains the desired information indicating the service is running
        assert!(
            !output_str.contains("The specified service does not exist as an installed service")
        );

        super::start_service_with_retry(TEST_SERVICE_NAME, 2, std::time::Duration::from_millis(15));
        let service_staus = super::query_service_status(TEST_SERVICE_NAME).unwrap();
        assert!(
            service_staus.current_state != windows_service::service::ServiceState::Running,
            "Test service should not be able to run"
        );

        // Check if service is stopped
        let expected_stop_service = super::stop_service(TEST_SERVICE_NAME).unwrap();
        let actual_stop_service = super::query_service_status(TEST_SERVICE_NAME).unwrap();
        assert_eq!(expected_stop_service, actual_stop_service);

        // //Clean up - delete service
        super::stop_and_delete_service(TEST_SERVICE_NAME).unwrap();
        //Check if service is running
        let output = Command::new("sc")
            .args(&["query", TEST_SERVICE_NAME])
            .output()
            .expect("Failed to execute command");

        let output_str = String::from_utf8_lossy(&output.stdout);
        print!("SC query output: {}", output_str);

        // Check if the output contains the desired information indicating the service is running
        assert!(output_str.contains("The specified service does not exist as an installed service"));
    }

    #[test]
    fn test_create_service() {
        let service_name = "test_create_service";
        let exe_path = PathBuf::from("notepad.exe");
        super::create_service(service_name, service_name, vec![], exe_path).unwrap();
        //Check if service is running
        let output = Command::new("sc")
            .args(&["query", service_name])
            .output()
            .expect("Failed to execute command");

        let output_str = String::from_utf8_lossy(&output.stdout);
        print!("SC query output: {}", output_str);
        // Check if the output contains the desired information indicating the service is running
        assert!(output_str.contains("STOPPED"));
        //Clean up - delete service
        super::stop_and_delete_service(service_name).unwrap();
    }
}
