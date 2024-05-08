// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#[cfg(windows)]
mod windows_service;
#[cfg(not(windows))]
mod linux_service;

use std::path::PathBuf;

#[cfg(windows)]
use crate::logger_manager;
#[cfg(windows)]
use std::io;

pub fn install_service(
    service_name: &str,
    _service_display_name: &str,
    _service_dependencies: Vec<&str>,
    _exe_path: PathBuf,
) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        match windows_service::install_or_update_service(
            service_name,
            _service_display_name,
            _service_dependencies,
            _exe_path,
        ) {
            Ok(_service) => {
                return Ok(());
            }
            Err(e) => {
                return Err(io::Error::new(io::ErrorKind::Other, e));
            }
        };
    }
    #[cfg(not(windows))]
    {
        linux_service::install_or_update_service(service_name);
        Ok(())
    }
}

pub fn stop_and_delete_service(service_name: &str) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        match windows_service::stop_and_delete_service(service_name) {
            Ok(_service) => {
                return Ok(());
            }
            Err(e) => {
                return Err(io::Error::new(io::ErrorKind::Other, e));
            }
        };
    }
    #[cfg(not(windows))]
    {
        linux_service::stop_service(service_name);
        linux_service::uninstall_service(service_name);
        Ok(())
    }
}

pub fn start_service(service_name: &str, _retry_count: u32, _duration: std::time::Duration) {
    #[cfg(windows)]
    {
        windows_service::start_service_with_retry(service_name, _retry_count, _duration);
    }
    #[cfg(not(windows))]
    {
        linux_service::start_service(service_name);
    }
}

pub fn stop_service(service_name: &str) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        match windows_service::stop_service(service_name) {
            Ok(_service) => {
                return Ok(());
            }
            Err(e) => {
                return Err(io::Error::new(io::ErrorKind::Other, e));
            }
        };
    }
    #[cfg(not(windows))]
    {
        linux_service::stop_service(service_name);
        Ok(())
    }
}

pub fn update_service(
    _service_name: &str,
    _service_display_name: &str,
    _service_dependencies: Vec<&str>,
    _exe_path: PathBuf,
) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        match windows_service::update_service(
            _service_name,
            _service_display_name,
            _service_dependencies,
            _exe_path,
        ) {
            Ok(_service) => {
                return Ok(());
            }
            Err(e) => {
                return Err(io::Error::new(io::ErrorKind::Other, e));
            }
        }
    }
    #[cfg(not(windows))]
    {
        println!("Not support update service on this platform");
        Ok(())
    }
}

pub fn query_service_executable_path(_service_name: &str) -> PathBuf {
    #[cfg(windows)]
    {
        match windows_service::query_service_config(_service_name) {
            Ok(service_config) => {
                logger_manager::write_info(format!(
                    "Service {} successfully queried",
                    _service_name
                ));
                return service_config.executable_path.to_path_buf();
            }
            Err(e) => {
                logger_manager::write_info(format!("Service {} query failed: {}", _service_name, e));
                eprintln!("Service {} query failed: {}", _service_name, e);
                return PathBuf::new();
            }
        }
    }
    #[cfg(not(windows))]
    {
        println!("Not support query service on this platform");
        return PathBuf::new();
    }
}

pub fn check_service_installed(_service_name: &str) -> (bool, String) {
    let message;
    #[cfg(windows)] {
        match windows_service::query_service_config(_service_name) {
            Ok(_service_config) => {
                message = format!(
                    "check_service_installed: Ebpf Driver: {} successfully queried.", _service_name
                );
                return (true, message);
            }
            Err(e) => {
                message = format!(
                    "check_service_installed: Ebpf Driver: {} unsuccessfully queried with error: {}.", _service_name, e
                );
                return (false, message);
            }
        }
    }
    #[cfg(not(windows))]
    {
        message = format!("Not support query service on this platform");
        return (false, message);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_update_service() {
        #[cfg(not(windows))]
        {
            let service_name = "test_update_service";
            let exe_path = std::env::current_exe().unwrap();
            let result = super::update_service(service_name, service_name, vec![], exe_path);
            assert!(result.is_ok());
        }
    }

    #[test]
    fn test_install_service() {
        #[cfg(not(windows))]
        {
            let service_name = "test_install_service";
            let exe_path = std::env::current_exe().unwrap();
            let result = super::install_service(service_name, service_name, vec![], exe_path);
            assert!(result.is_ok());
        }
    }

    #[test]
    fn test_check_service_installed() {
        #[cfg(windows)]
        {
            let service_name = "test_check_service_installed";
            let exe_path = std::env::current_exe().unwrap();
            let result = super::install_service(service_name, service_name, vec![], exe_path);
            assert!(result.is_ok());
            let (is_installed, message) = super::check_service_installed(service_name);
            assert!(is_installed);
            assert!(message.contains("successfully queried"));
        }
    }
}
