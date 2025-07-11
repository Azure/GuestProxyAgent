// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#[cfg(not(windows))]
mod linux_service;
#[cfg(windows)]
mod windows_service;

use std::path::PathBuf;

#[cfg(windows)]
use crate::logger::logger_manager;
use crate::result::Result;

pub fn install_service(
    service_name: &str,
    _service_display_name: &str,
    _service_dependencies: Vec<&str>,
    _exe_path: PathBuf,
) -> Result<()> {
    #[cfg(windows)]
    {
        windows_service::install_or_update_service(
            service_name,
            _service_display_name,
            _service_dependencies,
            _exe_path,
        )
    }
    #[cfg(not(windows))]
    {
        linux_service::install_or_update_service(service_name)
    }
}

pub async fn stop_and_delete_service(service_name: &str) -> Result<()> {
    #[cfg(windows)]
    {
        windows_service::stop_and_delete_service(service_name).await
    }
    #[cfg(not(windows))]
    {
        linux_service::stop_service(service_name)?;
        linux_service::uninstall_service(service_name)
    }
}

pub async fn start_service(
    service_name: &str,
    _retry_count: u32,
    _duration: std::time::Duration,
) -> Result<()> {
    #[cfg(windows)]
    {
        windows_service::start_service_with_retry(service_name, _retry_count, _duration).await
    }
    #[cfg(not(windows))]
    {
        linux_service::start_service(service_name)
    }
}

pub async fn stop_service(service_name: &str) -> Result<()> {
    #[cfg(windows)]
    {
        windows_service::stop_service(service_name)
            .await
            .map(|_| ())
    }
    #[cfg(not(windows))]
    {
        linux_service::stop_service(service_name)
    }
}

pub fn update_service(
    _service_name: &str,
    _service_display_name: &str,
    _service_dependencies: Vec<&str>,
    _exe_path: PathBuf,
) -> Result<()> {
    #[cfg(windows)]
    {
        windows_service::update_service(
            _service_name,
            _service_display_name,
            _service_dependencies,
            _exe_path,
        )
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
                logger_manager::write_info(
                    format!("Service {_service_name} successfully queried",),
                );
                service_config.executable_path.to_path_buf()
            }
            Err(e) => {
                logger_manager::write_info(format!("Service {_service_name} query failed: {e}",));
                eprintln!("Service {_service_name} query failed: {e}");
                PathBuf::new()
            }
        }
    }
    #[cfg(not(windows))]
    {
        println!("Not support query service on this platform");
        PathBuf::new()
    }
}

pub fn check_service_installed(_service_name: &str) -> (bool, String) {
    let message;
    #[cfg(windows)]
    {
        match windows_service::query_service_config(_service_name) {
            Ok(_service_config) => {
                message = format!(
                    "check_service_installed: Ebpf Driver: {_service_name} successfully queried.",
                );
                (true, message)
            }
            Err(e) => {
                message = format!(
                    "check_service_installed: Ebpf Driver: {_service_name} unsuccessfully queried with error: {e}"
                );
                (false, message)
            }
        }
    }
    #[cfg(not(windows))]
    {
        message = "Not support query service on this platform".to_string();
        (false, message)
    }
}

#[cfg(windows)]
pub use windows_service::set_default_failure_actions;

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

    #[tokio::test]
    async fn test_install_service() {
        #[cfg(not(windows))]
        {
            let service_name = "test_install_service";
            let exe_path = std::env::current_exe().unwrap();
            let result = super::install_service(service_name, service_name, vec![], exe_path);
            assert!(result.is_ok());
        }
    }

    #[tokio::test]
    async fn test_check_service_installed() {
        #[cfg(windows)]
        {
            let service_name = "test_check_service_installed";
            // try delete the service if it exists
            _ = super::stop_and_delete_service(service_name).await;

            let exe_path = std::env::current_exe().unwrap();
            let result = super::install_service(service_name, service_name, vec![], exe_path);
            assert!(result.is_ok());
            let (is_installed, message) = super::check_service_installed(service_name);
            assert!(is_installed);
            assert!(message.contains("successfully queried"));

            // clean up
            _ = super::stop_and_delete_service(service_name).await.unwrap();
        }
    }
}
