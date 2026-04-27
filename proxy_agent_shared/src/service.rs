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

pub fn query_service_executable_path(service_name: &str) -> PathBuf {
    #[cfg(windows)]
    {
        match windows_service::query_service_config(service_name) {
            Ok(service_config) => {
                logger_manager::write_info(format!("Service {service_name} successfully queried",));
                service_config.executable_path.to_path_buf()
            }
            Err(e) => {
                logger_manager::write_info(format!("Service {service_name} query failed: {e}",));
                eprintln!("Service {service_name} query failed: {e}");
                PathBuf::new()
            }
        }
    }
    #[cfg(not(windows))]
    {
        match linux_service::query_service_executable_path(service_name) {
            Ok(path) => path,
            Err(e) => {
                eprintln!("Service {service_name} query failed: {e}");
                PathBuf::new()
            }
        }
    }
}

pub fn check_service_installed(service_name: &str) -> (bool, String) {
    #[cfg(windows)]
    {
        match windows_service::query_service_config(service_name) {
            Ok(_) => {
                let message = format!(
                    "check_service_installed: service: {service_name} successfully queried.",
                );
                (true, message)
            }
            Err(e) => {
                let message = format!(
                    "check_service_installed: service: {service_name} unsuccessfully queried with error: {e}"
                );
                (false, message)
            }
        }
    }
    #[cfg(not(windows))]
    {
        linux_service::check_service_installed(service_name)
    }
}

/// Checks whether a Windows service is installed and queries its runtime state and start type.
/// Returns a `ServiceStatusInfo` whose `state` is `Some(ServiceState)` when the service exists,
/// or `None` when the service is not installed.
#[cfg(windows)]
pub fn check_service_status(service_name: &str) -> windows_service::ServiceStatusInfo {
    let (state, start_type) = match windows_service::query_service_status(service_name) {
        Ok(status) => {
            let start_type = match windows_service::query_service_config(service_name) {
                Ok(config) => format!("{:?}", config.start_type),
                Err(e) => {
                    log::warn!(
                        "Failed to query config for service '{}': {}",
                        service_name,
                        e
                    );
                    "Unknown".to_string()
                }
            };
            (Some(status.current_state), start_type)
        }
        Err(e) => {
            log::debug!(
                "Failed to query status for service '{}': {}. Treating as not installed.",
                service_name,
                e
            );
            (None, "NotInstalled".to_string())
        }
    };

    windows_service::ServiceStatusInfo {
        service_name: service_name.to_string(),
        state,
        start_type,
    }
}

#[cfg(windows)]
pub use windows_service::set_default_failure_actions;
#[cfg(windows)]
pub use windows_service::ServiceState;
#[cfg(windows)]
pub use windows_service::ServiceStatusInfo;

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

    #[tokio::test]
    async fn test_check_service_status() {
        #[cfg(windows)]
        {
            let service_name = "test_check_service_status";
            // try delete the service if it exists
            _ = super::stop_and_delete_service(service_name).await;

            // Verify non-existent service returns not installed
            let status = super::check_service_status(service_name);
            assert_eq!(status.state, None, "Expected None for non-existent service");
            assert!(status.message().contains("query failed"));
            assert_eq!(status.summary(), "NotInstalled");

            // Install a test service and verify status is reported
            let exe_path = std::env::current_exe().unwrap();
            let result = super::install_service(service_name, service_name, vec![], exe_path);
            assert!(result.is_ok());

            let status = super::check_service_status(service_name);
            assert!(status.state.is_some(), "Expected service to be installed");
            assert!(status.message().contains("status:"));
            // Service should be stopped (test exe can't actually run as a service)
            assert_eq!(
                status.state,
                Some(super::ServiceState::Stopped),
                "Expected Some(ServiceState::Stopped), got: {:?}",
                status.state
            );
            // Summary should also contain start type info
            let summary = status.summary();
            assert!(
                summary.contains("AutoStart"),
                "Expected summary to contain 'AutoStart', got: {summary}"
            );

            // clean up
            _ = super::stop_and_delete_service(service_name).await.unwrap();
        }
    }
}
