// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use crate::result::Result;
use crate::{logger::logger_manager, misc_helpers, time_buckets::Countable};
use serde_derive::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};
use time::OffsetDateTime;

#[cfg(windows)]
const PROXY_AGENT_AGGREGATE_STATUS_FOLDER: &str = "%SYSTEMDRIVE%\\WindowsAzure\\ProxyAgent\\Logs\\";
#[cfg(not(windows))]
const PROXY_AGENT_AGGREGATE_STATUS_FOLDER: &str = "/var/log/azure-proxy-agent/";
pub const PROXY_AGENT_AGGREGATE_STATUS_FILE_NAME: &str = "status.json";

/// The URL path for the proxy agent aggregated status endpoint.
pub const STATUS_URL_PATH: &str = "/gpa-aggregated-status";

pub fn get_proxy_agent_aggregate_status_folder() -> std::path::PathBuf {
    let path = misc_helpers::resolve_env_variables(PROXY_AGENT_AGGREGATE_STATUS_FOLDER);
    PathBuf::from(path)
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Clone)]
pub enum ModuleState {
    UNKNOWN,
    RUNNING,
    STOPPED,
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Clone)]
pub enum OverallState {
    SUCCESS,
    ERROR,
    UNKNOWN,
}

#[derive(Deserialize, Serialize)]
#[allow(non_snake_case)]
pub struct ProxyAgentDetailStatus {
    pub status: ModuleState, // ModuleState, RUNNING|STOPPED
    pub message: String,     // detail message
    #[serde(skip_serializing_if = "Option::is_none")]
    pub states: Option<HashMap<String, String>>, // module specific states
}

#[derive(Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct ProxyAgentStatus {
    pub version: String,
    pub status: OverallState, // OverallState, SUCCESS|FAILED
    pub monitorStatus: ProxyAgentDetailStatus,
    pub keyLatchStatus: ProxyAgentDetailStatus,
    pub ebpfProgramStatus: ProxyAgentDetailStatus,
    pub proxyListenerStatus: ProxyAgentDetailStatus,
    pub telemetryLoggerStatus: ProxyAgentDetailStatus,
    pub proxyConnectionsCount: u128,
}

#[derive(Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct ProxyConnectionSummary {
    pub userName: String,
    pub ip: String,
    pub port: u16,
    pub processCmdLine: String,
    pub responseStatus: String,
    pub count: u64,
    pub userGroups: Option<Vec<String>>,
    pub processFullPath: Option<String>,
}

impl Clone for ProxyConnectionSummary {
    fn clone(&self) -> Self {
        ProxyConnectionSummary {
            userName: self.userName.clone(),
            userGroups: self.userGroups.clone(),
            ip: self.ip.clone(),
            port: self.port,
            processFullPath: self.processFullPath.clone(),
            processCmdLine: self.processCmdLine.clone(),
            responseStatus: self.responseStatus.clone(),
            count: self.count,
        }
    }
}

impl Countable for ProxyConnectionSummary {
    fn set_count(&mut self, count: u64) {
        self.count = count;
    }
}

#[derive(Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct GuestProxyAgentAggregateStatus {
    pub timestamp: String,
    pub proxyAgentStatus: ProxyAgentStatus,
    pub proxyConnectionSummary: Vec<ProxyConnectionSummary>,
    pub failedAuthenticateSummary: Vec<ProxyConnectionSummary>,
}

impl GuestProxyAgentAggregateStatus {
    pub fn get_status_timestamp(&self) -> crate::result::Result<OffsetDateTime> {
        misc_helpers::parse_date_time_string(&self.timestamp)
    }
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Clone)]
pub enum GuestProxyAgentAggregateStatusSource {
    SERVER,
    FILE,
}

/// Get the proxy agent aggregate status from a specific port or file.
/// It attempts to fetch the status from proxy agent server first and then specified status file.
///
/// This helps remove the local disk write-permission dependency
/// when communicating the aggregate status between Proxy Agent service and the extension.
pub async fn get_proxy_agent_aggregate_status(
    http_ip: &str,
    http_port: u16,
    status_file_path: &Path,
) -> Result<(
    GuestProxyAgentAggregateStatus,
    GuestProxyAgentAggregateStatusSource,
)> {
    let server_error = match get_proxy_agent_aggregate_status_from_server(http_ip, http_port).await
    {
        Ok(status) => return Ok((status, GuestProxyAgentAggregateStatusSource::SERVER)),
        Err(e) => e,
    };

    // If the HTTP request fails, fall back to reading the status from the file.
    match misc_helpers::json_read_from_file::<GuestProxyAgentAggregateStatus>(status_file_path) {
        Ok(status) => Ok((status, GuestProxyAgentAggregateStatusSource::FILE)),
        Err(e) => Err(crate::error::Error::GetProxyAgentAggregateStatus(
            server_error.to_string(),
            e.to_string(),
        )),
    }
}

/// Get the proxy agent aggregate status from the proxy agent server.
pub async fn get_proxy_agent_aggregate_status_from_server(
    proxy_agent_server_ip: &str,
    proxy_agent_server_port: u16,
) -> Result<GuestProxyAgentAggregateStatus> {
    use crate::hyper_client;

    let endpoint = hyper_client::HostEndpoint::new(
        proxy_agent_server_ip,
        proxy_agent_server_port,
        STATUS_URL_PATH,
    );

    let mut headers = HashMap::new();
    headers.insert(
        hyper_client::METADATA_HEADER.to_string(),
        "true".to_string(),
    );
    hyper_client::get(&endpoint, &headers, None, None, logger_manager::write_warn).await
}

#[cfg(test)]
mod tests {

    #[tokio::test]
    async fn test_get_proxy_agent_aggregate_status_from_server_with_mock_server() {
        use crate::server_mock;
        use tokio_util::sync::CancellationToken;

        let ip = "127.0.0.1";
        let port = 9074u16;
        let cancellation_token = CancellationToken::new();

        let port = server_mock::start(ip.to_string(), port, cancellation_token.clone())
            .await
            .unwrap();
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let status = super::get_proxy_agent_aggregate_status_from_server(&ip, port)
            .await
            .unwrap();
        assert!(!status.proxyAgentStatus.version.is_empty());
        assert!(status.proxyConnectionSummary.is_empty());
        assert!(status.failedAuthenticateSummary.is_empty());
        assert!(status.proxyAgentStatus.proxyConnectionsCount == 0);
        assert!(status.proxyAgentStatus.status == super::OverallState::SUCCESS);
        assert!(status.proxyAgentStatus.version == "1.0");

        cancellation_token.cancel();
    }
}
