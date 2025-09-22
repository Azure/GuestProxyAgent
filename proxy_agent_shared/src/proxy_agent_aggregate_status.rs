// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use crate::misc_helpers;
use serde_derive::{Deserialize, Serialize};
use std::{collections::HashMap, path::PathBuf};

#[cfg(windows)]
const PROXY_AGENT_AGGREGATE_STATUS_FOLDER: &str = "%SYSTEMDRIVE%\\WindowsAzure\\ProxyAgent\\Logs\\";
#[cfg(not(windows))]
const PROXY_AGENT_AGGREGATE_STATUS_FOLDER: &str = "/var/log/azure-proxy-agent/";
pub const PROXY_AGENT_AGGREGATE_STATUS_FILE_NAME: &str = "status.json";

pub fn get_proxy_agent_aggregate_status_folder() -> std::path::PathBuf {
    let path = misc_helpers::resolve_env_variables(PROXY_AGENT_AGGREGATE_STATUS_FOLDER)
        .unwrap_or(PROXY_AGENT_AGGREGATE_STATUS_FOLDER.to_string());
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

#[derive(Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct GuestProxyAgentAggregateStatus {
    pub timestamp: String,
    pub proxyAgentStatus: ProxyAgentStatus,
    pub proxyConnectionSummary: Vec<ProxyConnectionSummary>,
    pub failedAuthenticateSummary: Vec<ProxyConnectionSummary>,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn get_proxy_agent_aggregate_status_folder_test() {
        let path = misc_helpers::resolve_env_variables(PROXY_AGENT_AGGREGATE_STATUS_FOLDER);
        assert!(path.is_ok());
        let path_buf = get_proxy_agent_aggregate_status_folder();
        assert_eq!(path_buf.to_string_lossy().into_owned(), path.unwrap());
    }

    #[test]
    fn guest_proxy_agent_aggregate_status_deserialize_test() {
        let json_str = r#"
        {
            "timestamp": "2025-10-10T12:00:00Z",
            "proxyAgentStatus": {
                "version": "1.0.0",
                "status": "SUCCESS",
                "monitorStatus": {
                    "status": "RUNNING",
                    "message": "Monitor is running",
                    "states": {
                        "monitorState": "TestState"
                    }
                },
                "keyLatchStatus": {
                    "status": "STOPPED",
                    "message": "Key latch is stopped"
                },
                "ebpfProgramStatus": {
                    "status": "UNKNOWN",
                    "message": "eBPF program status unknown"
                },
                "proxyListenerStatus": {
                    "status": "RUNNING",
                    "message": "Proxy listener is active"
                },
                "telemetryLoggerStatus": {
                    "status": "RUNNING",
                    "message": "Telemetry logger is operational"
                },
                "proxyConnectionsCount": 42
            },
            "proxyConnectionSummary": [
                {
                    "userName": "user1",
                    "ip": "192.168.1.1",
                    "port": 8080,
                    "processCmdLine": "cmd.exe /c whoami",
                    "responseStatus": "Success",
                    "count": 1,
                    "userGroups": ["Administrators"],
                    "processFullPath": "C:\\Windows\\System32\\cmd.exe"
                }
            ],
            "failedAuthenticateSummary": []
        }"#;
        let status: Result<GuestProxyAgentAggregateStatus, serde_json::Error> =
            serde_json::from_str(json_str);
        assert!(status.is_ok());
        let status = status.unwrap();
        assert_eq!(status.timestamp, "2025-10-10T12:00:00Z");
        assert_eq!(status.proxyAgentStatus.version, "1.0.0");
        assert_eq!(status.proxyAgentStatus.status, OverallState::SUCCESS);
        assert_eq!(
            status.proxyAgentStatus.monitorStatus.status,
            ModuleState::RUNNING
        );
        assert_eq!(
            status.proxyAgentStatus.monitorStatus.message,
            "Monitor is running"
        );
        assert_eq!(
            status
                .proxyAgentStatus
                .monitorStatus
                .states
                .unwrap()
                .get("monitorState")
                .unwrap(),
            "TestState"
        );
        assert_eq!(
            status.proxyAgentStatus.keyLatchStatus.status,
            ModuleState::STOPPED
        );
        assert_eq!(
            status.proxyAgentStatus.keyLatchStatus.message,
            "Key latch is stopped"
        );
        assert_eq!(
            status.proxyAgentStatus.ebpfProgramStatus.status,
            ModuleState::UNKNOWN
        );
        assert_eq!(
            status.proxyAgentStatus.ebpfProgramStatus.message,
            "eBPF program status unknown"
        );
        assert_eq!(
            status.proxyAgentStatus.proxyListenerStatus.status,
            ModuleState::RUNNING
        );
        assert_eq!(
            status.proxyAgentStatus.proxyListenerStatus.message,
            "Proxy listener is active"
        );
        assert_eq!(
            status.proxyAgentStatus.telemetryLoggerStatus.status,
            ModuleState::RUNNING
        );
        assert_eq!(
            status.proxyAgentStatus.telemetryLoggerStatus.message,
            "Telemetry logger is operational"
        );
    }
}
