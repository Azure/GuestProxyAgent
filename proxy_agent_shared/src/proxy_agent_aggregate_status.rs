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
