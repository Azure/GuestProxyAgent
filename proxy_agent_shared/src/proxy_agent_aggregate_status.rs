// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use serde_derive::{Deserialize, Serialize};
use std::collections::HashMap;

pub struct ModuleState;
impl ModuleState {
    pub const RUNNING: &'static str = "RUNNING";
    pub const STOPPED: &'static str = "STOPPED";
}

pub struct OverallState;
impl OverallState {
    pub const SUCCESS: &'static str = "SUCCESS"; // All required modules are running
    pub const ERROR: &'static str = "ERROR"; // One or more required modules are not running
}

#[derive(Deserialize, Serialize)]
#[allow(non_snake_case)]
pub struct ProxyAgentDetailStatus {
    pub status: String,  // ModuleState, RUNNING|STOPPED
    pub message: String, // detail message
    #[serde(skip_serializing_if = "Option::is_none")]
    pub states: Option<HashMap<String, String>>, // module specific states
}

#[derive(Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct ProxyAgentStatus {
    pub version: String,
    pub status: String, // OverallState, SUCCESS|FAILED
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
