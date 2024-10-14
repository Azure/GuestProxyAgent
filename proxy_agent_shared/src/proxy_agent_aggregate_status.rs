// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use serde_derive::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Deserialize, Serialize, Debug, PartialEq, Clone)]
pub enum ModuleState {
    Unknown,
    Running,
    Stopped,
}

impl ModuleState {
    const RUNNING: &'static str = "RUNNING";
    const STOPPED: &'static str = "STOPPED";
    const UNKNOWN: &'static str = "UNKNOWN";
}

impl From<&str> for ModuleState {
    fn from(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            ModuleState::RUNNING => ModuleState::Running,
            ModuleState::STOPPED => ModuleState::Stopped,
            _ => ModuleState::Unknown,
        }
    }
}

impl From<ModuleState> for String {
    fn from(s: ModuleState) -> Self {
        match s {
            ModuleState::Running => ModuleState::RUNNING.to_string(),
            ModuleState::Stopped => ModuleState::STOPPED.to_string(),
            ModuleState::Unknown => ModuleState::UNKNOWN.to_string(),
        }
    }
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Clone)]
pub enum OverallState {
    Success,
    Error,
    Unknown,
}

impl OverallState {
    const SUCCESS: &'static str = "SUCCESS"; // All required modules are running
    const ERROR: &'static str = "ERROR"; // One or more required modules are not running
    const UNKNOWN: &'static str = "UNKNOWN";
}

impl From<&str> for OverallState {
    fn from(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            OverallState::SUCCESS => OverallState::Success,
            OverallState::ERROR => OverallState::Error,
            _ => OverallState::Unknown,
        }
    }
}

impl From<OverallState> for String {
    fn from(s: OverallState) -> Self {
        match s {
            OverallState::Success => OverallState::SUCCESS.to_string(),
            OverallState::Error => OverallState::ERROR.to_string(),
            OverallState::Unknown => OverallState::UNKNOWN.to_string(),
        }
    }
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
