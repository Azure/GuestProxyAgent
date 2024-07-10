// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use proxy_agent_shared::proxy_agent_aggregate_status::ProxyConnectionSummary;
use serde_derive::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct ProxySummary {
    pub method: String,
    pub url: String,
    pub clientIp: String,
    pub ip: String,
    pub port: u16,
    pub userId: u64,
    pub userName: String,
    pub userGroups: Vec<String>,
    pub processFullPath: String,
    pub processCmdLine: String,
    pub runAsElevated: bool,
    pub responseStatus: String,
    pub elapsedTime: u128,
}

impl ProxySummary {
    pub fn to_key_string(&self) -> String {
        format!(
            "{} {} {} {} {} {} {}",
            self.userName,
            self.clientIp,
            self.ip,
            self.port,
            self.processFullPath,
            self.processCmdLine,
            self.responseStatus
        )
    }

    pub fn to_proxy_connection_summary(&self) -> ProxyConnectionSummary {
        ProxyConnectionSummary {
            userName: self.userName.to_string(),
            userGroups: self.userGroups.clone(),
            ip: self.ip.to_string(),
            port: self.port,
            processFullPath: self.processFullPath.to_string(),
            processCmdLine: self.processCmdLine.to_string(),
            responseStatus: self.responseStatus.to_string(),
            count: 1,
        }
    }
}
