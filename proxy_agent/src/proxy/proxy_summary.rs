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
}

impl From<ProxySummary> for ProxyConnectionSummary {
    fn from(proxy_summary: ProxySummary) -> ProxyConnectionSummary {
        ProxyConnectionSummary {
            userName: proxy_summary.userName.to_string(),
            userGroups: proxy_summary.userGroups.clone(),
            ip: proxy_summary.ip.to_string(),
            port: proxy_summary.port,
            processFullPath: proxy_summary.processFullPath.to_string(),
            processCmdLine: proxy_summary.processCmdLine.to_string(),
            responseStatus: proxy_summary.responseStatus.to_string(),
            count: 1,
        }
    }
}
