// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

//! This module contains the proxy summary struct.
//! The proxy summary struct is used to store the summary of the proxied connections.

use std::path::PathBuf;

use proxy_agent_shared::proxy_agent_aggregate_status::ProxyConnectionSummary;
use serde_derive::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
#[allow(non_snake_case)]
pub struct ProxySummary {
    pub id: u128,
    pub method: String,
    pub url: String,
    pub clientIp: String,
    pub clientPort: u16,
    pub ip: String,
    pub port: u16,
    pub userId: u64,
    pub userName: String,
    pub userGroups: Vec<String>,
    pub processFullPath: PathBuf,
    pub processCmdLine: String,
    pub runAsElevated: bool,
    pub responseStatus: String,
    pub elapsedTime: u128,
    pub errorDetails: String,
}

impl ProxySummary {
    pub fn to_key_string(&self) -> String {
        format!(
            "{} {} {} {} {} {} {}",
            self.userName,
            self.clientIp,
            self.ip,
            self.port,
            self.processFullPath.to_string_lossy(),
            self.processCmdLine,
            self.responseStatus
        )
    }
}

impl From<ProxySummary> for ProxyConnectionSummary {
    fn from(proxy_summary: ProxySummary) -> ProxyConnectionSummary {
        ProxyConnectionSummary {
            userName: proxy_summary.userName,
            userGroups: Some(proxy_summary.userGroups),
            ip: proxy_summary.ip,
            port: proxy_summary.port,
            processFullPath: Some(proxy_summary.processFullPath.to_string_lossy().to_string()),
            processCmdLine: proxy_summary.processCmdLine,
            responseStatus: proxy_summary.responseStatus,
            count: 1,
        }
    }
}
