// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
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
            self.userName.to_string(),
            self.clientIp.to_string(),
            self.ip.to_string(),
            self.port,
            self.processFullPath.to_string(),
            self.processCmdLine.to_string(),
            self.responseStatus.to_string()
        )
    }
}
