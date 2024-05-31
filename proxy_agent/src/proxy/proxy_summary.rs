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
