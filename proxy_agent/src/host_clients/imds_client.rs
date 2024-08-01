// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use super::instance_info::InstanceInfo;
use crate::common::http::{self};
use crate::common::logger;
use crate::shared_state::{key_keeper_wrapper, SharedState};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

pub struct ImdsClient {
    ip: String,
    port: u16,
    shared_state: Arc<Mutex<SharedState>>,
}

impl ImdsClient {
    pub fn new(ip: String, port: u16, shared_state: Arc<Mutex<SharedState>>) -> Self {
        ImdsClient {
            ip: ip.to_string(),
            port,
            shared_state,
        }
    }

    pub async fn get_imds_instance_info(&self) -> std::io::Result<InstanceInfo> {
        const IMDS_URI: &str = "metadata/instance?api-version=2018-02-01";
        let url = format!("http://{}:{}/{}", self.ip, self.port, IMDS_URI);
        let mut headers = HashMap::new();
        headers.insert("Metadata".to_string(), "true".to_string());

        http::get(
            &url,
            &headers,
            key_keeper_wrapper::get_current_key_guid(self.shared_state.clone()),
            key_keeper_wrapper::get_current_key_value(self.shared_state.clone()),
            logger::write_warning,
        )
        .await
    }
}
