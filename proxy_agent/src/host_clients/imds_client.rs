// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use super::instance_info::InstanceInfo;
use crate::common::{hyper_client, logger};
use crate::shared_state::{key_keeper_wrapper, SharedState};
use hyper::Uri;
use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use std::sync::{Arc, Mutex};

pub struct ImdsClient {
    ip: String,
    port: u16,
    shared_state: Arc<Mutex<SharedState>>,
}

const IMDS_URI: &str = "metadata/instance?api-version=2018-02-01";

impl ImdsClient {
    pub fn new(ip: &str, port: u16, shared_state: Arc<Mutex<SharedState>>) -> Self {
        ImdsClient {
            ip: ip.to_string(),
            port,
            shared_state,
        }
    }

    pub async fn get_imds_instance_info(&self) -> std::io::Result<InstanceInfo> {
        let url: Uri = (format!("http://{}:{}/{}", self.ip, self.port, IMDS_URI))
            .parse()
            .map_err(|e| {
                Error::new(
                    ErrorKind::InvalidInput,
                    format!("Failed to parse URL: {}", e),
                )
            })?;
        let mut headers = HashMap::new();
        headers.insert("Metadata".to_string(), "true".to_string());

        hyper_client::get(
            url,
            &headers,
            key_keeper_wrapper::get_current_key_guid(self.shared_state.clone()),
            key_keeper_wrapper::get_current_key_value(self.shared_state.clone()),
            logger::write_warning,
        )
        .await
    }
}
