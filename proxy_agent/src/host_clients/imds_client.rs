// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

//! This module contains the logic to interact with the IMDS service.
//! The IMDS service is used to get the instance information of the VM.
//! The GPA service uses the IMDS service to get the instance information of the VM.
//!
//! Example
//! ```rust
//! use proxy_agent::commom::constants;
//! use proxy_agent::host_clients::imds_client;
//! use proxy_agent::shared_state::SharedState;
//! use std::sync::{Arc, Mutex};
//!
//! let shared_state = SharedState::new();
//!
//! let imds_client = imds_client::ImdsClient::new(constants::IMDS_IP.to_string(), 80, shared_state);
//! let instance_info = imds_client.get_imds_instance_info().await;
//!
//! ```

use crate::common::error::Error;
use crate::common::result::Result;

use super::instance_info::InstanceInfo;
use crate::common::{hyper_client, logger};
use crate::shared_state::{key_keeper_wrapper, SharedState};
use hyper::Uri;
use std::collections::HashMap;
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

    pub async fn get_imds_instance_info(&self) -> Result<InstanceInfo> {
        let url: String = (format!("http://{}:{}/{}", self.ip, self.port, IMDS_URI));

        let url : Uri = url
            .parse()
            .map_err(|e| {
                Error::parse_url(
                    url, e
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
