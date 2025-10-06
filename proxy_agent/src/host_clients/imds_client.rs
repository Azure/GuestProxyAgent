// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

//! This module contains the logic to interact with the IMDS service.
//! The IMDS service is used to get the instance information of the VM.
//! The GPA service uses the IMDS service to get the instance information of the VM.
//!
//! Example
//! ```rust
//! use proxy_agent::common::constants;
//! use proxy_agent::host_clients::imds_client;
//! use proxy_agent::shared_state::key_keeper_wrapper::KeyKeeperSharedState;
//! let key_keeper_shared_state = KeyKeeperSharedState::new();
//! let imds_client = imds_client::ImdsClient::new(
//!    constants::IMDS_IP,
//!    constants::IMDS_PORT,
//!   key_keeper_shared_state,
//! );
//! let instance_info = imds_client.get_imds_instance_info().await.unwrap();
//!
//! ```

use super::instance_info::InstanceInfo;
use crate::common::{error::Error, logger, result::Result};
use crate::shared_state::key_keeper_wrapper::KeyKeeperSharedState;
use hyper::Uri;
use proxy_agent_shared::hyper_client;
use std::collections::HashMap;

pub struct ImdsClient {
    ip: String,
    port: u16,
    key_keeper_shared_state: KeyKeeperSharedState,
}

const IMDS_URI: &str = "metadata/instance?api-version=2018-02-01";

impl ImdsClient {
    pub fn new(ip: &str, port: u16, key_keeper_shared_state: KeyKeeperSharedState) -> Self {
        ImdsClient {
            ip: ip.to_string(),
            port,
            key_keeper_shared_state,
        }
    }

    pub async fn get_imds_instance_info(&self) -> Result<InstanceInfo> {
        let url: String = format!("http://{}:{}/{}", self.ip, self.port, IMDS_URI);

        let url: Uri = url
            .parse::<hyper::Uri>()
            .map_err(|e| Error::ParseUrl(url, e.to_string()))?;
        let mut headers = HashMap::new();
        headers.insert("Metadata".to_string(), "true".to_string());

        hyper_client::get(
            &url,
            &headers,
            self.key_keeper_shared_state
                .get_current_key_guid()
                .await
                .unwrap_or(None),
            self.key_keeper_shared_state
                .get_current_key_value()
                .await
                .unwrap_or(None),
            logger::write_warning,
        )
        .await
        .map_err(Error::ProxyAgentSharedError)
    }
}
