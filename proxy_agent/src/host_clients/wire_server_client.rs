// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

//! This module contains the logic to interact with the wire server for sending telemetry data and getting goal state.
//! Example
//! ```rust
//! use proxy_agent::common::constants;
//! use proxy_agent::host_clients::wire_server_client;
//! use proxy_agent::shared_state::key_keeper_wrapper::KeyKeeperSharedState;
//!
//! let key_keeper_shared_state = KeyKeeperSharedState::new();
//!
//! let wire_server_client = wire_server_client::WireServerClient::new(constants::WIRE_SERVER_IP.to_string(), 80, key_keeper_shared_state);
//! let goal_state = wire_server_client.get_goalstate().await;
//! let shared_config = wire_server_client.get_shared_config(goal_state.get_shared_config_uri()).await;
//!
//! let telemetry_data = "[xml telemetry data]".to_string();
//! wire_server_client.send_telemetry_data(telemetry_data).await;
//!
//! ```

use crate::host_clients::goal_state::{GoalState, SharedConfig};
use crate::shared_state::key_keeper_wrapper::KeyKeeperSharedState;
use http::Method;
use hyper::Uri;
use proxy_agent_shared::common::{
    error::{Error, WireServerErrorType},
    hyper_client, logger,
    result::Result,
};
use std::collections::HashMap;

pub struct WireServerClient {
    ip: String,
    port: u16,
    key_keeper_shared_state: KeyKeeperSharedState,
}

const TELEMETRY_DATA_URI: &str = "machine/?comp=telemetrydata";
const GOALSTATE_URI: &str = "machine?comp=goalstate";

impl WireServerClient {
    pub fn new(ip: &str, port: u16, key_keeper_shared_state: KeyKeeperSharedState) -> Self {
        WireServerClient {
            ip: ip.to_string(),
            port,
            key_keeper_shared_state,
        }
    }

    pub async fn send_telemetry_data(&self, xml_data: String) -> Result<()> {
        if xml_data.is_empty() {
            return Ok(());
        }

        let url = format!("http://{}:{}/{}", self.ip, self.port, TELEMETRY_DATA_URI);
        let url: Uri = url
            .parse::<hyper::Uri>()
            .map_err(|e| Error::ParseUrl(url, e.to_string()))?;
        let mut headers = HashMap::new();
        headers.insert("x-ms-version".to_string(), "2012-11-30".to_string());
        headers.insert(
            "Content-Type".to_string(),
            "text/xml; charset=utf-8".to_string(),
        );

        let request = hyper_client::build_request(
            Method::POST,
            &url,
            &headers,
            Some(xml_data.as_bytes()),
            None, // post telemetry data does not require signing
            None,
        )?;
        let response =
            match hyper_client::send_request(&self.ip, self.port, request, logger::write_warning)
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    return Err(Error::WireServer(
                        WireServerErrorType::Telemetry,
                        format!("Failed to send request {e}"),
                    ))
                }
            };

        let status = response.status();
        if !status.is_success() {
            return Err(Error::WireServer(
                WireServerErrorType::Telemetry,
                format!("Failed to get response from {url}, status code: {status}"),
            ));
        }

        Ok(())
    }

    pub async fn get_goalstate(&self) -> Result<GoalState> {
        let url = format!("http://{}:{}/{}", self.ip, self.port, GOALSTATE_URI);
        let url = url
            .parse::<hyper::Uri>()
            .map_err(|e| Error::ParseUrl(url, e.to_string()))?;
        let mut headers = HashMap::new();
        headers.insert("x-ms-version".to_string(), "2012-11-30".to_string());

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
        .map_err(|e| Error::WireServer(WireServerErrorType::GoalState, e.to_string()))
    }

    pub async fn get_shared_config(&self, url: String) -> Result<SharedConfig> {
        let mut headers = HashMap::new();
        let url = url
            .parse::<hyper::Uri>()
            .map_err(|e| Error::ParseUrl(url, e.to_string()))?;
        headers.insert("x-ms-version".to_string(), "2012-11-30".to_string());

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
        .map_err(|e| Error::WireServer(WireServerErrorType::SharedConfig, e.to_string()))
    }
}
