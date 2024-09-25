// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

//! This module contains the logic to interact with the wire server for sending telemetry data and getting goal state.
//! Example
//! ```rust
//! use proxy_agent::common::constants;
//! use proxy_agent::host_clients::wire_server_client;
//! use proxy_agent::shared_state::SharedState;
//! use std::sync::{Arc, Mutex};
//!
//! let shared_state = SharedState::new();
//!
//! let wire_server_client = wire_server_client::WireServerClient::new(constants::WIRE_SERVER_IP.to_string(), 80, shared_state);
//! let goal_state = wire_server_client.get_goalstate().await;
//! let shared_config = wire_server_client.get_shared_config(goal_state.get_shared_config_uri()).await;
//!
//! let telemetry_data = "xml telemetry data".to_string();
//! wire_server_client.send_telemetry_data(telemetry_data).await;
//!
//! ```

use crate::common::{hyper_client, logger};
use crate::host_clients::goal_state::{GoalState, SharedConfig};
use crate::shared_state::{key_keeper_wrapper, SharedState};
use http::Method;
use hyper::Uri;
use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use std::sync::{Arc, Mutex};

pub struct WireServerClient {
    ip: String,
    port: u16,
    shared_state: Arc<Mutex<SharedState>>,
}

const TELEMETRY_DATA_URI: &str = "machine/?comp=telemetrydata";
const GOALSTATE_URI: &str = "machine?comp=goalstate";

impl WireServerClient {
    pub fn new(ip: &str, port: u16, shared_state: Arc<Mutex<SharedState>>) -> Self {
        WireServerClient {
            ip: ip.to_string(),
            port,
            shared_state,
        }
    }

    pub async fn send_telemetry_data(&self, xml_data: String) -> std::io::Result<()> {
        if xml_data.is_empty() {
            return Ok(());
        }

        let url = format!("http://{}:{}/{}", self.ip, self.port, TELEMETRY_DATA_URI);
        let url: Uri = url.parse().map_err(|e| {
            Error::new(
                ErrorKind::InvalidInput,
                format!("Failed to parse URL {} with error: {}", url, e),
            )
        })?;
        let mut headers = HashMap::new();
        headers.insert("x-ms-version".to_string(), "2012-11-30".to_string());
        headers.insert(
            "Content-Type".to_string(),
            "text/xml; charset=utf-8".to_string(),
        );

        let request = hyper_client::build_request(
            Method::POST,
            url.clone(),
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
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("Failed to send telemetry request {}", e),
                    ))
                }
            };

        let status = response.status();
        if !status.is_success() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!(
                    "Failed to get telemetry response from {}, status code: {}",
                    url, status
                ),
            ));
        }

        Ok(())
    }

    pub async fn get_goalstate(&self) -> std::io::Result<GoalState> {
        let url = format!("http://{}:{}/{}", self.ip, self.port, GOALSTATE_URI);
        let url = url.parse().map_err(|e| {
            Error::new(
                ErrorKind::InvalidInput,
                format!("Failed to parse URL {} with error: {}", url, e),
            )
        })?;
        let mut headers = HashMap::new();
        headers.insert("x-ms-version".to_string(), "2012-11-30".to_string());

        hyper_client::get(
            url,
            &headers,
            key_keeper_wrapper::get_current_key_guid(self.shared_state.clone()),
            key_keeper_wrapper::get_current_key_value(self.shared_state.clone()),
            logger::write_warning,
        )
        .await
    }

    pub async fn get_shared_config(&self, url: String) -> std::io::Result<SharedConfig> {
        let mut headers = HashMap::new();
        let url = url.parse().map_err(|e| {
            Error::new(
                ErrorKind::InvalidInput,
                format!("Failed to parse URL {} with error: {}", url, e),
            )
        })?;
        headers.insert("x-ms-version".to_string(), "2012-11-30".to_string());

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
