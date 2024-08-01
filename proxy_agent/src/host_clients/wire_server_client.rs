// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use crate::common::{http, logger};
use crate::host_clients::goal_state::{GoalState, SharedConfig};
use crate::shared_state::{key_keeper_wrapper, SharedState};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

pub struct WireServerClient {
    ip: String,
    port: u16,
    shared_state: Arc<Mutex<SharedState>>,
}

impl WireServerClient {
    pub fn new(ip: String, port: u16, shared_state: Arc<Mutex<SharedState>>) -> Self {
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

        let url = format!(
            "http://{}:{}/{}",
            self.ip, self.port, "machine/?comp=telemetrydata"
        );
        let mut headers = HashMap::new();
        headers.insert("x-ms-version".to_string(), "2012-11-30".to_string());
        headers.insert(
            "Content-Type".to_string(),
            "text/xml; charset=utf-8".to_string(),
        );

        let request = http::get_request(
            "POST",
            &url,
            &headers,
            Some(xml_data.as_bytes()),
            None, // post telemetry data does not require signing
            None,
        )?;
        let response = match http::send_request(
            &self.ip.to_string(),
            self.port,
            request,
            logger::write_warning,
        )
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
        const GOALSTATE_URI: &str = "machine?comp=goalstate";
        let url = format!("http://{}:{}/{}", self.ip, self.port, GOALSTATE_URI);
        let mut headers = HashMap::new();
        headers.insert("x-ms-version".to_string(), "2012-11-30".to_string());

        http::get(
            &url,
            &headers,
            key_keeper_wrapper::get_current_key_guid(self.shared_state.clone()),
            key_keeper_wrapper::get_current_key_value(self.shared_state.clone()),
            logger::write_warning,
        )
        .await
    }

    pub async fn get_shared_config(&self, url: String) -> std::io::Result<SharedConfig> {
        let mut headers = HashMap::new();
        headers.insert("x-ms-version".to_string(), "2012-11-30".to_string());

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
