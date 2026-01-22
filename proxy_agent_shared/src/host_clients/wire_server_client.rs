// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

//! This module contains the logic to interact with the wire server for sending telemetry data and getting goal state.

use crate::host_clients::goal_state::{GoalState, SharedConfig};
use crate::hyper_client;
use crate::{
    error::{Error, WireServerErrorType},
    logger::logger_manager,
    result::Result,
};
use http::Method;
use hyper::Uri;
use std::collections::HashMap;

pub struct WireServerClient {
    ip: String,
    port: u16,
}

const TELEMETRY_DATA_URI: &str = "machine/?comp=telemetrydata";
const GOALSTATE_URI: &str = "machine?comp=goalstate";

impl WireServerClient {
    pub fn new(ip: &str, port: u16) -> Self {
        WireServerClient {
            ip: ip.to_string(),
            port,
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
        let response = match hyper_client::send_request(
            &self.ip,
            self.port,
            request,
            logger_manager::write_warn,
        )
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

    pub async fn get_goalstate(
        &self,
        key_guid: Option<String>,
        key: Option<String>,
    ) -> Result<GoalState> {
        let url = format!("http://{}:{}/{}", self.ip, self.port, GOALSTATE_URI);
        let url = url
            .parse::<hyper::Uri>()
            .map_err(|e| Error::ParseUrl(url, e.to_string()))?;
        let mut headers = HashMap::new();
        headers.insert("x-ms-version".to_string(), "2012-11-30".to_string());

        hyper_client::get(&url, &headers, key_guid, key, logger_manager::write_warn)
            .await
            .map_err(|e| Error::WireServer(WireServerErrorType::GoalState, e.to_string()))
    }

    pub async fn get_shared_config(
        &self,
        url: String,
        key_guid: Option<String>,
        key: Option<String>,
    ) -> Result<SharedConfig> {
        let mut headers = HashMap::new();
        let url = url
            .parse::<hyper::Uri>()
            .map_err(|e| Error::ParseUrl(url, e.to_string()))?;
        headers.insert("x-ms-version".to_string(), "2012-11-30".to_string());

        hyper_client::get(&url, &headers, key_guid, key, logger_manager::write_warn)
            .await
            .map_err(|e| Error::WireServer(WireServerErrorType::SharedConfig, e.to_string()))
    }
}
