// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use super::instance_info::InstanceInfo;
use crate::common::http::{self, http_request::HttpRequest, request::Request, response::Response};
use crate::shared_state::{key_keeper_wrapper, SharedState};
use std::io::{Error, ErrorKind};
use std::sync::{Arc, Mutex};
use url::Url;

pub struct ImdsClient {
    ip: String,
    port: u16,
    shared_state: Arc<Mutex<SharedState>>,
}

impl ImdsClient {
    pub fn new(ip: &str, port: u16, shared_state: Arc<Mutex<SharedState>>) -> Self {
        ImdsClient {
            ip: ip.to_string(),
            port,
            shared_state,
        }
    }

    pub fn get_imds_instance_info(&self) -> std::io::Result<InstanceInfo> {
        const IMDS_URI: &str = "/metadata/instance?api-version=2018-02-01";

        let req = Request::new(IMDS_URI.to_string(), "GET".to_string());
        let url = Url::parse(&format!("http://{}:{}", self.ip, self.port)).unwrap();
        let url = url.join(IMDS_URI).unwrap();
        let mut http_request = HttpRequest::new_proxy_agent_request(
            url,
            req,
            key_keeper_wrapper::get_current_key_guid(self.shared_state.clone()),
            key_keeper_wrapper::get_current_key_value(self.shared_state.clone()),
        )?;

        let response = http::get_response_in_string(&mut http_request)?;
        if response.status != Response::OK {
            return Err(Error::new(
                ErrorKind::Other,
                format!(
                    "Failed to retrieve instance info {} - {}",
                    response.status,
                    response.get_body_as_string()?
                ),
            ));
        }

        let instance_info_str = response.get_body_as_string()?;
        match serde_json::from_str::<InstanceInfo>(&instance_info_str) {
            Ok(instnce) => Ok(instnce),
            Err(e) => Err(Error::new(
                ErrorKind::Other,
                format!(
                    "Recevied instance info is invalid: {}, Error: {}",
                    instance_info_str, e
                ),
            )),
        }
    }
}
