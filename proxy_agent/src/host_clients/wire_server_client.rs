// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use crate::common::http::{
    self, headers, http_request::HttpRequest, request::Request, response::Response,
};
use crate::host_clients::goal_state::{GoalState, SharedConfig};
use crate::key_keeper;
use std::io::{Error, ErrorKind};
use std::{io::prelude::*, net::TcpStream};
use url::{Position, Url};

pub struct WireServerClient {
    ip: String,
    port: u16,
}

impl WireServerClient {
    pub fn new(ip: &str, port: u16) -> Self {
        WireServerClient {
            ip: ip.to_string(),
            port: port,
        }
    }

    fn endpoint(&self) -> String {
        format!("{}:{}", self.ip, self.port)
    }

    fn create_http_request(&self, method: &str, uri: String) -> std::io::Result<HttpRequest> {
        let mut url;
        match Url::parse(&uri) {
            Ok(u) => url = u,
            Err(_) => {
                url = Url::parse(&format!("http://{}:{}", self.ip.to_string(), self.port)).unwrap();
                match url.join(&uri) {
                    Ok(u) => url = u,
                    Err(e) => {
                        return Err(Error::new(
                            ErrorKind::InvalidData,
                            format!(
                                "Failed to construct url - {} with error: {}",
                                uri.to_string(),
                                e
                            ),
                        ));
                    }
                }
            }
        }

        let path_para = &url[Position::BeforePath..];
        let mut req = Request::new(path_para.to_string(), method.to_string());
        req.headers
            .add_header("x-ms-version".to_string(), "2012-11-30".to_string());
        let http_request = HttpRequest::new_proxy_agent_request(
            url,
            req,
            key_keeper::get_current_key_guid(),
            key_keeper::get_current_key(),
        )?;

        Ok(http_request)
    }

    pub fn send_telemetry_data(&self, xml_data: String) -> std::io::Result<()> {
        if xml_data.len() == 0 {
            return Ok(());
        }

        let data = xml_data.as_bytes();
        let mut http_request =
            self.create_http_request("POST", "/machine/?comp=telemetrydata".to_string())?;
        http_request.request.headers.add_header(
            "Content-Type".to_string(),
            "text/xml; charset=utf-8".to_string(),
        );
        http_request.request.headers.add_header(
            headers::CONTENT_LENGTH_HEADER_NAME.to_string(),
            data.len().to_string(),
        );
        http_request.request.headers.add_header(
            headers::EXPECT_HEADER_NAME.to_string(),
            headers::EXPECT_HEADER_VALUE.to_string(),
        );

        let mut client = TcpStream::connect(self.endpoint())?;
        // send http request without body
        _ = client.write_all(http_request.request.to_raw_string().as_bytes());
        _ = client.flush();
        let raw_response_data = http::receive_data_in_string(&client)?;
        let response = Response::from_raw_data(raw_response_data);
        if response.is_continue_response() {
            _ = client.write_all(&data);
            _ = client.flush();
            let raw_response_data = http::receive_data_in_string(&client)?;
            let response = Response::from_raw_data(raw_response_data);
            if response.status != Response::OK {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("Host resposned {}.", &response.status),
                ));
            }
        } else {
            return Err(Error::new(
                ErrorKind::ConnectionRefused,
                "Host does not resposne continue to receive the reqeust body.",
            ));
        }

        Ok(())
    }

    pub fn get_goalstate(&self) -> std::io::Result<GoalState> {
        const GOALSTATE_URI: &str = "/machine?comp=goalstate";
        let mut http_request = self.create_http_request("GET", GOALSTATE_URI.to_string())?;

        let response = http::get_response_in_string(&mut http_request)?;
        if response.status != Response::OK {
            return Err(Error::new(
                ErrorKind::Other,
                format!(
                    "Failed to retrieve GoalState {} - {}",
                    response.status,
                    response.get_body_as_string()?
                ),
            ));
        }

        let goal_state_str = response.get_body_as_string()?;
        match serde_xml_rs::from_str::<GoalState>(&goal_state_str) {
            Ok(goalstate) => Ok(goalstate),
            Err(err) => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!(
                    "Recevied goalstate is invalid: {}, Error: {}",
                    goal_state_str, err
                ),
            )),
        }
    }

    pub fn get_shared_config(&self, url: String) -> std::io::Result<SharedConfig> {
        let mut http_request = self.create_http_request("GET", url.to_string())?;

        let response = http::get_response_in_string(&mut http_request)?;
        if response.status != Response::OK {
            return Err(Error::new(
                ErrorKind::Other,
                format!(
                    "Failed to retrieve SharedConfig from url: {}. Response: {} - {}",
                    url.to_string(),
                    response.status,
                    response.get_body_as_string()?
                ),
            ));
        }

        let shared_config_str = response.get_body_as_string()?;
        match serde_xml_rs::from_str::<SharedConfig>(&shared_config_str) {
            Ok(shared_config) => Ok(shared_config),
            Err(err) => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!(
                    "Recevied shared_config is invalid: {}, Error: {}",
                    shared_config_str, err
                ),
            )),
        }
    }
}
