// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use url::Url;

use super::request::Request;
use crate::common::constants;
use crate::common::helpers;
use crate::common::logger;
use proxy_agent_shared::misc_helpers;

pub struct HttpRequest {
    uri: Url,
    pub request: Request,
}

impl HttpRequest {
    pub fn new(uri: Url, request: Request) -> Self {
        HttpRequest {
            uri: uri,
            request: request,
        }
    }

    pub fn new_proxy_agent_request(
        uri: Url,
        mut request: Request,
        key_guid: String,
        key: String,
    ) -> std::io::Result<Self> {
        //connection:Close
        request.headers.add_header(
            constants::CONNECTION_HEADER.to_string(),
            "Close".to_string(),
        );
        request
            .headers
            .add_header(constants::METADATA_HEADER.to_string(), "True".to_string());
        request.headers.add_header(
            constants::DATE_HEADER.to_string(),
            misc_helpers::get_date_time_rfc1123_string(),
        );
        request.headers.add_header(
            constants::CLAIMS_HEADER.to_string(),
            format!("{{ \"{}\": \"{}\"}}", constants::CLAIMS_IS_ROOT, true,),
        );
        let mut http_request = HttpRequest::new(uri, request);
        http_request
            .request
            .headers
            .add_header("Host".to_string(), http_request.get_host());

        if key != "" {
            let input_to_sign = http_request.request.as_sig_input();
            let authorization_value = format!(
                "{} {} {}",
                constants::AUTHORIZATION_SCHEME,
                key_guid,
                helpers::compute_signature(key.to_string(), &input_to_sign.as_slice())?
            );
            match String::from_utf8(input_to_sign) {
                Ok(data) => {
                    logger::write_information(format!(
                        "Computed the signature with input: {}",
                        data
                    ))
                }
                Err(e) => {
                    logger::write_information(format!(
                        "Failed convert the input_to_sign to string, error {}",
                        e
                    ));
                }
            }
            http_request.request.headers.add_header(
                constants::AUTHORIZATION_HEADER.to_string(),
                authorization_value.to_string(),
            );
        }

        Ok(http_request)
    }

    pub fn clone_without_body(uri: Url, request: &Request) -> Self {
        HttpRequest {
            uri: uri,
            request: request.clone_without_body(),
        }
    }

    pub fn get_host(&self) -> String {
        match self.uri.host_str() {
            Some(host) => host.to_owned(),
            None => "".to_owned(),
        }
    }

    pub fn get_port(&self) -> u16 {
        match self.uri.port_or_known_default() {
            Some(port) => port,
            None => 0,
        }
    }
}
