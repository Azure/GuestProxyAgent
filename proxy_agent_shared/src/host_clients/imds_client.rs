// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

//! This module contains the logic to interact with the IMDS service.
//! The IMDS service is used to get the instance information of the VM.
//! The GPA service uses the IMDS service to get the instance information of the VM.

use super::instance_info::InstanceInfo;
use crate::hyper_client;
use crate::logger::logger_manager;
use crate::{error::Error, result::Result};
use hyper::Uri;
use std::collections::HashMap;

pub struct ImdsClient {
    ip: String,
    port: u16,
}

const IMDS_URI: &str = "metadata/instance?api-version=2018-02-01";

impl ImdsClient {
    pub fn new(ip: &str, port: u16) -> Self {
        ImdsClient {
            ip: ip.to_string(),
            port,
        }
    }

    pub async fn get_imds_instance_info(
        &self,
        key_guid: Option<String>,
        key: Option<String>,
    ) -> Result<InstanceInfo> {
        let url: String = format!("http://{}:{}/{}", self.ip, self.port, IMDS_URI);

        let url: Uri = url
            .parse::<hyper::Uri>()
            .map_err(|e| Error::ParseUrl(url, e.to_string()))?;
        let mut headers = HashMap::new();
        headers.insert("Metadata".to_string(), "true".to_string());

        hyper_client::get(&url, &headers, key_guid, key, logger_manager::write_warn).await
    }
}
