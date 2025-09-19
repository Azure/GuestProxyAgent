use std::collections::HashMap;

use http::Uri;
use serde::Deserialize;

use crate::{
    client::data_model::wire_server_model::{GoalState, Versions},
    common::{error::Error, hyper_client, result::Result},
    logger::LoggerLevel,
};

pub struct WireServerClient {
    base_url: String,
    version: String,
    logger: fn(LoggerLevel, String) -> (),
}

impl WireServerClient {
    const X_MS_VERSION_HEADER: &'static str = "x-ms-version";
    const VERSIONS_URL: &'static str = "?comp=Versions";
    const GOAL_STATE_URL: &'static str = "machine?comp=goalstate";

    pub fn new(base_url: &str, logger: fn(LoggerLevel, String) -> ()) -> WireServerClient {
        WireServerClient {
            base_url: base_url.to_string(),
            version: "2015-04-05".to_string(),
            logger,
        }
    }

    // http://168.63.129.16?comp=Versions
    pub async fn get_versions(&self) -> Result<Versions> {
        self.get::<Versions>(Self::VERSIONS_URL).await
    }

    // http://168.63.129.16/machine?comp=goalstate
    pub async fn get_goal_state(&self) -> Result<GoalState> {
        self.get::<GoalState>(Self::GOAL_STATE_URL).await
    }

    pub async fn get<T>(&self, sub_url: &str) -> Result<T>
    where
        T: for<'a> Deserialize<'a>,
    {
        self.get_url(&format!("{}/{}", &self.base_url, sub_url))
            .await
    }

    pub async fn get_url<T>(&self, url: &str) -> Result<T>
    where
        T: for<'a> Deserialize<'a>,
    {
        let logger = self.logger;
        let url: Uri = url
            .parse::<hyper::Uri>()
            .map_err(|e| Error::ParseUrl(url.to_string(), e.to_string()))?;

        let mut headers = HashMap::new();
        headers.insert(Self::X_MS_VERSION_HEADER.to_string(), self.version.clone());

        let res = hyper_client::get(&url, &headers, None, None, move |message| {
            logger(LoggerLevel::Warn, message)
        })
        .await
        .unwrap();
        Ok(res)
    }
}
