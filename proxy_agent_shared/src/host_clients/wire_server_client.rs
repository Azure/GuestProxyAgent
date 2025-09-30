use std::{collections::HashMap, time::Duration};

use http::Uri;
use serde::Deserialize;
use tokio::time::timeout;

use crate::{
    common::{error::Error, formatted_error::FormattedError, hyper_client, result::Result},
    host_clients::data_model::wire_server_model::{GoalState, Versions},
    logger::LoggerLevel,
};

pub struct WireServerClient {
    base_url: String,
    version: String,
    logger: fn(LoggerLevel, String) -> (),
    timeout_in_seconds: Option<u32>,
}

impl WireServerClient {
    const X_MS_VERSION_HEADER: &'static str = "x-ms-version";
    const VERSIONS_URL: &'static str = "?comp=Versions";
    const GOAL_STATE_URL: &'static str = "machine?comp=goalstate";

    const DEFAULT_WIRE_VERSION: &'static str = "2012-11-30";

    pub fn new(
        base_url: &str,
        logger: fn(LoggerLevel, String) -> (),
        timeout_in_seconds: Option<u32>,
    ) -> WireServerClient {
        WireServerClient {
            base_url: base_url.to_string(),
            version: Self::DEFAULT_WIRE_VERSION.to_string(),
            logger,
            timeout_in_seconds,
        }
    }

    // http://168.63.129.16?comp=Versions
    pub async fn get_versions(&self) -> Result<Versions> {
        self.get_sub_url::<Versions>(Self::VERSIONS_URL).await
    }

    // http://168.63.129.16/machine?comp=goalstate
    pub async fn get_goal_state(&self) -> Result<GoalState> {
        self.get_sub_url::<GoalState>(Self::GOAL_STATE_URL).await
    }

    pub async fn refresh_wire_server_version(&mut self) -> Result<()> {
        let versions = self.get_versions().await?;
        self.update_version(versions);
        Ok(())
    }

    pub async fn get_sub_url<T>(&self, sub_url: &str) -> Result<T>
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

        let headers = self.common_headers();

        let res = if let Some(timeout_in_seconds) = self.timeout_in_seconds {
            timeout(
                Duration::from_secs(timeout_in_seconds as u64),
                hyper_client::get(&url, &headers, None, None, move |message| {
                    logger(LoggerLevel::Warn, message)
                }),
            )
            .await
            .map_err(Into::<FormattedError>::into)??
        } else {
            hyper_client::get(&url, &headers, None, None, move |message| {
                logger(LoggerLevel::Warn, message)
            })
            .await?
        };

        Ok(res)
    }

    fn common_headers(&self) -> HashMap<String, String> {
        let mut headers = HashMap::new();
        headers.insert(Self::X_MS_VERSION_HEADER.to_string(), self.version.clone());
        headers
    }

    fn update_version(&mut self, versions: Versions) {
        self.version = versions.preferred.version;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_server_client_creation_test() {
        let client = WireServerClient::new("http://localhost:8080", test_logger, None);
        assert_eq!(client.base_url, "http://localhost:8080");
        assert_eq!(client.version, WireServerClient::DEFAULT_WIRE_VERSION);
    }

    #[test]
    fn wire_server_client_common_headers_test() {
        let client = WireServerClient::new("http://localhost:8080", test_logger, None);
        let headers = client.common_headers();
        assert_eq!(
            headers.get("x-ms-version").unwrap(),
            WireServerClient::DEFAULT_WIRE_VERSION
        );
    }

    #[test]
    fn wire_server_client_update_version_test() {
        let mut client = WireServerClient::new("http://localhost:8080", test_logger, None);
        let versions = Versions {
            preferred: crate::host_clients::data_model::wire_server_model::Preferred {
                version: "2021-01-01".to_string(),
            },
            supported: crate::host_clients::data_model::wire_server_model::Supported {
                versions: vec![],
            },
        };
        client.update_version(versions);
        assert_eq!(client.version, "2021-01-01");
    }

    #[tokio::test]
    async fn wire_server_client_negative_test() {
        let mut client = WireServerClient::new("http://invalid:8080", test_logger, Some(1));
        assert!(client.get_goal_state().await.is_err());
        assert!(client.get_versions().await.is_err());
        assert!(client.refresh_wire_server_version().await.is_err());
    }

    #[tokio::test]
    async fn wire_server_client_get_url_invalid_uri() {
        let client = WireServerClient::new("http://localhost:8080", test_logger, None);

        let res: Result<Versions> = client.get_url("http://invalid uri").await;
        assert!(res.is_err());

        match res {
            Err(Error::ParseUrl(_, _)) => {} // expected
            _ => panic!("Expected Parse Url Error"),
        }
    }

    fn test_logger(level: LoggerLevel, message: String) {
        println!("{:?}: {}", level, message);
    }
}
