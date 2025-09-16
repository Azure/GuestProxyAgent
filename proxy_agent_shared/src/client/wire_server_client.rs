use quick_xml::de::from_str;
use reqwest::Client;
use serde::Deserialize;

use crate::client::data_model::{
    error::ErrorDetails,
    wire_server_model::{GoalState, Versions},
};

pub struct WireServerClient {
    base_url: String,
    version: String,
    client: Client,
}

impl WireServerClient {
    const X_MS_VERSION_HEADER: &'static str = "x-ms-version";
    const VERSIONS_URL: &'static str = "?comp=Versions";
    const GOAL_STATE_URL: &'static str = "machine?comp=goalstate";

    pub fn new(base_url: &str) -> WireServerClient {
        WireServerClient {
            base_url: base_url.to_string(),
            version: "2015-04-05".to_string(),
            client: Client::new(),
        }
    }

    // http://168.63.129.16?comp=Versions
    pub async fn get_versions(&self) -> Result<Versions, ErrorDetails> {
        self.get::<Versions>(Self::VERSIONS_URL).await
    }

    // http://168.63.129.16/machine?comp=goalstate
    pub async fn get_goal_state(&self) -> Result<GoalState, ErrorDetails> {
        self.get::<GoalState>(Self::GOAL_STATE_URL).await
    }

    pub async fn get<T>(&self, sub_url: &str) -> Result<T, ErrorDetails>
    where
        T: for<'a> Deserialize<'a>,
    {
        self.get_url(&format!("{}/{}", &self.base_url, sub_url))
            .await
    }

    pub async fn get_url<T>(&self, url: &str) -> Result<T, ErrorDetails>
    where
        T: for<'a> Deserialize<'a>,
    {
        match self
            .client
            .get(url)
            .header(Self::X_MS_VERSION_HEADER, &self.version)
            .send()
            .await
        {
            Ok(resp) => {
                if resp.status().is_success() {
                    let body = resp.text().await.map_err(|e| ErrorDetails {
                        code: -1,
                        message: format!("{}", e),
                    })?;
                    let result = from_str::<T>(&body).map_err(|e| ErrorDetails {
                        code: -2,
                        message: format!("XML Deserialization Failed: {}", e),
                    })?;
                    return Ok(result);
                } else {
                    let status = resp.status();
                    return Err(ErrorDetails {
                        code: status.as_u16() as i32,
                        message: format!(
                            "Http Error Status: {}, Body: {}",
                            status,
                            resp.text().await.unwrap_or_default()
                        ),
                    });
                }
            }
            Err(e) => {
                return Err(ErrorDetails {
                    code: -3,
                    message: format!("Request Error: {}", e),
                });
            }
        }
    }
}
