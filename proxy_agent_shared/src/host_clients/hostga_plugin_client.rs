use std::collections::HashMap;
use std::time::Duration;

use crate::certificate::certificate_helper::{
    decrypt_from_base64, generate_self_signed_certificate,
};
use crate::common::error::Error;
use crate::common::formatted_error::FormattedError;
use crate::common::hyper_client;
use crate::common::hyper_client::read_response_body_as_string;
use crate::common::result::Result;
use crate::host_clients::data_model::hostga_plugin_model::{
    Certificates, RawCertificatesPayload, VMSettings,
};
use crate::logger::LoggerLevel;
use base64::Engine;
use http::{Method, StatusCode, Uri};
use serde::{Deserialize, Serialize};
use tokio::time::timeout;
use uuid::Uuid;

pub struct HostGAPluginClient {
    base_url: String,
    logger: fn(LoggerLevel, String) -> (),
    timeout_in_seconds: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HostGAPluginResponse<T> {
    pub body: Option<T>,
    pub etag: Option<String>,
    pub certificates_revision: Option<u32>,
    pub version: Option<String>,
}

impl HostGAPluginClient {
    const CERTIFICATES_URL: &'static str = "certificates";
    const VMSETTINGS_URL: &'static str = "vmSettings";
    const HOSTGAP_CIPHER: &'static str = "AES256_CBC";

    const ETAG_HEADER: &'static str = "etag";
    const X_MS_SERVER_VERSION_HEADER: &'static str = "x-ms-server-version";
    const X_MS_CERTIFICATES_REVISION_HEADER: &'static str = "x-ms-certificates-revision";
    const TRANSPORT_CERTIFICATE_HEADER: &'static str = "x-ms-guest-agent-public-x509-cert";
    const TRANSPORT_CERTIFICATE_ENCRYPT_CIPHER_HEADER: &'static str = "x-ms-cipher-name";

    pub fn new(
        base_url: &str,
        logger: fn(LoggerLevel, String) -> (),
        timeout_in_seconds: Option<u32>,
    ) -> HostGAPluginClient {
        HostGAPluginClient {
            base_url: base_url.to_string(),
            logger,
            timeout_in_seconds,
        }
    }

    pub async fn get_vmsettings(
        &self,
        etag: Option<String>,
    ) -> Result<HostGAPluginResponse<VMSettings>> {
        let logger = self.logger;

        logger(
            LoggerLevel::Info,
            format!("Requesting VMSettings with etag: {etag:?}"),
        );

        let headers = self.vmsettings_request_headers(etag);

        self.get::<VMSettings>(
            &format!("{}/{}", self.base_url, Self::VMSETTINGS_URL),
            &headers,
        )
        .await
    }

    pub async fn get_certificates(
        &self,
        cert_revision: u32,
    ) -> Result<HostGAPluginResponse<Certificates>> {
        let logger = self.logger;
        logger(
            LoggerLevel::Info,
            format!("Requesting certificates with revision: {cert_revision}"),
        );

        let cert = generate_self_signed_certificate(&Uuid::new_v4().to_string())?;
        let cert_der = cert.get_public_cert_der();
        let cert_base64 = base64::engine::general_purpose::STANDARD.encode(cert_der);

        let headers = self.certificate_request_headers(&cert_base64);

        let raw_certs_resp = self
            .get::<RawCertificatesPayload>(
                &format!(
                    "{}/{}/{}",
                    self.base_url,
                    Self::CERTIFICATES_URL,
                    cert_revision
                ),
                &headers,
            )
            .await?;

        if let Some(cert_base64) = raw_certs_resp
            .body
            .as_ref()
            .and_then(|body| body.pkcs7_blob_with_pfx_contents.as_ref())
        {
            let certs = decrypt_from_base64(cert_base64, &cert)?;

            return Ok(HostGAPluginResponse {
                body: Some(
                    serde_json::from_str::<Certificates>(&certs).map_err(FormattedError::from)?,
                ),
                etag: raw_certs_resp.etag.clone(),
                certificates_revision: raw_certs_resp.certificates_revision,
                version: raw_certs_resp.version.clone(),
            });
        }
        Err(FormattedError {
            message: "certificate payload is empty.".to_string(),
            code: -1,
        }
        .into())
    }

    pub async fn get<T>(
        &self,
        url: &str,
        headers: &HashMap<String, String>,
    ) -> Result<HostGAPluginResponse<T>>
    where
        for<'a> T: Deserialize<'a>,
    {
        let logger = self.logger;
        let url: Uri = url
            .parse::<hyper::Uri>()
            .map_err(|e| Error::ParseUrl(url.to_string(), e.to_string()))?;

        let request = hyper_client::build_request(Method::GET, &url, headers, None, None, None)?;

        let (host, port) = hyper_client::host_port_from_uri(&url)?;

        let response = if let Some(timeout_in_seconds) = self.timeout_in_seconds {
            timeout(
                Duration::from_secs(timeout_in_seconds as u64),
                hyper_client::send_request(&host, port, request, move |m| {
                    logger(LoggerLevel::Warn, m)
                }),
            )
            .await
            .map_err(Into::<FormattedError>::into)??
        } else {
            hyper_client::send_request(&host, port, request, move |m| logger(LoggerLevel::Warn, m))
                .await?
        };

        let etag = response
            .headers()
            .get(Self::ETAG_HEADER)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.to_string());
        let version = response
            .headers()
            .get(Self::X_MS_SERVER_VERSION_HEADER)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.to_string());
        let certificates_revision = response
            .headers()
            .get(Self::X_MS_CERTIFICATES_REVISION_HEADER)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u32>().ok());

        let status = response.status();
        if status == StatusCode::NOT_MODIFIED {
            let _hostgap_response: HostGAPluginResponse<T> = HostGAPluginResponse {
                body: None,
                etag,
                version,
                certificates_revision,
            };
            return Ok(_hostgap_response);
        } else if status.is_success() {
            let body_obj = hyper_client::read_response_body::<T>(response).await?;
            return Ok(HostGAPluginResponse {
                body: Some(body_obj),
                etag,
                certificates_revision,
                version,
            });
        }
        let body_string = read_response_body_as_string(response, "utf-8").await?;
        Err(FormattedError {
            code: status.as_u16() as i32,
            message: format!("Http Error Status: {}, Body: {}", status, &body_string),
        }
        .into())
    }

    fn certificate_request_headers(&self, cert: &str) -> HashMap<String, String> {
        let mut headers = HashMap::new();
        headers.insert(
            Self::TRANSPORT_CERTIFICATE_HEADER.to_string(),
            cert.to_string(),
        );
        headers.insert(
            Self::TRANSPORT_CERTIFICATE_ENCRYPT_CIPHER_HEADER.to_string(),
            Self::HOSTGAP_CIPHER.to_string(),
        );
        headers
    }

    fn vmsettings_request_headers(&self, etag: Option<String>) -> HashMap<String, String> {
        let mut headers = HashMap::new();
        if let Some(etag) = etag {
            headers.insert(Self::ETAG_HEADER.to_string(), etag);
        }
        headers
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostgaplugin_client_creation_test() {
        let client = HostGAPluginClient::new(
            "http://localhost:8080",
            |level, message| {
                println!("{:?}: {}", level, message);
            },
            None,
        );
        assert_eq!(client.base_url, "http://localhost:8080");
        assert_eq!(client.timeout_in_seconds, None);
    }

    #[test]
    fn certificate_request_headers_test() {
        let client = HostGAPluginClient::new(
            "http://localhost:8080",
            |level, message| {
                println!("{:?}: {}", level, message);
            },
            None,
        );
        let cert = "test_cert";
        let headers = client.certificate_request_headers(cert);
        assert_eq!(
            headers
                .get(HostGAPluginClient::TRANSPORT_CERTIFICATE_HEADER)
                .unwrap(),
            cert
        );
        assert_eq!(
            headers
                .get(HostGAPluginClient::TRANSPORT_CERTIFICATE_ENCRYPT_CIPHER_HEADER)
                .unwrap(),
            HostGAPluginClient::HOSTGAP_CIPHER
        );
    }

    #[test]
    fn vmsettings_request_headers_test() {
        let client = HostGAPluginClient::new(
            "http://localhost:8080",
            |level, message| {
                println!("{:?}: {}", level, message);
            },
            None,
        );
        let etag = Some("test_etag".to_string());
        let headers = client.vmsettings_request_headers(etag.clone());
        assert_eq!(
            headers.get(HostGAPluginClient::ETAG_HEADER).unwrap(),
            etag.as_ref().unwrap()
        );

        let headers_no_etag = client.vmsettings_request_headers(None);
        assert!(headers_no_etag
            .get(HostGAPluginClient::ETAG_HEADER)
            .is_none());
    }

    #[tokio::test]
    async fn get_vmsettings_negative_test() {
        let client = HostGAPluginClient::new(
            "http://invalid:8080",
            |level, message| {
                println!("{:?}: {}", level, message);
            },
            Some(2),
        );
        let response = client.get_vmsettings(None).await;
        assert!(response.is_err());
    }

    #[tokio::test]
    async fn get_certificates_negative_test() {
        let client = HostGAPluginClient::new(
            "http://invalid:8080",
            |level, message| {
                println!("{:?}: {}", level, message);
            },
            Some(2),
        );
        let response = client.get_certificates(0).await;
        assert!(response.is_err());
    }

    #[test]
    fn get_hostgaplugin_certificates_response_test() {
        let response = r#"
        {
            "body": {
                "activityId": "11111111-1111111-11111111111-111111",
                "correlationId": "80e22e3b-3f9a-424e-b300-6cda2dd7e718",
                "certificates": [
                {
                    "name": "TenantEncryptionCert",
                    "storeName": "My",
                    "configurationLevel": "System",
                    "certificateInBase64": "certificateInBase64_test",
                    "includePrivateKey": false,
                    "thumbprint": "thumbprint_test",
                    "certificateBlobFormatType": "PfxInClear"
                }
                ]
            },
            "etag": null,
            "certificates_revision": null,
            "version": "1.0.8.179"
            }
        "#;
        let resp: HostGAPluginResponse<Certificates> =
            serde_json::from_str(response).expect("Deserialize HostGAPluginResponse failed");
        assert!(resp.body.is_some());
        let certs = resp.body.unwrap();
        assert_eq!(
            certs.activity_id.unwrap(),
            "11111111-1111111-11111111111-111111"
        );
        assert_eq!(
            certs.correlation_id.unwrap(),
            "80e22e3b-3f9a-424e-b300-6cda2dd7e718"
        );
        assert!(certs.certificates.is_some());
        let cert_list = certs.certificates.unwrap();
        assert_eq!(cert_list.len(), 1);
        let cert = &cert_list[0];
        assert_eq!(cert.name.as_ref().unwrap(), "TenantEncryptionCert");
        assert_eq!(
            cert.certificate_in_base64.as_ref().unwrap(),
            "certificateInBase64_test"
        );
        assert_eq!(cert.thumbprint.as_ref().unwrap(), "thumbprint_test");
    }

    #[test]
    fn get_hostgaplugin_vmsettings_response_test() {
        let response = r#"
        {
            "body": {
                "hostGAPluginVersion": "1.0.8.179",
                "activityId": "1111-11111111-1111-11-1111",
                "correlationId": "000000-00000000-000000-0000",
                "inSvdSeqNo": 1,
                "certificatesRevision": 0,
                "extensionsLastModifiedTickCount": 638931417044754873,
                "extensionGoalStatesSource": "FastTrack",
                "statusUploadBlob": {
                "statusBlobType": "PageBlob",
                "value": "string"
                },
                "gaFamilies": [
                {
                    "name": "Win7",
                    "version": "2.7.41491.1176",
                    "isVersionFromRSM": false,
                    "isVMEnabledForRSMUpgrades": true,
                    "uris": [
                    "uri"
                    ]
                },
                {
                    "name": "Win8",
                    "version": "2.7.41491.1176",
                    "isVersionFromRSM": false,
                    "isVMEnabledForRSMUpgrades": true,
                    "uris": [
                    "uri"
                    ]
                }
                ],
                "extensionGoalStates": [
                {
                    "name": "extension.test",
                    "version": "1.0.1",
                    "location": "location",
                    "failoverLocation": "location",
                    "additionalLocations": [
                    "location"
                    ],
                    "state": "enabled",
                    "autoUpgrade": true,
                    "runAsStartupTask": false,
                    "isJson": true,
                    "useExactVersion": true,
                    "settingsSeqNo": 0,
                    "isMultiConfig": false,
                    "settings": [
                    {
                        "protectedSettingsCertThumbprint": null,
                        "protectedSettings": null,
                        "publicSettings": "{}"
                    }
                    ]
                }
                ]
            },
            "etag": "5048704324908356042",
            "certificates_revision": 1,
            "version": "1.0.8.179"
            }
        "#;
        let resp: HostGAPluginResponse<VMSettings> =
            serde_json::from_str(response).expect("Deserialize HostGAPluginResponse failed");
        assert!(resp.body.is_some());
        assert_eq!(resp.etag.unwrap(), "5048704324908356042");
        assert_eq!(resp.certificates_revision.unwrap(), 1);

        let vmsettings = resp.body.unwrap();
        assert_eq!(
            vmsettings.activity_id.unwrap(),
            "1111-11111111-1111-11-1111"
        );
        assert_eq!(
            vmsettings.extensions_last_modified_tick_count.unwrap(),
            638931417044754873
        );
        assert_eq!(vmsettings.extension_goal_states.as_ref().unwrap().len(), 1);
        assert_eq!(vmsettings.ga_families.as_ref().unwrap().len(), 2);

        let extension = &vmsettings.extension_goal_states.as_ref().unwrap()[0];
        assert_eq!(extension.name.as_ref().unwrap(), "extension.test");
        assert_eq!(extension.version.as_ref().unwrap(), "1.0.1");
    }
}
