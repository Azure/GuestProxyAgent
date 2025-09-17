use crate::certificate::certificate_helper::{decrypt_from_base64, generate_self_signed_certificate, CertificateDetails};
use crate::client::data_model::error::ErrorDetails;
use crate::client::data_model::hostga_plugin_model::{
    Certificates, RawCertificatesPayload, VMSettings,
};
use base64::Engine;
use reqwest::header::HeaderMap;
use reqwest::header::HeaderValue;
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub struct HostGAPluginClient {
    base_url: String,
    client: Client,
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

    const ETAG_HEADER: &'static str = "etag";
    const X_MS_SERVER_VERSION_HEADER: &'static str = "x-ms-server-version";
    const X_MS_CERTIFICATES_REVISION_HEADER: &'static str = "x-ms-certificates-revision";
    const TRANSPORT_CERTIFICATE_HEADER: &'static str = "x-ms-guest-agent-public-x509-cert";
    const TRANSPORT_CERTIFICATE_ENCRYPT_CIPHER_HEADER: &'static str = "x-ms-cipher-name";

    pub fn new(base_url: &str) -> HostGAPluginClient {
        HostGAPluginClient {
            base_url: base_url.to_string(),
            client: Client::new(),
        }
    }

    pub async fn get_vmsettings(&self) -> Result<HostGAPluginResponse<VMSettings>, ErrorDetails> {
        self.get::<VMSettings>(
            &format!("{}/{}", self.base_url, Self::VMSETTINGS_URL),
            Option::None,
        )
        .await
    }

    pub async fn get_certificates(
        &self,
        cert_revision: u32,
    ) -> Result<HostGAPluginResponse<Certificates>, ErrorDetails> {
        let cert = generate_self_signed_certificate(&Uuid::new_v4().to_string())?;
        //let cert = get_cert_by_thumbprint("9bf93bb248b4504626c5d1247da2e7c5f8e0a03a")?;
        let cert_der = cert.get_public_cert_der();
        let cert_base64 = base64::engine::general_purpose::STANDARD.encode(cert_der);

        let mut headers = HeaderMap::new();
        headers.insert(
            Self::TRANSPORT_CERTIFICATE_HEADER,
            HeaderValue::from_str(&cert_base64)?,
        );
        headers.insert(
            Self::TRANSPORT_CERTIFICATE_ENCRYPT_CIPHER_HEADER,
            HeaderValue::from_str("AES256_CBC")?,
        );
        println!("Requesting certificates with headers: {:?}", headers);
        let raw_certs_resp = self
            .get::<RawCertificatesPayload>(
                &format!(
                    "{}/{}/{}",
                    self.base_url,
                    Self::CERTIFICATES_URL,
                    cert_revision
                ),
                Some(headers),
            )
            .await?;

        if let Some(cert_base64) = raw_certs_resp
            .body
            .as_ref()
            .and_then(|body| body.pkcs7_blob_with_pfx_contents.as_ref())
        {
            let certs = decrypt_from_base64(cert_base64, &cert)?;

            return Ok(HostGAPluginResponse {
                body: Some(serde_json::from_str::<Certificates>(&certs)?),
                etag: raw_certs_resp.etag.clone(),
                certificates_revision: raw_certs_resp.certificates_revision.clone(),
                version: raw_certs_resp.version.clone(),
            });
        }

        Err(ErrorDetails {
            message: format!("certificate payload is empty."),
            code: -1,
        })
    }

    pub async fn get<T>(
        &self,
        url: &str,
        headers_map: Option<HeaderMap>,
    ) -> Result<HostGAPluginResponse<T>, ErrorDetails>
    where
        for<'a> T: Deserialize<'a>,
    {
        let mut request = self.client.get(url);
        println!("Requesting URL: {}", url);
        if let Some(headers) = headers_map {
            request = request.headers(headers);
        }

        let resp = request.send().await.map_err(|e| {
            let mut error_code = -1;
            if let Some(status) = e.status() {
                error_code = status.as_u16() as i32;
            }
            ErrorDetails {
                code: error_code,
                message: format!("HostGAPlugin Request Error: {}, url: {}", e, url),
            }
        })?;

        let headers = resp.headers();

        let etag = headers
            .get(Self::ETAG_HEADER)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.to_string());

        let certificates_revision = headers
            .get(Self::X_MS_CERTIFICATES_REVISION_HEADER)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u32>().ok());

        let version = headers
            .get(Self::X_MS_SERVER_VERSION_HEADER)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.to_string());

        if resp.status() == StatusCode::NOT_MODIFIED {
            let _hostgap_response: HostGAPluginResponse<T> = HostGAPluginResponse {
                body: None,
                etag: etag,
                version: version,
                certificates_revision: certificates_revision,
            };
            return Ok(_hostgap_response);
        } else if resp.status().is_success() {
            let body = resp.text().await.map_err(|e| ErrorDetails {
                code: -1,
                message: format!("Failed to get response body: {}", e),
            })?;
            let body_json = serde_json::from_str::<T>(&body).map_err(|e| ErrorDetails {
                code: -1,
                message: format!("Failed to deserialized json payload, error: {}", e),
            })?;
            return Ok(HostGAPluginResponse {
                body: Option::Some(body_json),
                etag: etag,
                version: version,
                certificates_revision: certificates_revision,
            });
        }

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
