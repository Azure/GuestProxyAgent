use std::collections::HashMap;

use crate::certificate::certificate_helper::{
    decrypt_from_base64, generate_self_signed_certificate,
};
use crate::client::data_model::hostga_plugin_model::{
    Certificates, RawCertificatesPayload, VMSettings,
};
use crate::common::error::Error;
use crate::common::formatted_error::FormattedError;
use crate::common::hyper_client::read_response_body_as_string;
use crate::common::result::Result;
use crate::common::{hyper_client, logger};
use base64::Engine;
use http::{Method, StatusCode, Uri};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub struct HostGAPluginClient {
    base_url: String,
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

    pub fn new(base_url: &str) -> HostGAPluginClient {
        HostGAPluginClient {
            base_url: base_url.to_string(),
        }
    }

    pub async fn get_vmsettings(
        &self,
        etag: Option<String>,
    ) -> Result<HostGAPluginResponse<VMSettings>> {
        let mut headers = HashMap::new();
        if let Some(etag) = etag {
            headers.insert(Self::ETAG_HEADER.to_string(), etag);
        }
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
        let cert = generate_self_signed_certificate(&Uuid::new_v4().to_string())?;
        let cert_der = cert.get_public_cert_der();
        let cert_base64 = base64::engine::general_purpose::STANDARD.encode(cert_der);

        let mut headers = HashMap::new();
        headers.insert(Self::TRANSPORT_CERTIFICATE_HEADER.to_string(), cert_base64);
        headers.insert(
            Self::TRANSPORT_CERTIFICATE_ENCRYPT_CIPHER_HEADER.to_string(),
            Self::HOSTGAP_CIPHER.to_string(),
        );

        // to-do: use logger
        println!("Requesting certificates with headers: {headers:?}");
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
                    serde_json::from_str::<Certificates>(&certs)
                        .map_err(|e| FormattedError::from(e))?,
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
        let url: Uri = url
            .parse::<hyper::Uri>()
            .map_err(|e| Error::ParseUrl(url.to_string(), e.to_string()))?;

        let request = hyper_client::build_request(Method::GET, &url, headers, None, None, None)?;

        let (host, port) = hyper_client::host_port_from_uri(&url)?;
        let response =
            hyper_client::send_request(&host, port, request, logger::write_warning).await?;

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
}
