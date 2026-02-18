// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

//! This module contains the logic to send http requests and read the response body via hyper crate.

use super::error::{Error, HyperErrorType};
use super::misc_helpers;
use super::result::Result;
use http::request::Builder;
use http::request::Parts;
use http::Method;
use http_body_util::combinators::BoxBody;
use http_body_util::BodyExt;
use http_body_util::Empty;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::Request;
use hyper::Uri;
use hyper_util::rt::TokioIo;
use itertools::Itertools;
use serde::de::DeserializeOwned;
use std::collections::HashMap;
use tokio::net::TcpStream;

pub const DATE_HEADER: &str = "x-ms-azure-host-date";
pub const METADATA_HEADER: &str = "Metadata";
pub const CLAIMS_HEADER: &str = "x-ms-azure-host-claims";
pub const AUTHORIZATION_HEADER: &str = "x-ms-azure-host-authorization";
pub const AUTHORIZATION_SCHEME: &str = "Azure-HMAC-SHA256";
pub const CLAIMS_IS_ROOT: &str = "isRoot";

const LF: &str = "\n";

/// Pre-parsed HTTP endpoint containing host, port, and path/query.
/// Use this to avoid re-parsing URIs multiple times which is performance-sensitive.
#[derive(Debug, Clone)]
pub struct HostEndpoint {
    pub host: String,
    pub port: u16,
    /// The path and query portion of the URI (e.g., "/api/status?version=1")
    pub path_and_query: String,
}

impl HostEndpoint {
    pub const DEFAULT_HTTP_PORT: u16 = 80;
    pub const DEFAULT_HTTPS_PORT: u16 = 443;

    /// Create a new HostEndpoint with explicit components
    pub fn new(host: impl Into<String>, port: u16, path_and_query: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            port,
            path_and_query: path_and_query.into(),
        }
    }

    /// Create a HostEndpoint from a full URI string (e.g., "http://host:port/path?query")
    /// This will parse the URI and extract the host, port, and path/query components.
    /// Remark: Do not use this function in performance-sensitive code paths, as URI parsing can be relatively expensive.
    ///     Instead, use the `new` constructor with pre-parsed components when possible.
    /// Remark: This function assumes the URI is well-formed and contains a host. It will return an error if the URI is invalid or missing required components.
    pub fn from_full_uri(uri: Uri) -> Result<Self> {
        let host = match uri.host() {
            Some(h) => h.to_string(),
            None => {
                return Err(Error::Hyper(HyperErrorType::RequestBuilder(
                    "URI must have a host".to_string(),
                )));
            }
        };
        let default_port = if uri.scheme_str() == Some("https") {
            Self::DEFAULT_HTTPS_PORT
        } else {
            Self::DEFAULT_HTTP_PORT
        };
        let port = uri.port_u16().unwrap_or(default_port);
        let path_and_query = match uri.path_and_query() {
            Some(pq) => pq.as_str().to_string(),
            None => "/".to_string(), // default to root path
        };

        Ok(Self {
            host,
            port,
            path_and_query,
        })
    }

    /// Create a HostEndpoint from a URI string (e.g., "http://host:port/path?query")
    /// This will parse the URI and extract the host, port, and path/query components.
    /// Remark: Do not use this function in performance-sensitive code paths, as URI parsing can be relatively expensive.
    ///     Instead, use the `new` constructor with pre-parsed components when possible.
    pub fn from_uri_str(uri_str: &str) -> Result<Self> {
        let uri = uri_str.parse::<Uri>().map_err(|e| {
            Error::Hyper(HyperErrorType::RequestBuilder(format!(
                "Failed to parse URI string: {uri_str} with error: {e}"
            )))
        })?;
        Self::from_full_uri(uri)
    }

    /// Get the address string for TCP connection (host:port)
    #[inline]
    pub fn addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

impl std::fmt::Display for HostEndpoint {
    /// Format as full URI string (e.g., "http://host:port/path?query")
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "http://{}:{}{}",
            self.host, self.port, self.path_and_query
        )
    }
}

pub async fn get<T, F>(
    endpoint: &HostEndpoint,
    headers: &HashMap<String, String>,
    key_guid: Option<String>,
    key: Option<String>,
    log_fun: F,
) -> Result<T>
where
    T: DeserializeOwned,
    F: Fn(String) + Send + 'static,
{
    let request = build_request(Method::GET, endpoint, headers, None, key_guid, key)?;

    let response = send_request(&endpoint.host, endpoint.port, request, log_fun).await?;
    let status = response.status();
    if !status.is_success() {
        return Err(Error::Hyper(HyperErrorType::ServerError(
            endpoint.to_string(),
            status,
        )));
    }

    read_response_body(response).await
}

pub async fn read_response_body<T>(
    mut response: hyper::Response<hyper::body::Incoming>,
) -> Result<T>
where
    T: DeserializeOwned,
{
    // LATER:: need find a well_known way to get content_type and charset_type
    let (content_type, charset_type) =
        if let Some(content_type) = response.headers().get(hyper::header::CONTENT_TYPE) {
            if let Ok(content_type_str) = content_type.to_str() {
                let content_type_str = content_type_str.to_lowercase();
                let content_type;
                if content_type_str.contains("xml") {
                    content_type = "xml";
                } else if content_type_str.contains("json") {
                    content_type = "json";
                } else if content_type_str.contains("text") {
                    content_type = "text";
                } else {
                    content_type = "unknown";
                }

                let charset_type;
                if content_type_str.contains("utf-8") {
                    charset_type = "utf-8";
                } else if content_type_str.contains("utf-16") {
                    charset_type = "utf-16";
                } else if content_type_str.contains("utf-32") {
                    charset_type = "utf-32";
                } else {
                    charset_type = "unknown";
                }

                (content_type, charset_type)
            } else {
                ("unknown", "unknown")
            }
        } else {
            ("unknown", "unknown")
        };

    let mut body_string = String::new();
    while let Some(next) = response.frame().await {
        let frame = match next {
            Ok(f) => f,
            Err(e) => {
                return Err(Error::Hyper(HyperErrorType::Custom(
                    "Failed to get next frame from response".to_string(),
                    e,
                )))
            }
        };
        if let Some(chunk) = frame.data_ref() {
            match charset_type {
                "utf-16" => {
                    // Convert Bytes to Vec<u8>
                    let byte_vec: Vec<u8> = chunk.to_vec();
                    // Convert Vec<u8> to Vec<u16>
                    let u16_vec: Vec<u16> = byte_vec
                        .chunks(2)
                        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                        .collect();

                    body_string.push_str(&String::from_utf16_lossy(&u16_vec));
                }
                "utf-32" => {
                    return Err(Error::Hyper(HyperErrorType::Deserialize(
                        "utf-32 charset is not supported".to_string(),
                    )))
                }
                _ => {
                    // default to utf-8
                    body_string.push_str(&String::from_utf8_lossy(chunk));
                }
            };
        }
    }

    match content_type {
        "xml" => match serde_xml_rs::from_str(&body_string) {
            Ok(t) => Ok(t),
            Err(e) => Err(Error::Hyper(
                HyperErrorType::Deserialize(
                    format!(
                        "Failed to xml deserialize response body with content_type {content_type} from: {body_string} with error {e}"
                    )
                ),
            )),
        },
        // default to json
        _ => match serde_json::from_str(&body_string) {
            Ok(t) => Ok(t),
            Err(e) => Err(Error::Hyper(
                HyperErrorType::Deserialize(
                    format!(
                        "Failed to json deserialize response body with {content_type} from: {body_string} with error {e}"
                    )
                ),
            )),
        },
    }
}

pub fn build_request(
    method: http::Method,
    endpoint: &HostEndpoint,
    headers: &HashMap<String, String>,
    body: Option<&[u8]>,
    key_guid: Option<String>,
    key: Option<String>,
) -> Result<Request<BoxBody<Bytes, hyper::Error>>> {
    let mut request_builder = Request::builder()
        .method(method)
        .uri(&endpoint.path_and_query)
        .header(DATE_HEADER, misc_helpers::get_date_time_rfc1123_string())
        // The header() method accepts types that implement Into<HeaderValue>, and &str implements this trait.
        // The HeaderValue will internally copy the bytes (which is unavoidable since it needs to own the data),
        // So you're not creating any intermediate String allocations.
        .header(hyper::header::HOST, &endpoint.host)
        .header(
            CLAIMS_HEADER,
            format!("{{ \"{}\": \"{}\"}}", CLAIMS_IS_ROOT, true,),
        )
        .header(
            hyper::header::CONTENT_LENGTH,
            match body {
                Some(b) => b.len().to_string(),
                None => "0".to_string(),
            },
        );

    for (key, value) in headers {
        request_builder = request_builder.header(key, value);
    }

    if let (Some(key), Some(key_guid)) = (key, key_guid) {
        let body_vec = body.map(|b| b.to_vec());
        let input_to_sign = request_to_sign_input(&request_builder, body_vec)?;
        let authorization_value = format!(
            "{} {} {}",
            AUTHORIZATION_SCHEME,
            key_guid,
            misc_helpers::compute_signature(&key, input_to_sign.as_slice())?
        );
        request_builder = request_builder.header(
            AUTHORIZATION_HEADER.to_string(),
            authorization_value.to_string(),
        );
    }

    let boxed_body = match body {
        Some(body) => full_body(body.to_vec()),
        None => empty_body(),
    };
    match request_builder.body(boxed_body) {
        Ok(r) => Ok(r),
        Err(e) => Err(Error::Hyper(HyperErrorType::RequestBuilder(format!(
            "Failed to build request body: {e}"
        )))),
    }
}

pub async fn send_request<B, F>(
    host: &str,
    port: u16,
    request: Request<B>,
    log_fun: F,
) -> Result<hyper::Response<hyper::body::Incoming>>
where
    B: hyper::body::Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    F: FnMut(String) + Send + 'static,
{
    let full_url = request.uri().clone();
    let mut sender = build_http_sender(host, port, log_fun).await?;
    sender.send_request(request).await.map_err(|e| {
        Error::Hyper(HyperErrorType::Custom(
            format!("Failed to send request to {full_url}"),
            e,
        ))
    })
}

pub async fn build_http_sender<B, F>(
    host: &str,
    port: u16,
    mut log_fun: F,
) -> Result<hyper::client::conn::http1::SendRequest<B>>
where
    B: hyper::body::Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    F: FnMut(String) + Send + 'static,
{
    let addr = format!("{host}:{port}");
    let stream = match TcpStream::connect(addr.to_string()).await {
        Ok(tcp_stream) => tcp_stream,
        Err(e) => return Err(Error::Io(e)),
    };

    let io = TokioIo::new(stream);
    let (sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|e| {
            Error::Hyper(HyperErrorType::Custom(
                format!("Failed to establish connection to {addr}"),
                e,
            ))
        })?;
    tokio::task::spawn(async move {
        if let Err(err) = conn.await {
            log_fun(format!("Connection failed: {err:?}"));
        }
    });

    Ok(sender)
}

/*
    StringToSign = Method + "\n" +
           HexEncoded(Body) + "\n" +
           CanonicalizedHeaders + "\n"
           UrlEncodedPath + "\n"
           CanonicalizedParameters;
*/
pub fn as_sig_input(head: Parts, body: Bytes) -> Vec<u8> {
    let mut data: Vec<u8> = head.method.to_string().as_bytes().to_vec();
    data.extend(LF.as_bytes());
    data.extend(body);
    data.extend(LF.as_bytes());

    data.extend(headers_to_canonicalized_string(&head.headers).as_bytes());
    let path_para = get_path_and_canonicalized_parameters(&head.uri);
    data.extend(path_para.0.as_bytes());
    data.extend(LF.as_bytes());
    data.extend(path_para.1.as_bytes());

    data
}

fn request_to_sign_input(request_builder: &Builder, body: Option<Vec<u8>>) -> Result<Vec<u8>> {
    let mut data: Vec<u8> = match request_builder.method_ref() {
        Some(m) => m.as_str().as_bytes().to_vec(),
        None => {
            return Err(Error::Hyper(HyperErrorType::RequestBuilder(
                "Failed to get method from request builder".to_string(),
            )))
        }
    };
    data.extend(LF.as_bytes());
    if let Some(body) = body {
        data.extend(body);
    }
    data.extend(LF.as_bytes());

    match request_builder.headers_ref() {
        Some(h) => {
            data.extend(headers_to_canonicalized_string(h).as_bytes());
        }
        None => {
            // no headers
            data.extend(LF.as_bytes());
        }
    }
    match request_builder.uri_ref() {
        Some(u) => {
            let path_para = get_path_and_canonicalized_parameters(u);
            data.extend(path_para.0.as_bytes());
            data.extend(LF.as_bytes());
            data.extend(path_para.1.as_bytes());
        }
        None => {
            return Err(Error::Hyper(HyperErrorType::RequestBuilder(
                "Failed to get method from request builder".to_string(),
            )))
        }
    }

    Ok(data)
}

fn headers_to_canonicalized_string(headers: &hyper::HeaderMap) -> String {
    let mut canonicalized_headers = String::new();
    let separator = String::from(LF);
    let mut map: HashMap<String, (String, String)> = HashMap::new();

    for (key, value) in headers.iter() {
        let key = key.to_string();
        let value = value.to_str().unwrap().to_string();
        let key_lower_case = key.to_lowercase();
        map.insert(key_lower_case, (key, value));
    }

    for key in map.keys().sorted() {
        // skip the expect header
        if key.eq_ignore_ascii_case(AUTHORIZATION_HEADER) {
            continue;
        }
        let h = format!("{}:{}{}", key, map[key].1.trim(), separator);
        canonicalized_headers.push_str(&h);
    }

    canonicalized_headers
}

fn get_path_and_canonicalized_parameters(url: &Uri) -> (String, String) {
    let path = url.path().to_string();

    let query_pairs = query_pairs(url);
    let mut canonicalized_parameters = String::new();
    let mut pairs: HashMap<String, (String, String)> = HashMap::new();
    if !query_pairs.is_empty() {
        for (key, value) in query_pairs {
            let key = key.to_lowercase();
            pairs.insert(
                // add the query parameter value for sorting,
                // just in case of duplicate keys by value lexicographically in ascending order.
                format!("{key}{value}"),
                (key.to_lowercase(), value.to_string()),
            );
        }

        // Sort the parameters lexicographically by parameter name and value, in ascending order.
        let mut first = true;
        for key in pairs.keys().sorted() {
            if !first {
                canonicalized_parameters.push('&');
            }
            first = false;
            let query_pair = pairs[key].clone();
            // Join each parameter key value pair with '='
            let p = if query_pair.1.is_empty() {
                key.to_string()
            } else {
                format!("{}={}", query_pair.0, query_pair.1)
            };
            canonicalized_parameters.push_str(&p);
        }
    }

    (path, canonicalized_parameters)
}

/// get query parameters from uri
/// uri - the uri to get query parameters from
/// return - a vec of query parameters
///     first one is the query parameter key
///     second one is parameter value
pub fn query_pairs(uri: &Uri) -> Vec<(String, String)> {
    let query = uri.query().unwrap_or("");
    let mut pairs: Vec<(String, String)> = Vec::new();
    for pair in query.split('&') {
        let mut split = pair.splitn(2, '=');
        let key = split.next().unwrap_or("");
        if key.is_empty() {
            // parameter key is must have while value is optional
            continue;
        }
        let value = split.next().unwrap_or("");
        pairs.push((key.to_string(), value.to_string()));
    }

    pairs
}

pub fn empty_body() -> BoxBody<Bytes, hyper::Error> {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

pub fn full_body<T: Into<Bytes>>(chunk: T) -> BoxBody<Bytes, hyper::Error> {
    Full::new(chunk.into())
        .map_err(|never| match never {})
        .boxed()
}

/// Certain endpoints are exempt from enforcement regardless of the VM's configuration.
/// Restricting access to these non-security impacting endpoints would introduce unreasonable
/// overhead and/or harm live-site investigations. Since the service won't require a signature,
/// there is no reason to generate one.
pub fn should_skip_sig(method: &hyper::Method, relative_uri: &Uri) -> bool {
    let url = relative_uri.to_string().to_lowercase();

    // currently, we agreed to skip the sig for those requests:
    //      o PUT   /vmAgentLog
    //      o POST  /machine/?comp=telemetrydata
    (method == hyper::Method::PUT && url == "/vmagentlog")
        || (method == hyper::Method::POST && url == "/machine/?comp=telemetrydata")
}

#[cfg(test)]
mod tests {
    use crate::{
        host_clients::{imds_client::ImdsClient, wire_server_client::WireServerClient},
        logger::logger_manager,
        server_mock,
    };
    use tokio_util::sync::CancellationToken;

    #[test]
    fn get_path_and_canonicalized_parameters_test() {
        let url_str = "/machine/a8016240-7286-49ef-8981-63520cb8f6d0/49c242ba%2Dc18a%2D4f6c%2D8cf8%2D85ff790b6431.%5Fzpeng%2Debpf%2Dvm2?comp=config&keyOnly&comp=again&type=hostingEnvironmentConfig&incarnation=1&resource=https%3a%2f%2fstorage.azure.com%2f";
        let url = url_str.parse::<hyper::Uri>().unwrap();
        let path_para = super::get_path_and_canonicalized_parameters(&url);
        assert_eq!("/machine/a8016240-7286-49ef-8981-63520cb8f6d0/49c242ba%2Dc18a%2D4f6c%2D8cf8%2D85ff790b6431.%5Fzpeng%2Debpf%2Dvm2",
         path_para.0, "path mismatch");
        assert_eq!(
            "comp=again&comp=config&incarnation=1&keyonly&resource=https%3a%2f%2fstorage.azure.com%2f&type=hostingEnvironmentConfig", path_para.1,
            "query parameters mismatch"
        );
    }

    #[test]
    fn should_skip_sig_test() {
        let url_str = "/vmAgentLog";
        let url = url_str.parse::<hyper::Uri>().unwrap();
        assert!(super::should_skip_sig(&hyper::Method::PUT, &url));

        let url_str = "/machine/?comp=telemetrydata";
        let url = url_str.parse::<hyper::Uri>().unwrap();
        assert!(super::should_skip_sig(&hyper::Method::POST, &url));

        let url_str = "/machine/?comp=telemetrydata";
        let url = url_str.parse::<hyper::Uri>().unwrap();
        assert!(!super::should_skip_sig(&hyper::Method::GET, &url));

        let url_str = "/vmAgentLog";
        let url = url_str.parse::<hyper::Uri>().unwrap();
        assert!(!super::should_skip_sig(&hyper::Method::GET, &url));
    }

    #[tokio::test]
    async fn http_request_tests() {
        // start mock server
        let ip = "127.0.0.1";
        let port = 9072u16;
        let cancellation_token = CancellationToken::new();
        let port = server_mock::start(ip.to_string(), port, cancellation_token.clone())
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        logger_manager::write_info("server_mock started.".to_string());

        let wire_server_client = WireServerClient::new(ip, port);
        let goal_state = wire_server_client.get_goalstate(None, None).await.unwrap();
        let shared_config = wire_server_client
            .get_shared_config(goal_state.get_shared_config_uri(), None, None)
            .await
            .unwrap();
        assert!(!shared_config.get_role_name().is_empty());
        wire_server_client
            .send_telemetry_data("xml_data".to_string())
            .await
            .unwrap();

        let imds_client = ImdsClient::new(ip, port);
        let instance_info = imds_client
            .get_imds_instance_info(None, None)
            .await
            .unwrap();
        assert!(!instance_info.get_resource_group_name().is_empty());

        cancellation_token.cancel();
    }
}
