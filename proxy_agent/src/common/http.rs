// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

use super::{constants, helpers};
use http::request::Builder;
use http::request::Parts;
use http_body_util::combinators::BoxBody;
use http_body_util::BodyExt;
use http_body_util::Empty;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::Request;
use hyper_util::rt::TokioIo;
use itertools::Itertools;
use proxy_agent_shared::misc_helpers;
use serde::de::DeserializeOwned;
use std::collections::HashMap;
use tokio::net::TcpStream;
use url::Url;

pub fn htons(u: u16) -> u16 {
    u.to_be()
}

pub fn ntohs(u: u16) -> u16 {
    u16::from_be(u)
}

pub async fn get<T, F>(
    uri_str: &str,
    headers: &HashMap<String, String>,
    key_guid: Option<String>,
    key: Option<String>,
    log_fun: F,
) -> std::io::Result<T>
where
    T: DeserializeOwned,
    F: Fn(String) + Send + 'static,
{
    let request = get_request("GET", uri_str, headers, None, key_guid, key)?;

    let (host, port) = host_port_from_uri(uri_str)?;
    let response = match send_request(&host, port, request, log_fun).await {
        Ok(r) => r,
        Err(e) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Failed to send request to {}: {}", uri_str, e),
            ))
        }
    };
    let status = response.status();
    if !status.is_success() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!(
                "Failed to get response from {}, status code: {}",
                uri_str, status
            ),
        ));
    }

    read_response_body(response).await
}

pub async fn read_response_body<T>(
    mut response: hyper::Response<hyper::body::Incoming>,
) -> std::io::Result<T>
where
    T: DeserializeOwned,
{
    let mut body_string = String::new();
    while let Some(next) = response.frame().await {
        let frame = match next {
            Ok(f) => f,
            Err(e) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Failed to get next frame from response: {}", e),
                ))
            }
        };
        if let Some(chunk) = frame.data_ref() {
            body_string.push_str(&String::from_utf8_lossy(chunk));
        }
    }
    match serde_json::from_str(&body_string) {
        Ok(t) => Ok(t),
        Err(e) => Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Failed to deserialize response body from: {}", e),
        )),
    }
}

pub fn get_request(
    method: &str,
    uri_str: &str,
    headers: &HashMap<String, String>,
    body: Option<&[u8]>,
    key_guid: Option<String>,
    key: Option<String>,
) -> std::io::Result<Request<BoxBody<Bytes, hyper::Error>>> {
    let (host, _) = host_port_from_uri(uri_str)?;
    let uri = match uri_str.parse::<hyper::Uri>() {
        Ok(u) => u,
        Err(e) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Failed to parse uri {}: {}", uri_str, e),
            ))
        }
    };
    let mut request_builder = Request::builder()
        .method(method)
        .uri(match uri.path_and_query() {
            Some(pq) => pq.as_str(),
            None => uri.path(),
        })
        .header(
            constants::DATE_HEADER,
            misc_helpers::get_date_time_rfc1123_string(),
        )
        .header("Host", host)
        .header(
            constants::CLAIMS_HEADER,
            format!("{{ \"{}\": \"{}\"}}", constants::CLAIMS_IS_ROOT, true,),
        )
        .header(
            "Content-Length",
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
            constants::AUTHORIZATION_SCHEME,
            key_guid,
            helpers::compute_signature(key.to_string(), input_to_sign.as_slice())?
        );
        request_builder = request_builder.header(
            constants::AUTHORIZATION_HEADER.to_string(),
            authorization_value.to_string(),
        );
    }

    let boxed_body = match body {
        Some(body) => full_body(body.to_vec()),
        None => empty_body(),
    };
    match request_builder.body(boxed_body) {
        Ok(r) => Ok(r),
        Err(e) => Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Failed to build request body: {}", e),
        )),
    }
}

pub fn host_port_from_uri(uri_str: &str) -> std::io::Result<(String, u16)> {
    let uri = parse_uri(uri_str)?;
    let host = match uri.host() {
        Some(h) => h.to_string(),
        None => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Failed to get host from uri {}", uri),
            ))
        }
    };
    let port = match uri.port() {
        Some(p) => p.as_u16(),
        None => 80,
    };

    Ok((host, port))
}

fn parse_uri(uri_str: &str) -> std::io::Result<hyper::Uri> {
    match uri_str.parse::<hyper::Uri>() {
        Ok(u) => Ok(u),
        Err(e) => Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Failed to parse uri {}: {}", uri_str, e),
        )),
    }
}

pub async fn send_request<F>(
    host: &str,
    port: u16,
    request: Request<BoxBody<Bytes, hyper::Error>>,
    log_fun: F,
) -> std::io::Result<hyper::Response<hyper::body::Incoming>>
where
    F: Fn(String) + Send + 'static,
{
    let addr = format!("{}:{}", host, port);
    let stream = TcpStream::connect(addr.to_string()).await?;
    let io = TokioIo::new(stream);

    let (mut sender, conn) = match hyper::client::conn::http1::handshake(io).await {
        Ok((s, c)) => (s, c),
        Err(e) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Failed to establish connection to {}: {}", addr, e),
            ))
        }
    };
    tokio::task::spawn(async move {
        if let Err(err) = conn.await {
            log_fun(format!("Connection failed: {:?}", err));
        }
    });

    match sender.send_request(request).await {
        Ok(r) => Ok(r),
        Err(e) => Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Failed to send request: {:?}", e),
        )),
    }
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
    data.extend(constants::LF.as_bytes());
    data.extend(body);
    data.extend(constants::LF.as_bytes());

    data.extend(headers_to_canonicalized_string(&head.headers).as_bytes());
    let path_para = get_path_and_canonicalized_parameters(into_url(&head.uri));
    data.extend(path_para.0.as_bytes());
    data.extend(constants::LF.as_bytes());
    data.extend(path_para.1.as_bytes());

    data
}

pub fn request_to_sign_input(
    request_builder: &Builder,
    body: Option<Vec<u8>>,
) -> std::io::Result<Vec<u8>> {
    let mut data: Vec<u8> = match request_builder.method_ref() {
        Some(m) => m.as_str().as_bytes().to_vec(),
        None => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Failed to get method from request builder",
            ))
        }
    };
    data.extend(constants::LF.as_bytes());
    if let Some(body) = body {
        data.extend(body);
    }
    data.extend(constants::LF.as_bytes());

    match request_builder.headers_ref() {
        Some(h) => {
            data.extend(headers_to_canonicalized_string(h).as_bytes());
        }
        None => {
            // no headers
            data.extend(constants::LF.as_bytes());
        }
    }
    match request_builder.uri_ref() {
        Some(u) => {
            let path_para = get_path_and_canonicalized_parameters(into_url(u));
            data.extend(path_para.0.as_bytes());
            data.extend(constants::LF.as_bytes());
            data.extend(path_para.1.as_bytes());
        }
        None => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Failed to get uri from request builder",
            ))
        }
    }

    Ok(data)
}

fn headers_to_canonicalized_string(headers: &hyper::HeaderMap) -> String {
    let mut canonicalized_headers = String::new();
    let separator = String::from(constants::LF);
    let mut map: HashMap<String, (String, String)> = HashMap::new();

    for (key, value) in headers.iter() {
        let key = key.to_string();
        let value = value.to_str().unwrap().to_string();
        let key_lower_case = key.to_lowercase();
        map.insert(key_lower_case, (key, value));
    }

    for key in map.keys().sorted() {
        // skip the expect header
        if key.eq_ignore_ascii_case(constants::AUTHORIZATION_HEADER) {
            continue;
        }
        let h = format!("{}:{}{}", key, map[key].1.trim(), separator);
        canonicalized_headers.push_str(&h);
    }

    canonicalized_headers
}

fn into_url(uri: &hyper::Uri) -> Url {
    let path_query = match uri.path_and_query() {
        Some(pq) => pq.as_str(),
        None => uri.path(),
    };
    // Url crate does not support parsing relative paths, so we need to add a dummy base url
    let mut url = Url::parse("http://127.0.0.1").unwrap();
    if let Ok(u) = url.join(path_query) {
        url = u
    }
    url
}

fn get_path_and_canonicalized_parameters(url: Url) -> (String, String) {
    let path = url.path().to_string();
    let parameters = url.query_pairs();
    let mut pairs: HashMap<String, String> = HashMap::new();
    let mut canonicalized_parameters = String::new();
    if parameters.count() > 0 {
        for p in parameters {
            // Convert the parameter name to lowercase
            pairs.insert(p.0.to_lowercase(), p.1.to_string());
        }

        // Sort the parameters lexicographically by parameter name, in ascending order.
        let mut first = true;
        for key in pairs.keys().sorted() {
            if !first {
                canonicalized_parameters.push('&');
            }
            first = false;
            // Join each parameter key value pair with '='
            let p = format!("{}={}", key, pairs[key]);
            canonicalized_parameters.push_str(&p);
        }
    }

    (path, canonicalized_parameters)
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
