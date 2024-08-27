// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

use super::{constants, helpers};
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
use proxy_agent_shared::misc_helpers;
use serde::de::DeserializeOwned;
use std::collections::HashMap;
use tokio::net::TcpStream;

const LF: &str = "\n";

pub async fn get<T, F>(
    full_url: Uri,
    headers: &HashMap<String, String>,
    key_guid: Option<String>,
    key: Option<String>,
    log_fun: F,
) -> std::io::Result<T>
where
    T: DeserializeOwned,
    F: Fn(String) + Send + 'static,
{
    let request = build_request(Method::GET, full_url.clone(), headers, None, key_guid, key)?;

    let (host, port) = host_port_from_uri(full_url.clone())?;
    let response = match send_request(&host, port, request, log_fun).await {
        Ok(r) => r,
        Err(e) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Failed to send request to {}: {}", full_url, e),
            ))
        }
    };
    let status = response.status();
    if !status.is_success() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!(
                "Failed to get response from {}, status code: {}",
                full_url, status
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
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Failed to get next frame from response: {}", e),
                ))
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
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "utf-32 charset is not supported",
                    ))
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
            Err(e) => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!(
                    "Failed to xml deserialize response body with content_type {} from: {} with error {}",
               content_type,     body_string, e
                ),
            )),
        },
        // default to json
        _ => match serde_json::from_str(&body_string) {
            Ok(t) => Ok(t),
            Err(e) => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!(
                    "Failed to json deserialize response body with {} from: {} with error {}",
                  content_type,  body_string, e
                ),
            )),
        },
    }
}

pub fn build_request(
    method: http::Method,
    full_url: Uri,
    headers: &HashMap<String, String>,
    body: Option<&[u8]>,
    key_guid: Option<String>,
    key: Option<String>,
) -> std::io::Result<Request<BoxBody<Bytes, hyper::Error>>> {
    let (host, _) = host_port_from_uri(full_url.clone())?;

    let mut request_builder = Request::builder()
        .method(method)
        .uri(match full_url.path_and_query() {
            Some(pq) => pq.as_str(),
            None => full_url.path(),
        })
        .header(
            constants::DATE_HEADER,
            misc_helpers::get_date_time_rfc1123_string(),
        )
        .header(hyper::header::HOST, host)
        .header(
            constants::CLAIMS_HEADER,
            format!("{{ \"{}\": \"{}\"}}", constants::CLAIMS_IS_ROOT, true,),
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

    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Failed to establish connection to {}: {}", addr, e),
            )
        })?;

    tokio::task::spawn(async move {
        if let Err(err) = conn.await {
            log_fun(format!("Connection failed: {:?}", err));
        }
    });

    sender.send_request(request).await.map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Failed to send request: {:?}", e),
        )
    })
}

pub fn host_port_from_uri(full_url: Uri) -> std::io::Result<(String, u16)> {
    let host = match full_url.host() {
        Some(h) => h.to_string(),
        None => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Failed to get host from uri {}", full_url),
            ))
        }
    };
    let port = full_url.port_u16().unwrap_or(80);

    Ok((host, port))
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
    let path_para = get_path_and_canonicalized_parameters(head.uri.clone());
    data.extend(path_para.0.as_bytes());
    data.extend(LF.as_bytes());
    data.extend(path_para.1.as_bytes());

    data
}

fn request_to_sign_input(
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
            let path_para = get_path_and_canonicalized_parameters(u.clone());
            data.extend(path_para.0.as_bytes());
            data.extend(LF.as_bytes());
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
        if key.eq_ignore_ascii_case(constants::AUTHORIZATION_HEADER) {
            continue;
        }
        let h = format!("{}:{}{}", key, map[key].1.trim(), separator);
        canonicalized_headers.push_str(&h);
    }

    canonicalized_headers
}

fn get_path_and_canonicalized_parameters(url: hyper::Uri) -> (String, String) {
    let path = url.path().to_string();

    let query_pairs = query_pairs(&url);
    let mut canonicalized_parameters = String::new();
    let mut pairs: HashMap<String, (String, String)> = HashMap::new();
    if !query_pairs.is_empty() {
        for (key, value) in query_pairs {
            let key = key.to_lowercase();
            pairs.insert(
                // add the query paramter value for sorting,
                // just in case of duplicate keys by value lexicographically in ascending order.
                format!("{}{}", key, value),
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

#[cfg(test)]
mod tests {
    #[test]
    fn get_path_and_canonicalized_parameters_test() {
        let url_str = "/machine/a8016240-7286-49ef-8981-63520cb8f6d0/49c242ba%2Dc18a%2D4f6c%2D8cf8%2D85ff790b6431.%5Fzpeng%2Debpf%2Dvm2?comp=config&keyOnly&comp=again&type=hostingEnvironmentConfig&incarnation=1&resource=https%3a%2f%2fstorage.azure.com%2f";
        let url = url_str.parse::<hyper::Uri>().unwrap();
        let path_para = super::get_path_and_canonicalized_parameters(url);
        assert_eq!("/machine/a8016240-7286-49ef-8981-63520cb8f6d0/49c242ba%2Dc18a%2D4f6c%2D8cf8%2D85ff790b6431.%5Fzpeng%2Debpf%2Dvm2",
         path_para.0, "path mismatch");
        assert_eq!(
            "comp=again&comp=config&incarnation=1&keyonly&resource=https%3a%2f%2fstorage.azure.com%2f&type=hostingEnvironmentConfig", path_para.1,
            "query parameters mismatch"
        );
    }
}