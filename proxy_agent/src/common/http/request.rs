// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use crate::common::http::headers::Headers;
use itertools::Itertools;
use std::{
    collections::HashMap,
    io::{Error, ErrorKind},
};
use url::Url;

/*
HTTP is a text-based protocol, and a request takes this format:
Method Request-URI HTTP-Version CRLF
headers
CRLF
message-body
 */
pub struct Request {
    // first line of raw request data
    pub method: String, // GET, POST, PUT, DELETE, etc
    pub url: String,
    version: String, // HTTP/1.1

    pub headers: Headers,

    body: Vec<u8>,
}

impl Request {
    pub fn new(uri: String, method: String) -> Self {
        Request::create(uri, method, "HTTP/1.1".to_string())
    }

    pub fn create(uri: String, method: String, version: String) -> Self {
        Request {
            method: method,
            url: uri,
            version: version,
            headers: Headers::new(),
            body: Vec::new(),
        }
    }

    pub fn clone_without_body(&self) -> Self {
        Request {
            method: self.method.to_string(),
            url: self.url.to_string(),
            version: self.version.to_string(),
            headers: self.headers.copy(),
            body: Vec::new(),
        }
    }

    // first-line : Method Request-URI HTTP-Version CRLF
    pub fn from_first_line(first_line: String) -> std::io::Result<Self> {
        // parse first line
        let mut iter = first_line.split_whitespace();
        let method = match iter.next() {
            Some(m) => m.to_string(),
            None => {
                let message = format!(
                    "Failed to parse the first line of the request:{}, error: {}",
                    first_line, "method is empty"
                );
                return Err(Error::new(ErrorKind::InvalidData, message));
            }
        };
        let uri = match iter.next() {
            Some(u) => u.to_string(),
            None => {
                let message = format!(
                    "Failed to parse the first line of the request:{}, error: {}",
                    first_line, "uri is empty"
                );
                return Err(Error::new(ErrorKind::InvalidData, message));
            }
        };
        let version = match iter.next() {
            Some(v) => v.to_string(),
            None => {
                let message = format!(
                    "Failed to parse the first line of the request:{}, error: {}",
                    first_line, "version is empty"
                );
                return Err(Error::new(ErrorKind::InvalidData, message));
            }
        };

        Ok(Request::create(uri, method, version))
    }

    pub fn from_raw_request(raw_data: String) -> std::io::Result<Self> {
        // body is after the first empty line
        let mut body = "".to_string();
        let split = raw_data.find(super::DOUBLE_CRLF);
        let first_part;
        match split {
            Some(index) => {
                first_part = raw_data.chars().take(index).collect();
                body = raw_data.chars().skip(index + 4).collect(); // index+4 because of "\r\n\r\n"
            }
            None => {
                first_part = String::from(raw_data);
            }
        }

        // headers starts from second line
        let split = first_part.find(super::CRLF);
        let first_line;
        let mut raw_headers = "".to_string();
        match split {
            Some(index) => {
                first_line = first_part.chars().take(index).collect();
                raw_headers = first_part.chars().skip(index + 2).collect();
            }
            None => {
                first_line = String::from(first_part);
            }
        }

        let mut request = Request::from_first_line(first_line)?;
        request.headers = Headers::from_raw_data(raw_headers);
        request.set_body_as_string(body);

        Ok(request)
    }

    pub fn to_raw_string(&mut self) -> String {
        let mut raw_data = self.get_raw_string_without_body();

        // https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/100
        // a client must send Expect: 100-continue
        // as a header in its initial request and receive a 100 Continue
        // status code in response before sending the body.
        if !self.expect_continue_request() {
            match self.get_body_as_string() {
                Ok(data) => raw_data.push_str(&data),
                Err(_e) => { // ignore the body in binary data
                }
            };
        }

        raw_data
    }

    fn get_raw_string_without_body(&self) -> String {
        let mut raw_data = String::new();

        // first line
        let line = format!(
            "{} {} {}{}",
            self.method,
            self.url,
            self.version,
            super::CRLF
        );
        raw_data.push_str(&line);
        raw_data.push_str(&self.headers.to_raw_string());
        raw_data.push_str(super::CRLF);

        raw_data
    }

    pub fn to_raw_bytes(&self) -> Vec<u8> {
        let mut data: Vec<u8> = self.get_raw_string_without_body().as_bytes().to_vec();
        data.extend(self.body.iter().copied());

        data
    }

    pub fn description(&self) -> String {
        format!(
            "{} {} - headers count: {} - Content-Length: {}",
            self.method,
            self.url,
            self.headers.len(),
            self.headers.get_content_length_as_string()
        )
    }

    pub fn get_url(&self) -> Option<Url> {
        match Url::parse(&self.url) {
            Ok(url) => Some(url),
            Err(_) => None,
        }
    }

    fn get_url_path_and_canonicalized_parameters(&self) -> (String, String) {
        let mut url;
        match Url::parse(&self.url) {
            Ok(u) => url = u,
            Err(_) => {
                url = Url::parse("http://127.0.0.1").unwrap();
                match url.join(&self.url) {
                    Ok(u) => url = u,
                    Err(_) => return (self.url.to_string(), "".to_string()),
                }
            }
        }

        let path = String::from(url.path());

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
                    canonicalized_parameters.push_str("&");
                }
                first = false;
                // Join each parameter key value pair with '='
                let p = format!("{}={}", key, pairs[key]);
                canonicalized_parameters.push_str(&p);
            }
        }

        (path, canonicalized_parameters)
    }

    /*
        StringToSign = Method + "\n" +
               HexEncoded(Body) + "\n" +
               CanonicalizedHeaders + "\n"
               UrlEncodedPath + "\n"
               CanonicalizedParameters;
    */
    pub fn as_sig_input(&self) -> Vec<u8> {
        let mut data: Vec<u8> = self.method.as_bytes().to_vec();
        data.extend(super::LF.as_bytes());
        data.extend(self.body.clone());
        data.extend(super::LF.as_bytes());
        data.extend(self.headers.to_canonicalized_string().as_bytes());

        let path_para = self.get_url_path_and_canonicalized_parameters();
        data.extend(path_para.0.as_bytes());
        data.extend(super::LF.as_bytes());
        data.extend(path_para.1.as_bytes());

        data
    }

    pub fn expect_continue_request(&self) -> bool {
        self.headers.has_expect_continue()
    }

    pub fn set_body(&mut self, body: Vec<u8>) {
        self.body = body;
    }

    pub fn set_body_as_string(&mut self, body: String) {
        // set body
        self.body = body.as_bytes().to_vec();
    }

    fn get_body_as_string(&self) -> std::io::Result<String> {
        match String::from_utf8(self.body.clone()) {
            Ok(data) => return Ok(data),
            Err(e) => {
                let message = format!("Failed convert the body to string, error {}", e);
                return Err(Error::new(ErrorKind::InvalidData, message));
            }
        }
    }

    pub fn get_body(&self) -> &Vec<u8> {
        &self.body
    }

    pub fn get_body_len(&self) -> usize {
        self.body.len()
    }

    // try make sure the request could skip the sig
    // and stream the body to the server directly
    pub fn need_skip_sig(&self) -> bool {
        let method = self.method.to_uppercase();
        let url = self.url.to_lowercase();

        // currently, we agreed to skip the sig for those requests:
        //      o PUT   /vmAgentLog
        //      o POST  /machine/?comp=telemetrydata
        (method == "PUT" || method == "POST")
            && (url == "/machine/?comp=telemetrydata" || url == "/vmagentlog")
    }
}

#[cfg(test)]
mod tests {

    use crate::common::http::request::Request;

    #[test]
    fn request_test() {
        let mut raw_string = "GET http://download.windowsupdate.com/c/msdownload/update/others/2023/02/38363234_2e2f6538d77706f479374be2eec956c5a7544925.cab HTTP/1.1\r\n".to_string();
        raw_string.push_str("Connection: Keep-Alive\r\n");
        raw_string.push_str("Accept: */*\r\n");
        raw_string
            .push_str("User-Agent: Windows-Update-Agent/1022.1108.2012.0 Client-Protocol/2.71\r\n");
        raw_string.push_str("Host: download.windowsupdate.com\r\n");
        raw_string.push_str(super::super::CRLF);

        let mut request = Request::from_raw_request(raw_string.to_string()).unwrap();
        let to_raw_string = request.to_raw_string();
        assert_eq!(
            raw_string.len(), // cannot compare the content of the string since the headers are not in the same order in to_raw_string
            to_raw_string.len(),
            "to_raw_string len() mismatch when empty body"
        );

        // Add body with Unicode string
        let mut raw_string = raw_string.to_string();
        raw_string.push_str("Löwe 老虎 Léopard Gepardi");
        let mut request = Request::from_raw_request(raw_string.to_string()).unwrap();
        let to_raw_string = request.to_raw_string();
        assert_eq!(
            raw_string.len(),
            to_raw_string.len(),
            "to_raw_string len() mismatch when body with unicode string"
        );

        // Add body with multiple empty lines
        let mut raw_string = raw_string.to_string();
        raw_string.push_str("\r\n\r\nAother line\r\n");
        let mut request = Request::from_raw_request(raw_string.to_string()).unwrap();
        let to_raw_string = request.to_raw_string();
        assert_eq!(
            raw_string.len(),
            to_raw_string.len(),
            "to_raw_string len() mismatch when body with multple empty lines"
        );

        let path_para = request.get_url_path_and_canonicalized_parameters();
        assert_eq!("/c/msdownload/update/others/2023/02/38363234_2e2f6538d77706f479374be2eec956c5a7544925.cab",
         path_para.0, "path mismatch");
        assert_eq!("", path_para.1, "query parameters must be empty");
    }

    #[test]
    fn get_url_path_and_canonicalized_parameters_test() {
        let mut raw_string = "GET /machine/a8016240-7286-49ef-8981-63520cb8f6d0/49c242ba%2Dc18a%2D4f6c%2D8cf8%2D85ff790b6431.%5Fzpeng%2Debpf%2Dvm2?comp=config&type=hostingEnvironmentConfig&incarnation=1 HTTP/1.1\r\n".to_string();
        raw_string.push_str("Connection: Keep-Alive\r\n");
        raw_string.push_str("Accept: */*\r\n");
        raw_string.push_str(super::super::CRLF);
        let request = Request::from_raw_request(raw_string.to_string()).unwrap();

        let path_para = request.get_url_path_and_canonicalized_parameters();
        assert_eq!("/machine/a8016240-7286-49ef-8981-63520cb8f6d0/49c242ba%2Dc18a%2D4f6c%2D8cf8%2D85ff790b6431.%5Fzpeng%2Debpf%2Dvm2",
         path_para.0, "path mismatch");
        assert_eq!(
            "comp=config&incarnation=1&type=hostingEnvironmentConfig", path_para.1,
            "query parameters mismatch"
        );
    }
}
