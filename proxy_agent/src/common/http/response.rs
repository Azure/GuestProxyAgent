// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use crate::common::http::headers::Headers;
use std::io::{Error, ErrorKind};

/*
HTTP is a text-based protocol, and a response takes this format:
HTTP-Version Status-Code Reason-Phrase CRLF
headers
CRLF
message-body
 */
pub struct Response {
    // first line of raw response data
    version: String,    // HTTP/1.1
    pub status: String, // 200 OK

    pub headers: Headers,
    body: Vec<u8>,
}

impl Response {
    pub const MISDIRECTED: &'static str = "421 Misdirected Request";
    pub const FORBIDDEN: &'static str = "403 Forbidden Request";
    pub const BAD_GATEWAY: &'static str = "502 Bad Gateway";
    pub const CONTINUE: &'static str = "100 Continue";
    pub const BAD_REQUEST: &'static str = "400 Bad Request";
    pub const OK: &'static str = "200 OK";

    pub fn new(status: String, body: String) -> Self {
        Response {
            status: status,
            version: "HTTP/1.1".to_string(),
            headers: Headers::new(),
            body: body.as_bytes().to_vec(),
        }
    }

    // first line
    // HTTP-Version Status-Code Reason-Phrase CRLF
    pub fn from_first_line(first_line: String) -> Self {
        // parse first line, format "{version} {status}"
        let split = first_line.find(" ");
        let version;
        let mut status = "".to_string();
        match split {
            Some(index) => {
                version = first_line.chars().take(index).collect();
                status = first_line.chars().skip(index + 1).collect();
            }
            None => {
                version = String::from(first_line);
            }
        };

        Response {
            version: version,
            status: status.trim().to_string(),
            headers: Headers::new(),
            body: Vec::new(),
        }
    }

    pub fn from_raw_data(raw_data: String) -> Self {
        // body is after the first empty line
        let mut body = "".to_string();

        let split = raw_data.find(super::DOUBLE_CRLF);
        let first_part;
        match split {
            Some(index) => {
                first_part = raw_data.chars().take(index).collect();
                body = raw_data.chars().skip(index + 4).collect(); // index+2 because of "\r\n\r\n"
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

        let mut response = Response::from_first_line(first_line);
        response.headers = Headers::from_raw_data(raw_headers);
        response.set_body_as_string(body);

        response
    }

    pub fn to_raw_string(&mut self) -> String {
        let mut raw_response = self.get_raw_string_without_body();
        match self.get_body_as_string() {
            Ok(data) => raw_response.push_str(&data),
            Err(_e) => { // ignore the body in binary data
            }
        }

        raw_response
    }

    fn get_raw_string_without_body(&self) -> String {
        let mut raw_response = String::new();
        let first_line = format!("{} {}{}", self.version, self.status, super::CRLF);
        raw_response.push_str(&first_line);
        raw_response.push_str(&self.headers.to_raw_string());
        raw_response.push_str(super::CRLF);

        raw_response
    }

    pub fn to_raw_bytes(&self) -> Vec<u8> {
        let mut data: Vec<u8> = self.get_raw_string_without_body().as_bytes().to_vec();
        data.extend(self.body.iter().copied());

        data
    }

    pub fn description(&self) -> String {
        format!(
            "status: '{}' - headers count: {} - Content-Length: {}",
            self.status,
            self.headers.len(),
            self.headers.get_content_length_as_string()
        )
    }

    pub fn from_status(status: String) -> Self {
        Response::new(status, String::new())
    }

    pub fn new_misdirected_request_reponse() -> Self {
        Response::from_status(Response::MISDIRECTED.to_string())
    }

    pub fn new_forbidden_request_reponse() -> Self {
        Response::from_status(Response::FORBIDDEN.to_string())
    }

    pub fn get_body_as_string(&self) -> std::io::Result<String> {
        match String::from_utf8(self.body.clone()) {
            Ok(data) => return Ok(data),
            Err(e) => {
                let message = format!("Failed convert the body to string, error {}", e);
                return Err(Error::new(ErrorKind::InvalidData, message));
            }
        }
    }

    pub fn set_body(&mut self, body: Vec<u8>) {
        self.body = body;
    }

    pub fn set_body_as_string(&mut self, body: String) {
        self.body = body.as_bytes().to_vec();
    }

    pub fn is_continue_response(&self) -> bool {
        self.status == Response::CONTINUE.to_string()
    }

    pub fn get_body_len(&self) -> usize {
        self.body.len()
    }
}

#[cfg(test)]
mod tests {

    use crate::common::http::response::Response;

    #[test]
    fn response_test() {
        let mut raw_string = "HTTP/1.1 200 OK\r\n".to_string();
        raw_string.push_str("Accept-Ranges: bytes\r\n");
        raw_string.push_str("Age: 6783\r\n");
        raw_string.push_str("Cache-Control: public,max-age=172800\r\n");
        raw_string.push_str("Content-Type: application/vnd.ms-cab-compressed\r\n");
        raw_string.push_str("Date: Wed, 01 Feb 2023 03:43:47 GMT\r\n");
        raw_string.push_str("Etag: \"0c74072de35d91:0\"\r\n");
        raw_string.push_str("Last-Modified: Wed, 01 Feb 2023 01:42:30 GMT\r\n");
        raw_string.push_str("Server: ECAcc (saa/835B)\r\n");
        raw_string.push_str("X-Cache: HIT\r\n");
        raw_string.push_str("X-CCC: US\r\n");
        raw_string.push_str("X-CID: 11\r\n");
        raw_string.push_str("X-Powered-By: ASP.NET\r\n");
        raw_string.push_str("Content-Length: 7227\r\n");
        raw_string.push_str(super::super::CRLF);

        let mut response = Response::from_raw_data(raw_string.to_string());
        let to_raw_string = response.to_raw_string();
        assert_eq!(
            raw_string.len(), // cannot compare the content of the string since the headers are not in the same order in to_raw_string
            to_raw_string.len(),
            "to_raw_string len() mismatch when empty body"
        );

        // Add body with Unicode string
        let mut raw_string = raw_string.to_string();
        raw_string.push_str("Löwe 老虎 Léopard Gepardi");
        let mut request = Response::from_raw_data(raw_string.to_string());
        let to_raw_string = request.to_raw_string();
        assert_eq!(
            raw_string.len(),
            to_raw_string.len(),
            "to_raw_string len() mismatch when body with unicode string"
        );

        // Add body with multiple empty lines
        let mut raw_string = raw_string.to_string();
        raw_string.push_str("\n\nAother line\n");
        let mut request = Response::from_raw_data(raw_string.to_string());
        let to_raw_string = request.to_raw_string();
        assert_eq!(
            raw_string.len(),
            to_raw_string.len(),
            "to_raw_string len() mismatch when body with multple empty lines"
        );
    }
}
