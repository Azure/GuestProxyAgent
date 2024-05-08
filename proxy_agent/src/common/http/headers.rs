// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use crate::common::{constants, logger};
use itertools::Itertools;
use std::collections::HashMap;
use std::io::{Error, ErrorKind};

pub const CONTENT_LENGTH_HEADER_NAME: &str = "Content-Length";
pub const EXPECT_HEADER_NAME: &str = "Expect";
pub const EXPECT_HEADER_VALUE: &str = "100-continue";

pub struct Headers {
    // hash map for the headers
    // key - lower case of original header name
    // (String, String) - original header name and header value
    map: HashMap<String, (String, String)>,
}

impl Headers {
    pub fn new() -> Self {
        Headers {
            map: HashMap::new(),
        }
    }

    pub fn copy(&self) -> Self {
        let mut headers = Headers::new();
        for header in self.map.values() {
            headers.add_header(header.0.to_string(), header.1.to_string());
        }

        headers
    }

    pub fn from_raw_data(raw: String) -> Self {
        let mut headers = Headers::new();

        for line in raw.lines() {
            if line.is_empty() {
                continue;
            }
            headers.add_header_line(line.to_string());
        }

        headers
    }

    fn add_header_line(&mut self, line: String) {
        match line.find(":") {
            Some(split) => {
                let key: String = line.chars().take(split).collect();
                let value: String = line.chars().skip(split + 1).collect();
                self.add_header(key.trim().to_string(), value.trim().to_string());
            }
            None => {
                logger::write_warning(format!(
                    "{} is not a valid header, need to look further why",
                    line
                ));
            }
        }
    }

    pub fn add_header(&mut self, key: String, value: String) {
        let key_lower_case = key.to_lowercase();
        self.map.insert(key_lower_case, (key, value));
    }

    //CanonicalizedHeaders
    //Convert the header names to lowercase
    //Sort the headers lexicographically by header name, in ascending order. Duplicates are not permitted.
    ///Replace any linear whitespaces with a single space (See RFC 2616 Section 4.2  for details). Do not replace whitespace in quoted strings
    //Trim any whitespace around the colon in the header
    //Construct the final string by joining all headers in the list separated by "\n"
    pub fn to_canonicalized_string(&self) -> String {
        let mut canonicalized_headers = String::new();
        let separator = String::from(super::LF);

        for key in self.map.keys().sorted() {
            // skip the expect header
            if key.eq_ignore_ascii_case(constants::AUTHORIZATION_HEADER) {
                continue;
            }
            let h = format!("{}:{}{}", key, self.map[key].1.trim(), separator);
            canonicalized_headers.push_str(&h);
        }

        canonicalized_headers
    }

    // Raw headers with original header name
    pub fn to_raw_string(&self) -> String {
        let mut raw_headers = String::new();

        for key in self.map.keys() {
            let h = format!(
                "{}: {}{}",
                self.map[key].0.trim(),
                self.map[key].1.trim(),
                super::CRLF
            );
            raw_headers.push_str(&h);
        }

        raw_headers
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn has_expect_continue(&self) -> bool {
        let expect_key = EXPECT_HEADER_NAME.to_lowercase();
        if self.map.contains_key(&expect_key) {
            if self.map[&expect_key].1 == EXPECT_HEADER_VALUE {
                return true;
            }
        }

        false
    }

    pub fn get_content_length_as_string(&self) -> String {
        let content_length_key = CONTENT_LENGTH_HEADER_NAME.to_lowercase();
        if self.map.contains_key(&content_length_key) {
            return self.map[&content_length_key].1.to_string();
        }

        String::new()
    }

    pub fn get_content_length(&self) -> std::io::Result<usize> {
        let content_length_key = CONTENT_LENGTH_HEADER_NAME.to_lowercase();
        if self.map.contains_key(&content_length_key) {
            let length = self.map[&content_length_key].1.to_string();
            match length.parse::<usize>() {
                Ok(len) => return Ok(len),
                Err(e) => {
                    let message = format!("Failed parse content-length header, error {}", e);
                    return Err(Error::new(ErrorKind::InvalidData, message));
                }
            }
        }

        Ok(0)
    }
}

#[cfg(test)]
mod tests {
    use crate::common::http::headers::Headers;

    #[test]
    fn headers_test() {
        let raw_string = "Cache-Control: no-cache
        Pragma: no-cache
        Content-Type: application/json; charset=utf-8
        Expires: -1
        Server: Microsoft-IIS/8.5
        X-AspNet-Version: 4.0.30319
        X-Powered-By: ASP.NET
        x-ms-azure-host-authorization: 0000
        Date: Tue, 31 Jan 2023 20:04:32 GMT
        Content-Length: 727";

        let sorted_headers = "cache-control:no-cache
content-length:727
content-type:application/json; charset=utf-8
date:Tue, 31 Jan 2023 20:04:32 GMT
expires:-1
pragma:no-cache
server:Microsoft-IIS/8.5
x-aspnet-version:4.0.30319
x-powered-by:ASP.NET
";
        let mut headers = Headers::from_raw_data(raw_string.to_string());
        let canonicalized = headers.to_canonicalized_string();
        assert_eq!(
            sorted_headers, canonicalized,
            "to_canonicalized_string mismatch"
        );

        // add header value with Unicode
        headers.add_header(
            "my-UNICODE-Header".to_string(),
            "Löwe 老虎 Léopard Gepardi".to_string(),
        );
        let sorted_headers = "cache-control:no-cache
content-length:727
content-type:application/json; charset=utf-8
date:Tue, 31 Jan 2023 20:04:32 GMT
expires:-1
my-unicode-header:Löwe 老虎 Léopard Gepardi
pragma:no-cache
server:Microsoft-IIS/8.5
x-aspnet-version:4.0.30319
x-powered-by:ASP.NET
";
        let canonicalized = headers.to_canonicalized_string();
        assert_eq!(
            sorted_headers, canonicalized,
            "to_canonicalized_string mismatch with unicode header-value"
        );

        // add header value with empty header value
        headers.add_header("my-EMPTY-Header".to_string(), "".to_string());
        let sorted_headers = "cache-control:no-cache
content-length:727
content-type:application/json; charset=utf-8
date:Tue, 31 Jan 2023 20:04:32 GMT
expires:-1
my-empty-header:
my-unicode-header:Löwe 老虎 Léopard Gepardi
pragma:no-cache
server:Microsoft-IIS/8.5
x-aspnet-version:4.0.30319
x-powered-by:ASP.NET
";
        let canonicalized = headers.to_canonicalized_string();
        assert_eq!(
            sorted_headers, canonicalized,
            "to_canonicalized_string mismatch with empty header-value"
        );

        let copied_headers = headers.copy();
        let canonicalized = copied_headers.to_canonicalized_string();
        assert_eq!(
            sorted_headers, canonicalized,
            "to_canonicalized_string mismatch with copied_headers"
        );
    }
}
