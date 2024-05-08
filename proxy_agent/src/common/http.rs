// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
pub mod headers;
pub mod http_request;
pub mod request;
pub mod response;

#[cfg(windows)]
mod windows;

use crate::common::http::http_request::HttpRequest;
use request::Request;
use response::Response;
use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use std::{
    io::{prelude::*, BufReader},
    net::TcpStream,
};

use self::headers::Headers;

pub const LF: &str = "\n";
pub const CRLF: &str = "\r\n";
pub const DOUBLE_CRLF: &str = "\r\n\r\n";

// receive TcpStream in string format
// the stream len must less than DEFAULT_BUF_SIZE
pub fn receive_data_in_string(stream: &TcpStream) -> std::io::Result<String> {
    let mut reader = BufReader::new(stream);
    let received: Vec<u8> = reader.fill_buf()?.to_vec();
    let rec_data;
    match String::from_utf8(received) {
        Ok(data) => rec_data = data,
        Err(e) => {
            let message = format!("Failed convert the received data to string, error {}", e);
            return Err(Error::new(ErrorKind::InvalidData, message));
        }
    }
    reader.consume(rec_data.len());

    Ok(rec_data)
}

// send request and receive response body in string
// use this method only if you are sure
// both the request and response body are string and small
pub fn get_response_in_string(http_req: &mut HttpRequest) -> std::io::Result<Response> {
    let addrs = format!("{}:{}", http_req.get_host(), http_req.get_port());
    let mut client = TcpStream::connect(addrs)?;
    _ = client.write_all(http_req.request.to_raw_string().as_bytes());
    _ = client.flush();

    let data = receive_data_in_string(&client)?;
    let mut response = Response::from_raw_data(data);

    // check the body is streamed or not
    match response.headers.get_content_length() {
        Ok(len) => {
            let body_len = response.get_body_len();
            if len != 0 && body_len == 0 {
                response.set_body_as_string(receive_data_in_string(&client)?);
            }
        }
        Err(_) => {}
    }

    Ok(response)
}

pub fn receive_request_data(stream: &TcpStream) -> std::io::Result<Request> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();

    reader.read_line(&mut line)?;
    let mut request = Request::from_first_line(line)?;
    request.headers = Headers::from_raw_data(read_header_lines(&mut reader)?);

    // if request contains expects continue header,
    // the body will send at next socket data
    if !request.expect_continue_request() {
        let content_length = request.headers.get_content_length()?;
        request.set_body(receive_body_internal(&mut reader, content_length)?);
    }

    Ok(request)
}

pub fn receive_response_data(stream: &TcpStream) -> std::io::Result<Response> {
    let mut reader = BufReader::new(stream);
    let mut response = read_response_without_body(&mut reader)?;

    let content_length = response.headers.get_content_length()?;
    response.set_body(receive_body_internal(&mut reader, content_length)?);

    Ok(response)
}

fn read_header_lines(reader: &mut BufReader<&TcpStream>) -> std::io::Result<String> {
    let mut lines = String::new();

    loop {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        lines.push_str(&line);

        let line = line.trim();
        if line.len() == 0 {
            // empty line means end of the headers section
            break;
        }
    }

    Ok(lines)
}

fn receive_body_internal(
    reader: &mut BufReader<&TcpStream>,
    len: usize,
) -> std::io::Result<Vec<u8>> {
    let mut data: Vec<u8> = Vec::new();
    while data.len() < len {
        match reader.fill_buf() {
            Ok(d) => {
                let received = d.to_vec();
                let received_len = received.len();
                reader.consume(received_len);
                data.extend(received.iter().copied());
            }
            Err(_e) => {
                // read timeout, assume no more incoming data in the TcpStream
                return Ok(data);
            }
        };
    }

    Ok(data)
}

pub fn receive_body(stream: &TcpStream, content_length: usize) -> std::io::Result<Vec<u8>> {
    let mut reader = BufReader::new(stream);
    receive_body_internal(&mut reader, content_length)
}

fn stream_body_internal(
    mut reader: BufReader<&TcpStream>,
    mut dest_stream: &TcpStream,
    len: usize,
) -> std::io::Result<usize> {
    let mut received: usize = 0;

    while received < len {
        match reader.fill_buf() {
            Ok(d) => {
                let read = d.len();
                dest_stream.write_all(d)?;
                reader.consume(read);
                received = received + read;
            }
            Err(_e) => {
                // read timeout, assume no more incoming data in the TcpStream
                break;
            }
        };
    }

    dest_stream.flush()?;
    Ok(received)
}

// receive body from source stream and,
// send to dest stream directly
pub fn stream_body(
    source_stream: &TcpStream,
    dest_stream: &TcpStream,
    content_length: usize,
) -> std::io::Result<usize> {
    let reader = BufReader::new(source_stream);
    stream_body_internal(reader, dest_stream, content_length)
}

// forward response from server TcpStream to client TcpStream
// insert extra headers if have
pub fn forward_response(
    server_stream: &TcpStream,
    mut client_stream: &TcpStream,
    extra_headers: HashMap<&str, &str>,
) -> std::io::Result<(Response, usize)> {
    let mut response_reader = BufReader::new(server_stream);

    let mut response_without_body;
    match read_response_without_body(&mut response_reader) {
        Ok(r) => response_without_body = r,
        Err(e) => {
            let message = format!("Failed to read response without body from Host - {}", e);
            return Err(Error::new(e.kind(), message));
        }
    }

    if response_without_body.is_continue_response() {
        return Ok((response_without_body, 0));
    }

    // insert extra headers
    for (key, value) in extra_headers {
        response_without_body
            .headers
            .add_header(key.to_string(), value.to_string());
    }
    match client_stream.write_all(&response_without_body.to_raw_bytes()) {
        Ok(_) => {}
        Err(e) => {
            let message = format!("Failed to write response without body to Guest - {}", e);
            return Err(Error::new(e.kind(), message));
        }
    }

    // stream body
    let content_length;
    match response_without_body.headers.get_content_length() {
        Ok(len) => content_length = len,
        Err(e) => {
            let message = format!("Failed to get content length {}", e);
            return Err(Error::new(e.kind(), message));
        }
    }

    let forwarded;
    match stream_body_internal(response_reader, client_stream, content_length) {
        Ok(len) => forwarded = len,
        Err(e) => {
            let message = format!("Failed to stream body {}", e);
            return Err(Error::new(e.kind(), message));
        }
    }

    Ok((response_without_body, forwarded))
}

fn read_response_without_body(
    response_reader: &mut BufReader<&TcpStream>,
) -> std::io::Result<Response> {
    let mut line = String::new();
    response_reader.read_line(&mut line)?;
    let mut response = Response::from_first_line(line);

    response.headers = Headers::from_raw_data(read_header_lines(response_reader)?);

    Ok(response)
}

pub fn connect_to_server(
    ip: String,
    port: u16,
    _client_stream: &TcpStream,
) -> std::io::Result<TcpStream> {
    let server_stream;
    #[cfg(windows)]
    {
        server_stream = windows::connect_with_redirect_record(ip, port, _client_stream)?;
    }
    #[cfg(not(windows))]
    {
        // Linux does not have the redirect record feature,
        // hence it will avoid the redirect by skip_process_map in ebpf program.
        server_stream = TcpStream::connect(format!("{}:{}", ip, port))?;
    }

    Ok(server_stream)
}

pub fn htons(u: u16) -> u16 {
    u.to_be()
}

pub fn ntohs(u: u16) -> u16 {
    u16::from_be(u)
}


#[cfg(test)]
mod tests {

    use super::headers;
    use crate::common::http;
    use crate::common::http::http_request::HttpRequest;
    use crate::common::http::response::Response;
    use crate::common::http::Request;
    use std::fs;
    use std::io::Write;
    use std::net::TcpListener;
    use std::net::TcpStream;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;
    use url::Url;

    const ENDPOINT_ADDRESS: &str = "127.0.0.1:8082";
    #[test]
    fn http_binary_body_test() {
        let shut_down: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
        let cloned_shut_down = shut_down.clone();

        let listener_thread = thread::Builder::new()
            .name("listener".to_string())
            .spawn(move || {
                let listener = TcpListener::bind(ENDPOINT_ADDRESS).unwrap();
                for stream in listener.incoming() {
                    if cloned_shut_down.load(Ordering::Relaxed) {
                        break;
                    }
                    let stream = stream.unwrap();
                    handle_binary_body(stream);
                }
            })
            .unwrap();
        thread::sleep(Duration::from_millis(100));

        //// test GET response with binary data
        test_get_response_binary();

        // test POST requests
        test_post_requests();

        // stop listener thread
        shut_down.store(true, Ordering::Relaxed);
        _ = TcpStream::connect(ENDPOINT_ADDRESS);
        listener_thread.join().unwrap();
    }

    fn handle_binary_body(mut stream: TcpStream) {
        // set read timeout to handle the case when body content is less than Content-Length in request header
        _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
        let mut request = http::receive_request_data(&stream).unwrap();

        let mut response = Response::from_status(Response::OK.to_string());
        if request.method == "GET" {
            let file = std::env::current_exe().unwrap();
            let body = fs::read(file).unwrap();
            response.headers.add_header(
                headers::CONTENT_LENGTH_HEADER_NAME.to_string(),
                body.len().to_string(),
            );
            response.set_body(body);
            _ = stream.write_all(&response.to_raw_bytes());
            _ = stream.flush();
        } else if request.method == "POST" {
            let content_length = request.headers.get_content_length().unwrap();

            if request.expect_continue_request() {
                if request.get_body_len() != 0 {
                    send_response(
                        &stream,
                        Response::BAD_REQUEST,
                        "request body_len must be 0 for expect_continue_request",
                    );
                    return;
                }

                let mut response = Response::from_status(Response::CONTINUE.to_string());
                _ = stream.write_all(response.to_raw_string().as_bytes());
                _ = stream.flush();

                request.set_body(http::receive_body(&stream, content_length).unwrap());
            }

            // check actual body length against content-length
            if request.get_body_len() != content_length {
                send_response(&stream, Response::BAD_REQUEST, "request body_len mistmatch");
                return;
            }

            return send_response(&stream, Response::OK, "");
        }
    }

    fn send_response(mut stream: &TcpStream, response_status: &str, response_message: &str) {
        let mut response = Response::from_status(response_status.to_string());
        let len = response_message.len();
        if len > 0 {
            response.set_body_as_string(response_message.to_string());
        }

        _ = stream.write_all(&response.to_raw_bytes());
        _ = stream.flush();
    }

    fn test_get_response_binary() {
        let mut client = TcpStream::connect(ENDPOINT_ADDRESS).unwrap();
        let mut request = Request::new("/file".to_string(), "GET".to_string());
        client
            .write_all(request.to_raw_string().as_bytes())
            .unwrap();
        client.flush().unwrap();

        let response = http::receive_response_data(&client).unwrap();
        assert_eq!(
            response.headers.get_content_length().unwrap(),
            response.get_body_len(),
            "get_body_len and content_length mismatch."
        );

        let file = std::env::current_exe().unwrap();
        assert_eq!(
            file.metadata().unwrap().len() as usize,
            response.get_body_len(),
            "get_body_len and file length mismatch."
        );
    }

    fn test_post_requests() {
        let file = std::env::current_exe().unwrap();
        let body = fs::read(file).unwrap();
        let uri = format!("http://{ENDPOINT_ADDRESS}/file");
        let mut request = Request::new(uri.to_string(), "POST".to_string());
        request.headers.add_header(
            headers::CONTENT_LENGTH_HEADER_NAME.to_string(),
            body.len().to_string(),
        );

        // send request with incorrect body size
        request.set_body_as_string("small body".to_string());
        let mut http_req = HttpRequest::clone_without_body(Url::parse(&uri).unwrap(), &request);
        let response = http::get_response_in_string(&mut http_req).unwrap();
        assert_eq!(
            Response::BAD_REQUEST,
            response.status,
            "response.status mismatch"
        );
        assert_eq!(
            "request body_len mistmatch",
            response.get_body_as_string().unwrap(),
            "response body mismatch"
        );

        // send request with full body directly
        request.set_body(body);
        let mut client_stream = TcpStream::connect(ENDPOINT_ADDRESS).unwrap();
        _ = client_stream.write_all(&request.to_raw_bytes());
        _ = client_stream.flush();
        let response = http::receive_response_data(&client_stream).unwrap();
        assert_eq!(Response::OK, response.status, "response.status must be OK");
        assert_eq!(
            "",
            response.get_body_as_string().unwrap(),
            "response body must be empty"
        );

        // add expect-continue header
        request.headers.add_header(
            headers::EXPECT_HEADER_NAME.to_string(),
            headers::EXPECT_HEADER_VALUE.to_string(),
        );
        let mut client_stream = TcpStream::connect(ENDPOINT_ADDRESS).unwrap();
        _ = client_stream.write_all(&request.to_raw_string().as_bytes());
        _ = client_stream.flush();
        let response = http::receive_response_data(&client_stream).unwrap();
        assert_eq!(
            Response::CONTINUE,
            response.status,
            "response.status must be CONTINUE"
        );
        assert_eq!(
            "",
            response.get_body_as_string().unwrap(),
            "response body must be empty"
        );

        // Send body only after CONTINUE response
        _ = client_stream.write_all(&request.get_body());
        _ = client_stream.flush();
        let response = http::receive_response_data(&client_stream).unwrap();
        assert_eq!(Response::OK, response.status, "response.status must be OK");
        assert_eq!(
            "",
            response.get_body_as_string().unwrap(),
            "response body must be empty"
        );
    }
}
