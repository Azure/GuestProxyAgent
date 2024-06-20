// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use super::proxy_authentication;
use super::proxy_pool::ProxyPool;
use crate::common::config;
use crate::common::constants;
use crate::common::helpers;
use crate::common::http;
use crate::common::http::request::Request;
use crate::common::http::response::Response;
use crate::common::logger;
use crate::provision;
use crate::proxy::proxy_connection::Connection;
use crate::proxy::proxy_summary::ProxySummary;
use crate::proxy::Claims;
use crate::proxy_agent_status;
use crate::redirector;
use crate::shared_state::{key_keeper_wrapper, proxy_listener_wrapper, SharedState};
use proxy_agent_shared::misc_helpers;
use proxy_agent_shared::proxy_agent_aggregate_status::{ModuleState, ProxyAgentDetailStatus};
use proxy_agent_shared::telemetry::event_logger;
use std::collections::HashMap;
use std::io::prelude::*;
use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use std::time::Instant;

pub fn start_async(port: u16, pool_size: u16, shared_state: Arc<Mutex<SharedState>>) {
    _ = thread::Builder::new()
        .name("proxy_listener".to_string())
        .spawn(move || {
            start(port, pool_size, shared_state);
        });
}

fn start(port: u16, pool_size: u16, shared_state: Arc<Mutex<SharedState>>) {
    Connection::init_logger(config::get_logs_dir());

    // listen to wildcard ip address to accept request from
    // loopback address and local ip addresses
    let addr = format!("{}:{}", Ipv4Addr::UNSPECIFIED, port);
    logger::write(format!("Start proxy listener at '{}'.", &addr));

    let listener = match TcpListener::bind(&addr) {
        Ok(l) => l,
        Err(e) => {
            let message = format!("Failed to bind TcpListener '{}' with error {}.", addr, e);
            proxy_listener_wrapper::set_status_message(shared_state.clone(), message.to_string());
            logger::write_error(message);
            return;
        }
    };

    let message = helpers::write_startup_event(
        "Started proxy listener, ready to accept request",
        "start",
        "proxy_listener",
        logger::AGENT_LOGGER_KEY,
    );
    proxy_listener_wrapper::set_status_message(shared_state.clone(), message.to_string());
    provision::listener_started(shared_state.clone());

    let pool = ProxyPool::new(pool_size as usize);

    for connection in listener.incoming() {
        if proxy_listener_wrapper::get_shutdown(shared_state.clone()) {
            let message = "Stop signal received, stop the listener.";
            proxy_listener_wrapper::set_status_message(shared_state.clone(), message.to_string());
            logger::write_warning(message.to_string());
            break;
        }
        let mut connection_count: u128 =
            proxy_listener_wrapper::get_connection_count(shared_state.clone());
        if connection_count == u128::MAX {
            // reset connection count
            connection_count = 0;
        }
        connection_count += 1;
        proxy_listener_wrapper::set_connection_count(shared_state.clone(), connection_count);

        let cloned_shared_state = shared_state.clone();
        match connection {
            Ok(stream) => {
                pool.execute(move || {
                    let mut connection = Connection {
                        stream,
                        id: connection_count,
                        now: Instant::now(),
                        cliams: None,
                        ip: String::new(),
                        port: 0,
                    };
                    handle_connection(&mut connection, cloned_shared_state);
                });
            }
            Err(e) => {
                logger::write_warning(format!("Incoming connection with error {e}; ignore it."));
                continue;
            }
        }
    }

    logger::write("ProxyListener stopped accepting new request.".to_string());
}

pub fn stop(port: u16, shared_state: Arc<Mutex<SharedState>>) {
    proxy_listener_wrapper::set_shutdown(shared_state.clone(), true);
    let _ = TcpStream::connect(format!("127.0.0.1:{}", port));
    logger::write_warning("Sending stop signal.".to_string());
}

fn handle_connection(connection: &mut Connection, shared_state: Arc<Mutex<SharedState>>) {
    let stream = &connection.stream;
    Connection::write_information(connection.id, "Received connection.".to_string());

    // set read timeout to handle the case
    // when the actual body content is less than
    // Content-Length in request header
    _ = stream.set_read_timeout(Some(Duration::from_secs(10)));

    // received data from original client
    let mut request: Request;
    match http::receive_request_data(stream) {
        Ok(data) => request = data,
        Err(e) => {
            Connection::write_warning(
                connection.id,
                format!("Failed to received data from client: {}", e),
            );
            return;
        }
    };
    Connection::write_warning(
        connection.id,
        format!("Got request: {}", request.description()),
    );

    // lookup the eBPF audit_map
    let client_source_ip: IpAddr;
    let client_source_port: u16;
    match stream.peer_addr() {
        Ok(addr) => {
            client_source_port = addr.port();
            client_source_ip = addr.ip();
            Connection::write(
                connection.id,
                format!(
                    "Got request from client - {}:{}",
                    client_source_ip, client_source_port
                ),
            );
        }
        Err(e) => {
            Connection::write_warning(
                connection.id,
                format!("Failed to get client_source_port: {}", e),
            );
            return;
        }
    };
    let entry;
    match redirector::lookup_audit(client_source_port) {
        Ok(data) => entry = data,
        Err(e) => {
            let err = format!("Failed to get lookup_audit: {}", e);
            event_logger::write_event(
                event_logger::WARN_LEVEL,
                err,
                "handle_connection",
                "proxy_listener",
                Connection::CONNECTION_LOGGER_KEY,
            );

            Connection::write_information(
                connection.id,
                "Try to get audit entry from socket stream".to_string(),
            );
            match redirector::get_audit_from_stream(stream) {
                Ok(data) => entry = data,
                Err(e) => {
                    if e.kind() != std::io::ErrorKind::Unsupported {
                        let err = format!("Failed to get lookup_audit_from_stream: {}", e);
                        event_logger::write_event(
                            event_logger::WARN_LEVEL,
                            err,
                            "handle_connection",
                            "proxy_listener",
                            Connection::CONNECTION_LOGGER_KEY,
                        );
                    }
                    send_response(stream, Response::MISDIRECTED);
                    log_connection_summary(connection, &request, Response::MISDIRECTED.to_string());
                    return;
                }
            }
        }
    }
    let claims = Claims::from_audit_entry(&entry, client_source_ip);

    let claim_details: String = match serde_json::to_string(&claims) {
        Ok(json) => json,
        Err(e) => {
            Connection::write_warning(
                connection.id,
                format!("Failed to get claim json string: {}", e),
            );
            send_response(stream, Response::MISDIRECTED);
            log_connection_summary(connection, &request, Response::MISDIRECTED.to_string());
            return;
        }
    };
    Connection::write(connection.id, claim_details.to_string());
    connection.cliams = Some(claims.clone());

    // Get the dst ip and port to remote server
    let (ip, port);
    ip = redirector::ip_to_string(entry.destination_ipv4);
    port = http::ntohs(entry.destination_port);
    Connection::write(connection.id, format!("Use lookup value:{ip}:{port}."));
    connection.ip = ip.to_string();
    connection.port = port;

    // authenticate the connection
    let auth = proxy_authentication::get_authenticate(ip.to_string(), port, claims.clone());
    Connection::write(connection.id, format!("Got auth: {}", auth.to_string()));
    if !auth.authenticate(connection.id, request.url.to_string()) {
        Connection::write_warning(
            connection.id,
            format!("Denied unauthorize request: {}", claim_details),
        );
        send_response(stream, Response::FORBIDDEN);
        log_connection_summary(connection, &request, Response::FORBIDDEN.to_string());
        return;
    }

    // start new request to the Host endpoint
    let mut server_stream;
    match http::connect_to_server(ip.to_string(), port, stream) {
        Ok(data) => server_stream = data,
        Err(e) => {
            Connection::write_warning(
                connection.id,
                format!("Failed to start new request to host: {}", e),
            );
            send_response(stream, Response::MISDIRECTED);
            log_connection_summary(connection, &request, Response::MISDIRECTED.to_string());
            return;
        }
    }

    // Add required headers
    let host_claims = format!(
        "{{ \"{}\": \"{}\"}}",
        constants::CLAIMS_IS_ROOT,
        claims.runAsElevated
    );
    request.headers.add_header(
        constants::CLAIMS_HEADER.to_string(),
        host_claims.to_string(),
    );
    request.headers.add_header(
        constants::DATE_HEADER.to_string(),
        misc_helpers::get_date_time_rfc1123_string(),
    );

    if request.need_skip_sig() {
        // skip the signature and send the request headers to host now
        return handle_connection_without_signature(connection, request, &mut server_stream);
    }

    handle_connection_with_signature(
        connection,
        request,
        &mut server_stream,
        shared_state.clone(),
    );
}

fn handle_connection_with_signature(
    connection: &mut Connection,
    mut request: Request,
    server_stream: &mut TcpStream,
    shared_state: Arc<Mutex<SharedState>>,
) {
    let client_stream = &connection.stream;
    if request.expect_continue_request() {
        handle_expect_continue_request(connection, client_stream, &mut request);
    }

    // Add header x-ms-azure-host-authorization
    if let Some(key) = key_keeper_wrapper::get_current_key_value(shared_state.clone()) {
        if let Some(key_guid) = key_keeper_wrapper::get_current_key_guid(shared_state.clone()) {
            let input_to_sign = request.as_sig_input();
            match helpers::compute_signature(key.to_string(), input_to_sign.as_slice()) {
                Ok(sig) => {
                    match String::from_utf8(input_to_sign) {
                        Ok(data) => Connection::write(
                            connection.id,
                            format!("Computed the signature with input: {}", data),
                        ),
                        Err(e) => {
                            Connection::write_warning(
                                connection.id,
                                format!("Failed convert the input_to_sign to string, error {}", e),
                            );
                        }
                    }

                    let authorization_value =
                        format!("{} {} {}", constants::AUTHORIZATION_SCHEME, key_guid, sig);
                    request.headers.add_header(
                        constants::AUTHORIZATION_HEADER.to_string(),
                        authorization_value.to_string(),
                    );
                    Connection::write(
                        connection.id,
                        format!("Added authorization header {}", authorization_value),
                    )
                }
                Err(e) => {
                    Connection::write_error(
                        connection.id,
                        format!("compute_signature failed with error: {}", e),
                    );
                }
            }
        }
    } else {
        Connection::write(
            connection.id,
            "current key is empty, skip compute signature for testing.".to_string(),
        );
    }

    // send to remote server
    _ = server_stream.write_all(request.as_raw_string().as_bytes());
    _ = server_stream.flush();

    // insert default x-ms-azure-host-authorization header to let the client know it is through proxy agent
    let mut extra_response_headers: HashMap<&str, &str> = HashMap::new();
    extra_response_headers.insert(constants::AUTHORIZATION_HEADER, "value");

    let mut response_without_body;
    match http::forward_response(server_stream, client_stream, extra_response_headers.clone()) {
        Ok(data) => {
            response_without_body = data.0;
            Connection::write(
                connection.id,
                format!(
                    "Forwarded host response: {}, streamed body length: {}",
                    response_without_body.description(),
                    data.1
                ),
            );
        }
        Err(e) => {
            Connection::write_warning(
                connection.id,
                format!("Failed to forward response from host: {}", e),
            );
            return;
        }
    };

    if response_without_body.is_continue_response() {
        Connection::write(
            connection.id,
            "Current response expect sending original request body now.".to_string(),
        );
        _ = server_stream.write_all(request.get_body());
        _ = server_stream.flush();

        match http::forward_response(server_stream, client_stream, extra_response_headers.clone()) {
            Ok(data) => {
                response_without_body = data.0;
                Connection::write(
                    connection.id,
                    format!(
                        "Forwarded host response: {}, streamed body length: {}",
                        response_without_body.description(),
                        data.1
                    ),
                );
            }
            Err(e) => {
                Connection::write_warning(
                    connection.id,
                    format!("Failed to forward response from host: {}", e),
                );
                return;
            }
        };
    }

    log_connection_summary(
        connection,
        &request,
        response_without_body.status.to_string(),
    );
}

fn handle_expect_continue_request(
    connection: &Connection,
    client_stream: &TcpStream,
    request: &mut Request,
) {
    // send 'continue' response to the original client
    send_response(client_stream, Response::CONTINUE);

    let content_length = match request.headers.get_content_length() {
        Ok(len) => len,
        Err(e) => {
            Connection::write_warning(connection.id, format!(" {}", e));
            send_response(client_stream, Response::BAD_REQUEST);
            log_connection_summary(connection, request, Response::BAD_REQUEST.to_string());
            return;
        }
    };

    // receive body content from client

    let data = match http::receive_body(client_stream, content_length) {
        Ok(d) => d,
        Err(e) => {
            Connection::write_warning(
                connection.id,
                format!("Failed to received body from client: {}", e),
            );
            send_response(client_stream, Response::BAD_REQUEST);
            log_connection_summary(connection, request, Response::BAD_REQUEST.to_string());
            return;
        }
    };
    request.set_body(data);
}

fn handle_connection_without_signature(
    connection: &mut Connection,
    mut request: Request,
    server_stream: &mut TcpStream,
) {
    Connection::write_information(
        connection.id,
        format!(
            "Current request {} could send to host without signature.",
            request.description()
        ),
    );
    let mut client_stream = &connection.stream;

    // send the request without signature to host
    _ = server_stream.write_all(request.as_raw_string().as_bytes());
    _ = server_stream.flush();
    let mut response;
    match http::receive_response_data(server_stream) {
        Ok(data) => response = data,
        Err(e) => {
            Connection::write_warning(
                connection.id,
                format!("Failed to receive data from host: {}", e),
            );
            send_response(client_stream, Response::BAD_GATEWAY);
            log_connection_summary(connection, &request, Response::BAD_GATEWAY.to_string());
            return;
        }
    };
    Connection::write(
        connection.id,
        format!("Received host response: {}", response.description()),
    );

    if response.is_continue_response() {
        let content_length = match request.headers.get_content_length() {
            Ok(len) => len,
            Err(e) => {
                Connection::write_warning(connection.id, format!(" {}", e));
                send_response(client_stream, Response::BAD_REQUEST);
                log_connection_summary(connection, &request, Response::BAD_REQUEST.to_string());
                return;
            }
        };

        // send 'continue' response to the original client
        send_response(client_stream, Response::CONTINUE);

        Connection::write(
            connection.id,
            "Current response expect streaming original body now.".to_string(),
        );
        match http::stream_body(client_stream, server_stream, content_length) {
            Ok(l) => {
                if l < content_length {
                    Connection::write_warning(
                        connection.id,
                        format!(
                            "Streamed data {} from request body is less than Content-Length {}",
                            l, content_length
                        ),
                    );
                    send_response(client_stream, Response::BAD_REQUEST);
                    log_connection_summary(connection, &request, Response::BAD_REQUEST.to_string());
                    return;
                }
            }
            Err(e) => {
                Connection::write_warning(
                    connection.id,
                    format!("Failed streaming the request body, error {}", e),
                );
                send_response(client_stream, Response::BAD_GATEWAY);
                log_connection_summary(connection, &request, Response::BAD_GATEWAY.to_string());
                return;
            }
        };

        match http::receive_response_data(server_stream) {
            Ok(data) => response = data,
            Err(e) => {
                Connection::write_warning(
                    connection.id,
                    format!("Failed to receive data from host: {}", e),
                );
                send_response(client_stream, Response::BAD_GATEWAY);
                log_connection_summary(connection, &request, Response::BAD_GATEWAY.to_string());
                return;
            }
        };
        Connection::write(
            connection.id,
            format!("Received host response: {}", response.description()),
        );
    }

    // insert default x-ms-azure-host-authorization header to let the client know it is through proxy agent
    response.headers.add_header(
        constants::AUTHORIZATION_HEADER.to_string(),
        "value".to_string(),
    );

    // response to original client
    _ = client_stream.write_all(&response.to_raw_bytes());
    _ = client_stream.flush();

    log_connection_summary(connection, &request, response.status.to_string());
}

fn log_connection_summary(connection: &Connection, request: &Request, response_status: String) {
    let elapsed_time = connection.now.elapsed();
    let claims = match &connection.cliams {
        Some(c) => c.clone(),
        None => Claims::empty(),
    };

    let summary = ProxySummary {
        userId: claims.userId,
        userName: claims.userName.to_string(),
        userGroups: claims.userGroups.clone(),
        clientIp: claims.clientIp.to_string(),
        processFullPath: claims.processFullPath.to_string(),
        processCmdLine: claims.processCmdLine.to_string(),
        runAsElevated: claims.runAsElevated,
        method: request.method.to_string(),
        url: request.url.to_string(),
        ip: connection.ip.to_string(),
        port: connection.port,
        responseStatus: response_status.to_string(),
        elapsedTime: elapsed_time.as_millis(),
    };
    if let Ok(json) = serde_json::to_string(&summary) {
        event_logger::write_event(
            event_logger::INFO_LEVEL,
            json,
            "log_connection_summary",
            "proxy_listener",
            Connection::CONNECTION_LOGGER_KEY,
        );
    };
    proxy_agent_status::add_connection_summary(summary, false);
}

fn send_response(mut client_stream: &TcpStream, status: &str) {
    let mut response = Response::from_status(status.to_string());

    // insert default x-ms-azure-host-authorization header to let the client know it is through proxy agent
    response.headers.add_header(
        constants::AUTHORIZATION_HEADER.to_string(),
        "value".to_string(),
    );

    // response to original client
    _ = client_stream.write_all(response.as_raw_string().as_bytes());
    _ = client_stream.flush();
}

pub fn get_status(shared_state: Arc<Mutex<SharedState>>) -> ProxyAgentDetailStatus {
    let status = if proxy_listener_wrapper::get_shutdown(shared_state.clone()) {
        ModuleState::STOPPED.to_string()
    } else {
        ModuleState::RUNNING.to_string()
    };

    ProxyAgentDetailStatus {
        status,
        message: proxy_listener_wrapper::get_status_message(shared_state.clone()),
        states: None,
    }
}

#[cfg(test)]
mod tests {
    use crate::common::constants;
    use crate::common::http;
    use crate::common::http::headers;
    use crate::common::http::request::Request;
    use crate::common::http::response::Response;
    use crate::common::logger;
    use crate::key_keeper::key::Key;
    use crate::proxy::proxy_listener;
    use crate::proxy::proxy_listener::Connection;
    use crate::proxy::Claims;
    use crate::shared_state::key_keeper_wrapper;
    use proxy_agent_shared::logger_manager;
    use std::env;
    use std::fs;
    use std::io::Write;
    use std::net::TcpListener;
    use std::net::TcpStream;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;
    use std::time::Instant;

    #[test]
    fn direct_request_test() {
        let logger_key = "direct_request_test";
        let mut temp_test_path = env::temp_dir();
        temp_test_path.push(logger_key);
        logger_manager::init_logger(
            logger::AGENT_LOGGER_KEY.to_string(), // production code uses 'Agent_Log' to write.
            temp_test_path.clone(),
            logger_key.to_string(),
            10 * 1024 * 1024,
            20,
        );
        Connection::init_logger(temp_test_path.to_path_buf());

        // start listener, the port must different from the one used in production code
        let shared_state = crate::shared_state::new_shared_state();
        let s = shared_state.clone();
        let port: u16 = 8091;
        let handle = thread::spawn(move || {
            proxy_listener::start(port, 1, s);
        });

        // give some time to let the listener started
        let sleep_duration = Duration::from_millis(100);
        thread::sleep(sleep_duration);

        let mut client = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
        let mut request = Request::new(format!("http://127.0.0.1:{}", port), "GET".to_string());
        client
            .write_all(request.as_raw_string().as_bytes())
            .unwrap();
        client.flush().unwrap();

        let response = http::receive_response_data(&client).unwrap();

        // stop listener
        proxy_listener::stop(port, shared_state);
        handle.join().unwrap();

        assert_eq!(
            Response::MISDIRECTED,
            response.status,
            "response.status mismatched."
        );

        // clean up and ignore the clean up errors
        _ = fs::remove_dir_all(temp_test_path);
    }

    const PROXY_ENDPOINT_ADDRESS: &str = "127.0.0.1:8083";
    const SERVER_ENDPOINT_ADDRESS: &str = "127.0.0.1:9093";
    #[test]
    fn http_stream_tests() {
        let logger_key = "http_stream_tests";
        let mut temp_test_path = env::temp_dir();
        temp_test_path.push(logger_key);
        logger_manager::init_logger(
            logger::AGENT_LOGGER_KEY.to_string(), // production code uses 'Agent_Log' to write.
            temp_test_path.clone(),
            logger_key.to_string(),
            10 * 1024 * 1024,
            20,
        );
        Connection::init_logger(temp_test_path.to_path_buf());
        let shut_down: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));

        let cloned_shut_down = shut_down.clone();
        let listener_thread = thread::Builder::new()
            .name("listener".to_string())
            .spawn(move || {
                let listener = TcpListener::bind(SERVER_ENDPOINT_ADDRESS).unwrap();
                for stream in listener.incoming() {
                    if cloned_shut_down.load(Ordering::Relaxed) {
                        break;
                    }
                    let stream = stream.unwrap();
                    handle_connection_stream(stream);
                }
            })
            .unwrap();

        let cloned_shut_down = shut_down.clone();
        let proxy_thread = thread::Builder::new()
            .name("proxy".to_string())
            .spawn(move || {
                let listener = TcpListener::bind(PROXY_ENDPOINT_ADDRESS).unwrap();

                for (id, stream) in listener.incoming().enumerate() {
                    if cloned_shut_down.load(Ordering::Relaxed) {
                        break;
                    }
                    let stream = stream.unwrap();
                    let mut connection = Connection {
                        stream,
                        id: id.try_into().unwrap(),
                        now: Instant::now(),
                        cliams: None,
                        ip: String::new(),
                        port: 0,
                    };
                    proxy_connection_stream(&mut connection);
                }
            })
            .unwrap();
        thread::sleep(Duration::from_millis(100));

        //// test GET response with binary data
        test_get_response();

        // test POST requests
        test_post_requests("/file");
        // test post request could skip sig
        test_post_requests("/vmagentlog");

        // stop listener/proxy thread
        shut_down.store(true, Ordering::Relaxed);
        _ = TcpStream::connect(PROXY_ENDPOINT_ADDRESS);
        _ = TcpStream::connect(SERVER_ENDPOINT_ADDRESS);
        listener_thread.join().unwrap();
        proxy_thread.join().unwrap();

        // clean up and ignore the clean up errors
        _ = fs::remove_dir_all(temp_test_path);
    }

    fn handle_connection_stream(mut stream: TcpStream) {
        // set read timeout to handle the case when body content is less than Content-Length in request header
        _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
        let mut request = http::receive_request_data(&stream).unwrap();

        let mut response = Response::from_status(Response::OK.to_string());
        if request.method == "GET" {
            let file = env::current_exe().unwrap();
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
                    super::send_response(&stream, Response::BAD_REQUEST);
                    return;
                }

                let mut response = Response::from_status(Response::CONTINUE.to_string());
                _ = stream.write_all(response.as_raw_string().as_bytes());
                _ = stream.flush();

                request.set_body(http::receive_body(&stream, content_length).unwrap());
            }

            // check actual body length against content-length
            if request.get_body_len() != content_length {
                super::send_response(&stream, Response::BAD_REQUEST);
                return;
            }

            return super::send_response(&stream, Response::OK);
        }
    }

    fn proxy_connection_stream(connection: &mut Connection) {
        let stream = &connection.stream;
        // set read timeout to handle the case when body content is less than Content-Length in request header
        _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
        let mut request = http::receive_request_data(stream).unwrap();
        let claims = Claims {
            userId: 999,
            userName: "test user".to_string(),
            userGroups: vec!["group1".to_string(), "group2".to_string()],
            processId: 1234,
            processName: "proxy_connection_stream".to_string(),
            processFullPath: "proxy_connection_stream_full".to_string(),
            processCmdLine: "proxy_connection_stream_cmd".to_string(),
            runAsElevated: true,
            clientIp: "127.0.0.1".to_string(),
        };
        // Add header x-ms-azure-host-claims
        request.headers.add_header(
            constants::CLAIMS_HEADER.to_string(),
            serde_json::to_string(&claims).unwrap(),
        );
        connection.cliams = Some(claims);
        connection.ip = "127.0.0.1".to_string();
        connection.port = 8084;
        let mut server_stream = TcpStream::connect(SERVER_ENDPOINT_ADDRESS).unwrap();

        if request.need_skip_sig() {
            // skip the signature and send the request headers to host now
            return super::handle_connection_without_signature(
                connection,
                request,
                &mut server_stream,
            );
        }

        let shared_state = crate::shared_state::new_shared_state();
        key_keeper_wrapper::set_key(shared_state.clone(), Key::empty());
        super::handle_connection_with_signature(
            connection,
            request,
            &mut server_stream,
            shared_state.clone(),
        );
    }

    fn test_get_response() {
        let mut client = TcpStream::connect(PROXY_ENDPOINT_ADDRESS).unwrap();
        let mut request = Request::new("/file".to_string(), "GET".to_string());
        client
            .write_all(request.as_raw_string().as_bytes())
            .unwrap();
        client.flush().unwrap();

        let response = http::receive_response_data(&client).unwrap();
        assert_eq!(
            response.headers.get_content_length().unwrap(),
            response.get_body_len(),
            "get_body_len and content_length mismatch."
        );

        let file = env::current_exe().unwrap();
        assert_eq!(
            file.metadata().unwrap().len() as usize,
            response.get_body_len(),
            "get_body_len and file length mismatch."
        );
    }

    fn test_post_requests(uri: &str) {
        let file = env::current_exe().unwrap();
        let body = fs::read(file).unwrap();

        let mut request = Request::new(uri.to_string(), "POST".to_string());
        request.headers.add_header(
            headers::CONTENT_LENGTH_HEADER_NAME.to_string(),
            body.len().to_string(),
        );

        // post request with full body directly
        request.set_body(body);
        let mut client_stream = TcpStream::connect(PROXY_ENDPOINT_ADDRESS).unwrap();
        client_stream.write_all(&request.to_raw_bytes()).unwrap();
        client_stream.flush().unwrap();
        let response = http::receive_response_data(&client_stream).unwrap();
        assert_eq!(
            Response::BAD_REQUEST,
            response.status,
            "response.status must be 400 Bad Request"
        );
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
        let mut client_stream = TcpStream::connect(PROXY_ENDPOINT_ADDRESS).unwrap();
        client_stream
            .write_all(request.as_raw_string().as_bytes())
            .unwrap();
        client_stream.flush().unwrap();
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
        client_stream.write_all(request.get_body()).unwrap();
        client_stream.flush().unwrap();
        let response = http::receive_response_data(&client_stream).unwrap();
        assert_eq!(Response::OK, response.status, "response.status must be OK");
        assert_eq!(
            "",
            response.get_body_as_string().unwrap(),
            "response body must be empty"
        );
    }
}
