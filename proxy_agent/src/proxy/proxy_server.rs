// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

//! This module is responsible for starting the proxy server and handling incoming requests.
//! It listens on a specified port and forwards the requests to the target server,
//!  then forward the response from the target server and sends it back to the client.
//! It also handles the provision state check request.
//! It uses the `hyper` crate to handle the HTTP requests and responses,
//!  uses the `tower` crate to limit the incoming request body size.
//!
//! Example:
//! ```rust
//! use crate::common::config;
//! use crate::proxy::proxy_server;
//! use crate::shared_state::SharedState;
//!
//! let shared_state = SharedState::start_all();
//! let port = config::get_proxy_port();
//! let proxy_server = proxy_server::ProxyServer::new(port, &shared_state);
//! tokio::spawn(proxy_server.start());
//! ```

use super::proxy_authorizer::AuthorizeResult;
use crate::common::{
    config, constants, error::Error, helpers, hyper_client, logger, result::Result,
};
use crate::proxy::proxy_connection::{Connection, ConnectionContext};
use crate::proxy::{proxy_authorizer, proxy_summary::ProxySummary, Claims};
use crate::shared_state::agent_status_wrapper::{AgentStatusModule, AgentStatusSharedState};
use crate::shared_state::key_keeper_wrapper::KeyKeeperSharedState;
use crate::shared_state::provision_wrapper::ProvisionSharedState;
use crate::shared_state::proxy_server_wrapper::ProxyServerSharedState;
use crate::shared_state::redirector_wrapper::RedirectorSharedState;
use crate::shared_state::telemetry_wrapper::TelemetrySharedState;
use crate::shared_state::SharedState;
use crate::{provision, redirector};
use http_body_util::Full;
use http_body_util::{combinators::BoxBody, BodyExt};
use hyper::body::{Bytes, Frame, Incoming};
use hyper::header::{HeaderName, HeaderValue};
use hyper::service::service_fn;
use hyper::StatusCode;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use proxy_agent_shared::misc_helpers;
use proxy_agent_shared::proxy_agent_aggregate_status::ModuleState;
use proxy_agent_shared::telemetry::event_logger;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;
use tower::Service;
use tower_http::{body::Limited, limit::RequestBodyLimitLayer};

const INITIAL_CONNECTION_ID: u128 = 0;
const REQUEST_BODY_LOW_LIMIT_SIZE: usize = 1024 * 100; // 100KB
const REQUEST_BODY_LARGE_LIMIT_SIZE: usize = 1024 * REQUEST_BODY_LOW_LIMIT_SIZE; // 100MB
const START_LISTENER_RETRY_COUNT: u16 = 5;
const START_LISTENER_RETRY_SLEEP_DURATION: Duration = Duration::from_secs(1);

#[derive(Clone)]
pub struct ProxyServer {
    port: u16,
    cancellation_token: CancellationToken,
    key_keeper_shared_state: KeyKeeperSharedState,
    telemetry_shared_state: TelemetrySharedState,
    provision_shared_state: ProvisionSharedState,
    agent_status_shared_state: AgentStatusSharedState,
    redirector_shared_state: RedirectorSharedState,
    proxy_server_shared_state: ProxyServerSharedState,
}

impl ProxyServer {
    pub fn new(port: u16, shared_state: &SharedState) -> Self {
        ProxyServer {
            port,
            cancellation_token: shared_state.get_cancellation_token(),
            key_keeper_shared_state: shared_state.get_key_keeper_shared_state(),
            telemetry_shared_state: shared_state.get_telemetry_shared_state(),
            provision_shared_state: shared_state.get_provision_shared_state(),
            agent_status_shared_state: shared_state.get_agent_status_shared_state(),
            redirector_shared_state: shared_state.get_redirector_shared_state(),
            proxy_server_shared_state: shared_state.get_proxy_server_shared_state(),
        }
    }

    /// start listener at the given address with retry logic if the address is in use
    async fn start_listener_with_retry(
        addr: &str,
        retry_count: u16,
        sleep_duration: Duration,
    ) -> Result<TcpListener> {
        for i in 0..retry_count {
            let listener = TcpListener::bind(addr).await;
            match listener {
                Ok(l) => {
                    return Ok(l);
                }
                Err(e) => match e.kind() {
                    std::io::ErrorKind::AddrInUse => {
                        let message = format!(
                        "Failed bind to '{}' with error 'AddrInUse', wait '{:#?}' and retrying {}.",
                        addr, sleep_duration, (i+1)
                    );
                        logger::write_warning(message);
                        tokio::time::sleep(sleep_duration).await;
                        continue;
                    }
                    _ => {
                        // other error, return it
                        return Err(Error::Io(
                            format!("Failed to bind TcpListener '{}'", addr),
                            e,
                        ));
                    }
                },
            }
        }

        // one more effort try bind to the addr
        TcpListener::bind(addr)
            .await
            .map_err(|e| Error::Io(format!("Failed to bind TcpListener '{}'", addr), e))
    }

    pub async fn start(&self) {
        Connection::init_logger(config::get_logs_dir());

        let addr = format!("{}:{}", std::net::Ipv4Addr::LOCALHOST, self.port);
        logger::write(format!("Start proxy listener at '{}'.", &addr));

        let listener = match Self::start_listener_with_retry(
            &addr,
            START_LISTENER_RETRY_COUNT,
            START_LISTENER_RETRY_SLEEP_DURATION,
        )
        .await
        {
            Ok(listener) => listener,
            Err(e) => {
                let message = e.to_string();
                if let Err(e) = self
                    .agent_status_shared_state
                    .set_module_status_message(message.to_string(), AgentStatusModule::ProxyServer)
                    .await
                {
                    Connection::write_warning(
                        INITIAL_CONNECTION_ID,
                        format!("Failed to set module status message: {}", e),
                    );
                }
                // send this critical error to event logger
                event_logger::write_event(
                    event_logger::WARN_LEVEL,
                    message,
                    "start",
                    "proxy_server",
                    Connection::CONNECTION_LOGGER_KEY,
                );

                return;
            }
        };

        let message = helpers::write_startup_event(
            "Started proxy listener, ready to accept request",
            "start",
            "proxy_server",
            logger::AGENT_LOGGER_KEY,
        );
        if let Err(e) = self
            .agent_status_shared_state
            .set_module_status_message(message.to_string(), AgentStatusModule::ProxyServer)
            .await
        {
            Connection::write_warning(
                INITIAL_CONNECTION_ID,
                format!("Failed to set module status message: {}", e),
            );
        }
        if let Err(e) = self
            .agent_status_shared_state
            .set_module_state(ModuleState::RUNNING, AgentStatusModule::ProxyServer)
            .await
        {
            Connection::write_warning(
                INITIAL_CONNECTION_ID,
                format!("Failed to set module state: {}", e),
            );
        }
        provision::listener_started(
            self.cancellation_token.clone(),
            self.key_keeper_shared_state.clone(),
            self.telemetry_shared_state.clone(),
            self.provision_shared_state.clone(),
            self.agent_status_shared_state.clone(),
        )
        .await;

        // We start a loop to continuously accept incoming connections
        loop {
            tokio::select! {
                _ = self.cancellation_token.cancelled() => {
                    logger::write_warning("cancellation token signal received, stop the listener.".to_string());
                    let _= self.agent_status_shared_state
                        .set_module_state(ModuleState::STOPPED, AgentStatusModule::ProxyServer)
                        .await;
                    return;
                }
                result = listener.accept() => {
                    match result {
                        Ok((stream, client_addr)) =>{
                           self.accept_one_request(stream, client_addr).await;
                        },
                        Err(e) => {
                            logger::write_error(format!("Failed to accept connection: {}", e));
                        }
                    }
                }
            }
        }
    }

    async fn accept_one_request(&self, stream: TcpStream, client_addr: std::net::SocketAddr) {
        Connection::write(
            INITIAL_CONNECTION_ID,
            "Accepted new connection.".to_string(),
        );

        tokio::spawn({
            let cloned_proxy_server = self.clone();
            async move {
                let (stream, cloned_std_stream) = match Self::set_stream_read_time_out(stream) {
                    Ok((stream, cloned_std_stream)) => (stream, cloned_std_stream),
                    Err(e) => {
                        Connection::write_error(
                            INITIAL_CONNECTION_ID,
                            format!("Failed to set stream read timeout: {}", e),
                        );
                        return;
                    }
                };
                let cloned_std_stream = Arc::new(Mutex::new(cloned_std_stream));
                // move client addr, cloned std stream and shared_state to the service_fn
                let service = service_fn(move |req| {
                    // use tower service as middleware to limit the request body size
                    let low_limit_layer = RequestBodyLimitLayer::new(REQUEST_BODY_LOW_LIMIT_SIZE);
                    let large_limit_layer =
                        RequestBodyLimitLayer::new(REQUEST_BODY_LARGE_LIMIT_SIZE);
                    let low_limited_tower_service =
                        tower::ServiceBuilder::new().layer(low_limit_layer);
                    let large_limited_tower_service =
                        tower::ServiceBuilder::new().layer(large_limit_layer);
                    let tower_service_layer =
                        if crate::common::hyper_client::should_skip_sig(req.method(), req.uri()) {
                            // skip signature check for large request
                            large_limited_tower_service.clone()
                        } else {
                            // use low limit for normal request
                            low_limited_tower_service.clone()
                        };

                    let cloned_std_stream = cloned_std_stream.clone();
                    let cloned_proxy_server = cloned_proxy_server.clone();
                    let mut tower_service =
                        tower_service_layer.service_fn(move |req: Request<_>| {
                            let connection = ConnectionContext {
                                stream: cloned_std_stream.clone(),
                                client_addr,
                                id: INITIAL_CONNECTION_ID,
                                now: std::time::Instant::now(),
                                method: req.method().clone(),
                                url: req.uri().clone(),
                                ip: None,
                                port: 0,
                                claims: None,
                            };

                            let cloned_proxy_server = cloned_proxy_server.clone();
                            cloned_proxy_server.handle_request(req, connection)
                        });
                    tower_service.call(req)
                });

                // Use an adapter to access something implementing `tokio::io` traits as if they implement
                let io = TokioIo::new(stream);
                // We use the `hyper::server::conn::Http` to serve the connection
                let http = hyper::server::conn::http1::Builder::new();
                if let Err(e) = http.serve_connection(io, service).await {
                    Connection::write_warning(
                        INITIAL_CONNECTION_ID,
                        format!("ProxyListener serve_connection error: {}", e),
                    );
                }
            }
        });
    }

    // Set the read timeout for the stream
    fn set_stream_read_time_out(stream: TcpStream) -> Result<(TcpStream, std::net::TcpStream)> {
        // Convert the stream to a std stream
        let std_stream = stream.into_std().map_err(|e| {
            Error::Io(
                "Failed to convert Tokio stream into std equivalent".to_string(),
                e,
            )
        })?;

        // Set the read timeout
        if let Err(e) = std_stream.set_read_timeout(Some(std::time::Duration::from_secs(10))) {
            Connection::write_warning(
                INITIAL_CONNECTION_ID,
                format!("Failed to set read timeout: {}", e),
            );
        }

        // Clone the stream for the service_fn
        let cloned_std_stream = std_stream
            .try_clone()
            .map_err(|e| Error::Io("Failed to clone TCP stream".to_string(), e))?;

        // Convert the std stream back
        let tokio_tcp_stream = TcpStream::from_std(std_stream).map_err(|e| {
            Error::Io(
                "Failed to convert std stream into Tokio equivalent".to_string(),
                e,
            )
        })?;

        Ok((tokio_tcp_stream, cloned_std_stream))
    }

    async fn handle_request(
        self,
        request: Request<Limited<hyper::body::Incoming>>,
        mut connection: ConnectionContext,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>> {
        let connection_id = match self
            .agent_status_shared_state
            .increase_connection_count()
            .await
        {
            Ok(id) => id,
            Err(e) => {
                Connection::write_error(
                    INITIAL_CONNECTION_ID,
                    format!("Failed to increase connection count: {}", e),
                );
                return Ok(Self::empty_response(StatusCode::INTERNAL_SERVER_ERROR));
            }
        };
        connection.id = connection_id;
        Connection::write_information(
            connection_id,
            format!(
                "Got request from {} for {} {}",
                connection.client_addr, connection.method, connection.url
            ),
        );

        if connection.url == provision::PROVISION_URL_PATH {
            return self
                .handle_provision_state_check_request(connection.id, request)
                .await;
        }

        let client_source_ip = connection.client_addr.ip();
        let client_source_port = connection.client_addr.port();

        let mut entry = None;
        match redirector::lookup_audit(client_source_port, self.redirector_shared_state.clone())
            .await
        {
            Ok(data) => entry = Some(data),
            Err(e) => {
                let err = format!("Failed to get lookup_audit: {}", e);
                event_logger::write_event(
                    event_logger::WARN_LEVEL,
                    err,
                    "handle_request",
                    "proxy_server",
                    Connection::CONNECTION_LOGGER_KEY,
                );
                #[cfg(windows)]
                {
                    Connection::write_information(
                        connection_id,
                        "Try to get audit entry from socket stream".to_string(),
                    );
                    use std::os::windows::io::AsRawSocket;
                    match redirector::get_audit_from_stream_socket(
                        connection.stream.lock().unwrap().as_raw_socket() as usize,
                    ) {
                        Ok(data) => entry = Some(data),
                        Err(e) => {
                            let err = format!("Failed to get lookup_audit_from_stream: {}", e);
                            event_logger::write_event(
                                event_logger::WARN_LEVEL,
                                err,
                                "handle_request",
                                "proxy_server",
                                Connection::CONNECTION_LOGGER_KEY,
                            );
                        }
                    }
                }
            }
        }
        let entry = match entry {
            Some(e) => e,
            None => {
                self.log_connection_summary(&connection, StatusCode::MISDIRECTED_REQUEST, false)
                    .await;
                return Ok(Self::empty_response(StatusCode::MISDIRECTED_REQUEST));
            }
        };

        let claims = match Claims::from_audit_entry(
            &entry,
            client_source_ip,
            self.proxy_server_shared_state.clone(),
        )
        .await
        {
            Ok(claims) => claims,
            Err(e) => {
                Connection::write_warning(
                    connection_id,
                    format!("Failed to get claims from audit entry: {}", e),
                );
                self.log_connection_summary(&connection, StatusCode::MISDIRECTED_REQUEST, false)
                    .await;
                return Ok(Self::empty_response(StatusCode::MISDIRECTED_REQUEST));
            }
        };

        let claim_details: String = match serde_json::to_string(&claims) {
            Ok(json) => json,
            Err(e) => {
                Connection::write_warning(
                    connection_id,
                    format!("Failed to get claim json string: {}", e),
                );
                self.log_connection_summary(&connection, StatusCode::MISDIRECTED_REQUEST, false)
                    .await;
                return Ok(Self::empty_response(StatusCode::MISDIRECTED_REQUEST));
            }
        };
        Connection::write(connection_id, claim_details.to_string());
        connection.claims = Some(claims.clone());

        // Get the dst ip and port to remote server
        let (ip, port);
        ip = entry.destination_ipv4_addr();
        port = entry.destination_port_in_host_byte_order();
        Connection::write(connection_id, format!("Use lookup value:{ip}:{port}."));
        connection.ip = Some(ip);
        connection.port = port;

        // authenticate the connection
        let access_control_rules = match proxy_authorizer::get_access_control_rules(
            ip.to_string(),
            self.key_keeper_shared_state.clone(),
        )
        .await
        {
            Ok(rules) => rules,
            Err(e) => {
                Connection::write_error(
                    connection_id,
                    format!("Failed to get access control rules: {}", e),
                );
                self.log_connection_summary(&connection, StatusCode::INTERNAL_SERVER_ERROR, false)
                    .await;
                return Ok(Self::empty_response(StatusCode::INTERNAL_SERVER_ERROR));
            }
        };
        let result = proxy_authorizer::authorize(
            ip.to_string(),
            port,
            connection_id,
            request.uri().clone(),
            claims.clone(),
            access_control_rules,
        );
        if result != AuthorizeResult::Ok {
            // log to authorize failed connection summary
            self.log_connection_summary(&connection, StatusCode::FORBIDDEN, true)
                .await;
            if result == AuthorizeResult::Forbidden {
                Connection::write_warning(
                    connection_id,
                    format!("Denied unauthorize request: {}", claim_details),
                );
                self.log_connection_summary(&connection, StatusCode::FORBIDDEN, false)
                    .await;
                return Ok(Self::empty_response(StatusCode::FORBIDDEN));
            }
        }

        // forward the request to the target server
        let mut proxy_request = request;

        // Add required headers
        let host_claims = format!(
            "{{ \"{}\": \"{}\"}}",
            constants::CLAIMS_IS_ROOT,
            claims.runAsElevated
        );
        proxy_request.headers_mut().insert(
            HeaderName::from_static(constants::CLAIMS_HEADER),
            match HeaderValue::from_str(&host_claims) {
                Ok(value) => value,
                Err(e) => {
                    Connection::write_error(
                        connection_id,
                        format!(
                            "Failed to add claims header: {} with error: {}",
                            host_claims, e
                        ),
                    );
                    return Ok(Self::empty_response(StatusCode::BAD_GATEWAY));
                }
            },
        );
        proxy_request.headers_mut().insert(
            HeaderName::from_static(constants::DATE_HEADER),
            match HeaderValue::from_str(&misc_helpers::get_date_time_rfc1123_string()) {
                Ok(value) => value,
                Err(e) => {
                    Connection::write_error(
                        connection_id,
                        format!("Failed to add date header with error: {}", e),
                    );
                    return Ok(Self::empty_response(StatusCode::BAD_GATEWAY));
                }
            },
        );

        if connection.should_skip_sig() {
            Connection::write(
                connection_id,
                format!(
                    "Skip compute signature for the request for {} {}",
                    connection.method, connection.url
                ),
            );
        } else {
            return self
                .handle_request_with_signature(connection, proxy_request)
                .await;
        }

        // start new request to the Host endpoint
        let proxy_response =
            hyper_client::send_request(ip.to_string().as_str(), port, proxy_request, move |msg| {
                Connection::write_warning(connection_id, msg);
            })
            .await;
        self.forward_response(proxy_response, connection).await
    }

    async fn handle_provision_state_check_request(
        &self,
        connection_id: u128,
        request: Request<Limited<hyper::body::Incoming>>,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>> {
        // check MetaData header exists or not
        if request.headers().get(constants::METADATA_HEADER).is_none() {
            Connection::write_warning(
                connection_id,
                "No MetaData header found in the request.".to_string(),
            );
            return Ok(Self::empty_response(StatusCode::BAD_REQUEST));
        }

        // notify key_keeper to poll the status
        if let Err(e) = self.key_keeper_shared_state.notify().await {
            Connection::write_warning(connection_id, format!("Failed to notify key_keeper: {}", e));
        }

        let provision_state = provision::get_provision_state(
            self.provision_shared_state.clone(),
            self.agent_status_shared_state.clone(),
        )
        .await;
        match serde_json::to_string(&provision_state) {
            Ok(json) => {
                Connection::write(connection_id, format!("Provision state: {}", json));
                let mut response = Response::new(hyper_client::full_body(json.as_bytes().to_vec()));
                response.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    HeaderValue::from_static("application/json; charset=utf-8"),
                );
                Ok(response)
            }
            Err(e) => {
                let error = format!("Failed to get provision state: {}", e);
                Connection::write_warning(connection_id, error.to_string());
                let mut response =
                    Response::new(hyper_client::full_body(error.as_bytes().to_vec()));
                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                Ok(response)
            }
        }
    }

    async fn forward_response(
        &self,
        proxy_response: Result<Response<Incoming>>,
        connection: ConnectionContext,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>> {
        let connection_id = connection.id;
        let proxy_response = match proxy_response {
            Ok(response) => response,
            Err(e) => {
                Connection::write_warning(
                    connection_id,
                    format!("Failed to send request to host: {}", e),
                );
                self.log_connection_summary(&connection, StatusCode::SERVICE_UNAVAILABLE, false)
                    .await;
                return Ok(Self::empty_response(StatusCode::SERVICE_UNAVAILABLE));
            }
        };

        let (head, body) = proxy_response.into_parts();
        let frame_stream = body.map_frame(move |frame| {
            let frame = match frame.into_data() {
                Ok(data) => data.iter().map(|byte| byte.to_be()).collect::<Bytes>(),
                Err(e) => {
                    Connection::write_error(
                        connection_id,
                        format!("Failed to get frame data: {:?}", e),
                    );
                    Bytes::new()
                }
            };

            Frame::data(frame)
        });
        let mut response = Response::from_parts(head, frame_stream.boxed());

        // insert default x-ms-azure-host-authorization header to let the client know it is through proxy agent
        response.headers_mut().insert(
            HeaderName::from_static(constants::AUTHORIZATION_HEADER),
            HeaderValue::from_static("value"),
        );

        self.log_connection_summary(&connection, response.status(), false)
            .await;
        Ok(response)
    }

    async fn log_connection_summary(
        &self,
        connection: &ConnectionContext,
        response_status: StatusCode,
        log_authorize_failed: bool,
    ) {
        let elapsed_time = connection.now.elapsed();
        let claims = match &connection.claims {
            Some(c) => c.clone(),
            None => Claims::empty(),
        };

        let summary = ProxySummary {
            id: connection.id,
            userId: claims.userId,
            userName: claims.userName.to_string(),
            userGroups: claims.userGroups.clone(),
            clientIp: claims.clientIp.to_string(),
            processFullPath: claims.processFullPath.to_string(),
            processCmdLine: claims.processCmdLine.to_string(),
            runAsElevated: claims.runAsElevated,
            method: connection.method.to_string(),
            url: connection.url.to_string(),
            ip: connection.get_ip_string(),
            port: connection.port,
            responseStatus: response_status.to_string(),
            elapsedTime: elapsed_time.as_millis(),
        };
        if let Ok(json) = serde_json::to_string(&summary) {
            event_logger::write_event(
                event_logger::INFO_LEVEL,
                json,
                "log_connection_summary",
                "proxy_server",
                Connection::CONNECTION_LOGGER_KEY,
            );
        };
        if log_authorize_failed {
            if let Err(e) = self
                .agent_status_shared_state
                .add_one_failed_connection_summary(summary)
                .await
            {
                Connection::write_warning(
                    connection.id,
                    format!("Failed to add failed connection summary: {}", e),
                );
            }
        } else if let Err(e) = self
            .agent_status_shared_state
            .add_one_connection_summary(summary)
            .await
        {
            Connection::write_warning(
                connection.id,
                format!("Failed to add connection summary: {}", e),
            );
        }
    }

    // We create some utility functions to make Empty and Full bodies
    // fit our broadened Response body type.
    fn empty_response(status_code: StatusCode) -> Response<BoxBody<Bytes, hyper::Error>> {
        let mut response = Response::new(hyper_client::empty_body());
        *response.status_mut() = status_code;

        response
    }

    async fn handle_request_with_signature(
        &self,
        connection: ConnectionContext,
        request: Request<Limited<Incoming>>,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>> {
        let (head, body) = request.into_parts();
        let whole_body = match body.collect().await {
            Ok(data) => data.to_bytes(),
            Err(e) => {
                Connection::write_error(
                    connection.id,
                    format!("Failed to receive the request body: {}", e),
                );
                return Ok(Self::empty_response(StatusCode::BAD_REQUEST));
            }
        };

        Connection::write(
            connection.id,
            format!(
                "Received the client request body (len={}) for {} {}",
                whole_body.len(),
                connection.method,
                connection.url,
            ),
        );

        // create a new request to the Host endpoint
        let mut proxy_request: Request<Full<Bytes>> =
            Request::from_parts(head.clone(), Full::new(whole_body.clone()));

        // sign the request
        // Add header x-ms-azure-host-authorization
        if let (Some(key), Some(key_guid)) = (
            self.key_keeper_shared_state
                .get_current_key_value()
                .await
                .unwrap_or(None),
            self.key_keeper_shared_state
                .get_current_key_guid()
                .await
                .unwrap_or(None),
        ) {
            let input_to_sign = hyper_client::as_sig_input(head, whole_body);
            match helpers::compute_signature(&key, input_to_sign.as_slice()) {
                Ok(sig) => {
                    let authorization_value =
                        format!("{} {} {}", constants::AUTHORIZATION_SCHEME, key_guid, sig);
                    proxy_request.headers_mut().insert(
                        HeaderName::from_static(constants::AUTHORIZATION_HEADER),
                        match HeaderValue::from_str(&authorization_value) {
                            Ok(value) => value,
                            Err(e) => {
                                Connection::write_error(
                                    connection.id,
                                    format!(
                                        "Failed to add authorization header: {} with error: {}",
                                        authorization_value, e
                                    ),
                                );
                                return Ok(Self::empty_response(StatusCode::BAD_GATEWAY));
                            }
                        },
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
        } else {
            Connection::write(
                connection.id,
                "current key is empty, skip computing the signature.".to_string(),
            );
        }

        // start new request to the Host endpoint
        let connection_id = connection.id;
        let proxy_response = hyper_client::send_request(
            &connection.get_ip_string(),
            connection.port,
            proxy_request,
            move |msg| {
                Connection::write_warning(connection_id, msg);
            },
        )
        .await;

        self.forward_response(proxy_response, connection).await
    }
}

#[cfg(test)]
mod tests {
    use crate::common::hyper_client;
    use crate::common::logger;
    use crate::proxy::proxy_connection::Connection;
    use crate::proxy::proxy_server;
    use crate::shared_state;
    use http::Method;
    use proxy_agent_shared::logger_manager;
    use std::collections::HashMap;
    use std::env;
    use std::fs;
    use std::time::Duration;

    #[tokio::test]
    async fn direct_request_test() {
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
        let host = "127.0.0.1";
        let port: u16 = 8091;
        let shared_state = shared_state::SharedState::start_all();
        let key_keeper_shared_state = shared_state.get_key_keeper_shared_state();
        let cancellation_token = shared_state.get_cancellation_token();
        let proxy_server = proxy_server::ProxyServer::new(port, &shared_state);

        tokio::spawn({
            let proxy_server = proxy_server.clone();
            async move {
                proxy_server.start().await;
            }
        });

        // give some time to let the listener started
        let sleep_duration = Duration::from_millis(100);
        tokio::time::sleep(sleep_duration).await;

        let url: hyper::Uri = format!("http://{}:{}/", host, port).parse().unwrap();
        let request = hyper_client::build_request(
            Method::GET,
            &url,
            &HashMap::new(),
            None,
            key_keeper_shared_state
                .get_current_key_guid()
                .await
                .unwrap_or(None),
            key_keeper_shared_state
                .get_current_key_value()
                .await
                .unwrap_or(None),
        )
        .unwrap();
        let response = hyper_client::send_request(host, port, request, logger::write_warning)
            .await
            .unwrap();
        assert_eq!(
            http::StatusCode::MISDIRECTED_REQUEST,
            response.status(),
            "response.status must be MISDIRECTED_REQUEST."
        );

        // test large request body
        let body = vec![88u8; super::REQUEST_BODY_LOW_LIMIT_SIZE + 1];
        let request = hyper_client::build_request(
            Method::POST,
            &url,
            &HashMap::new(),
            Some(body.as_slice()),
            key_keeper_shared_state
                .get_current_key_guid()
                .await
                .unwrap_or(None),
            key_keeper_shared_state
                .get_current_key_value()
                .await
                .unwrap_or(None),
        )
        .unwrap();
        let response = hyper_client::send_request(host, port, request, logger::write_warning)
            .await
            .unwrap();
        assert_eq!(
            http::StatusCode::PAYLOAD_TOO_LARGE,
            response.status(),
            "response.status must be PAYLOAD_TOO_LARGE."
        );

        // stop the listener
        cancellation_token.cancel();

        // clean up and ignore the clean up errors
        _ = fs::remove_dir_all(temp_test_path);
    }
}
