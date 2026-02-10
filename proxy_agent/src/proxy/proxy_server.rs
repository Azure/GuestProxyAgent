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
use super::proxy_connection::{ConnectionLogger, HttpConnectionContext, TcpConnectionContext};
use crate::common::{constants, error::Error, helpers, logger, result::Result};
use crate::provision;
use crate::proxy::{proxy_authorizer, proxy_summary::ProxySummary, Claims};
use crate::shared_state::access_control_wrapper::AccessControlSharedState;
use crate::shared_state::agent_status_wrapper::{AgentStatusModule, AgentStatusSharedState};
use crate::shared_state::connection_summary_wrapper::ConnectionSummarySharedState;
use crate::shared_state::key_keeper_wrapper::KeyKeeperSharedState;
use crate::shared_state::provision_wrapper::ProvisionSharedState;
use crate::shared_state::proxy_server_wrapper::ProxyServerSharedState;
use crate::shared_state::redirector_wrapper::RedirectorSharedState;
use crate::shared_state::{EventThreadsSharedState, SharedState};
use http_body_util::Full;
use http_body_util::{combinators::BoxBody, BodyExt};
use hyper::body::{Bytes, Incoming};
use hyper::header::{HeaderName, HeaderValue};
use hyper::service::service_fn;
use hyper::StatusCode;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use proxy_agent_shared::common_state::CommonState;
use proxy_agent_shared::error::HyperErrorType;
use proxy_agent_shared::hyper_client;
use proxy_agent_shared::logger::LoggerLevel;
use proxy_agent_shared::misc_helpers;
use proxy_agent_shared::proxy_agent_aggregate_status::ModuleState;
use proxy_agent_shared::telemetry::event_logger;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio_util::bytes::BytesMut;
use tokio_util::sync::CancellationToken;
use tower::Service;
use tower_http::{body::Limited, limit::RequestBodyLimitLayer};

const REQUEST_BODY_LOW_LIMIT_SIZE: usize = 1024 * 100; // 100KB
const REQUEST_BODY_LARGE_LIMIT_SIZE: usize = 1024 * REQUEST_BODY_LOW_LIMIT_SIZE; // 100MB
const START_LISTENER_RETRY_COUNT: u16 = 5;
const START_LISTENER_RETRY_SLEEP_DURATION: Duration = Duration::from_secs(1);

#[derive(Clone)]
pub struct ProxyServer {
    port: u16,
    cancellation_token: CancellationToken,
    key_keeper_shared_state: KeyKeeperSharedState,
    common_state: CommonState,
    provision_shared_state: ProvisionSharedState,
    agent_status_shared_state: AgentStatusSharedState,
    redirector_shared_state: RedirectorSharedState,
    proxy_server_shared_state: ProxyServerSharedState,
    access_control_shared_state: AccessControlSharedState,
    connection_summary_shared_state: ConnectionSummarySharedState,
}

impl ProxyServer {
    pub fn new(port: u16, shared_state: &SharedState) -> Self {
        ProxyServer {
            port,
            cancellation_token: shared_state.get_cancellation_token(),
            key_keeper_shared_state: shared_state.get_key_keeper_shared_state(),
            common_state: shared_state.get_common_state(),
            provision_shared_state: shared_state.get_provision_shared_state(),
            agent_status_shared_state: shared_state.get_agent_status_shared_state(),
            redirector_shared_state: shared_state.get_redirector_shared_state(),
            proxy_server_shared_state: shared_state.get_proxy_server_shared_state(),
            access_control_shared_state: shared_state.get_access_control_shared_state(),
            connection_summary_shared_state: shared_state.get_connection_summary_shared_state(),
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
                        return Err(Error::Io(format!("Failed to bind TcpListener '{addr}'"), e));
                    }
                },
            }
        }

        // one more effort try bind to the addr
        TcpListener::bind(addr)
            .await
            .map_err(|e| Error::Io(format!("Failed to bind TcpListener '{addr}'"), e))
    }

    pub async fn start(&self) {
        let addr = format!("{}:{}", std::net::Ipv4Addr::LOCALHOST, self.port);
        logger::write_information(format!("Start proxy listener at '{}'.", &addr));

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
                    logger::write_warning(format!("Failed to set module status message: {e}"));
                }
                if let Err(e) = self
                    .agent_status_shared_state
                    .set_module_state(ModuleState::STOPPED, AgentStatusModule::ProxyServer)
                    .await
                {
                    logger::write_warning(format!("Failed to set module state: {e}"));
                }

                // send this critical error to event logger
                event_logger::write_event(
                    LoggerLevel::Warn,
                    message,
                    "start",
                    "proxy_server",
                    logger::AGENT_LOGGER_KEY,
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
            logger::write_warning(format!("Failed to set module status message: {e}"));
        }
        if let Err(e) = self
            .agent_status_shared_state
            .set_module_state(ModuleState::RUNNING, AgentStatusModule::ProxyServer)
            .await
        {
            logger::write_warning(format!("Failed to set module state: {e}"));
        }
        provision::listener_started(EventThreadsSharedState {
            cancellation_token: self.cancellation_token.clone(),
            common_state: self.common_state.clone(),
            access_control_shared_state: self.access_control_shared_state.clone(),
            redirector_shared_state: self.redirector_shared_state.clone(),
            key_keeper_shared_state: self.key_keeper_shared_state.clone(),
            provision_shared_state: self.provision_shared_state.clone(),
            agent_status_shared_state: self.agent_status_shared_state.clone(),
            connection_summary_shared_state: self.connection_summary_shared_state.clone(),
        })
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
                           self.handle_new_tcp_connection(stream, client_addr).await;
                        },
                        Err(e) => {
                            logger::write_error(format!("Failed to accept connection: {e}"));
                        }
                    }
                }
            }
        }
    }

    async fn handle_new_tcp_connection(
        &self,
        stream: TcpStream,
        client_addr: std::net::SocketAddr,
    ) {
        let tcp_connection_id = match self
            .agent_status_shared_state
            .increase_tcp_connection_count()
            .await
        {
            Ok(id) => id,
            Err(e) => {
                ConnectionLogger::new(0, 0).write(
                    LoggerLevel::Error,
                    format!("Failed to increase tcp connection count: {e}"),
                );
                return;
            }
        };
        let mut tcp_connection_logger = ConnectionLogger::new(tcp_connection_id, 0);
        tcp_connection_logger.write(
            LoggerLevel::Trace,
            format!("Accepted new tcp connection [{tcp_connection_id}]."),
        );

        tokio::spawn({
            let cloned_proxy_server = self.clone();
            async move {
                let (stream, _cloned_std_stream) =
                    match Self::set_stream_read_time_out(stream, &mut tcp_connection_logger) {
                        Ok((stream, cloned_std_stream)) => (stream, cloned_std_stream),
                        Err(e) => {
                            tcp_connection_logger.write(
                                LoggerLevel::Error,
                                format!("Failed to set stream read timeout: {e}"),
                            );
                            return;
                        }
                    };
                let tcp_connection_context = TcpConnectionContext::new(
                    tcp_connection_id,
                    client_addr,
                    cloned_proxy_server.redirector_shared_state.clone(),
                    cloned_proxy_server.proxy_server_shared_state.clone(),
                    #[cfg(windows)]
                    ProxyServer::get_stream_rocket_id(&_cloned_std_stream),
                )
                .await;

                let cloned_tcp_connection_context = tcp_connection_context.clone();
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
                        if hyper_client::should_skip_sig(req.method(), req.uri()) {
                            // skip signature check for large request
                            large_limited_tower_service.clone()
                        } else {
                            // use low limit for normal request
                            low_limited_tower_service.clone()
                        };

                    let cloned_proxy_server = cloned_proxy_server.clone();
                    let cloned_tcp_connection_context = cloned_tcp_connection_context.clone();
                    let mut tower_service =
                        tower_service_layer.service_fn(move |req: Request<_>| {
                            let cloned_proxy_server = cloned_proxy_server.clone();
                            cloned_proxy_server
                                .handle_new_http_request(req, cloned_tcp_connection_context.clone())
                        });
                    tower_service.call(req)
                });

                // Use an adapter to access something implementing `tokio::io` traits as if they implement
                let io = TokioIo::new(stream);
                // We use the `hyper::server::conn::Http` to serve the connection
                let mut http = hyper::server::conn::http1::Builder::new();
                if let Err(e) = http
                    .keep_alive(true) // set keep_alive to true explicitly
                    .serve_connection(io, service)
                    .await
                {
                    tcp_connection_logger.write(
                        LoggerLevel::Warn,
                        format!("ProxyListener serve_connection error: {e}"),
                    );
                }
            }
        });
    }

    #[cfg(windows)]
    fn get_stream_rocket_id(stream: &std::net::TcpStream) -> usize {
        use std::os::windows::io::AsRawSocket;
        stream.as_raw_socket() as usize
    }

    // Set the read timeout for the stream
    fn set_stream_read_time_out(
        stream: TcpStream,
        connection_logger: &mut ConnectionLogger,
    ) -> Result<(TcpStream, std::net::TcpStream)> {
        // Convert the stream to a std stream
        let std_stream = stream.into_std().map_err(|e| {
            Error::Io(
                "Failed to convert Tokio stream into std equivalent".to_string(),
                e,
            )
        })?;

        // Set the read timeout
        if let Err(e) = std_stream.set_read_timeout(Some(std::time::Duration::from_secs(10))) {
            connection_logger.write(
                LoggerLevel::Warn,
                format!("Failed to set read timeout: {e}"),
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

    async fn handle_new_http_request(
        self,
        request: Request<Limited<hyper::body::Incoming>>,
        mut tcp_connection_context: TcpConnectionContext,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>> {
        let connection_id = match self
            .agent_status_shared_state
            .increase_connection_count()
            .await
        {
            Ok(id) => id,
            Err(e) => {
                tcp_connection_context.log(
                    LoggerLevel::Error,
                    format!("Failed to increase connection count: {e}"),
                );
                return Ok(Self::closed_response(StatusCode::INTERNAL_SERVER_ERROR));
            }
        };

        let mut http_connection_context = HttpConnectionContext::new(
            connection_id,
            request.method().clone(),
            request.uri().clone(),
            tcp_connection_context.clone(),
        );
        http_connection_context.log(
            LoggerLevel::Trace,
            format!(
                "Got request from {} for {} {}",
                tcp_connection_context.client_addr,
                http_connection_context.method,
                http_connection_context.url
            ),
        );

        if http_connection_context.contains_traversal_characters() {
            self.log_connection_summary(
                &mut http_connection_context,
                StatusCode::NOT_FOUND,
                false,
                "Traversal characters found in the request, return NOT_FOUND!".to_string(),
            )
            .await;
            return Ok(Self::closed_response(StatusCode::NOT_FOUND));
        }

        if http_connection_context.url == provision::provision_query::PROVISION_URL_PATH {
            return self
                .handle_provision_state_check_request(
                    http_connection_context.get_logger_mut_ref(),
                    request,
                )
                .await;
        }

        http_connection_context.log(
            LoggerLevel::Trace,
            "Getting destination IP and port.".to_string(),
        );
        let ip = match tcp_connection_context.destination_ip {
            Some(ip) => ip,
            None => {
                self.log_connection_summary(
                    &mut http_connection_context,
                    StatusCode::MISDIRECTED_REQUEST,
                    false,
                    "No remote destination_ip found in the request, return!".to_string(),
                )
                .await;
                return Ok(Self::closed_response(StatusCode::MISDIRECTED_REQUEST));
            }
        };
        let port = tcp_connection_context.destination_port;
        http_connection_context.log(
            LoggerLevel::Trace,
            "Getting claims from the tcp_connection_context.".to_string(),
        );
        let claims = match tcp_connection_context.claims {
            Some(c) => c.clone(),
            None => {
                self.log_connection_summary(
                    &mut http_connection_context,
                    StatusCode::MISDIRECTED_REQUEST,
                    true,
                    "No claims found in the request, return!".to_string(),
                )
                .await;
                return Ok(Self::closed_response(StatusCode::MISDIRECTED_REQUEST));
            }
        };
        http_connection_context.log(LoggerLevel::Trace, format!("Use lookup value:{ip}:{port}."));
        let claim_details: String = match serde_json::to_string(&claims) {
            Ok(json) => json,
            Err(e) => {
                self.log_connection_summary(
                    &mut http_connection_context,
                    StatusCode::MISDIRECTED_REQUEST,
                    false,
                    format!("Failed to get claims json string: {e}"),
                )
                .await;
                return Ok(Self::closed_response(StatusCode::MISDIRECTED_REQUEST));
            }
        };
        http_connection_context.log(LoggerLevel::Trace, claim_details.to_string());

        // authenticate the connection
        let access_control_rules = match proxy_authorizer::get_access_control_rules(
            ip.to_string(),
            port,
            self.access_control_shared_state.clone(),
        )
        .await
        {
            Ok(rules) => rules,
            Err(e) => {
                self.log_connection_summary(
                    &mut http_connection_context,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    false,
                    format!("Failed to get access control rules: {e}"),
                )
                .await;
                return Ok(Self::closed_response(StatusCode::INTERNAL_SERVER_ERROR));
            }
        };
        http_connection_context.log(LoggerLevel::Trace, "Authorizing the request.".to_string());
        let result = proxy_authorizer::authorize(
            ip.to_string(),
            port,
            http_connection_context.get_logger_mut_ref(),
            request.uri().clone(),
            claims.clone(),
            access_control_rules,
        );
        if result != AuthorizeResult::Ok {
            // log to authorize failed connection summary
            self.log_connection_summary(
                &mut http_connection_context,
                StatusCode::FORBIDDEN,
                true,
                "Authorize failed".to_string(),
            )
            .await;
            if result == AuthorizeResult::Forbidden {
                self.log_connection_summary(
                    &mut http_connection_context,
                    StatusCode::FORBIDDEN,
                    false,
                    format!("Block unauthorized request: {claim_details}"),
                )
                .await;
                return Ok(Self::closed_response(StatusCode::FORBIDDEN));
            }
        }

        http_connection_context.log(
            LoggerLevel::Trace,
            "Forwarding request to target server.".to_string(),
        );
        let mut proxy_request = request;

        // Add required headers
        let host_claims = format!(
            "{{ \"{}\": \"{}\"}}",
            hyper_client::CLAIMS_IS_ROOT,
            claims.runAsElevated
        );
        proxy_request.headers_mut().insert(
            HeaderName::from_static(hyper_client::CLAIMS_HEADER),
            match HeaderValue::from_str(&host_claims) {
                Ok(value) => value,
                Err(e) => {
                    http_connection_context.log(
                        LoggerLevel::Error,
                        format!("Failed to add claims header: {host_claims} with error: {e}"),
                    );
                    return Ok(Self::closed_response(StatusCode::BAD_GATEWAY));
                }
            },
        );
        proxy_request.headers_mut().insert(
            HeaderName::from_static(hyper_client::DATE_HEADER),
            match HeaderValue::from_str(&misc_helpers::get_date_time_rfc1123_string()) {
                Ok(value) => value,
                Err(e) => {
                    http_connection_context.log(
                        LoggerLevel::Error,
                        format!("Failed to add date header with error: {e}"),
                    );
                    return Ok(Self::closed_response(StatusCode::BAD_GATEWAY));
                }
            },
        );

        if http_connection_context.should_skip_sig() {
            http_connection_context.log(
                LoggerLevel::Trace,
                format!(
                    "Skip compute signature for the request for {} {}",
                    http_connection_context.method, http_connection_context.url
                ),
            );
        } else {
            return self
                .handle_request_with_signature(http_connection_context, proxy_request)
                .await;
        }

        // start new request to the Host endpoint
        http_connection_context.log(
            LoggerLevel::Trace,
            format!(
                "Create new http request to the target server {} {}",
                http_connection_context.method, http_connection_context.url
            ),
        );

        let (head, body) = proxy_request.into_parts();
        // Stream the request body directly without buffering
        let request = Request::from_parts(head, body.boxed());
        http_connection_context.log(
            LoggerLevel::Trace,
            format!(
                "Sending request to the target server: {} {}",
                http_connection_context.method, http_connection_context.url
            ),
        );
        let proxy_response = http_connection_context.send_request(request).await;
        http_connection_context.log(
            LoggerLevel::Trace,
            format!(
                "Received response from the target server: {} {}",
                http_connection_context.method, http_connection_context.url
            ),
        );
        self.forward_response(proxy_response, http_connection_context)
            .await
    }

    async fn handle_provision_state_check_request(
        &self,
        logger: &mut ConnectionLogger,
        request: Request<Limited<hyper::body::Incoming>>,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>> {
        // check MetaData header exists or not
        if request
            .headers()
            .get(hyper_client::METADATA_HEADER)
            .is_none()
        {
            logger.write(
                LoggerLevel::Warn,
                "No MetaData header found in the request.".to_string(),
            );
            return Ok(Self::closed_response(StatusCode::BAD_REQUEST));
        }
        // Get the query time_tick
        let query_time_tick = match request.headers().get(constants::TIME_TICK_HEADER) {
            Some(time_tick) => time_tick.to_str().unwrap_or("0"),
            None => {
                logger.write(
                    LoggerLevel::Warn,
                    format!(
                        "No '{}' header found in the request, use '0'.",
                        constants::TIME_TICK_HEADER
                    ),
                );
                "0"
            }
        };
        let query_time_tick = match query_time_tick.parse::<i128>() {
            Ok(time_tick) => time_tick,
            Err(e) => {
                logger.write(
                    LoggerLevel::Warn,
                    format!("Failed to parse time_tick header: {e}"),
                );
                0
            }
        };

        let provision_state = provision::get_provision_state_internal(
            self.provision_shared_state.clone(),
            self.agent_status_shared_state.clone(),
            self.key_keeper_shared_state.clone(),
        )
        .await;

        // report as provision finished state
        // true only if the finished_time_tick is greater than or equal to the query_time_tick or
        //      the secure channel is latched already and finished_time_tick is greater than 0
        let report_provision_finished = provision_state.finished_time_tick >= query_time_tick
            || (provision_state.is_secure_channel_latched()
                && provision_state.finished_time_tick > 0);

        let find_notify_header = request.headers().get(constants::NOTIFY_HEADER).is_some();
        if find_notify_header && !report_provision_finished {
            logger.write(
                LoggerLevel::Warn,
                "Provision is not finished yet, notify key_keeper to pull the status.".to_string(),
            );
            if let Err(e) = self.key_keeper_shared_state.notify().await {
                logger.write(
                    LoggerLevel::Warn,
                    format!("Failed to notify key_keeper: {e}"),
                );
            }
        }

        let provision_state = provision::provision_query::ProvisionState::new(
            report_provision_finished,
            provision_state.error_message,
        );
        match serde_json::to_string(&provision_state) {
            Ok(json) => {
                logger.write(LoggerLevel::Info, format!("Provision state: {json}"));
                let mut response = Response::new(hyper_client::full_body(json.as_bytes().to_vec()));
                response.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    HeaderValue::from_static("application/json; charset=utf-8"),
                );
                Ok(response)
            }
            Err(e) => {
                let error = format!("Failed to get provision state: {e}");
                logger.write(LoggerLevel::Warn, error.to_string());
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
        mut http_connection_context: HttpConnectionContext,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>> {
        let proxy_response = match proxy_response {
            Ok(response) => response,
            Err(e) => {
                let http_status_code = match e {
                    Error::Hyper(HyperErrorType::HostConnection(_)) => StatusCode::BAD_GATEWAY,
                    _ => StatusCode::SERVICE_UNAVAILABLE,
                };
                self.log_connection_summary(
                    &mut http_connection_context,
                    http_status_code,
                    false,
                    format!("Failed to send request to host: {e}"),
                )
                .await;
                return Ok(Self::closed_response(http_status_code));
            }
        };

        http_connection_context.log(
            LoggerLevel::Trace,
            "Converting response to the client format.".to_string(),
        );
        let (head, body) = proxy_response.into_parts();
        // Stream the response body directly without buffering
        let mut response = Response::from_parts(head, body.boxed());

        http_connection_context.log(LoggerLevel::Trace, "Adding proxy agent header.".to_string());
        // insert default x-ms-azure-host-authorization header to let the client know it is through proxy agent
        response.headers_mut().insert(
            HeaderName::from_static(hyper_client::AUTHORIZATION_HEADER),
            HeaderValue::from_static("value"),
        );

        self.log_connection_summary(
            &mut http_connection_context,
            response.status(),
            false,
            "".to_string(),
        )
        .await;

        http_connection_context.log(
            LoggerLevel::Trace,
            "Returning response to the client.".to_string(),
        );
        Ok(response)
    }

    async fn log_connection_summary(
        &self,
        http_connection_context: &mut HttpConnectionContext,
        response_status: StatusCode,
        log_authorize_failed: bool,
        mut error_details: String,
    ) {
        http_connection_context.log(
            LoggerLevel::Trace,
            format!("Http connection finished with status code: {response_status}."),
        );
        let elapsed_time = http_connection_context.now.elapsed();
        let claims = match &http_connection_context.tcp_connection_context.claims {
            Some(c) => c.clone(),
            None => {
                let mut claim = Claims::empty();
                // set the client ip and port from connection.client_addr
                claim.clientIp = http_connection_context
                    .tcp_connection_context
                    .client_addr
                    .ip()
                    .to_string();
                claim.clientPort = http_connection_context
                    .tcp_connection_context
                    .client_addr
                    .port();

                claim
            }
        };

        const MAX_ERROR_DETAILS_LEN: usize = 4096; // 4KB
        if error_details.len() > MAX_ERROR_DETAILS_LEN {
            error_details.truncate(MAX_ERROR_DETAILS_LEN);
        }

        http_connection_context.log(
            LoggerLevel::Trace,
            "Starting report connection summary event.".to_string(),
        );
        let summary = ProxySummary {
            id: http_connection_context.id,
            userId: claims.userId,
            userName: claims.userName.to_string(),
            userGroups: claims.userGroups.clone(),
            clientIp: claims.clientIp.to_string(),
            clientPort: claims.clientPort,
            processFullPath: claims.processFullPath,
            processCmdLine: claims.processCmdLine.to_string(),
            runAsElevated: claims.runAsElevated,
            method: http_connection_context.method.to_string(),
            url: http_connection_context.url.to_string(),
            ip: http_connection_context
                .tcp_connection_context
                .get_ip_string(),
            port: http_connection_context
                .tcp_connection_context
                .destination_port,
            responseStatus: response_status.to_string(),
            elapsedTime: elapsed_time.as_millis(),
            errorDetails: error_details,
        };
        http_connection_context.log(
            LoggerLevel::Trace,
            "Starting add connection summary for status reporting.".to_string(),
        );

        if log_authorize_failed {
            match self
                .connection_summary_shared_state
                .add_one_failed_connection_summary(summary.clone())
                .await
            {
                Ok(is_new_bucket) => {
                    if is_new_bucket {
                        // if it's a new bucket, we don't need to add to failed connection summary again
                        if let Ok(json) = serde_json::to_string(&summary) {
                            event_logger::write_event(
                                LoggerLevel::Info,
                                json,
                                "log_connection_summary",
                                "proxy_server",
                                ConnectionLogger::CONNECTION_LOGGER_KEY,
                            );
                        };
                    }
                }
                Err(e) => {
                    http_connection_context.log(
                        LoggerLevel::Warn,
                        format!("Failed to add failed connection summary: {e}"),
                    );
                }
            }
        } else {
            match self
                .connection_summary_shared_state
                .add_one_connection_summary(summary.clone())
                .await
            {
                Ok(is_new_bucket) => {
                    if is_new_bucket {
                        // if it's a new bucket, we log it to event logger
                        if let Ok(json) = serde_json::to_string(&summary) {
                            event_logger::write_event(
                                LoggerLevel::Info,
                                json,
                                "log_connection_summary",
                                "proxy_server",
                                ConnectionLogger::CONNECTION_LOGGER_KEY,
                            );
                        };
                    }
                }
                Err(e) => {
                    http_connection_context.log(
                        LoggerLevel::Warn,
                        format!("Failed to add connection summary: {e}"),
                    );
                }
            }
        }

        http_connection_context.log(
            LoggerLevel::Trace,
            "Finished log_connection_summary.".to_string(),
        );
    }

    // We create some utility functions to make Empty and Full bodies
    // fit our broadened Response body type.
    fn empty_response(status_code: StatusCode) -> Response<BoxBody<Bytes, hyper::Error>> {
        let mut response = Response::new(hyper_client::empty_body());
        *response.status_mut() = status_code;

        response
    }

    fn closed_response(status_code: StatusCode) -> Response<BoxBody<Bytes, hyper::Error>> {
        let mut response = Self::empty_response(status_code);

        // Add the Connection: close header to close the tcp connection
        response
            .headers_mut()
            .insert(hyper::header::CONNECTION, HeaderValue::from_static("close"));

        response
    }

    async fn handle_request_with_signature(
        &self,
        mut http_connection_context: HttpConnectionContext,
        request: Request<Limited<Incoming>>,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>> {
        let (head, body) = request.into_parts();
        http_connection_context.log(
            LoggerLevel::Trace,
            "Starting to collect the client request body.".to_string(),
        );
        let whole_body = Self::read_body_bytes(body).await?;
        http_connection_context.log(
            LoggerLevel::Trace,
            format!(
                "Received the client request body (len={}) for {} {}",
                whole_body.len(),
                http_connection_context.method,
                http_connection_context.url,
            ),
        );

        // create a new request to the Host endpoint
        let body = Full::new(whole_body.clone())
            .map_err(|never| -> Box<dyn std::error::Error + Send + Sync> { match never {} })
            .boxed();
        let mut proxy_request: Request<super::proxy_connection::RequestBody> =
            Request::from_parts(head.clone(), body);

        // sign the request
        // Add header x-ms-azure-host-authorization
        http_connection_context.log(
            LoggerLevel::Trace,
            "Starting to compute the signature.".to_string(),
        );
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
            match misc_helpers::compute_signature(&key, input_to_sign.as_slice()) {
                Ok(sig) => {
                    let authorization_value = format!(
                        "{} {} {}",
                        hyper_client::AUTHORIZATION_SCHEME,
                        key_guid,
                        sig
                    );
                    proxy_request.headers_mut().insert(
                        HeaderName::from_static(hyper_client::AUTHORIZATION_HEADER),
                        match HeaderValue::from_str(&authorization_value) {
                            Ok(value) => value,
                            Err(e) => {
                                http_connection_context.log(
                                    LoggerLevel::Error,
                                    format!(
                                        "Failed to add authorization header: {authorization_value} with error: {e}"
                                    ),
                                );
                                return Ok(Self::closed_response(StatusCode::BAD_GATEWAY));
                            }
                        },
                    );

                    http_connection_context.log(
                        LoggerLevel::Trace,
                        format!("Added authorization header {authorization_value}"),
                    )
                }
                Err(e) => {
                    http_connection_context.log(
                        LoggerLevel::Error,
                        format!("compute_signature failed with error: {e}"),
                    );
                }
            }
        } else {
            http_connection_context.log(
                LoggerLevel::Trace,
                "current key is empty, skip computing the signature.".to_string(),
            );
        }

        // start new request to the Host endpoint
        http_connection_context.log(
            LoggerLevel::Trace,
            format!(
                "Forwarding request to the target server: {} {}",
                http_connection_context.method, http_connection_context.url
            ),
        );
        let proxy_response = http_connection_context.send_request(proxy_request).await;
        http_connection_context.log(
            LoggerLevel::Trace,
            format!(
                "Received response from the target server: {} {}",
                http_connection_context.method, http_connection_context.url
            ),
        );
        // forward the response to the client
        self.forward_response(proxy_response, http_connection_context)
            .await
    }

    /// It reads the body in chunks and concatenates them into a single Bytes object
    /// It also yields control to the tokio scheduler to avoid blocking the thread if the body is large
    async fn read_body_bytes<B>(mut body: B) -> Result<Bytes>
    where
        B: hyper::body::Body<Data = Bytes> + Unpin,
        B::Error: std::fmt::Display + Send + Sync + 'static,
    {
        let body_size = body.size_hint().upper().unwrap_or(4 * 1024 * 1024);
        let mut buf = BytesMut::with_capacity(body_size as usize);
        while let Some(chunk) = body.frame().await {
            match chunk {
                Ok(chunk) => {
                    if let Ok(data) = chunk.into_data() {
                        buf.extend_from_slice(&data)
                    }
                }
                Err(e) => {
                    return Err(Error::Hyper(HyperErrorType::ReceiveBody(e.to_string())));
                }
            }
            // yield control to the tokio scheduler to avoid blocking the thread if the body is large
            tokio::task::yield_now().await;
        }
        Ok(buf.freeze())
    }
}

#[cfg(test)]
mod tests {
    use crate::common::logger;
    use crate::proxy::proxy_server;
    use crate::shared_state;
    use http::Method;
    use proxy_agent_shared::hyper_client;
    use std::collections::HashMap;
    use std::time::Duration;

    #[tokio::test]
    async fn direct_request_test() {
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
        let mut sender = hyper_client::build_http_sender(host, port, logger::write_warning)
            .await
            .unwrap();
        let response = sender.send_request(request).await.unwrap();
        assert_eq!(
            http::StatusCode::MISDIRECTED_REQUEST,
            response.status(),
            "response.status must be MISDIRECTED_REQUEST."
        );

        // verify the connection is closed
        response.headers().get("connection").map(|v| {
            assert_eq!(
                v.to_str().unwrap(),
                "close",
                "response.headers.connection must be close."
            );
        });
        assert!(
            sender.is_closed(),
            "sender must be closed after the request."
        );

        // test with traversal characters
        let url: hyper::Uri = format!("http://{}:{}/test/../", host, port)
            .parse()
            .unwrap();
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
            http::StatusCode::NOT_FOUND,
            response.status(),
            "response.status must be NOT_FOUND."
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
    }
}
