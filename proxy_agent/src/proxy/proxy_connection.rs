// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

//! This module contains the connection context struct for the proxy listener, and write proxy processing logs to local file.

use crate::common::config;
use crate::common::error::Error;
use crate::common::result::Result;
use crate::proxy::Claims;
use crate::redirector::{self, AuditEntry};
use crate::shared_state::proxy_server_wrapper::ProxyServerSharedState;
use crate::shared_state::redirector_wrapper::RedirectorSharedState;
use hyper::body::Bytes;
use hyper::client::conn::http1;
use hyper::Request;
use proxy_agent_shared::error::HyperErrorType;
use proxy_agent_shared::hyper_client;
use proxy_agent_shared::logger::{self, logger_manager, LoggerLevel};
use proxy_agent_shared::misc_helpers;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;

pub type RequestBody =
    http_body_util::combinators::BoxBody<Bytes, Box<dyn std::error::Error + Send + Sync>>;
struct Client {
    sender: http1::SendRequest<RequestBody>,
}

impl Client {
    async fn send_request(
        &mut self,
        req: Request<RequestBody>,
    ) -> Result<hyper::Response<hyper::body::Incoming>> {
        if self.sender.is_closed() {
            return Err(Error::Hyper(HyperErrorType::HostConnection(
                "the connection has been closed".to_string(),
            )));
        }

        let full_url = req.uri().to_string();
        self.sender.send_request(req).await.map_err(|e| {
            Error::Hyper(HyperErrorType::Custom(
                format!("Failed to send request to {full_url}"),
                e,
            ))
        })
    }
}

#[derive(Clone)]
pub struct TcpConnectionContext {
    pub id: u128,
    pub client_addr: SocketAddr,
    pub claims: Option<Claims>,
    pub destination_ip: Option<Ipv4Addr>, // currently, we only support IPv4
    pub destination_port: u16,
    sender: std::result::Result<Arc<Mutex<Client>>, String>,
    logger: ConnectionLogger,
}

impl TcpConnectionContext {
    pub async fn new(
        id: u128,
        client_addr: SocketAddr,
        redirector_shared_state: RedirectorSharedState,
        proxy_server_shared_state: ProxyServerSharedState,
        #[cfg(windows)] raw_socket_id: usize, // windows only, it is the raw socket id, used to get audit entry from socket stream
    ) -> Self {
        let client_source_ip = client_addr.ip();
        let client_source_port = client_addr.port();
        let mut logger = ConnectionLogger::new(id, 0);

        let (claims, destination_ip, destination_port, sender) = match Self::get_audit_entry(
            &client_addr,
            &redirector_shared_state,
            &mut logger,
            #[cfg(windows)]
            raw_socket_id,
        )
        .await
        {
            Ok(audit_entry) => {
                let claims = match Claims::from_audit_entry(
                    &audit_entry,
                    client_source_ip,
                    client_source_port,
                    proxy_server_shared_state,
                )
                .await
                {
                    Ok(claims) => Some(claims),
                    Err(e) => {
                        logger.write(
                            LoggerLevel::Error,
                            format!("Failed to get claims from audit entry: {e}"),
                        );
                        // return None for claims
                        None
                    }
                };

                let host_ip = audit_entry.destination_ipv4_addr().to_string();
                let host_port = audit_entry.destination_port_in_host_byte_order();
                let mut cloned_logger = logger.clone();
                let fun = move |message: String| {
                    cloned_logger.write(LoggerLevel::Warn, message);
                };
                let sender = match hyper_client::build_http_sender(&host_ip, host_port, fun).await {
                    Ok(sender) => {
                        logger.write(
                            LoggerLevel::Trace,
                            "Successfully created http sender".to_string(),
                        );
                        Ok(Arc::new(Mutex::new(Client { sender })))
                    }
                    Err(e) => Err(e.to_string()),
                };

                (
                    claims,
                    Some(audit_entry.destination_ipv4_addr()),
                    host_port,
                    sender,
                )
            }
            Err(e) => {
                logger.write(
                    LoggerLevel::Warn,
                    "This tcp connection may send to proxy agent tcp listener directly".to_string(),
                );
                (None, None, 0, Err(e.to_string()))
            }
        };

        Self {
            id,
            client_addr,
            claims,
            destination_ip,
            destination_port,
            sender,
            logger,
        }
    }

    async fn get_audit_entry(
        client_addr: &SocketAddr,
        redirector_shared_state: &RedirectorSharedState,
        logger: &mut ConnectionLogger,
        #[cfg(windows)] raw_socket_id: usize,
    ) -> Result<AuditEntry> {
        let client_source_port = client_addr.port();
        match redirector::lookup_audit(client_source_port, redirector_shared_state, logger).await {
            Ok(data) => {
                logger.write(
                    LoggerLevel::Trace,
                    format!(
                        "Found audit entry with client_source_port '{client_source_port}' successfully"
                    ),
                );
                match redirector::remove_audit(client_source_port, redirector_shared_state).await {
                    Ok(_) => logger.write(
                        LoggerLevel::Trace,
                        format!(
                            "Removed audit entry with client_source_port '{client_source_port}' successfully"
                        ),
                    ),
                    Err(e) => {
                        logger.write(
                            LoggerLevel::Warn,
                            format!("Failed to remove audit entry: {e}"),
                        );
                    }
                }

                Ok(data)
            }
            Err(e) => {
                let message = format!(
                    "Failed to find audit entry with client_source_port '{client_source_port}' with error: {e}"
                );
                logger.write(LoggerLevel::Warn, message.clone());

                #[cfg(not(windows))]
                {
                    Err(Error::FindAuditEntryError(message))
                }

                #[cfg(windows)]
                {
                    logger.write(
                        LoggerLevel::Info,
                        "Try to get audit entry from socket stream".to_string(),
                    );

                    match redirector::get_audit_from_stream_socket(raw_socket_id, logger) {
                        Ok(data) => {
                            logger.write(
                                LoggerLevel::Info,
                                "Found audit entry from socket stream successfully".to_string(),
                            );
                            Ok(data)
                        }
                        Err(e) => {
                            logger.write(
                                LoggerLevel::Warn,
                                format!("Failed to get lookup_audit_from_stream with error: {e}"),
                            );
                            Err(Error::FindAuditEntryError(message))
                        }
                    }
                }
            }
        }
    }

    /// Get the target server ip address in string for logging purpose.
    pub fn get_ip_string(&self) -> String {
        if let Some(ip) = &self.destination_ip {
            return ip.to_string();
        }
        "None".to_string()
    }

    pub fn log(&mut self, logger_level: LoggerLevel, message: String) {
        self.logger.write(logger_level, message)
    }

    async fn send_request(
        &self,
        request: hyper::Request<RequestBody>,
    ) -> Result<hyper::Response<hyper::body::Incoming>> {
        match &self.sender {
            Ok(sender) => sender.lock().await.send_request(request).await,
            Err(e) => Err(Error::Hyper(HyperErrorType::HostConnection(e.clone()))),
        }
    }
}

pub struct HttpConnectionContext {
    pub id: u128,
    pub now: Instant,
    pub method: hyper::Method,
    pub url: hyper::Uri,
    pub tcp_connection_context: TcpConnectionContext,
    pub logger: ConnectionLogger,
    pub stages: Vec<String>,
}

impl HttpConnectionContext {
    pub fn new(
        id: u128,
        method: hyper::Method,
        url: hyper::Uri,
        tcp_connection_context: TcpConnectionContext,
    ) -> Self {
        let logger = ConnectionLogger::new(tcp_connection_context.id, id);
        Self {
            id,
            now: Instant::now(),
            method,
            url,
            tcp_connection_context,
            logger,
            stages: Vec::new(),
        }
    }

    fn add_stage(&mut self, value: String) {
        self.stages.push(format!(
            "[{}] - {} - {} - {}",
            self.id,
            self.now.elapsed().as_millis(),
            misc_helpers::get_date_time_string_with_milliseconds(),
            value
        ));
    }

    pub fn should_skip_sig(&self) -> bool {
        hyper_client::should_skip_sig(&self.method, &self.url)
    }

    /// Pre-canonical defense-in-depth guard. Returns `true` if the request
    /// path contains a pattern commonly used to bypass prefix-based
    /// authorization rules. See [`path_has_traversal`] for the exact set.
    /// This is checked in `handle_new_http_request` before any rule lookup
    /// so suspicious paths short-circuit to 403 without ever reaching the
    /// matcher or the upstream.
    ///
    /// Once the canonical pipeline graduates to enforce mode (M5), the
    /// `PathUnderflow` / slash-collapsing / encoded-dot handling in
    /// `crate::proxy::canonical::path` subsumes this check entirely and
    /// this method can be removed.
    pub fn contains_traversal_characters(&self) -> bool {
        path_has_traversal(self.url.path())
    }

    pub fn log(&mut self, logger_level: LoggerLevel, message: String) {
        if config::get_enable_http_proxy_trace() {
            self.add_stage(message.clone());
        }

        self.logger.write(logger_level, message)
    }

    pub fn get_logger_mut_ref(&mut self) -> &mut ConnectionLogger {
        &mut self.logger
    }

    pub async fn send_request(
        &self,
        request: hyper::Request<RequestBody>,
    ) -> Result<hyper::Response<hyper::body::Incoming>> {
        self.tcp_connection_context.send_request(request).await
    }
}

impl Drop for HttpConnectionContext {
    fn drop(&mut self) {
        if !self.stages.is_empty() {
            logger_manager::write_system_log(LoggerLevel::Warn, self.stages.join("\n"));
        }
    }
}

pub struct ConnectionLogger {
    pub tcp_connection_id: u128,
    pub http_connection_id: u128,
    queue: Vec<String>,
}
impl ConnectionLogger {
    pub const CONNECTION_LOGGER_KEY: &'static str = "Connection_Logger";

    pub fn new(tcp_connection_id: u128, http_connection_id: u128) -> Self {
        Self {
            tcp_connection_id,
            http_connection_id,
            queue: Vec::new(),
        }
    }

    pub fn write(&mut self, logger_level: LoggerLevel, message: String) {
        let message = format!(
            "{}[{}] - {}",
            self.http_connection_id, self.tcp_connection_id, message
        );

        // write to system log for connection logger explicitly,
        // as the connection logger only writes to file when the connection is dropped and,
        // connection logger file log does not write to system log implicitly.
        logger_manager::write_system_log(logger_level, message.clone());

        if let Some(log_for_event) = crate::common::config::get_file_log_level_for_events() {
            if log_for_event >= logger_level {
                // write to event
                proxy_agent_shared::telemetry::event_logger::write_event_only(
                    logger_level,
                    message.clone(),
                    "ConnectionLogger",
                    "ProxyAgent",
                );
            }
        }

        if logger_level > logger_manager::get_max_logger_level()
            || config::get_logs_dir() == misc_helpers::empty_path()
        {
            // If the logger level is higher than the max logger level or logs directory is not set, skip logging
            return;
        }

        let mut msg = logger::get_log_header(logger_level);
        msg.push_str(&message);
        self.queue.push(msg);
    }
}

impl Drop for ConnectionLogger {
    fn drop(&mut self) {
        if !self.queue.is_empty() {
            self.queue.push(format!(
                "{}{}[{}] - {}",
                logger::get_log_header(LoggerLevel::Info),
                self.http_connection_id,
                self.tcp_connection_id,
                "------------------------ ConnectionLogger is dropped ------------------------"
            ));
            logger_manager::write_many(
                Some(Self::CONNECTION_LOGGER_KEY.to_string()),
                self.queue.clone(),
            );
        }
    }
}

impl Clone for ConnectionLogger {
    fn clone(&self) -> Self {
        Self {
            tcp_connection_id: self.tcp_connection_id,
            http_connection_id: self.http_connection_id,
            queue: Vec::new(), // Do not clone the queue, as it is used for logging
        }
    }
}

/// Returns `true` if `raw_path` (the path component of a request URI in
/// its on-wire, *not yet percent-decoded* form) contains a pattern that
/// is commonly used to bypass prefix-based authorization rules.
///
/// Caught by this function (rejected with 404 by the caller):
///   * `..` — literal dot-dot anywhere in the path
///   * `%2E%2E`, `%2e%2e`, and mixed-case (`%2E%2e`, `%2e%2E`) — caught
///     after a single percent-decode pass
///   * `.%2e`, `%2E.`, etc. — same single-decode pass collapses them
///     into a literal `..`
///   * `//` — two or more consecutive slashes (multi-slash bypass).
///     Legacy prefix-matching treats `/foo//bar` as a distinct path
///     from `/foo/bar`; reject the raw form so attackers cannot pivot
///     past a privilege whose path string lacks the extra slash.
///
/// INTENTIONALLY NOT rejected here (the canonical pipeline in
/// [`crate::proxy::canonical::path`] handles these and will subsume this
/// guard entirely once it graduates to enforce mode in M5):
///   * single `.` segments — valid in real paths like `/.well-known/*`
///   * `;` matrix parameters — sub-delim that is legal inside a segment
///   * non-ASCII / Unicode-confusable bytes — caught by `reject_non_ascii`
///   * embedded `?` after percent-decode — caught by canonical's EmbQ check
///   * trailing-slash variation — clamped by canonical's normalizer
///
/// Decoding uses `decode_utf8_lossy`: any invalid-UTF-8 percent
/// sequences are replaced by U+FFFD (which does not contain `..`), and
/// truly malformed sequences are passed through unchanged. This keeps
/// the check fail-open for the rare valid non-ASCII path while staying
/// safe for the traversal cases that matter.
fn path_has_traversal(raw_path: &str) -> bool {
    if raw_path.contains("//") {
        return true;
    }
    let decoded = percent_encoding::percent_decode_str(raw_path).decode_utf8_lossy();
    decoded.contains("..")
}

#[cfg(test)]
mod tests {
    use super::path_has_traversal;

    #[test]
    fn clean_paths_are_not_traversal() {
        for p in [
            "/",
            "/metadata/instance",
            "/metadata/identity/oauth2/token",
            "/machine/?comp=goalstate",
            "/.well-known/foo",
            "/metadata/instance?api-version=2021-02-01",
        ] {
            assert!(
                !path_has_traversal(p),
                "expected clean path, got traversal: {p:?}"
            );
        }
    }

    #[test]
    fn literal_dot_dot_is_traversal() {
        for p in [
            "/foo/../bar",
            "/metadata/./identity/../identity/oauth2/token",
            "/..",
            "../etc/passwd",
        ] {
            assert!(path_has_traversal(p), "expected traversal: {p:?}");
        }
    }

    #[test]
    fn percent_encoded_dot_dot_is_traversal() {
        // Uppercase, lowercase, and mixed-case percent encodings must all
        // be caught — they all decode to a literal `..` in a single pass.
        for p in [
            "/foo/%2E%2E/bar",
            "/foo/%2e%2e/bar",
            "/foo/%2E%2e/bar",
            "/foo/%2e%2E/bar",
            "/foo/.%2e/bar",
            "/foo/%2E./bar",
            "/metadata/%2E/identity/%2E%2E/identity/oauth2/token",
        ] {
            assert!(
                path_has_traversal(p),
                "expected percent-encoded traversal: {p:?}"
            );
        }
    }

    #[test]
    fn multi_slash_is_traversal() {
        for p in [
            "//metadata/instance",
            "/metadata//instance",
            "/metadata///identity//oauth2//token",
            "//",
        ] {
            assert!(
                path_has_traversal(p),
                "expected multi-slash traversal: {p:?}"
            );
        }
    }

    #[test]
    fn single_dot_and_matrix_params_are_not_traversal_here() {
        // Single `.` segments and matrix params (`;`) are not traversal
        // markers and must pass through this pre-canonical guard. The
        // canonical pipeline applies its own normalization in M5.
        for p in [
            "/metadata/./instance",
            "/metadata/instance;jsessionid=abc",
            "/.well-known/openid-configuration",
        ] {
            assert!(
                !path_has_traversal(p),
                "expected non-traversal (deferred to canonical): {p:?}"
            );
        }
    }
}
