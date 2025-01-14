// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

//! This module contains the connection context struct for the proxy listener, and write proxy processing logs to local file.

use crate::common::error::{Error, HyperErrorType};
use crate::common::result::Result;
use crate::common::{constants, hyper_client};
use crate::proxy::Claims;
use crate::redirector::{self, AuditEntry};
use crate::shared_state::proxy_server_wrapper::ProxyServerSharedState;
use crate::shared_state::redirector_wrapper::RedirectorSharedState;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::client::conn::http1;
use hyper::Request;
use proxy_agent_shared::logger_manager::{self, LoggerLevel};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;

pub type RequestBody = Full<Bytes>;
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
                format!("Failed to send request to {}", full_url),
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
        let logger = ConnectionLogger {
            tcp_connection_id: id,
            http_connection_id: 0,
        };

        let (claims, destination_ip, destination_port, sender) = match Self::get_audit_entry(
            &client_addr,
            &redirector_shared_state,
            &logger,
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
                            format!("Failed to get claims from audit entry: {}", e),
                        );
                        // return None for claims
                        None
                    }
                };

                let host_ip = audit_entry.destination_ipv4_addr().to_string();
                let host_port = audit_entry.destination_port_in_host_byte_order();
                let cloned_logger = logger.clone();
                let fun = move |message: String| {
                    cloned_logger.write(LoggerLevel::Warning, message);
                };
                let sender = match hyper_client::build_http_sender(&host_ip, host_port, fun).await {
                    Ok(sender) => {
                        logger.write(
                            LoggerLevel::Verbose,
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
                    LoggerLevel::Warning,
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
        logger: &ConnectionLogger,
        #[cfg(windows)] raw_socket_id: usize,
    ) -> Result<AuditEntry> {
        let client_source_port = client_addr.port();
        match redirector::lookup_audit(client_source_port, redirector_shared_state).await {
            Ok(data) => {
                logger.write(
                    LoggerLevel::Verbose,
                    format!(
                        "Found audit entry with client_source_port '{}' successfully",
                        client_source_port
                    ),
                );
                match redirector::remove_audit(client_source_port, redirector_shared_state).await {
                    Ok(_) => logger.write(
                        LoggerLevel::Verbose,
                        format!(
                            "Removed audit entry with client_source_port '{}' successfully",
                            client_source_port
                        ),
                    ),
                    Err(e) => {
                        logger.write(
                            LoggerLevel::Warning,
                            format!("Failed to remove audit entry: {}", e),
                        );
                    }
                }

                Ok(data)
            }
            Err(e) => {
                let message = format!(
                    "Failed to find audit entry with client_source_port '{}' with error: {}",
                    client_source_port, e
                );
                logger.write(LoggerLevel::Warning, message.clone());

                #[cfg(not(windows))]
                {
                    Err(Error::FindAuditEntryError(message))
                }

                #[cfg(windows)]
                {
                    logger.write(
                        LoggerLevel::Information,
                        "Try to get audit entry from socket stream".to_string(),
                    );

                    match redirector::get_audit_from_stream_socket(raw_socket_id) {
                        Ok(data) => {
                            logger.write(
                                LoggerLevel::Information,
                                "Found audit entry from socket stream successfully".to_string(),
                            );
                            Ok(data)
                        }
                        Err(e) => {
                            logger.write(
                                LoggerLevel::Warning,
                                format!("Failed to get lookup_audit_from_stream with error: {}", e),
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

    pub fn log(&self, logger_level: LoggerLevel, message: String) {
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
}

impl HttpConnectionContext {
    pub fn should_skip_sig(&self) -> bool {
        hyper_client::should_skip_sig(&self.method, &self.url)
    }

    pub fn log(&self, logger_level: LoggerLevel, message: String) {
        self.logger.write(logger_level, message)
    }

    pub fn get_logger(&self) -> ConnectionLogger {
        self.logger.clone()
    }

    pub async fn send_request(
        &self,
        request: hyper::Request<RequestBody>,
    ) -> Result<hyper::Response<hyper::body::Incoming>> {
        self.tcp_connection_context.send_request(request).await
    }
}

#[derive(Clone)]
pub struct ConnectionLogger {
    pub tcp_connection_id: u128,
    pub http_connection_id: u128,
}
impl ConnectionLogger {
    pub const CONNECTION_LOGGER_KEY: &'static str = "Connection_Logger";
    pub async fn init_logger(log_folder: PathBuf) {
        logger_manager::init_logger(
            Self::CONNECTION_LOGGER_KEY.to_string(),
            log_folder,
            "ProxyAgent.Connection.log".to_string(),
            constants::MAX_LOG_FILE_SIZE,
            constants::MAX_LOG_FILE_COUNT as u16,
        )
        .await;
    }

    pub fn write(&self, logger_level: LoggerLevel, message: String) {
        logger_manager::log(
            Self::CONNECTION_LOGGER_KEY.to_string(),
            logger_level,
            format!(
                "Connection:{}[{}] - {}",
                self.http_connection_id, self.tcp_connection_id, message
            ),
        )
    }
}
