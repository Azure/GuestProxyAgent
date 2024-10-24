// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

//! This module contains the connection context struct for the proxy listener, and write proxy processing logs to local file.

use crate::common::{constants, hyper_client};
use crate::proxy::Claims;
use proxy_agent_shared::{logger_manager, rolling_logger::RollingLogger};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;

pub struct ConnectionContext {
    pub id: u128,
    pub stream: Arc<Mutex<TcpStream>>,
    pub client_addr: SocketAddr,
    pub now: Instant,
    pub claims: Option<Claims>,
    pub method: hyper::Method,
    pub url: hyper::Uri,
    pub ip: Option<Ipv4Addr>, // currently, we only support IPv4
    pub port: u16,
}

impl ConnectionContext {
    pub fn should_skip_sig(&self) -> bool {
        hyper_client::should_skip_sig(&self.method, &self.url)
    }

    /// Get the target server ip address in string for logging purpose.
    pub fn get_ip_string(&self) -> String {
        if let Some(ip) = &self.ip {
            return ip.to_string();
        }
        "None".to_string()
    }
}

pub struct Connection {}
impl Connection {
    pub const CONNECTION_LOGGER_KEY: &'static str = "Connection_Logger";
    pub fn init_logger(log_folder: PathBuf) {
        logger_manager::init_logger(
            Connection::CONNECTION_LOGGER_KEY.to_string(),
            log_folder,
            "ProxyAgent.Connection.log".to_string(),
            constants::MAX_LOG_FILE_SIZE,
            constants::MAX_LOG_FILE_COUNT as u16,
        );
    }

    fn get_connection_logger() -> Arc<Mutex<RollingLogger>> {
        logger_manager::get_logger(Connection::CONNECTION_LOGGER_KEY)
    }

    pub fn write(connection_id: u128, message: String) {
        if let Err(e) = Connection::get_connection_logger()
            .lock()
            .unwrap()
            .write(format!("Connection:{} - {}", connection_id, message))
        {
            eprintln!("Failed to write to connection logger: {}", e);
        }
    }

    pub fn write_information(connection_id: u128, message: String) {
        if let Err(e) = Connection::get_connection_logger()
            .lock()
            .unwrap()
            .write_information(format!("Connection:{} - {}", connection_id, message))
        {
            eprintln!("Failed to write to connection logger: {}", e);
        }
    }

    pub fn write_warning(connection_id: u128, message: String) {
        if let Err(e) = Connection::get_connection_logger()
            .lock()
            .unwrap()
            .write_warning(format!("Connection:{} - {}", connection_id, message))
        {
            eprintln!("Failed to write to connection logger: {}", e);
        }
    }

    pub fn write_error(connection_id: u128, message: String) {
        if let Err(e) = Connection::get_connection_logger()
            .lock()
            .unwrap()
            .write_error(format!("Connection:{} - {}", connection_id, message))
        {
            eprintln!("Failed to write to connection logger: {}", e);
        }
    }
}
