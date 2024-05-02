use crate::proxy::Claims;
use proxy_agent_shared::{logger_manager, rolling_logger::RollingLogger};
use std::net::TcpStream;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;

pub struct Connection {
    pub stream: TcpStream,
    pub id: u128,

    pub now: Instant,
    pub cliams: Option<Claims>,
    pub ip: String,
    pub port: u16,
}

impl Connection {
    pub const CONNECTION_LOGGER_KEY: &'static str = "Connection_Logger";
    pub fn init_logger(log_folder: PathBuf) {
        logger_manager::init_logger(
            Connection::CONNECTION_LOGGER_KEY.to_string(),
            log_folder,
            "ProxyAgent.Connection.log".to_string(),
            20 * 1024 * 1024,
            30,
        );
    }

    fn get_connection_logger() -> Arc<Mutex<RollingLogger>> {
        logger_manager::get_logger(Connection::CONNECTION_LOGGER_KEY)
    }

    pub fn write(connection_id:u128, message: String) {
        _ = Connection::get_connection_logger()
            .lock()
            .unwrap()
            .write(format!("Connection:{} - {}", connection_id, message));
    }

    pub fn write_information(connection_id:u128, message: String) {
        _ = Connection::get_connection_logger()
            .lock()
            .unwrap()
            .write_information(format!("Connection:{} - {}", connection_id, message));
    }

    pub fn write_warning(connection_id:u128, message: String) {
        _ = Connection::get_connection_logger()
            .lock()
            .unwrap()
            .write_warning(format!("Connection:{} - {}", connection_id, message));
    }

    pub fn write_error(connection_id:u128, message: String) {
        _ = Connection::get_connection_logger()
            .lock()
            .unwrap()
            .write_error(format!("Connection:{} - {}", connection_id, message));
    }
}
