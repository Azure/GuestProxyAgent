// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

use std::error::Error as StdError;
use std::fmt::{Display};

#[derive(Debug)]
pub struct Error(Box<ErrorType>);

impl Error {
    pub fn new(error: ErrorType) -> Self {
        Self(Box::new(error))
    }

    pub fn io(message: String, error: std::io::Error) -> Self {
        Self::new(ErrorType::IO(message, error))
    }

    pub fn hyper(error: HyperErrorType) -> Self {
        Self::new(ErrorType::Hyper(error))
    }

    pub fn http(message: String, error: http::Error) -> Self {
        Self::new(ErrorType::Http(message, error))
    }

    pub fn hex(message: String, error: hex::FromHexError) -> Self {
        Self::new(ErrorType::Hex(message, error))
    }

    pub fn key(message: String) -> Self {
        Self::new(ErrorType::Key(message))
    }

    pub fn parse(message: String) -> Self {
        Self::new(ErrorType::Parse(message))
    }

    pub fn wireserver(error_type: WireServerErrorType, message: String) -> Self {
        Self::new(ErrorType::WireServer(error_type, message))
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl StdError for Error {}

#[derive(Debug, thiserror::Error)]
pub enum ErrorType {
    #[error("IO error: {0}: {1}")]
    IO(String, std::io::Error),

    #[error("{0}")]
    Hyper(HyperErrorType),

    #[error("{0}: {1}")]
    Http(String, http::Error),

    #[error("Hex encoded key '{0}' is invalid: {1}")]
    Hex(String, hex::FromHexError),

    #[error("{0}")]
    Key(String),

    #[error("{0}: {1}")]
    WireServer(WireServerErrorType, String),

    #[error("{0}")]
    Parse(String)
}

#[derive(Debug, thiserror::Error)]
pub enum HyperErrorType {
    #[error("{0}: {1}")]
    Custom(String, hyper::Error),
    
    #[error("Failed to get {0} from request builder")]
    RequestBuilder(String),

    #[error("Failed to get response from {0}, status code: {1}")]
    ServerError(String, u16),

    #[error("Deserialization failed: {0}")]
    Deserialize(String)
}

#[derive(Debug, thiserror::Error)]
pub enum WireServerErrorType
{
    #[error("Telemetry error")]
    Telemetry,

    #[error("Goal state error")]
    GoalState,

    #[error("Shared config error")]
    SharedConfig
}