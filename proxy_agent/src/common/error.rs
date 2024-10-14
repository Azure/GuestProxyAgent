// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

use std::error::Error as StdError;
use std::fmt;

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

    pub fn hex(message: String, error: hex::FromHexError) -> Self {
        Self::new(ErrorType::Hex(message, error))
    }

    pub fn key(message: String) -> Self {
        Self::new(ErrorType::Key(message))
    }

    pub fn parse(message: String) -> Self {
        Self::new(ErrorType::Parse(message))
    }

    pub fn wireserver(message: String, error_type: WireServerErrorType) -> Self {
        Self::new(ErrorType::WireServer(message, error_type))
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.description())
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match *self.0 {
            ErrorType::Hyper(ref err) => {
                match err {
                    HyperErrorType::Request(_, ref hyper_err) => Some(hyper_err),
                    _ => None
                }
            },
            _ => None
        }
    }
}

impl From<hyper::Error> for Error {
    fn from(error: hyper::Error) -> Self {
        Error::hyper(HyperErrorType::Request("".to_string(), error))
    }
}

#[derive(Debug)]
pub enum ErrorType {
    IO(String, std::io::Error),
    Hyper(HyperErrorType),
    Hex(String, hex::FromHexError),
    Key(String),
    WireServer(String, WireServerErrorType),
    Parse(String)
}

#[derive(Debug)]
pub enum HyperErrorType {
    Request(String, hyper::Error),
    Response(String, hyper::Error),
    Http(String, http::Error),
    RequestBuilder(String),
    ServerError(String),
    Deserialize(String)
}

#[derive(Debug)]
pub enum WireServerErrorType
{
    Telemetry,
    GoalState,
    SharedConfig
}