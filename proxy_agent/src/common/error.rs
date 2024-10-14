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

    pub fn hyper(error: HyperClientError) -> Self {
        Self::new(ErrorType::Hyper(error))
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
                    HyperClientError::Request(_, ref hyper_err) => Some(hyper_err),
                    _ => None
                }
            },
            _ => None
        }
    }
}

#[derive(Debug)]
pub enum ErrorType {
    Hyper(HyperClientError),
    //Hyper(String, hyper::Error),
    Http(String, http::Error),
    Custom(CustomErrorType, String)
}

#[derive(Debug)]
pub enum HyperClientError {
    Request(String, hyper::Error),
    Response(String, hyper::Error),
    Http(String, http::Error),
    RequestBuilder(String),
    ServerError(String),
    Deserialize(String),
    InvalidUrl(String),
}

#[derive(Debug)]
pub enum CustomErrorType {
    Parse,
    Deserialize
}