use std::{fmt, string::FromUtf8Error};

use base64::DecodeError;
use reqwest::header::InvalidHeaderValue;

#[derive(Debug, Clone)]
pub struct ErrorDetails {
    pub message: String,
    pub code: i32,
}

impl fmt::Display for ErrorDetails {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for ErrorDetails {}

impl From<DecodeError> for ErrorDetails {
    fn from(value: DecodeError) -> Self {
        ErrorDetails {
            message: format!("Decode Error: {value:?}"),
            code: -1,
        }
    }
}

impl From<FromUtf8Error> for ErrorDetails {
    fn from(value: FromUtf8Error) -> Self {
        ErrorDetails {
            message: format!("Uft8 Convert Error: {value:?}"),
            code: -1,
        }
    }
}

impl From<InvalidHeaderValue> for ErrorDetails {
    fn from(value: InvalidHeaderValue) -> Self {
        ErrorDetails {
            message: format!("Invalid Http Header Value: {value:?}"),
            code: -1,
        }
    }
}

impl From<serde_json::Error> for ErrorDetails {
    fn from(value: serde_json::Error) -> Self {
        ErrorDetails {
            message: format!("Json Error: {value:?}"),
            code: -1,
        }
    }
}

#[cfg(windows)]
impl From<windows::core::Error> for ErrorDetails {
    fn from(value: windows::core::Error) -> Self {
        ErrorDetails {
            message: format!("Windows API Error: {value:?}"),
            code: -1,
        }
    }
}
