use std::{fmt, string::FromUtf8Error};

use base64::DecodeError;

#[derive(Debug, Clone)]
pub struct FormattedError {
    pub message: String,
    pub code: i32,
}

impl fmt::Display for FormattedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "code: {}, message: {}", self.code, self.message)
    }
}

impl std::error::Error for FormattedError {}

impl From<DecodeError> for FormattedError {
    fn from(value: DecodeError) -> Self {
        FormattedError {
            message: format!("Decode Error: {value:?}"),
            code: -1,
        }
    }
}

impl From<FromUtf8Error> for FormattedError {
    fn from(value: FromUtf8Error) -> Self {
        FormattedError {
            message: format!("Utf-8 Convert Error: {value:?}"),
            code: -1,
        }
    }
}

impl From<serde_json::Error> for FormattedError {
    fn from(value: serde_json::Error) -> Self {
        FormattedError {
            message: format!("Json Error: {value:?}"),
            code: -1,
        }
    }
}

#[cfg(windows)]
impl From<windows::core::Error> for FormattedError {
    fn from(value: windows::core::Error) -> Self {
        FormattedError {
            message: format!("Windows API Error: {value:?}"),
            code: -1,
        }
    }
}
