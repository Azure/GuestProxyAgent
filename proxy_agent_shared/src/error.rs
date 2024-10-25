use std::error::Error as StdError;
use std::fmt::Display;
use std::io;

#[derive(Debug)]
pub struct Error(Box<ErrorType>);

impl Error {
    fn new(error: ErrorType) -> Self {
        Self(Box::new(error))
    }

    pub fn parse_version(message: String) -> Self {
        Self::new(ErrorType::ParseVersion(message))
    }

    pub fn findmnt(message: String) -> Self {
        Self::new(ErrorType::FindMnt(message))
    }
}

impl<T: Into<ErrorType>> From<T> for Error {
    fn from(cause: T) -> Self {
        Self::new(cause.into())
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
    #[cfg(windows)]
    #[error(transparent)]
    WindowsService(#[from] windows_service::Error),

    #[error(transparent)]
    IO(#[from] io::Error),
    
    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error("Failed to create regex with error: {0}")]
    Regex(#[from] regex::Error),

    #[error("{0}")]
    ParseVersion(String),

    #[error("Findmnt command {0}")]
    FindMnt(String)
}