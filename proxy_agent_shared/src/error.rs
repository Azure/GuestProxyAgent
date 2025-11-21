// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use http::StatusCode;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    // windows_service::Error is a custom error type from the windows-service crate
    // it does not display the IO error message, so we need to add it manually
    #[cfg(windows)]
    #[error("{0}: {1}")]
    WindowsService(windows_service::Error, std::io::Error),

    #[error("{0}")]
    Hyper(HyperErrorType),

    #[error("Hex encoded key '{0}' is invalid: {1}")]
    Hex(String, hex::FromHexError),

    #[cfg(not(windows))]
    #[error("ComputeSignature error in {0}: {1}")]
    ComputeSignature(String, openssl::error::ErrorStack),
    #[cfg(windows)]
    #[error("ComputeSignature error in {0}: error code: {1}")]
    ComputeSignature(String, windows_sys::Win32::Foundation::NTSTATUS),

    #[error("Failed to parse URL {0} with error: {1}")]
    ParseUrl(String, String),

    #[error("{0} with the error: {1}")]
    WireServer(WireServerErrorType, String),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error("Failed to create regex with error: {0}")]
    Regex(#[from] regex::Error),

    #[cfg(windows)]
    #[error("WindowsApi '{0}' failed with error: {1}")]
    WindowsApi(String, std::io::Error),

    #[error("{0}")]
    ParseVersion(ParseVersionErrorType),

    #[error("{0} command: {1}")]
    Command(CommandErrorType, String),

    #[error("Failed to send '{0}' action response with error {1}")]
    SendError(String, String),

    #[error("Failed to receive '{0}' action response with error {1}")]
    RecvError(String, tokio::sync::oneshot::error::RecvError),
}

#[derive(Debug, thiserror::Error)]
pub enum ParseVersionErrorType {
    #[error("Invalid version string '{0}'")]
    InvalidString(String),

    #[error("Cannot read Major build from {0}")]
    MajorBuild(String),

    #[error("Cannot read Minor build from {0}")]
    MinorBuild(String),
}

#[derive(Debug, thiserror::Error)]
pub enum CommandErrorType {
    #[error("Findmnt")]
    Findmnt,
    #[error("{0}")]
    CommandName(String),
}

#[derive(Debug, thiserror::Error)]
pub enum HyperErrorType {
    #[error("{0}: {1}")]
    Custom(String, hyper::Error),

    #[error("Host connection error: {0}")]
    HostConnection(String),

    #[error("Failed to build request with error: {0}")]
    RequestBuilder(String),

    #[error("Failed to receive the request body with error: {0}")]
    RequestBody(String),

    #[error("Failed to get response from {0}, status code: {1}")]
    ServerError(String, StatusCode),

    #[error("Deserialization failed: {0}")]
    Deserialize(String),
}

#[derive(Debug, thiserror::Error)]
pub enum WireServerErrorType {
    #[error("Telemetry call to wire server failed")]
    Telemetry,

    #[error("Goal state call to wire server failed")]
    GoalState,

    #[error("Shared config call to wire server failed")]
    SharedConfig,
}

#[cfg(test)]
mod test {
    use super::{CommandErrorType, Error, ParseVersionErrorType, WireServerErrorType};
    use std::fs;

    #[test]
    fn error_formatting_test() {
        let mut error: Error = fs::metadata("file.txt").map_err(Into::into).unwrap_err();
        let expected_err = if cfg!(windows) {
            "The system cannot find the file specified. (os error 2)"
        } else {
            "No such file or directory (os error 2)"
        };
        assert_eq!(error.to_string(), expected_err);

        error = Error::WireServer(
            WireServerErrorType::Telemetry,
            "Invalid response".to_string(),
        );
        assert_eq!(
            error.to_string(),
            "Telemetry call to wire server failed with the error: Invalid response"
        );

        error = regex::Regex::new(r"abc(").map_err(Into::into).unwrap_err();
        assert!(error
            .to_string()
            .contains("Failed to create regex with error: regex parse error:"));

        error = Error::ParseVersion(ParseVersionErrorType::MajorBuild("1.5.0".to_string()));
        assert_eq!(error.to_string(), "Cannot read Major build from 1.5.0");

        error = Error::Command(
            CommandErrorType::Findmnt,
            format!("Failed with exit code: {}", 5),
        );
        assert_eq!(
            error.to_string(),
            "Findmnt command: Failed with exit code: 5"
        );

        let error = Error::Hyper(super::HyperErrorType::ServerError(
            "testurl.com".to_string(),
            http::StatusCode::from_u16(500).unwrap(),
        ));
        assert_eq!(
            error.to_string(),
            "Failed to get response from testurl.com, status code: 500 Internal Server Error"
        );
    }
}
