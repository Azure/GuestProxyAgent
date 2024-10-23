// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

use http::{uri::InvalidUri, StatusCode};
use std::error::Error as StdError;
use std::fmt::Display;

#[derive(Debug)]
pub struct Error(Box<ErrorType>);

impl Error {
    fn new(error: ErrorType) -> Self {
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

    pub fn key(error: KeyErrorType) -> Self {
        Self::new(ErrorType::Key(error))
    }

    pub fn parse_url(url: String, error: InvalidUri) -> Self {
        Self::new(ErrorType::ParseUrl(url, error.to_string()))
    }

    pub fn parse_url_message(url: String, message: String) -> Self {
        Self::new(ErrorType::ParseUrl(url, message))
    }

    pub fn wire_server(error_type: WireServerErrorType, message: String) -> Self {
        Self::new(ErrorType::WireServer(error_type, message))
    }

    pub fn acl(error: AclErrorType, error_code: u32) -> Self {
        Self::new(ErrorType::Acl(error, error_code))
    }

    pub fn bpf(error: BpfErrorType) -> Self {
        Self::new(ErrorType::Bpf(error))
    }

    pub fn windows_api(error: WindowsApiErrorType) -> Self {
        Self::new(ErrorType::WindowsApi(error))
    }

    pub fn invalid(error: String) -> Self {
        Self::new(ErrorType::Invalid(error))
    }

    pub fn general(error: String) -> Self {
        Self::new(ErrorType::General(error))
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl StdError for Error {}

#[derive(Debug, thiserror::Error)]
enum ErrorType {
    #[error("IO error: {0}: {1}")]
    IO(String, std::io::Error),

    #[error("{0}")]
    Hyper(HyperErrorType),

    #[error("Hex encoded key '{0}' is invalid: {1}")]
    Hex(String, hex::FromHexError),

    #[error("Key error: {0}")]
    Key(KeyErrorType),

    #[error("{0} with the error: {1}")]
    WireServer(WireServerErrorType, String),

    #[error("Failed to parse URL {0} with error: {1}")]
    ParseUrl(String, String),

    #[error("acl_directory: {0} with error: {1}")]
    Acl(AclErrorType, u32),

    #[error("{0}")]
    Bpf(BpfErrorType),

    #[error("{0}")]
    WindowsApi(WindowsApiErrorType),

    #[error("{0} is invalid")]
    Invalid(String),

    #[error("{0}")]
    General(String),
}

#[derive(Debug, thiserror::Error)]
pub enum HyperErrorType {
    #[error("{0}: {1}")]
    Custom(String, hyper::Error),

    #[error("Failed to build request with error: {0}")]
    RequestBuilder(String),

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

#[derive(Debug, thiserror::Error)]
pub enum KeyErrorType {
    #[error("Key status validation failed with the error: {0}")]
    KeyStatusValidation(String),

    #[error("Failed to send {0} key with error: {1}")]
    SendKeyRequest(String, String),

    #[error("Failed to {0} key with status code: {1}")]
    KeyResponse(String, StatusCode),

    #[error("Failed to join {0} and {1} with error: {2}")]
    ParseKeyUrl(String, String, InvalidUri),
}

#[derive(Debug, thiserror::Error)]
pub enum AclErrorType {
    #[error("Failed to get ACL object for folder '{0}'")]
    AclObject(String),

    #[error("Failed to get SID for '{0}'")]
    Sid(String),

    #[error("Failed to get ACL entries for folder '{0}'")]
    AclEntries(String),

    #[error("Failed to add entry for SID '{0}'")]
    AddEntry(String),
}

#[derive(Debug, thiserror::Error)]
pub enum BpfErrorType {
    #[error("Failed to lookup element '{0}' in BPF map 'audit_map'. {1}")]
    MapLookupElem(String, String),

    #[error("Failed to retrieve file descriptor of the BPF map 'audit_map' with error: {0}")]
    MapFileDescriptor(String),

    #[error("Failed to get valid map 'audit_map' in BPF object with error: {0}")]
    GetBpfMap(String),

    #[error("Failed to get eBPF API: API is not loaded")]
    GetBpfApi,

    #[error("Failed to get BPF object: Object is not initialized")]
    GetBpfObject,

    #[error("Loading eBPF API from file path '{0}' failed with error: {1}")]
    LoadBpfApi(String, String),

    #[error("Loading BPF API function '{0}' failed with error: {1}")]
    LoadBpfApiFunction(String, String),

    #[error("Failed to load HashMap 'audit_map' with error: {0}")]
    LoadBpfMapHashMap(String),

    #[error("CString initialization failed with error: {0}")]
    CString(std::ffi::NulError),
}

#[derive(Debug, thiserror::Error)]
pub enum WindowsApiErrorType {
    #[error("Loading NetUserGetLocalGroups failed with error: {0}")]
    LoadNetUserGetLocalGroups(String),

    #[error("LsaGetLogonSessionData {0}")]
    LsaGetLogonSessionData(String),

    #[error("WinSock::WSAIoctl - SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT: {0}")]
    WSAIoctl(i32),

    #[error("GlobalMemoryStatusEx failed: {0}")]
    GlobalMemoryStatusEx(String),

    #[error("{0}")]
    WindowsOsError(std::io::Error),
}

#[cfg(test)]
mod test {
    use super::{Error, KeyErrorType, WireServerErrorType};
    use http::StatusCode;

    #[test]
    fn error_formatting_test() {
        let mut error = Error::hyper(super::HyperErrorType::ServerError(
            "testurl.com".to_string(),
            StatusCode::from_u16(500).unwrap(),
        ));
        assert_eq!(
            error.to_string(),
            "Failed to get response from testurl.com, status code: 500 Internal Server Error"
        );

        error = Error::wire_server(
            WireServerErrorType::Telemetry,
            "Invalid response".to_string(),
        );
        assert_eq!(
            error.to_string(),
            "Telemetry call to wire server failed with the error: Invalid response"
        );

        error = Error::key(KeyErrorType::SendKeyRequest(
            "acquire".to_string(),
            error.to_string(),
        ));
        assert_eq!(
            error.to_string(),
            "Key error: Failed to send acquire key with error: Telemetry call to wire server failed with the error: Invalid response"
        );
    }
}
