// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

use http::{uri::InvalidUri, StatusCode};

#[derive(Debug, thiserror::Error)]
pub enum Error {
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

    #[error("Failed to get valid map '{0}' in BPF object with error: {1}")]
    GetBpfMap(String, String),

    #[error("Failed to get eBPF API: API is not loaded")]
    GetBpfApi,

    #[error("Failed to get BPF object: Object is not initialized")]
    GetBpfObject,

    #[error("Loading eBPF API from file path '{0}' failed with error: {1}")]
    LoadBpfApi(String, String),

    #[error("Loading BPF API function '{0}' failed with error: {1}")]
    LoadBpfApiFunction(String, String),

    #[error("Failed to load HashMap '{0}' with error: {1}")]
    LoadBpfMapHashMap(String, String),

    #[error("Failed to update HashMap '{0}' for '{1}' with error: {2}")]
    UpdateBpfMapHashMap(String, String, String),

    #[error("Failed to get program '{0}' with error: {1}")]
    GetBpfProgram(String, String),

    #[error("Failed to load program '{0}' with error: {1}")]
    LoadBpfProgram(String, String),

    #[error("Failed to attach program '{0}' with error: {1}")]
    AttachBpfProgram(String, String),

    #[error("Failed to convert program to '{0}' with error: {1}")]
    ConvertBpfProgram(String, String),

    #[error("Failed to open cgroup '{0}' with error: {1}")]
    OpenCgroup(String, String),

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
        let mut error = Error::Hyper(super::HyperErrorType::ServerError(
            "testurl.com".to_string(),
            StatusCode::from_u16(500).unwrap(),
        ));
        assert_eq!(
            error.to_string(),
            "Failed to get response from testurl.com, status code: 500 Internal Server Error"
        );

        error = Error::WireServer(
            WireServerErrorType::Telemetry,
            "Invalid response".to_string(),
        );
        assert_eq!(
            error.to_string(),
            "Telemetry call to wire server failed with the error: Invalid response"
        );

        error = Error::Key(KeyErrorType::SendKeyRequest(
            "acquire".to_string(),
            error.to_string(),
        ));
        assert_eq!(
            error.to_string(),
            "Key error: Failed to send acquire key with error: Telemetry call to wire server failed with the error: Invalid response"
        );
    }
}
