// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#[derive(Debug, thiserror::Error)]
pub enum Error {
    // windows_service::Error is a custom error type from the windows-service crate
    // it does not display the IO error message, so we need to add it manually
    #[cfg(windows)]
    #[error("{0}: {1}")]
    WindowsService(windows_service::Error, std::io::Error),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error("Failed to create regex with error: {0}")]
    Regex(#[from] regex::Error),

    #[error("{0}")]
    ParseVersion(ParseVersionErrorType),

    #[error("{0} command: {1}")]
    Command(CommandErrorType, String),
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

#[cfg(test)]
mod test {
    use super::{CommandErrorType, Error, ParseVersionErrorType};
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
    }
}
