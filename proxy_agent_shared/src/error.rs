#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[cfg(windows)]
    #[error(transparent)]
    WindowsService(#[from] windows_service::Error),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error("Failed to create regex with error: {0}")]
    Regex(#[from] regex::Error),

    #[error("{0}")]
    ParseVersion(ParseVersionErrorType),

    #[error("Findmnt command {0}")]
    Findmnt(String),
}

#[derive(Debug, thiserror::Error)]
pub enum ParseVersionErrorType {
    #[error("Invalid version string")]
    InvalidString,

    #[error("Cannot read Major build from {0}")]
    MajorBuild(String),

    #[error("Cannot read Minor build from {0}")]
    MinorBuild(String),
}

#[cfg(test)]
mod test {
    use super::{Error, ParseVersionErrorType};
    use std::fs;

    #[test]
    fn error_formatting_test() {
        let mut error: Error = fs::metadata("file.txt").map_err(Into::into).unwrap_err();
        assert_eq!(
            error.to_string(),
            "The system cannot find the file specified. (os error 2)"
        );

        error = regex::Regex::new(r"abc(").map_err(Into::into).unwrap_err();
        assert!(error
            .to_string()
            .contains("Failed to create regex with error: regex parse error:"));

        error = Error::ParseVersion(ParseVersionErrorType::MajorBuild("1.5.0".to_string()));
        assert_eq!(error.to_string(), "Cannot read Major build from 1.5.0");

        error = Error::Findmnt(format!("failed with exit code: {}", 5));
        assert_eq!(
            error.to_string(),
            "Findmnt command failed with exit code: 5"
        );
    }
}
