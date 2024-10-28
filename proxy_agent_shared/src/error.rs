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
    ParseVersion(String),

    #[error("Findmnt command {0}")]
    FindMnt(String),
}

#[cfg(test)]
mod test {
    use super::Error;
    use std::fs;

    #[test]
    fn error_formatting_test() {
        let mut error: Error = fs::metadata("nonexistentfile.txt")
            .map_err(Into::into)
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "The system cannot find the file specified. (os error 2)"
        );

        error = regex::Regex::new(r"abc(").map_err(Into::into).unwrap_err();
        assert!(error
            .to_string()
            .contains("Failed to create regex with error: regex parse error:"));

        error = Error::FindMnt(format!("failed with exit code: {}", 5));
        assert_eq!(
            error.to_string(),
            "Findmnt command failed with exit code: 5"
        );
    }
}
