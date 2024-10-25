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
    use super::{Error, KeyErrorType, WireServerErrorType};
    use http::StatusCode;

    #[test]
    fn error_formatting_test() {
        let metadata = fs::metadata(&file_full_path)?;
        
    }
}
