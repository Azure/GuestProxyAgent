use std::{fmt, string::FromUtf8Error};

use base64::DecodeError;
use tokio::time::error::Elapsed;

use crate::error::Error;

#[derive(Debug, Clone)]
pub struct FormattedErrorMessage {
    pub message: String,
    pub code: i32,
}

impl fmt::Display for FormattedErrorMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "code: {}, message: {}", self.code, self.message)
    }
}

impl std::error::Error for FormattedErrorMessage {}

impl From<DecodeError> for FormattedErrorMessage {
    fn from(value: DecodeError) -> Self {
        FormattedErrorMessage {
            message: format!("Decode Error: {value:?}"),
            code: -1,
        }
    }
}

impl From<FromUtf8Error> for FormattedErrorMessage {
    fn from(value: FromUtf8Error) -> Self {
        FormattedErrorMessage {
            message: format!("Utf-8 Convert Error: {value:?}"),
            code: -1,
        }
    }
}

impl From<serde_json::Error> for FormattedErrorMessage {
    fn from(value: serde_json::Error) -> Self {
        FormattedErrorMessage {
            message: format!("Json Error: {value:?}"),
            code: -1,
        }
    }
}

impl From<String> for FormattedErrorMessage {
    fn from(value: String) -> Self {
        FormattedErrorMessage {
            message: format!("GeneralError: {value}"),
            code: -1,
        }
    }
}

impl From<Elapsed> for FormattedErrorMessage {
    fn from(value: Elapsed) -> Self {
        FormattedErrorMessage {
            message: format!("Operation timeout: {value}"),
            code: -1,
        }
    }
}

impl From<FormattedErrorMessage> for Error {
    fn from(value: FormattedErrorMessage) -> Self {
        Error::OtherError(value)
    }
}

#[cfg(windows)]
impl From<windows::core::Error> for FormattedErrorMessage {
    fn from(value: windows::core::Error) -> Self {
        FormattedErrorMessage {
            message: format!("Windows API Error: {value:?}"),
            code: -1,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::time::timeout;

    use super::*;

    #[test]
    fn formatted_error_display_test() {
        let error = FormattedErrorMessage {
            message: "An error occurred".to_string(),
            code: 404,
        };
        assert_eq!(
            format!("{}", error),
            "code: 404, message: An error occurred"
        );
    }

    #[tokio::test]
    async fn formatted_error_from_test() {
        let decode_error = DecodeError::InvalidLength(0);
        let formatted_error: FormattedErrorMessage = decode_error.into();
        assert_eq!(formatted_error.message, "Decode Error: InvalidLength(0)");

        let utf8_bytes = vec![0, 159, 146, 150];
        let utf8_error = String::from_utf8(utf8_bytes).unwrap_err();
        let formatted_error: FormattedErrorMessage = utf8_error.into();
        assert!(formatted_error.message.starts_with("Utf-8 Convert Error:"));

        let json_error = serde_json::from_str::<serde_json::Value>("invalid json").unwrap_err();
        let formatted_error: FormattedErrorMessage = json_error.into();
        assert!(formatted_error.message.starts_with("Json Error:"));

        let elapsed_error = timeout(Duration::from_millis(10), async {
            tokio::time::sleep(Duration::from_secs(1)).await;
        })
        .await;

        let elapsed_error = elapsed_error.unwrap_err();
        let formatted_error: FormattedErrorMessage = elapsed_error.into();
        assert!(formatted_error.message.starts_with("Operation timeout"));

        #[cfg(windows)]
        {
            let windows_error = windows::core::Error::from_win32();
            let formatted_error: FormattedErrorMessage = windows_error.into();
            assert!(formatted_error.message.starts_with("Windows API Error:"));
        }
    }
}
