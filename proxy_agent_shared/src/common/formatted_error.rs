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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formatted_error_display_test() {
        let error = FormattedError {
            message: "An error occurred".to_string(),
            code: 404,
        };
        assert_eq!(
            format!("{}", error),
            "code: 404, message: An error occurred"
        );
    }

    #[test]
    fn formatted_error_from_test() {
        let decode_error = DecodeError::InvalidLength(0);
        let formatted_error: FormattedError = decode_error.into();
        assert_eq!(formatted_error.message, "Decode Error: InvalidLength(0)");

        let utf8_bytes = vec![0, 159, 146, 150];
        let utf8_error = String::from_utf8(utf8_bytes).unwrap_err();
        let formatted_error: FormattedError = utf8_error.into();
        assert!(formatted_error.message.starts_with("Utf-8 Convert Error:"));

        let json_error = serde_json::from_str::<serde_json::Value>("invalid json").unwrap_err();
        let formatted_error: FormattedError = json_error.into();
        assert!(formatted_error.message.starts_with("Json Error:"));

        #[cfg(windows)]
        {
            let windows_error = windows::core::Error::from_win32();
            let formatted_error: FormattedError = windows_error.into();
            assert!(formatted_error.message.starts_with("Windows API Error:"));
        }
    }
}
