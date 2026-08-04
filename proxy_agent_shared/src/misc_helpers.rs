// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use crate::{
    error::{CommandErrorType, Error},
    result::Result,
};
use regex::Regex;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::{
    borrow::Cow,
    fs::{self, File},
    path::{Path, PathBuf},
    process::Command,
    sync::RwLock,
    time::Instant,
};
use thread_id;
use time::{format_description, OffsetDateTime, PrimitiveDateTime};

#[cfg(windows)]
use super::windows;

#[cfg(not(windows))]
use super::linux;

pub fn get_thread_identity() -> String {
    format!("{:0>8}", thread_id::get())
}

// Static format descriptors parsed once and reused for all calls
static ISO8601_MILLIS_FORMAT: std::sync::LazyLock<
    Vec<time::format_description::FormatItem<'static>>,
> = std::sync::LazyLock::new(|| {
    format_description::parse("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond]")
        .expect("Invalid ISO8601 millis date format")
});

static ISO8601_FORMAT: std::sync::LazyLock<Vec<time::format_description::FormatItem<'static>>> =
    std::sync::LazyLock::new(|| {
        format_description::parse("[year]-[month]-[day]T[hour]:[minute]:[second]Z")
            .expect("Invalid ISO8601 date format")
    });

// This format is also the preferred HTTP date format. https://httpwg.org/specs/rfc9110.html#http.date
static RFC1123_FORMAT: std::sync::LazyLock<Vec<time::format_description::FormatItem<'static>>> =
    std::sync::LazyLock::new(|| {
        format_description::parse(
            "[weekday repr:short], [day] [month repr:short] [year] [hour]:[minute]:[second] GMT",
        )
        .expect("Invalid RFC1123 date format")
    });

struct HostTimeSyncState {
    synced_host_utc: OffsetDateTime,
    synced_instant: Instant,
}

static HOST_TIME_SYNC_STATE: std::sync::LazyLock<RwLock<Option<HostTimeSyncState>>> =
    std::sync::LazyLock::new(|| RwLock::new(None));

pub fn get_date_time_string_with_milliseconds() -> String {
    let time_str = OffsetDateTime::now_utc()
        .format(&*ISO8601_MILLIS_FORMAT)
        .expect("Failed to format ISO8601 millis date");
    // Truncate to 23 chars: "YYYY-MM-DDTHH:MM:SS.mmm"
    time_str.chars().take(23).collect()
}

pub fn get_date_time_string() -> String {
    OffsetDateTime::now_utc()
        .format(&*ISO8601_FORMAT)
        .expect("Failed to format ISO8601 date")
}

pub fn get_date_time_rfc1123_string() -> String {
    get_current_utc_time_synced()
        .format(&*RFC1123_FORMAT)
        .expect("Failed to format RFC1123 date")
}

/// Update host-time sync state from a RFC1123 datetime string.
/// Returns true when sync state is updated successfully, false otherwise.
pub fn sync_host_utc_time_from_rfc1123_string(host_utc_rfc1123: &str) -> bool {
    let Ok(parsed_host_utc) = parse_rfc1123_to_offset_datetime(host_utc_rfc1123) else {
        return false;
    };

    let Ok(mut state) = HOST_TIME_SYNC_STATE.write() else {
        return false;
    };

    *state = Some(HostTimeSyncState {
        synced_host_utc: parsed_host_utc,
        synced_instant: Instant::now(),
    });
    true
}

pub fn parse_rfc1123_to_offset_datetime(rfc1123_str: &str) -> Result<OffsetDateTime> {
    PrimitiveDateTime::parse(rfc1123_str, &*RFC1123_FORMAT)
        .map(|dt| dt.assume_utc())
        .map_err(|e| {
            Error::ParseDateTimeStringError(format!(
                "Failed to parse RFC1123 datetime string '{rfc1123_str}': {e}"
            ))
        })
}

/// Returns true when current host-time sync state is older than `max_age`.
/// If there is no host-time sync state yet, this returns true.
pub fn host_time_sync_is_stale(max_age: std::time::Duration) -> bool {
    let Ok(state) = HOST_TIME_SYNC_STATE.read() else {
        return true;
    };
    state
        .as_ref()
        .is_none_or(|synced| synced.synced_instant.elapsed() > max_age)
}

fn get_current_utc_time_synced() -> OffsetDateTime {
    let Ok(state) = HOST_TIME_SYNC_STATE.read() else {
        return OffsetDateTime::now_utc();
    };

    let Some(synced) = state.as_ref() else {
        return OffsetDateTime::now_utc();
    };

    let elapsed = synced.synced_instant.elapsed();
    match time::Duration::try_from(elapsed) {
        Ok(elapsed_time) => synced.synced_host_utc + elapsed_time,
        Err(_) => OffsetDateTime::now_utc(),
    }
}

pub fn get_date_time_unix_nano() -> i128 {
    OffsetDateTime::now_utc().unix_timestamp_nanos()
}

pub fn get_current_utc_time() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

/// Parse a datetime string to OffsetDateTime (UTC)
/// Supports multiple formats:
/// - ISO 8601 with/without 'Z': "YYYY-MM-DDTHH:MM:SS" or "YYYY-MM-DDTHH:MM:SSZ"
/// - With milliseconds: "YYYY-MM-DDTHH:MM:SS.mmm"
/// # Arguments
/// * `datetime_str` - A datetime string to parse
/// # Returns
/// A Result containing the parsed OffsetDateTime (UTC) or an error if parsing fails
/// # Example
/// ```rust
/// use proxy_agent_shared::misc_helpers;
/// let datetime1 = misc_helpers::parse_date_time_string("2024-01-15T10:30:45Z").unwrap();
/// let datetime2 = misc_helpers::parse_date_time_string("2024-01-15T10:30:45").unwrap();
/// let datetime3 = misc_helpers::parse_date_time_string("2024-01-15T10:30:45.123").unwrap();
/// ```
pub fn parse_date_time_string(datetime_str: &str) -> Result<OffsetDateTime> {
    // Remove the 'Z' suffix if present
    let datetime_str_trimmed = datetime_str.trim_end_matches('Z');

    // Try parsing with milliseconds first
    let date_format_with_millis =
        format_description::parse("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond]")
            .map_err(|e| {
                Error::ParseDateTimeStringError(format!("Failed to parse date format: {e}"))
            })?;

    if let Ok(primitive_datetime) =
        PrimitiveDateTime::parse(datetime_str_trimmed, &date_format_with_millis)
    {
        return Ok(primitive_datetime.assume_utc());
    }

    // Fall back to parsing without milliseconds
    let date_format = format_description::parse("[year]-[month]-[day]T[hour]:[minute]:[second]")
        .map_err(|e| {
            Error::ParseDateTimeStringError(format!("Failed to parse date format: {e}"))
        })?;

    let primitive_datetime =
        PrimitiveDateTime::parse(datetime_str_trimmed, &date_format).map_err(|e| {
            Error::ParseDateTimeStringError(format!(
                "Failed to parse datetime string '{datetime_str}': {e}"
            ))
        })?;

    Ok(primitive_datetime.assume_utc())
}

pub fn try_create_folder(dir: &Path) -> Result<()> {
    match dir.try_exists() {
        Ok(exists) => {
            if !exists {
                fs::create_dir_all(dir)?; // Recursively create a directory and all of its parent components if they are missing
            }
        }
        Err(error) => panic!(
            "Problem check the directory '{}' exists: {:?}",
            dir.display(),
            error
        ),
    };

    Ok(())
}

/// Writes a serializable object to a file in JSON format.
/// It first writes to a temporary file and then renames it to the target file to avoid leaving a corrupted file if the write operation fails.
/// Remark: it uses BufWriter to reduce system calls and improve performance.
/// Remark: Called from sync code, infrequent writes and small objects
pub fn json_write_to_file<T>(obj: &T, file_path: &Path) -> Result<()>
where
    T: ?Sized + Serialize,
{
    use std::io::BufWriter;

    // write to a temp file and rename to avoid corrupted file
    let temp_file_path = file_path.with_extension("tmp");
    let file = File::create(&temp_file_path)?;
    let writer = BufWriter::new(file); // Reduces system calls
    serde_json::to_writer_pretty(writer, obj)?;
    std::fs::rename(temp_file_path, file_path)?;

    Ok(())
}

/// Async version of json_write_to_file using tokio::fs
/// Serializes to memory first (CPU work), then writes asynchronously (IO work)
/// This avoids blocking the async runtime during serialization
/// Remark: Called from async context, writing while handing concurrent requests, and potentially larger objects
pub async fn json_write_to_file_async<T>(obj: &T, file_path: &Path) -> Result<()>
where
    T: ?Sized + Serialize,
{
    // Serialize to memory first (CPU work - fast)
    let json_bytes = serde_json::to_vec_pretty(obj)?;

    // Write asynchronously (IO work)
    let temp_file_path = file_path.with_extension("tmp");
    tokio::fs::write(&temp_file_path, json_bytes).await?;
    tokio::fs::rename(&temp_file_path, file_path).await?;

    Ok(())
}

/// Reads `file_path`, decodes it using the detected text encoding and
/// deserializes the resulting JSON into `T`.
///
/// Supports UTF-8, UTF-16LE, UTF-16BE, UTF-32LE and UTF-32BE, each with or
/// without a BOM - the 10 encodings a JSON file produced by an arbitrary
/// editor or tool can realistically use. Any BOM is consumed while decoding and
/// never reaches serde_json, which would fail if the json payload contains BOM prefix.
pub fn json_read_from_file<T>(file_path: &Path) -> Result<T>
where
    T: DeserializeOwned,
{
    let bytes = fs::read(file_path)?;
    let text = decode_text(&bytes)
        .map_err(|detail| Error::DecodeFile(path_to_string(file_path), detail))?;
    let obj: T = serde_json::from_str(&text)?;

    Ok(obj)
}

/// The Unicode transformation format of the detected encoding.
#[derive(Clone, Copy)]
enum TextEncoding {
    /// UTF-8 (and plain ASCII) - 1 byte per code unit.
    Utf8,
    /// UTF-16 - 2 bytes per code unit.
    Utf16,
    /// UTF-32 - 4 bytes per code unit.
    Utf32,
}

/// The text encoding detected from the leading bytes of a file.
struct DetectedEncoding {
    /// The Unicode transformation format.
    text_encoding: TextEncoding,
    /// True for big endian, false for little endian. Not meaningful for UTF-8.
    big_endian: bool,
    /// Length of the BOM in bytes, 0 when the file has no BOM.
    bom_len: usize,
}

impl DetectedEncoding {
    const fn new(text_encoding: TextEncoding, big_endian: bool, bom_len: usize) -> Self {
        Self {
            text_encoding,
            big_endian,
            bom_len,
        }
    }
}

/// Detects the text encoding of `bytes`.
///
/// A BOM is a Unicode construct rather than a JSON one, so BOM detection here is
/// format agnostic. The BOM-less fallback, however, assumes the document starts
/// with an ASCII character - true for JSON, XML and most text config formats.
///
/// Wider BOMs must be tested first: the UTF-32LE BOM (FF FE 00 00) starts with
/// the UTF-16LE BOM (FF FE), so a shortest-first scan would mis-detect a
/// UTF-32LE file as UTF-16LE.
fn detect_text_encoding(bytes: &[u8]) -> DetectedEncoding {
    if bytes.starts_with(&[0x00, 0x00, 0xFE, 0xFF]) {
        DetectedEncoding::new(TextEncoding::Utf32, true, 4) // UTF-32BE with BOM
    } else if bytes.starts_with(&[0xFF, 0xFE, 0x00, 0x00]) {
        DetectedEncoding::new(TextEncoding::Utf32, false, 4) // UTF-32LE with BOM
    } else if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        DetectedEncoding::new(TextEncoding::Utf8, false, 3) // UTF-8 with BOM
    } else if bytes.starts_with(&[0xFE, 0xFF]) {
        DetectedEncoding::new(TextEncoding::Utf16, true, 2) // UTF-16BE with BOM
    } else if bytes.starts_with(&[0xFF, 0xFE]) {
        DetectedEncoding::new(TextEncoding::Utf16, false, 2) // UTF-16LE with BOM
    } else {
        // No BOM. The document is expected to start with an ASCII character
        // (for JSON that is `[`, `{`, `"`, a digit or whitespace), so the NUL
        // padding around the first code unit identifies both the width and the
        // byte order. The 4-byte patterns are checked first because they are a
        // superset of the 2-byte ones.
        let is_nul = |i: usize| bytes.get(i) == Some(&0x00);
        let is_text = |i: usize| matches!(bytes.get(i), Some(b) if *b != 0x00);

        if is_nul(0) && is_nul(1) && is_nul(2) && is_text(3) {
            DetectedEncoding::new(TextEncoding::Utf32, true, 0) // 00 00 00 xx -> UTF-32BE
        } else if is_text(0) && is_nul(1) && is_nul(2) && is_nul(3) {
            DetectedEncoding::new(TextEncoding::Utf32, false, 0) // xx 00 00 00 -> UTF-32LE
        } else if is_nul(0) && is_text(1) {
            DetectedEncoding::new(TextEncoding::Utf16, true, 0) // 00 xx -> UTF-16BE
        } else if is_text(0) && is_nul(1) {
            DetectedEncoding::new(TextEncoding::Utf16, false, 0) // xx 00 -> UTF-16LE
        } else {
            DetectedEncoding::new(TextEncoding::Utf8, false, 0) // anything else, including plain ASCII / UTF-8
        }
    }
}

/// Decodes `bytes` into UTF-8 text using the encoding detected by
/// [`detect_text_encoding`], skipping the BOM when present.
/// UTF-8 input is borrowed as-is, so the common case does not allocate.
///
/// On failure it returns only a description of what made the content
/// undecodable; the caller attaches the source of the bytes.
fn decode_text(bytes: &[u8]) -> std::result::Result<Cow<'_, str>, String> {
    let encoding = detect_text_encoding(bytes);
    let big_endian = encoding.big_endian;
    let payload = &bytes[encoding.bom_len..];

    match encoding.text_encoding {
        TextEncoding::Utf8 => std::str::from_utf8(payload)
            .map(Cow::Borrowed)
            .map_err(|e| format!("content is not valid UTF-8: {e}")),
        TextEncoding::Utf16 => {
            if !payload.len().is_multiple_of(2) {
                return Err(format!(
                    "UTF-16 content is truncated: {} bytes is not a whole number of 16-bit code units",
                    payload.len()
                ));
            }

            let code_units = payload.chunks_exact(2).map(|chunk| {
                let unit = [chunk[0], chunk[1]];
                if big_endian {
                    u16::from_be_bytes(unit)
                } else {
                    u16::from_le_bytes(unit)
                }
            });

            // `decode_utf16` pairs surrogates, so astral-plane characters
            // (emoji) are reassembled correctly; a lone surrogate is rejected
            // rather than silently replaced.
            char::decode_utf16(code_units)
                .collect::<std::result::Result<String, _>>()
                .map(Cow::Owned)
                .map_err(|e| format!("UTF-16 content has an unpaired surrogate: {e}"))
        }
        TextEncoding::Utf32 => {
            if !payload.len().is_multiple_of(4) {
                return Err(format!(
                    "UTF-32 content is truncated: {} bytes is not a whole number of 32-bit code units",
                    payload.len()
                ));
            }

            payload
                .chunks_exact(4)
                .map(|chunk| {
                    let unit = [chunk[0], chunk[1], chunk[2], chunk[3]];
                    let scalar = if big_endian {
                        u32::from_be_bytes(unit)
                    } else {
                        u32::from_le_bytes(unit)
                    };
                    char::from_u32(scalar).ok_or_else(|| {
                        format!("UTF-32 content has an invalid scalar value: {scalar:#010X}")
                    })
                })
                .collect::<std::result::Result<String, String>>()
                .map(Cow::Owned)
        }
    }
}

pub fn json_clone<T>(obj: &T) -> Result<T>
where
    T: Serialize + DeserializeOwned,
{
    let json = serde_json::to_string(obj)?;
    serde_json::from_str(&json).map_err(Into::into)
}

pub fn get_current_exe_dir() -> PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop();
    path
}

pub fn get_long_os_version() -> String {
    // os
    let os;
    #[cfg(windows)]
    {
        os = windows::get_long_os_version();
    }
    #[cfg(not(windows))]
    {
        os = linux::get_long_os_version();
    }
    os
}

pub fn get_processor_arch() -> String {
    //arch
    let arch;
    #[cfg(windows)]
    {
        arch = windows::get_processor_arch();
    }
    #[cfg(not(windows))]
    {
        arch = linux::get_processor_arch()
    }
    arch
}

pub fn path_to_string(path: &Path) -> String {
    path.display().to_string()
}

pub fn get_file_name(path: &Path) -> String {
    match path.file_name() {
        Some(s) => s.to_str().unwrap_or("InvalidPath").to_string(),
        None => "InvalidPath".to_string(),
    }
}

/// It is the version from Cargo.toml of proxy_agent_shared crate
const VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn get_current_version() -> String {
    VERSION.to_string()
}

/// Get the current executable version,
/// trying to read version from file properties on Windows,
/// otherwise fallback to Cargo.toml version.
/// # Returns
/// A string representing the current executable version
pub(crate) fn get_current_exe_version() -> String {
    #[cfg(windows)]
    {
        match try_get_current_exe_version() {
            Ok(version) => version,
            Err(e) => {
                eprintln!(
                    "Failed to get current exe version from file properties, fallback to Cargo.toml version: {e}",
                );
                get_current_version()
            }
        }
    }
    #[cfg(not(windows))]
    {
        get_current_version()
    }
}

#[cfg(windows)]
pub fn try_get_current_exe_version() -> Result<String> {
    let exe_path = std::env::current_exe()?;
    let version = windows::get_file_product_version(&exe_path)?;
    Ok(version.to_string())
}

pub fn get_files(dir: &Path) -> Result<Vec<PathBuf>> {
    // search files
    let mut files: Vec<PathBuf> = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let file_full_path = entry.path();
        let metadata = fs::metadata(&file_full_path)?;
        if !metadata.is_file() {
            continue;
        }
        files.push(file_full_path);
    }
    files.sort();
    Ok(files)
}

// Returns a new empty PathBuf
pub fn empty_path() -> PathBuf {
    PathBuf::new()
}

/// Search files in a directory with a regex
/// # Arguments
/// * `dir` - The directory to search
/// * `search_regex` - The regex to search
/// # Returns
/// A vector of PathBufs that match the search pattern in ascending order
/// # Errors
/// Returns an error if the regex pattern is invalid or if there is an IO error
/// Remarks: The Regex::new is expensive, so the caller should cache the regex if it is used frequently,
///     for example, by using once_cell::sync::Lazy or std::sync::LazyLock to create a static regex instance.
pub fn search_files(dir: &Path, search_regex: &Regex) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();

    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let file_full_path = entry.path();
        let metadata = fs::metadata(&file_full_path)?;
        if !metadata.is_file() {
            continue;
        }
        let file_name = get_file_name(&file_full_path);
        if search_regex.is_match(&file_name) {
            files.push(file_full_path);
        }
    }
    files.sort();
    Ok(files)
}

pub struct CommandOutput {
    exit_code: i32,
    stdout: String,
    stderr: String,
}

impl CommandOutput {
    pub fn new(exit_code: i32, stdout: String, stderr: String) -> Self {
        Self {
            exit_code,
            stdout,
            stderr,
        }
    }

    pub fn is_success(&self) -> bool {
        self.exit_code == 0
    }

    pub fn stdout(&self) -> String {
        self.stdout.to_string()
    }

    pub fn stderr(&self) -> String {
        self.stderr.to_string()
    }

    pub fn exit_code(&self) -> i32 {
        self.exit_code
    }

    pub fn message(&self) -> String {
        format!(
            "exit code: '{}', stdout: '{}', stderr: '{}'",
            self.exit_code, self.stdout, self.stderr
        )
    }
}

pub fn execute_command(
    program: &str,
    args: Vec<&str>,
    default_error_code: i32,
) -> Result<CommandOutput> {
    let output = Command::new(program).args(args).output()?;
    Ok(CommandOutput::new(
        output.status.code().unwrap_or(default_error_code),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    ))
}

pub fn get_proxy_agent_version(proxy_agent_exe: &Path) -> Result<String> {
    let proxy_agent_exe_str = path_to_string(proxy_agent_exe);
    if !proxy_agent_exe.exists() {
        return Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("File '{proxy_agent_exe_str}' does not found"),
        )));
    }
    if !proxy_agent_exe.is_file() {
        return Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("'{proxy_agent_exe_str}' is not a file"),
        )));
    }

    let output = execute_command(&path_to_string(proxy_agent_exe), vec!["--version"], -1)?;
    if output.is_success() {
        Ok(output.stdout().trim().to_string())
    } else {
        Err(Error::Command(
            CommandErrorType::CommandName(proxy_agent_exe_str),
            output.message(),
        ))
    }
}

/// Static regex for matching environment variables like %VAR%
/// expect() only panics on failure to compile the regex, which should not happen since the pattern is constant and valid
/// This is the idiomatic Rust pattern for creating a static regex that is compiled once and reused, ensuring thread safety and performance
/// Remark: Regex::new is performance-sensitive, so we use LazyLock to compile it only once and reuse it for subsequent calls to resolve_env_variables, which can be called frequently.
///     This avoids the overhead of compiling the regex on every call, improving performance while ensuring thread safety.
static ENV_VAR_REGEX: std::sync::LazyLock<Regex> =
    std::sync::LazyLock::new(|| Regex::new(r"%(\w+)%").expect("Invalid env var regex pattern"));

/// This function replaces all occurrences of %VAR% in the input string with the value of the environment variable VAR
/// If the environment variable is not set, it returns the original string with VAR unchanged.
/// # Arguments
/// * `input` - The input string to resolve environment variables in
/// # Returns
/// A Result containing the resolved string or an error if the regex pattern is invalid
/// The resolved string with environment variables expanded
pub fn resolve_env_variables(input: &str) -> String {
    if input.is_empty() || !input.contains('%') {
        // If the input string is empty or does not contain '%', return the original string
        return input.to_string();
    }

    ENV_VAR_REGEX
        .replace_all(input, |caps: &regex::Captures| {
            std::env::var(&caps[1]).unwrap_or_else(|_| caps[1].to_string())
        })
        .to_string()
}

/// Compute HMAC-SHA256 signature for the input using the provided hex-encoded key
/// # Arguments
/// * `hex_encoded_key` - The hex-encoded key used for HMAC-SHA256
/// * `input_to_sign` - The input data to be signed
/// # Returns
/// A Result containing the hex-encoded signature or an error if the key is invalid
/// # Example
/// ```rust
/// use proxy_agent_shared::misc_helpers;
/// let hex_encoded_key = "4A404E635266556A586E3272357538782F413F4428472B4B6250645367566B59";
/// let input_to_sign = b"Sample input data";
/// let signature = misc_helpers::compute_signature(hex_encoded_key, input_to_sign).unwrap();
/// ```
#[cfg(all(not(windows), feature = "signing"))]
pub use linux::compute_signature;
#[cfg(windows)]
pub use windows::compute_signature;

// replace xml escape characters
pub fn xml_escape(s: String) -> String {
    s.replace('&', "&amp;")
        .replace('\'', "&apos;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[cfg(test)]
mod tests {
    use regex::Regex;
    use serde_derive::{Deserialize, Serialize};
    use std::env;
    use std::fs;
    use std::path::PathBuf;
    use std::time::Duration;

    #[derive(Serialize, Deserialize)]
    struct TestStruct {
        thread_id: String,
        date_time_string_with_milliseconds: String,
        date_time_string: String,
        date_time_rfc1123_string: String,
        date_time_unix_nano: i128,
        long_os_version: String,
        current_exe_dir: String,
    }

    #[test]
    fn json_write_read_from_file_test() {
        let mut temp_test_path = env::temp_dir();
        temp_test_path.push("json_Write_read_from_file_test");
        // clean up and ignore the clean up errors
        _ = fs::remove_dir_all(&temp_test_path);
        super::try_create_folder(&temp_test_path).unwrap();

        let json_file = temp_test_path.as_path();
        let json_file = json_file.join("test.json");

        let test = TestStruct {
            thread_id: super::get_thread_identity(),
            date_time_string_with_milliseconds: super::get_date_time_string_with_milliseconds(),
            date_time_string: super::get_date_time_string(),
            date_time_rfc1123_string: super::get_date_time_rfc1123_string(),
            date_time_unix_nano: super::get_date_time_unix_nano(),
            long_os_version: super::get_long_os_version(),
            current_exe_dir: super::get_current_exe_dir().to_str().unwrap().to_string(),
        };

        super::json_write_to_file(&test, &json_file).unwrap();
        let json = super::json_read_from_file::<TestStruct>(&json_file).unwrap();

        assert_eq!(test.thread_id, json.thread_id);
        assert_eq!(
            test.date_time_string_with_milliseconds,
            json.date_time_string_with_milliseconds
        );
        assert_eq!(test.date_time_string, json.date_time_string);
        assert_eq!(test.date_time_rfc1123_string, json.date_time_rfc1123_string);
        assert_eq!(test.date_time_unix_nano, json.date_time_unix_nano);
        assert_eq!(test.long_os_version, json.long_os_version);
        assert_eq!(test.current_exe_dir, json.current_exe_dir);

        _ = fs::remove_dir_all(&temp_test_path);
    }

    #[test]
    fn json_read_from_file_skips_utf8_bom_test() {
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct Small {
            name: String,
            value: u32,
        }

        let mut temp_test_path = env::temp_dir();
        temp_test_path.push("json_read_from_file_skips_utf8_bom_test");
        _ = fs::remove_dir_all(&temp_test_path);
        super::try_create_folder(&temp_test_path).unwrap();

        let body = r#"{"name":"hello","value":42}"#;
        let expected = Small {
            name: "hello".to_string(),
            value: 42,
        };

        // 1. BOM-less file parses (regression guard for existing behavior).
        let no_bom = temp_test_path.join("no_bom.json");
        fs::write(&no_bom, body.as_bytes()).unwrap();
        assert_eq!(
            super::json_read_from_file::<Small>(&no_bom).unwrap(),
            expected
        );

        // 2. UTF-8 BOM-prefixed file parses (the actual fix).
        let with_bom = temp_test_path.join("with_bom.json");
        let mut bytes = Vec::with_capacity(3 + body.len());
        bytes.extend_from_slice(&[0xEF, 0xBB, 0xBF]);
        bytes.extend_from_slice(body.as_bytes());
        fs::write(&with_bom, &bytes).unwrap();
        assert_eq!(
            super::json_read_from_file::<Small>(&with_bom).unwrap(),
            expected
        );

        // 3. A bare BOM (no payload) still surfaces as a parse error rather
        //    than being silently treated as an empty document.
        let bom_only = temp_test_path.join("bom_only.json");
        fs::write(&bom_only, &[0xEF, 0xBB, 0xBF]).unwrap();
        assert!(super::json_read_from_file::<Small>(&bom_only).is_err());

        _ = fs::remove_dir_all(&temp_test_path);
    }

    #[test]
    fn json_read_from_file_supports_all_ten_encodings_test() {
        // Latin-1 accent + CJK + an astral-plane emoji (a surrogate pair in
        // UTF-16) so multi-byte decoding and surrogate pairing are exercised,
        // not just the ASCII fast path.
        const NON_ASCII_MESSAGE: &str = "caf\u{00e9} \u{6d4b}\u{8bd5} \u{1F600}";

        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct EncodingTestStruct {
            name: String,
            code: i32,
            message: String,
            enabled: bool,
        }

        #[derive(Clone, Copy)]
        enum Encoding {
            Utf8,
            Utf16Le,
            Utf16Be,
            Utf32Le,
            Utf32Be,
        }

        /// Encodes `text` into the raw bytes written to each test file.
        fn encode(text: &str, encoding: Encoding, with_bom: bool) -> Vec<u8> {
            let mut bytes = Vec::new();

            if with_bom {
                bytes.extend_from_slice(match encoding {
                    Encoding::Utf8 => &[0xEF, 0xBB, 0xBF][..],
                    Encoding::Utf16Le => &[0xFF, 0xFE][..],
                    Encoding::Utf16Be => &[0xFE, 0xFF][..],
                    Encoding::Utf32Le => &[0xFF, 0xFE, 0x00, 0x00][..],
                    Encoding::Utf32Be => &[0x00, 0x00, 0xFE, 0xFF][..],
                });
            }

            match encoding {
                Encoding::Utf8 => bytes.extend_from_slice(text.as_bytes()),
                Encoding::Utf16Le => {
                    for unit in text.encode_utf16() {
                        bytes.extend_from_slice(&unit.to_le_bytes());
                    }
                }
                Encoding::Utf16Be => {
                    for unit in text.encode_utf16() {
                        bytes.extend_from_slice(&unit.to_be_bytes());
                    }
                }
                Encoding::Utf32Le => {
                    for ch in text.chars() {
                        bytes.extend_from_slice(&(ch as u32).to_le_bytes());
                    }
                }
                Encoding::Utf32Be => {
                    for ch in text.chars() {
                        bytes.extend_from_slice(&(ch as u32).to_be_bytes());
                    }
                }
            }

            bytes
        }

        let mut temp_test_path = env::temp_dir();
        temp_test_path.push("json_read_from_file_supports_all_ten_encodings_test");
        // clean up and ignore the clean up errors
        _ = fs::remove_dir_all(&temp_test_path);
        super::try_create_folder(&temp_test_path).unwrap();

        let json = format!(
            r#"{{"name":"EncodingTest","code":7,"message":"{NON_ASCII_MESSAGE}","enabled":true}}"#
        );
        let expected = EncodingTestStruct {
            name: "EncodingTest".to_string(),
            code: 7,
            message: NON_ASCII_MESSAGE.to_string(),
            enabled: true,
        };

        // The same JSON document written 10 times, byte-for-byte encoded
        // differently. The UTF-32LE-with-BOM case is the ambiguous one: its BOM
        // starts with the UTF-16LE BOM.
        let combinations = [
            ("utf8_bom.json", Encoding::Utf8, true),
            ("utf8_no_bom.json", Encoding::Utf8, false),
            ("utf16le_bom.json", Encoding::Utf16Le, true),
            ("utf16le_no_bom.json", Encoding::Utf16Le, false),
            ("utf16be_bom.json", Encoding::Utf16Be, true),
            ("utf16be_no_bom.json", Encoding::Utf16Be, false),
            ("utf32le_bom.json", Encoding::Utf32Le, true),
            ("utf32le_no_bom.json", Encoding::Utf32Le, false),
            ("utf32be_bom.json", Encoding::Utf32Be, true),
            ("utf32be_no_bom.json", Encoding::Utf32Be, false),
        ];

        for (file_name, encoding, with_bom) in combinations {
            let file_path = temp_test_path.join(file_name);
            fs::write(&file_path, encode(&json, encoding, with_bom)).unwrap();

            let actual = super::json_read_from_file::<EncodingTestStruct>(&file_path)
                .unwrap_or_else(|e| panic!("{file_name}: {e}"));

            assert_eq!(expected, actual, "{file_name}: decoded payload differs");
        }

        // Odd byte count cannot be a whole number of UTF-16 code units.
        let truncated = temp_test_path.join("truncated_utf16.json");
        fs::write(&truncated, [0x7B, 0x00, 0x22]).unwrap();
        let error = super::json_read_from_file::<EncodingTestStruct>(&truncated)
            .unwrap_err()
            .to_string();
        assert!(error.contains("truncated"), "{error}");

        // 0x0011_0000 is one past the highest Unicode scalar value.
        let bad_scalar = temp_test_path.join("bad_utf32_scalar.json");
        fs::write(
            &bad_scalar,
            [0x7B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x00],
        )
        .unwrap();
        let error = super::json_read_from_file::<EncodingTestStruct>(&bad_scalar)
            .unwrap_err()
            .to_string();
        assert!(error.contains("invalid scalar value"), "{error}");

        _ = fs::remove_dir_all(&temp_test_path);
    }

    #[test]
    fn detect_text_encoding_short_input_test() {
        use super::TextEncoding;

        /// True when `bytes` is detected as plain UTF-8 with no BOM.
        fn is_utf8_no_bom(bytes: &[u8]) -> bool {
            let detected = super::detect_text_encoding(bytes);
            matches!(detected.text_encoding, TextEncoding::Utf8)
                && !detected.big_endian
                && detected.bom_len == 0
        }

        // 1. An empty input is UTF-8 with no BOM.
        assert!(is_utf8_no_bom(&[]), "empty input");
        // 2. A single ASCII byte is UTF-8 with no BOM.
        assert!(is_utf8_no_bom(&[0]), "single NUL byte");
        // 3. Two bytes that are invalid
        assert!(is_utf8_no_bom(&[1, 2]), "two invalid bytes");
    }

    #[test]
    fn path_to_string_test() {
        let path = "path_to_string_test";
        let path_str = super::path_to_string(&PathBuf::from(path));
        assert_eq!(path_str, path, "path_str mismatch");
    }

    #[test]
    fn execute_command_test() {
        let mut temp_test_path = env::temp_dir();
        temp_test_path.push("execute_command_test");
        // clean up and ignore the clean up errors
        _ = fs::remove_dir_all(&temp_test_path);
        super::try_create_folder(&temp_test_path).unwrap();

        let program: &str;
        let script_content: &str;
        let script_file_name: &str;
        let mut args: Vec<&str>;

        #[cfg(windows)]
        {
            program = "powershell.exe";
            args = vec!["-ExecutionPolicy", "Bypass", "-File"];
            script_file_name = "test.ps1";
            script_content = r#"write-host "this is stdout message"
            write-error "This is stderr message"
            exit 1
            "#;
        }
        #[cfg(not(windows))]
        {
            program = "sh";
            args = vec![];
            script_file_name = "test.sh";
            script_content = r#"echo "this is stdout message"
            >&2 echo "This is stderr message"
            exit 1
            "#;
        }

        let script_file_path = temp_test_path.join(script_file_name);
        _ = fs::write(&script_file_path, script_content);

        let script_file_path_str = super::path_to_string(&script_file_path);
        args.push(&script_file_path_str);

        let default_error_code = -1;
        let output = super::execute_command(program, args, default_error_code).unwrap();
        assert_eq!(1, output.exit_code(), "exit code mismatch");
        assert_eq!(
            "this is stdout message",
            output.stdout().trim(),
            "stdout message mismatch"
        );
        assert!(
            output.stderr().contains("This is stderr message"),
            "stderr message mismatch"
        );

        _ = fs::remove_dir_all(&temp_test_path);
    }

    #[test]
    fn get_file_name_test() {
        let path = PathBuf::from("test.txt");
        let file_name = super::get_file_name(&path);
        assert_eq!("test.txt", file_name, "file_name mismatch");

        let path = PathBuf::new();
        let file_name = super::get_file_name(&path);
        assert_eq!("InvalidPath", file_name, "file_name mismatch");
    }

    #[test]
    fn search_files_test() {
        let mut temp_test_path = env::temp_dir();
        temp_test_path.push("search_files_test");
        // clean up and ignore the clean up errors
        _ = fs::remove_dir_all(&temp_test_path);
        super::try_create_folder(&temp_test_path).unwrap();

        let test = TestStruct {
            thread_id: super::get_thread_identity(),
            date_time_string_with_milliseconds: super::get_date_time_string_with_milliseconds(),
            date_time_string: super::get_date_time_string(),
            date_time_rfc1123_string: super::get_date_time_rfc1123_string(),
            date_time_unix_nano: super::get_date_time_unix_nano(),
            long_os_version: super::get_long_os_version(),
            current_exe_dir: super::get_current_exe_dir().to_str().unwrap().to_string(),
        };

        // write 2 json files to the temp_test_path
        let json_file = temp_test_path.as_path();
        let json_file = json_file.join("test.json");
        super::json_write_to_file(&test, &json_file).unwrap();
        let json_file = temp_test_path.as_path();
        let json_file = json_file.join("test_1.json");
        super::json_write_to_file(&test, &json_file).unwrap();

        let regex = Regex::new(r"test.json").unwrap();
        let files = super::search_files(&temp_test_path, &regex).unwrap();
        assert_eq!(
            1,
            files.len(),
            "file count mismatch with 'test.json' search"
        );

        let regex = Regex::new(r"^test.*\.json$").unwrap();
        let files = super::search_files(&temp_test_path, &regex).unwrap();
        assert_eq!(
            2,
            files.len(),
            "file count mismatch with 'test*.json' search"
        );
        assert_eq!(
            "test.json",
            super::get_file_name(&files[0]),
            "First file name mismatch"
        );
        assert_eq!(
            "test_1.json",
            super::get_file_name(&files[1]),
            "Second file name mismatch"
        );

        _ = fs::remove_dir_all(&temp_test_path);
    }

    #[test]
    fn empty_path_test() {
        let empty_path = super::empty_path();
        assert_eq!(PathBuf::from(""), empty_path, "Empty path is not empty");
    }

    #[test]
    fn json_clone_test() {
        let test = TestStruct {
            thread_id: super::get_thread_identity(),
            date_time_string_with_milliseconds: super::get_date_time_string_with_milliseconds(),
            date_time_string: super::get_date_time_string(),
            date_time_rfc1123_string: super::get_date_time_rfc1123_string(),
            date_time_unix_nano: super::get_date_time_unix_nano(),
            long_os_version: super::get_long_os_version(),
            current_exe_dir: super::get_current_exe_dir().to_str().unwrap().to_string(),
        };

        let cloned = super::json_clone(&test).unwrap();

        assert_eq!(test.thread_id, cloned.thread_id);
        assert_eq!(
            test.date_time_string_with_milliseconds,
            cloned.date_time_string_with_milliseconds
        );
        assert_eq!(test.date_time_string, cloned.date_time_string);
        assert_eq!(
            test.date_time_rfc1123_string,
            cloned.date_time_rfc1123_string
        );
        assert_eq!(test.date_time_unix_nano, cloned.date_time_unix_nano);
        assert_eq!(test.long_os_version, cloned.long_os_version);
        assert_eq!(test.current_exe_dir, cloned.current_exe_dir);
    }

    #[test]
    fn resolve_env_variables_test() {
        let input = r"%SYSTEMDRIVE%\%WindowsAzure%\ProxyAgent\Package_1.0.0";
        let expected = format!(
            "{}\\WindowsAzure\\ProxyAgent\\Package_1.0.0",
            env::var("SYSTEMDRIVE").unwrap_or("SYSTEMDRIVE".to_string())
        );
        let resolved = super::resolve_env_variables(input);
        assert_eq!(expected, resolved, "resolved string mismatch");

        let input = "/var/log/azure-proxy-agent/";
        let expected = "/var/log/azure-proxy-agent/".to_string();
        let resolved = super::resolve_env_variables(input);
        assert_eq!(expected, resolved, "resolved string mismatch");
    }

    #[cfg(feature = "signing")]
    #[test]
    fn compute_signature_test() {
        let hex_encoded_key = "4A404E635266556A586E3272357538782F413F4428472B4B6250645367566B59";
        let message = "Hello world";
        let result = super::compute_signature(hex_encoded_key, message.as_bytes()).unwrap();
        println!("compute_signature: {result}");
        assert_eq!(
            "a15b46f621193876a6d3121b836dc2af4180e2786642e55235ef916fc5b082a3", result,
            "compute_signature results mismatch"
        );
        let invalid_hex_encoded_key =
            "YA404E635266556A586E3272357538782F413F4428472B4B6250645367566B59";
        let result = super::compute_signature(invalid_hex_encoded_key, message.as_bytes());
        assert!(result.is_err(), "invalid key should fail.");

        let e = result.unwrap_err();
        let error = e.to_string();
        assert!(
            error.contains(invalid_hex_encoded_key),
            "Error does not contains the invalid key"
        )
    }

    #[test]
    fn get_current_exe_version_test() {
        let version = super::get_current_exe_version();
        println!("get_current_exe_version: {version}");
        assert!(
            !version.is_empty(),
            "get_current_exe_version should return a non-empty string"
        );

        let cargo_version = super::get_current_version();
        #[cfg(windows)]
        {
            // "%UserProfile%\\.cargo\\bin\\rustup.exe" does not have file version info
            // so get_current_exe_version uses the version from current Cargo.toml file
            assert_eq!(
                cargo_version, version,
                "get_current_exe_version should return the same version as Cargo.toml as '%UserProfile%\\.cargo\\bin\\rustup.exe' does not have file version info"
            );
        }
        #[cfg(not(windows))]
        {
            assert_eq!(
                cargo_version, version,
                "get_current_exe_version should return the same version as Cargo.toml in Linux"
            );
        }
    }

    #[test]
    fn parse_date_time_string_test() {
        // Test parsing with milliseconds
        let datetime_str = "2024-01-15T10:30:45.123";
        let result = super::parse_date_time_string(datetime_str);
        assert!(
            result.is_ok(),
            "Failed to parse datetime string with milliseconds"
        );

        let datetime = result.unwrap();
        assert_eq!(datetime.year(), 2024);
        assert_eq!(datetime.month() as u8, 1);
        assert_eq!(datetime.day(), 15);
        assert_eq!(datetime.hour(), 10);
        assert_eq!(datetime.minute(), 30);
        assert_eq!(datetime.second(), 45);
        assert_eq!(datetime.millisecond(), 123);

        // Test parsing with 'Z' suffix
        let datetime_str = "2024-01-15T10:30:45Z";
        let result = super::parse_date_time_string(datetime_str);
        assert!(
            result.is_ok(),
            "Failed to parse datetime string with Z suffix"
        );

        let datetime = result.unwrap();
        assert_eq!(datetime.year(), 2024);
        assert_eq!(datetime.month() as u8, 1);
        assert_eq!(datetime.day(), 15);
        assert_eq!(datetime.hour(), 10);
        assert_eq!(datetime.minute(), 30);
        assert_eq!(datetime.second(), 45);

        // Test parsing without 'Z' suffix
        let datetime_str_without_z = "2024-01-15T10:30:45";
        let result = super::parse_date_time_string(datetime_str_without_z);
        assert!(result.is_ok(), "Should parse datetime string without 'Z'");

        // Test round-trip with milliseconds format
        let original_datetime_str = super::get_date_time_string_with_milliseconds();
        let result = super::parse_date_time_string(&original_datetime_str);
        assert!(
            result.is_ok(),
            "Failed to parse datetime string with milliseconds"
        );

        // Test round-trip with standard format
        let original_datetime_str = super::get_date_time_string();
        let result = super::parse_date_time_string(&original_datetime_str);
        assert!(
            result.is_ok(),
            "Failed to parse datetime string without milliseconds"
        );

        // Test invalid format
        let invalid_datetime_str = "2024-01-15 10:30:45"; // space instead of 'T'
        let result = super::parse_date_time_string(invalid_datetime_str);
        assert!(
            result.is_err(),
            "Should fail to parse invalid datetime string"
        );

        let invalid_datetime_str = "2024-01-15T10:30"; // without seconds
        let result = super::parse_date_time_string(invalid_datetime_str);
        assert!(
            result.is_err(),
            "Should fail to parse invalid datetime string"
        );
    }

    #[test]
    fn sync_host_utc_time_from_rfc1123_string_test() {
        let host_time = "Mon, 01 Jan 2024 00:00:00 GMT";
        assert!(
            super::sync_host_utc_time_from_rfc1123_string(host_time),
            "Expected valid host RFC1123 time to update sync state"
        );

        assert!(
            !super::host_time_sync_is_stale(Duration::from_secs(3600)),
            "Sync state should not be stale right after update"
        );

        std::thread::sleep(Duration::from_millis(1));
        assert!(
            super::host_time_sync_is_stale(Duration::from_millis(0)),
            "Sync state should be stale when max_age is zero"
        );

        // reset sync state to None for other tests
        let _ = super::HOST_TIME_SYNC_STATE
            .write()
            .map(|mut state| *state = None);
    }

    #[test]
    fn sync_host_utc_time_from_rfc1123_string_invalid_input_test() {
        assert!(
            !super::sync_host_utc_time_from_rfc1123_string("invalid-rfc1123"),
            "Expected invalid host RFC1123 time to fail"
        );
    }
}
