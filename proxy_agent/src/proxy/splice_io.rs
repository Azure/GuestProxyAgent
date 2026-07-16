// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

//! Linux-only zero-copy response body relay via `splice(2)`.
//!
//! # Why splice?
//!
//! Regular hyper path (two kernel↔user copies per byte):
//! ```text
//! upstream_socket --[recv, kernel→user copy]--> Bytes --[send]--> client_socket
//! ```
//!
//! Splice path (one copy direction eliminated):
//! ```text
//! upstream_socket --[splice, kernel page-remap]--> kernel_pipe
//!     --[read, one copy]--> Bytes --[send]--> client_socket
//! ```
//!
//! The upstream→pipe leg uses `SPLICE_F_MOVE` to remap kernel pages instead
//! of memcpy-ing bytes, which is measurably cheaper for large bodies (>16 KB).
//! The pipe→user read is unavoidable while the client side is still owned by
//! hyper — eliminating it is a Phase 2 goal.
//!
//! # Architecture
//!
//! Used by the signed **GET/HEAD** download path in `proxy_server` — the large
//! payloads (WireServer/IMDS goal-state and config blobs) live in the response
//! body of these body-less, idempotent requests:
//!
//! 1. [`forward_via_raw_socket`] is the entry point.  It calls
//!    [`raw_upstream_request`] to open a **new** raw `TcpStream` to the
//!    upstream, write the HTTP/1.1 request manually, and read response headers
//!    **byte-by-byte** so the socket is positioned exactly at the first body
//!    byte with no bytes buffered in user space.
//! 2. Large responses go through [`splice_to_pipe`], which moves the
//!    `TcpStream` to a `spawn_blocking` task that calls `splice(2)` in a tight
//!    loop until EOF or `content_length` is exhausted, writing into the write
//!    end of a tokio unix pipe.  [`SpliceBody`] wraps the pipe read end as a
//!    hyper `Body`, yielding chunks to the client.
//! 3. Small responses are read directly into a buffered `Full` body (no second
//!    request to the host).
//! 4. Chunked / unknown-length responses return [`RawOutcome::FallBack`]; the
//!    caller re-sends over the pooled hyper connection (safe because GET/HEAD
//!    are idempotent).
//!
//! # Fallback
//!
//! Every public function returns `std::io::Result`.  Callers fall back to the
//! regular hyper copy loop on any error or when splice is not applicable.

#![cfg(target_os = "linux")]

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::{Body, Frame};
use hyper::header::{HeaderMap, HeaderName, HeaderValue};
use hyper::{Response, StatusCode};
use std::io;
use std::os::unix::io::{AsRawFd, RawFd};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::unix::pipe;
use tokio::net::TcpStream;

// ── Tunables ──────────────────────────────────────────────────────────────────

/// Response bodies smaller than this threshold are read directly into a
/// buffered `Full` body instead of splicing.  `splice(2)` has per-call
/// overhead; below ~16 KB it does not pay off, which also matches the design
/// goal of targeting large downloads (goal-state / config blobs).
pub const SPLICE_THRESHOLD: usize = 16 * 1024;

/// Number of bytes requested per `splice(2)` call.  Linux caps a single
/// splice at the pipe buffer capacity (default 64 KB on most kernels).
const SPLICE_CHUNK: usize = 64 * 1024;

// ── Telemetry counters ────────────────────────────────────────────────────────

/// Total response-body bytes forwarded via `splice(2)` in this process.
pub static SPLICE_BYTES_TOTAL: AtomicU64 = AtomicU64::new(0);
/// Total response-body bytes forwarded via the regular copy path.
pub static COPY_BYTES_TOTAL: AtomicU64 = AtomicU64::new(0);

pub fn record_splice_bytes(n: u64) {
    SPLICE_BYTES_TOTAL.fetch_add(n, Ordering::Relaxed);
}

pub fn record_copy_bytes(n: u64) {
    COPY_BYTES_TOTAL.fetch_add(n, Ordering::Relaxed);
}

// ── splice_to_pipe ─────────────────────────────────────────────────────────────

/// Move `stream` to a `spawn_blocking` task that splices bytes from it into
/// a kernel pipe, and return the pipe's read end.
///
/// The function takes **ownership** of `stream` so that:
/// - The raw fd is valid for the lifetime of the blocking task.
/// - No other tokio task races on the same fd via a separate `AsyncFd`
///   registration.
///
/// The write end of the pipe is dropped when the task finishes (EOF or
/// `content_length` exhausted), causing the read end to return `Ok(0)` on
/// the next read and signalling EOF to [`SpliceBody`].
pub fn splice_to_pipe(
    stream: TcpStream,
    content_length: Option<u64>,
) -> io::Result<pipe::Receiver> {
    // Convert the tokio TcpStream to a std TcpStream for use in spawn_blocking.
    // Switch to blocking mode so the splice loop can block on I/O without a
    // readiness-notification mechanism (which would conflict with tokio's
    // reactor since the same fd must not be registered twice).
    let std_stream = stream.into_std()?;
    std_stream.set_nonblocking(false)?;
    let src_fd: RawFd = std_stream.as_raw_fd();

    // Create a tokio unix pipe.  The sender's fd is where splice writes;
    // the receiver is what SpliceBody reads from asynchronously.
    let (tx, rx) = pipe::pipe()?;
    let pipe_write_fd: RawFd = tx.as_raw_fd();

    tokio::task::spawn_blocking(move || {
        // Keep both ends alive for the duration of the task.
        let _stream = std_stream;
        let _tx = tx; // dropped at end → closes write fd → EOF on rx

        let mut remaining = content_length;

        loop {
            if remaining == Some(0) {
                break;
            }

            let to_splice = remaining
                .map(|r| r.min(SPLICE_CHUNK as u64) as usize)
                .unwrap_or(SPLICE_CHUNK);

            // SAFETY: src_fd and pipe_write_fd are valid for the duration of
            // this task because we hold _stream and _tx above.
            let n = unsafe {
                libc::splice(
                    src_fd,
                    std::ptr::null_mut::<libc::loff_t>(),
                    pipe_write_fd,
                    std::ptr::null_mut::<libc::loff_t>(),
                    to_splice,
                    libc::SPLICE_F_MOVE,
                )
            };

            match n {
                0 => break, // upstream EOF
                n if n < 0 => {
                    let e = io::Error::last_os_error();
                    if e.kind() == io::ErrorKind::Interrupted {
                        continue; // EINTR – retry
                    }
                    break; // EBADF, EPIPE, etc.
                }
                n => {
                    record_splice_bytes(n as u64);
                    if let Some(rem) = remaining.as_mut() {
                        *rem = rem.saturating_sub(n as u64);
                    }
                }
            }
        }
        // _tx dropped → pipe write end closed → SpliceBody sees EOF
    });

    Ok(rx)
}

// ── SpliceBody ────────────────────────────────────────────────────────────────

/// A hyper [`Body`] backed by the read end of a tokio unix pipe.
///
/// Yields `Frame::data(Bytes)` chunks until the pipe write end is closed (EOF),
/// then returns `Poll::Ready(None)`.
pub struct SpliceBody {
    reader: pipe::Receiver,
}

impl SpliceBody {
    pub fn new(reader: pipe::Receiver) -> Self {
        Self { reader }
    }

    /// Convert into a `BoxBody<Bytes, hyper::Error>` compatible with the rest
    /// of `proxy_server`.  Pipe I/O errors panic (they are extremely rare on
    /// Linux and not recoverable in the streaming body protocol).
    pub fn into_box(self) -> BoxBody<Bytes, hyper::Error> {
        self.map_err(|e: io::Error| panic!("SpliceBody pipe read error: {e}"))
            .boxed()
    }
}

impl Body for SpliceBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        let mut buf = vec![0u8; SPLICE_CHUNK];
        let mut read_buf = tokio::io::ReadBuf::new(&mut buf);

        match Pin::new(&mut self.reader).poll_read(cx, &mut read_buf) {
            Poll::Ready(Ok(())) => {
                let n = read_buf.filled().len();
                if n == 0 {
                    Poll::Ready(None) // pipe write end was closed – EOF
                } else {
                    buf.truncate(n);
                    Poll::Ready(Some(Ok(Frame::data(Bytes::from(buf)))))
                }
            }
            Poll::Ready(Err(e)) => Poll::Ready(Some(Err(e))),
            Poll::Pending => Poll::Pending,
        }
    }
}

// ── RawUpstreamResponse ───────────────────────────────────────────────────────

/// Parsed upstream response, with the `TcpStream` positioned at the first
/// byte of the response body.
pub struct RawUpstreamResponse {
    /// HTTP status from the upstream.
    pub status: StatusCode,
    /// Response headers (excluding the status line).
    pub headers: HeaderMap,
    /// Value of the `Content-Length` header, if present.
    pub content_length: Option<u64>,
    /// True when the upstream used `Transfer-Encoding: chunked`.
    /// The splice path does not support chunked de-chunking; callers should
    /// fall back to the regular hyper path when this is `true`.
    pub is_chunked: bool,
    /// The TcpStream, positioned exactly at the first body byte.
    /// Consumed by [`forward_via_raw_socket`] (splice or buffered read) or
    /// dropped to close the connection.
    pub stream: TcpStream,
}

// ── raw_upstream_request ──────────────────────────────────────────────────────

/// Connect a raw TCP socket to `{ip}:{port}`, write the HTTP/1.1 request
/// (method, URI, headers, body), then read the response status line and
/// headers.
///
/// The returned `RawUpstreamResponse::stream` is positioned **exactly** at
/// the first response-body byte — no bytes are consumed past the
/// `\r\n\r\n` boundary into a user-space buffer.  This is achieved by
/// reading one byte at a time until `\r\n\r\n` is found, which is safe
/// because headers are typically small (< 2 KB).
///
/// # Errors
/// Returns an error on I/O failure, a malformed status line, or headers
/// larger than 64 KB.
pub async fn raw_upstream_request(
    ip: &str,
    port: u16,
    method: &hyper::Method,
    uri: &hyper::Uri,
    headers: &HeaderMap,
    body: &[u8],
) -> io::Result<RawUpstreamResponse> {
    let addr = format!("{ip}:{port}");
    let mut stream = TcpStream::connect(&addr)
        .await
        .map_err(|e| io::Error::new(e.kind(), format!("connect {addr}: {e}")))?;

    // ── Format and send the request ────────────────────────────────────────────
    let path_and_query = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");

    let mut req = format!("{method} {path_and_query} HTTP/1.1\r\n");

    // HTTP/1.1 requires a Host header.
    let host = uri.host().unwrap_or(ip);
    req.push_str(&format!("Host: {host}\r\n"));

    for (name, value) in headers {
        let n = name.as_str();
        if n.eq_ignore_ascii_case("host") {
            continue; // already written above
        }
        if let Ok(v) = value.to_str() {
            req.push_str(&format!("{n}: {v}\r\n"));
        }
    }

    if !body.is_empty() {
        req.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    // Connection: close avoids the upstream trying to pipeline another request
    // on a socket that we are about to hand off to the splice task.
    req.push_str("Connection: close\r\n");
    req.push_str("\r\n");

    stream.write_all(req.as_bytes()).await?;
    if !body.is_empty() {
        stream.write_all(body).await?;
    }
    stream.flush().await?;

    // ── Read response headers (byte-by-byte, no buffer overrun) ───────────────
    //
    // Using `BufReader` would silently read body bytes into its internal
    // buffer, making them invisible to `splice(2)` on the raw fd.
    // Reading one byte at a time is slower but guarantees the socket is
    // positioned exactly at the first body byte after we find `\r\n\r\n`.
    let mut hdr_buf: Vec<u8> = Vec::with_capacity(2048);
    const MAX_HEADER_BYTES: usize = 64 * 1024;
    let mut single = [0u8; 1];

    loop {
        stream.read_exact(&mut single).await?;
        hdr_buf.push(single[0]);

        if hdr_buf.ends_with(b"\r\n\r\n") {
            break;
        }
        if hdr_buf.len() > MAX_HEADER_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("response headers exceed {MAX_HEADER_BYTES} bytes"),
            ));
        }
    }

    // ── Parse status line ──────────────────────────────────────────────────────
    let hdr_text =
        std::str::from_utf8(&hdr_buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let mut lines = hdr_text.lines();
    let status_line = lines
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "empty HTTP response"))?;

    // Expected: "HTTP/1.1 200 OK"
    let status_code: u16 = status_line
        .splitn(3, ' ')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("cannot parse status code from: {status_line:?}"),
            )
        })?;

    let status = StatusCode::from_u16(status_code)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    // ── Parse response headers ─────────────────────────────────────────────────
    let mut response_headers = HeaderMap::new();
    let mut content_length: Option<u64> = None;
    let mut is_chunked = false;

    for line in lines {
        let line = line.trim_end_matches('\r').trim();
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();

        match name.as_str() {
            "content-length" => {
                content_length = value.parse().ok();
            }
            "transfer-encoding" if value.to_ascii_lowercase().contains("chunked") => {
                is_chunked = true;
            }
            _ => {}
        }

        if let (Ok(hn), Ok(hv)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(value),
        ) {
            response_headers.append(hn, hv);
        }
    }

    Ok(RawUpstreamResponse {
        status,
        headers: response_headers,
        content_length,
        is_chunked,
        stream,
    })
}

// ── Response orchestration ────────────────────────────────────────────────────

/// Outcome of [`forward_via_raw_socket`].
pub enum RawOutcome {
    /// A complete client response was produced directly from the raw upstream
    /// connection — either splice-backed (large body) or buffered (small body).
    Response(Response<BoxBody<Bytes, hyper::Error>>),
    /// The upstream response was not eligible for the raw path (chunked
    /// `Transfer-Encoding` or missing `Content-Length`).  The caller should
    /// fall back to the pooled hyper path.  Because this function is only used
    /// for idempotent GET/HEAD requests, a fallback re-send is safe.
    FallBack,
}

/// Send `method uri` (with `headers`/`body`) to `{ip}:{port}` over a raw TCP
/// socket and turn the upstream response into a client [`Response`].
///
/// - Large bodies (`Content-Length >= SPLICE_THRESHOLD`) are streamed through a
///   kernel pipe via `splice(2)` — no upstream→user-space memcpy.
/// - Small bodies are read directly into a buffered `Full` body (a single read,
///   no second request to the host).
/// - Chunked or unknown-length responses return [`RawOutcome::FallBack`].
///
/// # Errors
/// Returns an error only on hard I/O failures (connect / write / read /
/// splice setup).  Callers treat any error as a signal to fall back to the
/// pooled hyper path.
pub async fn forward_via_raw_socket(
    ip: &str,
    port: u16,
    method: &hyper::Method,
    uri: &hyper::Uri,
    headers: &HeaderMap,
    body: &[u8],
) -> io::Result<RawOutcome> {
    let upstream_resp = raw_upstream_request(ip, port, method, uri, headers, body).await?;

    // Chunked de-chunking is not supported on the raw path, and without a
    // Content-Length we cannot bound the splice / buffered read.
    if upstream_resp.is_chunked || upstream_resp.content_length.is_none() {
        return Ok(RawOutcome::FallBack);
    }

    let content_length = upstream_resp.content_length.unwrap();

    if content_length as usize >= SPLICE_THRESHOLD {
        Ok(RawOutcome::Response(splice_response(upstream_resp)?))
    } else {
        record_copy_bytes(content_length);
        Ok(RawOutcome::Response(
            buffered_response(upstream_resp, content_length).await?,
        ))
    }
}

/// Build a hyper `Response<BoxBody<…>>` whose body is spliced from the upstream
/// socket through a kernel pipe.
///
/// Ownership of `upstream_resp.stream` is transferred to the background splice
/// task; the caller must not access it afterwards.
fn splice_response(
    upstream_resp: RawUpstreamResponse,
) -> io::Result<Response<BoxBody<Bytes, hyper::Error>>> {
    let RawUpstreamResponse {
        status,
        headers,
        content_length,
        stream,
        ..
    } = upstream_resp;

    let rx = splice_to_pipe(stream, content_length)?;

    let mut response = Response::new(SpliceBody::new(rx).into_box());
    *response.status_mut() = status;
    *response.headers_mut() = headers;
    Ok(response)
}

/// Read exactly `content_length` body bytes from the upstream socket and build
/// a buffered `Full` response.  Used for small bodies where splice overhead is
/// not worthwhile; avoids a second request to the host.
async fn buffered_response(
    upstream_resp: RawUpstreamResponse,
    content_length: u64,
) -> io::Result<Response<BoxBody<Bytes, hyper::Error>>> {
    let RawUpstreamResponse {
        status,
        headers,
        mut stream,
        ..
    } = upstream_resp;

    let mut buf = vec![0u8; content_length as usize];
    stream.read_exact(&mut buf).await?;

    let body = Full::new(Bytes::from(buf))
        .map_err(|never| match never {})
        .boxed();
    let mut response = Response::new(body);
    *response.status_mut() = status;
    *response.headers_mut() = headers;
    Ok(response)
}
