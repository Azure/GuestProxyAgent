// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

//! Canonical request model (Innovation 2.1).
//!
//! Provides a single, total, idempotent normalization step that reduces
//! every incoming [`hyper::Uri`] (and, separately, every authorization
//! rule pattern) to the same [`CanonicalRequest`] form before they meet
//! the matcher. The goal is to eliminate the rule/request asymmetries
//! that produce SSRF-style AuthZ bypasses (pentest categories D1, C7).
//!
//! ## Pipeline
//!
//! ```text
//! hyper::Uri
//!   │
//!   ▼  parse_scheme_method   (http only; allow-list of methods)
//!   ▼  classify_destination  (IP/host -> Destination; covers numeric forms)
//!   ▼  validate_userinfo     (must be empty)
//!   ▼  decode_path_once      (single percent-decode; strict UTF-8)
//!   ▼  reject_control_chars  (no CR/LF/NUL/HTAB after decode)
//!   ▼  ascii_lowercase_path  (case-insensitive matching)
//!   ▼  split_segments        (split '/'; collapse '.'; resolve '..')
//!   ▼  strip_matrix_params   (drop `;k=v` suffix on each segment)
//!   ▼  decode_query_once     (k/v percent-decode once; lowercase keys)
//!   ▼  reject_embedded_query (decoded path must not contain literal '?')
//!   ▼  fold_into_btreemap    (group by key)
//! CanonicalRequest
//! ```
//!
//! ## Fail-closed
//!
//! Every error variant in [`CanonError`] denies the request. There is no
//! "best effort" branch.
//!
//! ## Idempotency
//!
//! `canonicalize(canonicalize(x).render()) == canonicalize(x)`. This is
//! enforced via property tests in `tests::proptests`.
//!
//! ## Fuzzing (M2)
//!
//! The M2 exit criterion is "zero panics in 1 CPU-day of fuzzing." We
//! currently meet it with the [`proptests`] module — `no_panics` runs
//! `canonicalize_str` against random printable-ASCII strings and
//! `idempotent` exercises the parse-canonicalize-render-reparse loop.
//! Crank case counts via the standard env var:
//!
//! ```text
//! PROPTEST_CASES=1000000 cargo test -p azure-proxy-agent --release \
//!     proxy::canonical::proptests
//! ```
//!
//! A dedicated `cargo-fuzz` (libFuzzer) target would give better corpus
//! minimization and coverage feedback. It is **deferred** because
//! `proxy_agent` is a binary crate (`src/main.rs`, no `lib.rs`) and
//! `cargo-fuzz` requires importing a library. The non-invasive
//! follow-up:
//!
//! 1. Add a `lib.rs` re-exporting `pub mod proxy;` (and whatever else
//!    the fuzz targets need). The existing binary should stay
//!    `bin/azure-proxy-agent.rs` to avoid disturbing release artifact
//!    paths.
//! 2. `cargo fuzz init` in the crate, then add targets
//!    `fuzz_targets/canonicalize.rs` and `fuzz_targets/matches.rs`
//!    calling `azure_proxy_agent::proxy::canonical::canonicalize_str`
//!    and `CanonicalPattern::matches` respectively.
//! 3. Wire `cargo fuzz run canonicalize -- -max_total_time=86400` into
//!    the nightly CI matrix.

pub mod destination;
pub mod path;
pub mod query;
pub mod rule;

// Innovation 2.1 M2 property tests live behind the `proptests` feature
// so the default `cargo test` inner loop stays fast. CI picks them up
// through `cargo test --all-features` (see build-linux.sh).
#[cfg(all(test, feature = "proptests"))]
mod property_tests;

use std::collections::BTreeMap;
use std::fmt;

use hyper::{Method, Uri};
use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};

pub use destination::{AddrFamily, Destination};
pub use rule::CanonicalPattern;

/// Bytes that must be percent-encoded inside a path segment so that
/// re-parsing the rendered output yields the same canonical form.
///
/// - `%` would otherwise be interpreted as the start of an escape on
///   the second decode pass.
/// - `#` would be stripped by hyper as a fragment delimiter.
/// - `?` would be flagged by the canonicalizer as `EmbeddedQuery`.
/// - `;` would be re-stripped as a matrix-param sentinel.
/// - space and the C0 controls are invalid in a URI per RFC 3986.
///
/// `/` is intentionally NOT in this set because [`path::split_and_resolve`]
/// already guarantees no literal `/` survives inside a segment.
const PATH_SEG_ENCODE: &AsciiSet = &CONTROLS.add(b' ').add(b'%').add(b'#').add(b'?').add(b';');

/// Bytes that must be percent-encoded inside a query key or value.
///
/// In addition to the path-segment hazards, query strings treat `&` and
/// `=` as delimiters, and [`query::decode_query_component`] turns `+`
/// into a literal space — so a raw `+` in the rendered output would
/// round-trip to a space and lose data. All three must be encoded.
const QUERY_ENCODE: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'%')
    .add(b'#')
    .add(b'&')
    .add(b'=')
    .add(b'+');

/// Fully-normalized form of an HTTP request as it is fed to the matcher.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CanonicalRequest {
    /// HTTP method, restricted to the allow-list.
    pub method: Method,

    /// Classified destination. Matching uses the typed enum only; the raw
    /// host text is never compared.
    pub destination: Destination,

    /// Canonical path segments: percent-decoded once, ASCII-lowercased,
    /// `.` collapsed, `..` resolved, matrix params stripped.
    ///
    /// Always begins with the empty root segment (so `/metadata/identity`
    /// becomes `["", "metadata", "identity"]`).
    pub path_segments: Vec<String>,

    /// Whether the original path ended in `/`. Preserved as a single bit
    /// so rules can opt to be slash-sensitive without re-introducing
    /// string-level asymmetry.
    pub trailing_slash: bool,

    /// Query parameters, canonical form: keys lowercased & decoded once,
    /// values decoded once, grouped by key. Insertion order within a key
    /// is preserved; key order is lexicographic.
    pub query: BTreeMap<String, Vec<String>>,
}

impl CanonicalRequest {
    /// Stable textual rendering. Re-parsing this string and canonicalizing
    /// it must yield the same `CanonicalRequest` (idempotency invariant).
    ///
    /// Path segments and query components are percent-encoded on the way
    /// out (using [`PATH_SEG_ENCODE`] / [`QUERY_ENCODE`]) so that bytes
    /// which the pipeline decoded once — `%`, `&`, `=`, `+`, ` `, `#` and
    /// friends — survive a parse-decode-canonicalize round trip without
    /// being re-interpreted as delimiters.
    pub fn render(&self) -> String {
        let mut out = String::new();
        if self.path_segments.is_empty() {
            out.push('/');
        } else {
            for (i, seg) in self.path_segments.iter().enumerate() {
                if i == 0 && seg.is_empty() {
                    // root marker
                    out.push('/');
                    continue;
                }
                if i > 0 {
                    out.push('/');
                }
                out.extend(utf8_percent_encode(seg, PATH_SEG_ENCODE));
            }
        }
        if self.trailing_slash && !out.ends_with('/') {
            out.push('/');
        }
        if !self.query.is_empty() {
            out.push('?');
            let mut first = true;
            for (k, values) in self.query.iter() {
                for v in values {
                    if !first {
                        out.push('&');
                    }
                    first = false;
                    out.extend(utf8_percent_encode(k, QUERY_ENCODE));
                    out.push('=');
                    out.extend(utf8_percent_encode(v, QUERY_ENCODE));
                }
            }
        }
        out
    }
}

impl fmt::Display for CanonicalRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} {}", self.method, self.destination, self.render())
    }
}

/// Typed errors produced by the canonicalizer. All variants are
/// **fail-closed**: callers must deny the request when any of these is
/// returned.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CanonError {
    #[error("scheme not http")]
    SchemeNotHttp,
    #[error("method not allowed")]
    MethodNotAllowed,
    #[error("userinfo present in URL")]
    UserinfoPresent,
    #[error("malformed percent-encoding")]
    MalformedPercent,
    #[error("overlong UTF-8 in path/query")]
    OverlongUtf8,
    #[error("invalid UTF-8 in path/query")]
    InvalidUtf8,
    /// Decoded **path** bytes were well-formed UTF-8 but contained at
    /// least one non-ASCII codepoint. Separated from
    /// [`CanonError::InvalidUtf8`] so audit logs distinguish *encoding
    /// corruption* (random bytes, wrong codec) from *Unicode-confusable
    /// attacks* (e.g. U+0131 dotless-i looks like ASCII `i`, fullwidth
    /// solidus U+FF0F looks like ASCII `/`, Cyrillic homoglyphs) where the
    /// attacker hand-crafts perfectly valid UTF-8 specifically to fool
    /// ASCII-only string comparisons. The two classes have very different
    /// triage paths, so they get different stable codes. Only the path
    /// pipeline raises this — the query pipeline allows non-ASCII values
    /// (ARM ids may contain Unicode).
    #[error("non-ASCII codepoint in path")]
    NonAscii,
    #[error("control character in path/query")]
    ControlChar,
    #[error("path traversal past root")]
    PathUnderflow,
    #[error("embedded '?' after decoding")]
    EmbeddedQuery,
    #[error("unparseable host")]
    BadHost,
    #[error("unparseable port")]
    BadPort,
}

impl CanonError {
    /// Stable short code suitable for audit logs and pentest assertions.
    pub fn code(&self) -> &'static str {
        match self {
            CanonError::SchemeNotHttp => "CANON_SCHEME",
            CanonError::MethodNotAllowed => "CANON_METHOD",
            CanonError::UserinfoPresent => "CANON_USERINFO",
            CanonError::MalformedPercent => "CANON_PCT",
            CanonError::OverlongUtf8 => "CANON_OVERLONG",
            CanonError::InvalidUtf8 => "CANON_UTF8",
            CanonError::NonAscii => "CANON_NON_ASCII",
            CanonError::ControlChar => "CANON_CTRL",
            CanonError::PathUnderflow => "CANON_UNDERFLOW",
            CanonError::EmbeddedQuery => "CANON_EMBQ",
            CanonError::BadHost => "CANON_HOST",
            CanonError::BadPort => "CANON_PORT",
        }
    }
}

/// HTTP methods accepted by the canonicalizer. Anything not on this list
/// is rejected with [`CanonError::MethodNotAllowed`].
///
/// Kept in sync with `proxy_server::ProxyServer::ALLOWED_METHODS`.
const ALLOWED_METHODS: &[Method] = &[
    Method::GET,
    Method::POST,
    Method::PUT,
    Method::DELETE,
    Method::HEAD,
    Method::OPTIONS,
    Method::PATCH,
];

fn check_method(method: &Method) -> Result<(), CanonError> {
    if ALLOWED_METHODS.iter().any(|m| m == method) {
        Ok(())
    } else {
        Err(CanonError::MethodNotAllowed)
    }
}

fn check_scheme(uri: &Uri) -> Result<(), CanonError> {
    match uri.scheme_str() {
        // Hyper guarantees the connect-target form for absolute URIs has a
        // scheme; the proxy receives origin-form requests where the scheme
        // is omitted. Both cases are acceptable. A non-http scheme (https,
        // ws, gopher, ...) is a hard reject.
        None => Ok(()),
        Some(s) if s.eq_ignore_ascii_case("http") => Ok(()),
        Some(_) => Err(CanonError::SchemeNotHttp),
    }
}

/// Reject any URL whose authority carries `userinfo` (the `user[:pass]@`
/// prefix before the host).
///
/// Hyper exposes the full authority string via [`Uri::authority`]; the
/// presence of a literal `@` is the unambiguous signal of userinfo. We
/// refuse it entirely because it is the canonical host-smuggle vector
/// (pentest C7): `http://169.254.169.254:80@evil.com/` *looks* like
/// IMDS to a careless parser but resolves to `evil.com` in real HTTP
/// clients. Symmetrically, `http://attacker@169.254.169.254/` lets the
/// attacker decorate an otherwise-legitimate URL with audit-confusing
/// junk.
fn check_userinfo(uri: &Uri) -> Result<(), CanonError> {
    if let Some(authority) = uri.authority() {
        if authority.as_str().contains('@') {
            return Err(CanonError::UserinfoPresent);
        }
    }
    Ok(())
}

/// Canonicalize a parsed request.
///
/// Returns `Ok(CanonicalRequest)` for inputs that survive every stage of
/// the pipeline, or a typed [`CanonError`] otherwise. The function is
/// **total** — every well-formed `hyper::Uri` produces exactly one of
/// these two outcomes; it never panics.
pub fn canonicalize(uri: &Uri, method: &Method) -> Result<CanonicalRequest, CanonError> {
    check_scheme(uri)?;
    check_method(method)?;
    check_userinfo(uri)?;

    let destination = destination::classify(uri)?;

    let (path_segments, trailing_slash) = path::canonicalize_path(uri.path())?;
    let query = query::canonicalize_query(uri.query().unwrap_or(""))?;

    Ok(CanonicalRequest {
        method: method.clone(),
        destination,
        path_segments,
        trailing_slash,
        query,
    })
}

/// Convenience: parse and canonicalize a string. Useful for tests and the
/// shadow-mode shim that takes raw URLs from telemetry replay.
#[allow(dead_code)]
pub fn canonicalize_str(url: &str) -> Result<CanonicalRequest, CanonError> {
    let uri: Uri = url.parse().map_err(|_| CanonError::BadHost)?;
    canonicalize(&uri, &Method::GET)
}

/// Rollout flag controlling whether the canonical pipeline shadows or
/// replaces the legacy authorizer.
///
/// See `doc/plans/Innovation-2.1-canonical-request.md` §9 (Shadow-Mode
/// Rollout). Defaults to [`CanonicalMode::Off`] so production traffic
/// keeps the pre-canonical behavior bit-for-bit.
///
/// - [`Off`](CanonicalMode::Off): legacy decides; canonical not invoked.
/// - [`Shadow`](CanonicalMode::Shadow): legacy decides; canonical runs
///   in parallel and divergences are logged as telemetry. **Behavior
///   unchanged** — this is the M3 default for dev/test.
/// - [`Enforce`](CanonicalMode::Enforce): canonical decides; legacy is
///   still computed for divergence telemetry. Wired but only intended
///   for use once shadow-mode reports zero divergences (M5/M6).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CanonicalMode {
    #[default]
    Off,
    Shadow,
    Enforce,
}

impl std::fmt::Display for CanonicalMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CanonicalMode::Off => write!(f, "off"),
            CanonicalMode::Shadow => write!(f, "shadow"),
            CanonicalMode::Enforce => write!(f, "enforce"),
        }
    }
}

impl std::str::FromStr for CanonicalMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "off" | "" => Ok(CanonicalMode::Off),
            "shadow" => Ok(CanonicalMode::Shadow),
            "enforce" => Ok(CanonicalMode::Enforce),
            other => Err(format!("Invalid CanonicalMode: {other}")),
        }
    }
}

#[cfg(test)]
mod mod_tests {
    //! Cross-cutting tests for the canonical pipeline.
    //!
    //! Helper-specific golden vectors live next to their helpers
    //! (`path::path_tests::appendix_a1_*`,
    //! `destination::destination_tests::appendix_a2_*`). What lives
    //! here is what cuts across every helper:
    //!
    //! - Scheme / method / userinfo gating (the top-level checks in
    //!   [`canonicalize`]).
    //! - Idempotency: `canonicalize(canonicalize(x).render()) ==
    //!   canonicalize(x)` — verifies the renderer round-trips every
    //!   helper's output.
    //! - Total / no-panic on adversarial inputs.
    //! - Stability of [`CanonError::code`] strings (audit-log contract).

    use hyper::{Method, Uri};

    use super::*;

    #[test]
    fn userinfo_rejected_at_pipeline_entry() {
        // hyper may either parse-and-reject or refuse outright. Either
        // is a deny, but UserinfoPresent is the preferred surfacing.
        let err = canonicalize_str("http://user@169.254.169.254/x").unwrap_err();
        assert!(
            matches!(err, CanonError::UserinfoPresent | CanonError::BadHost),
            "userinfo: got {err:?}"
        );
    }

    #[test]
    fn allowed_methods_are_accepted_others_rejected() {
        let uri: Uri = "http://169.254.169.254/x".parse().unwrap();

        // Positive: every method in ALLOWED_METHODS canonicalizes
        // successfully. Locks the slice's contents against accidental
        // shrinking — a removal would surface here as a method that
        // used to work and now doesn't.
        let allowed = &[
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::HEAD,
            Method::OPTIONS,
            Method::PATCH,
        ];
        for m in allowed {
            assert!(
                canonicalize(&uri, m).is_ok(),
                "method {m:?} should be accepted"
            );
        }

        // Negative: methods explicitly NOT on the list deny with
        // MethodNotAllowed.
        let denied = &[Method::CONNECT, Method::TRACE];
        for m in denied {
            assert_eq!(
                canonicalize(&uri, m).unwrap_err(),
                CanonError::MethodNotAllowed,
                "method {m:?} should be rejected"
            );
        }
    }

    #[test]
    fn non_http_schemes_rejected() {
        // Anything not bare `http://` is a deny. Hyper may refuse to
        // parse some of these as absolute URIs; either path is a deny,
        // but the explicit canonicalize() rejection is what we want to
        // pin for the schemes hyper does accept.
        let cases: &[(&str, &str)] = &[
            ("https", "https://169.254.169.254/x"),
            ("ftp", "ftp://169.254.169.254/x"),
            ("file", "file://169.254.169.254/x"),
        ];
        for (label, url) in cases {
            match url.parse::<Uri>() {
                Ok(uri) => assert_eq!(
                    canonicalize(&uri, &Method::GET).unwrap_err(),
                    CanonError::SchemeNotHttp,
                    "scheme={label}"
                ),
                Err(_) => {
                    // hyper refused to parse — equally a deny, no-op.
                }
            }
        }
    }

    #[test]
    fn canonical_form_is_idempotent() {
        // canonicalize(canonicalize(x).render()) == canonicalize(x).
        //
        // Per-vector idempotency catches a class of bugs where the
        // renderer and the parser disagree on something subtle
        // (encoding of `+`, matrix-param re-emergence, etc).
        let cases: &[(&str, &str)] = &[
            (
                "typical imds token",
                "http://169.254.169.254/Metadata/Identity/oauth2/token?api-version=2018-02-01&Resource=https%3A%2F%2Fmanagement.azure.com%2F",
            ),
            ("root only", "http://169.254.169.254/"),
            (
                "empty query",
                "http://169.254.169.254/metadata/identity?",
            ),
            (
                "multi-key query with case fold",
                "http://169.254.169.254/m?Foo=1&BAR=2&baz=3",
            ),
            (
                // Value contains decoded space (`%20`) and decoded `&`
                // (`%26`). render() must re-encode both, otherwise the
                // re-parse would either fail (space is invalid in a
                // URI) or split the value on the spurious `&`.
                "query value with reserved chars",
                "http://169.254.169.254/m?k=a%20b%26c",
            ),
            (
                // Value contains decoded `+` (`%2B`).
                // decode_query_component turns raw `+` into a space, so
                // render must re-encode `+` as `%2B` to round-trip.
                "query value with literal plus",
                "http://169.254.169.254/m?k=a%2Bb",
            ),
            (
                // Path segment contains a literal `%` after one decode
                // (`%252F` -> `%2f` literal). render() must emit
                // `%252f` so the second decode lands on the same
                // literal byte.
                "path segment with literal percent",
                "http://169.254.169.254/metadata%252Fidentity",
            ),
            (
                "dot segments collapse first time",
                "http://169.254.169.254/a/./b/../c",
            ),
        ];
        for (label, url) in cases {
            let c1 = canonicalize_str(url).expect(label);
            // render() drops host; reattach so the second pass sees the
            // same destination.
            let rendered = format!("http://169.254.169.254{}", c1.render());
            let c2 = canonicalize_str(&rendered).expect(label);
            assert_eq!(c1, c2, "not idempotent: {label}");
        }
    }

    #[test]
    fn canonicalize_never_panics_on_adversarial_inputs() {
        // Sanity smoke test — a proptest target lives in a follow-up
        // PR. For every shape hyper consents to parse, the
        // canonicalizer must return either Ok or a typed CanonError.
        // Panics here are bugs.
        let paths = &[
            "/",
            "//",
            "/.",
            "/..",
            "/%00",
            "/a/b/c?",
            "/?",
            "/a;",
            "/a;b;c;",
            "/%",
            "/%%",
            "/%%%",
            "/%C0%AF", // overlong utf-8
            "/very/long/path/that/repeats/very/long/path/that/repeats",
            "/a/../../..",     // underflow
            "/a/b/c/../../..", // exact-root underflow
        ];
        let methods = &[Method::GET, Method::POST, Method::CONNECT];
        for raw in paths {
            if let Ok(uri) = format!("http://169.254.169.254{raw}").parse::<Uri>() {
                for m in methods {
                    let _ = canonicalize(&uri, m);
                }
            }
        }
    }

    #[test]
    fn error_codes_are_stable() {
        // Stability of these strings is a CONTRACT with the audit log
        // and pentest scripts. Changing any one of these is a breaking
        // change that must bump the canonical-request schema version.
        let cases: &[(CanonError, &str)] = &[
            (CanonError::SchemeNotHttp, "CANON_SCHEME"),
            (CanonError::MethodNotAllowed, "CANON_METHOD"),
            (CanonError::UserinfoPresent, "CANON_USERINFO"),
            (CanonError::MalformedPercent, "CANON_PCT"),
            (CanonError::OverlongUtf8, "CANON_OVERLONG"),
            (CanonError::InvalidUtf8, "CANON_UTF8"),
            (CanonError::NonAscii, "CANON_NON_ASCII"),
            (CanonError::ControlChar, "CANON_CTRL"),
            (CanonError::PathUnderflow, "CANON_UNDERFLOW"),
            (CanonError::EmbeddedQuery, "CANON_EMBQ"),
            (CanonError::BadHost, "CANON_HOST"),
            (CanonError::BadPort, "CANON_PORT"),
        ];
        for (err, expected_code) in cases {
            assert_eq!(err.code(), *expected_code, "variant={err:?}");
        }
    }

    #[test]
    fn canonical_mode_parses_and_defaults_off() {
        use std::str::FromStr;

        // Empty / missing config string defaults to Off so production
        // traffic is unchanged when the config key is absent.
        assert_eq!(CanonicalMode::default(), CanonicalMode::Off);
        assert_eq!(CanonicalMode::from_str("").unwrap(), CanonicalMode::Off);

        // Accepted spellings — case- and whitespace-insensitive so
        // operators can write "Shadow" or " enforce " without surprises.
        let cases: &[(&str, CanonicalMode)] = &[
            ("off", CanonicalMode::Off),
            ("Off", CanonicalMode::Off),
            ("shadow", CanonicalMode::Shadow),
            ("SHADOW", CanonicalMode::Shadow),
            ("  shadow  ", CanonicalMode::Shadow),
            ("enforce", CanonicalMode::Enforce),
        ];
        for (input, expected) in cases {
            assert_eq!(
                CanonicalMode::from_str(input).unwrap(),
                *expected,
                "input={input:?}"
            );
        }

        // Unknown strings reject — better to fail loud at config load
        // than silently fall through to Off and lie in telemetry.
        assert!(CanonicalMode::from_str("audit").is_err());
        assert!(CanonicalMode::from_str("on").is_err());
    }
}
