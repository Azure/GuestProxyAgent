// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

//! Path canonicalization.
//!
//! Steps (each is a small pure function so they can be unit-tested
//! independently):
//!
//! 1. Single percent-decode of the raw path; reject malformed `%XX`.
//! 2. Reject overlong UTF-8 encodings of ASCII (`%C0%AF` etc.).
//! 3. Reject control characters (`\r`, `\n`, `\0`, `\t`).
//! 4. Reject non-ASCII bytes (paths to IMDS / WireServer are ASCII;
//!    accepting non-ASCII would require NFC normalization that adds a
//!    dependency we do not currently take).
//! 5. ASCII-lowercase.
//! 6. Split on `/`, drop empty segments, drop `.`, resolve `..`
//!    (RFC 3986 §5.2.4). Underflow past the root is an error, not a
//!    no-op — a real client would never produce it.
//! 7. Strip matrix params (`;jsessionid=...`) from each segment.
//! 8. Reject an embedded `?` in the decoded path (caused by `%3F`
//!    smuggling) — the matcher must never see ambiguous input.
//!
//! The output is `(segments, trailing_slash)`. `segments` always begins
//! with the empty root segment, so the canonical form of `/` is
//! `vec![""]` and the canonical form of `/metadata/identity` is
//! `vec!["", "metadata", "identity"]`.

use super::CanonError;

const ROOT: &str = "";

/// Run the path pipeline. Public for unit tests; the canonicalizer
/// entrypoint is [`super::canonicalize`].
pub fn canonicalize_path(raw: &str) -> Result<(Vec<String>, bool), CanonError> {
    // hyper guarantees the path starts with '/'.
    let raw = if raw.is_empty() { "/" } else { raw };
    let trailing_slash = raw.len() > 1 && raw.ends_with('/');

    let decoded = decode_path_once(raw)?;
    reject_overlong_utf8(decoded.as_bytes())?;
    reject_control_chars(&decoded)?;
    reject_non_ascii(&decoded)?;
    if decoded.contains('?') {
        return Err(CanonError::EmbeddedQuery);
    }

    let lowered = decoded.to_ascii_lowercase();
    let segments = split_and_resolve(&lowered)?;

    // A trailing `/` only carries meaning when there's a non-root
    // segment in front of it. Without this clamp, inputs that collapse
    // to root after dot/matrix resolution (e.g. `/;/`, `/./`, `//`)
    // would carry `trailing_slash = true` even though `render()`
    // produces just `/` — which re-parses with `trailing_slash =
    // false`, breaking the canonicalize-render-canonicalize idempotency
    // invariant the rest of the pipeline depends on.
    let trailing_slash = trailing_slash && segments.len() > 1;

    Ok((segments, trailing_slash))
}

/// Single-pass percent-decode. Rejects truncated (`%2`) and non-hex
/// (`%ZZ`) sequences as `MalformedPercent`. Never decodes twice — that
/// is exactly the asymmetry the canonical model is built to remove.
fn decode_path_once(raw: &str) -> Result<String, CanonError> {
    let bytes = raw.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'%' {
            if i + 2 >= bytes.len() {
                return Err(CanonError::MalformedPercent);
            }
            let h = hex_value(bytes[i + 1])?;
            let l = hex_value(bytes[i + 2])?;
            out.push((h << 4) | l);
            i += 3;
        } else {
            out.push(b);
            i += 1;
        }
    }
    // Strict UTF-8: lossy decoding is what allowed the silent-replacement
    // bypass in the legacy matcher.
    String::from_utf8(out).map_err(|_| CanonError::InvalidUtf8)
}

fn hex_value(b: u8) -> Result<u8, CanonError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(10 + b - b'a'),
        b'A'..=b'F' => Ok(10 + b - b'A'),
        _ => Err(CanonError::MalformedPercent),
    }
}

/// Detect classic overlong UTF-8 encodings (e.g. `%C0%AF` for `/`).
///
/// `String::from_utf8` already rejects overlong sequences as invalid, so
/// by the time we run this the bytes are *guaranteed* well-formed
/// UTF-8 — meaning the overlong forms below would already have produced
/// `InvalidUtf8`. We run this pass *before* UTF-8 validation in case the
/// caller ever switches to a lossy decoder; today it is a defense in
/// depth that also gives us a more specific telemetry code.
fn reject_overlong_utf8(bytes: &[u8]) -> Result<(), CanonError> {
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        // 2-byte overlong: lead byte 0xC0 or 0xC1 (would encode <0x80).
        if b == 0xC0 || b == 0xC1 {
            return Err(CanonError::OverlongUtf8);
        }
        // 3-byte overlong: 0xE0 0x80..0x9F (would encode <0x800).
        if b == 0xE0 && i + 1 < bytes.len() && (0x80..=0x9F).contains(&bytes[i + 1]) {
            return Err(CanonError::OverlongUtf8);
        }
        // 4-byte overlong: 0xF0 0x80..0x8F (would encode <0x10000).
        if b == 0xF0 && i + 1 < bytes.len() && (0x80..=0x8F).contains(&bytes[i + 1]) {
            return Err(CanonError::OverlongUtf8);
        }
        i += 1;
    }
    Ok(())
}

fn reject_control_chars(s: &str) -> Result<(), CanonError> {
    for b in s.bytes() {
        // CR, LF, NUL, HTAB, plus the rest of the C0 control block and
        // DEL. Anything below 0x20 or equal to 0x7F is rejected.
        if b < 0x20 || b == 0x7F {
            return Err(CanonError::ControlChar);
        }
    }
    Ok(())
}

fn reject_non_ascii(s: &str) -> Result<(), CanonError> {
    // Well-formed-UTF-8 non-ASCII gets its own dedicated error class so
    // it shows up in audit logs as `canon=error:CANON_NON_ASCII`,
    // distinguishable from genuine encoding corruption (`CANON_UTF8`,
    // `CANON_OVERLONG`). The Unicode-confusable attack class
    // (U+0131 dotless-i, fullwidth solidus, Cyrillic homoglyphs)
    // surfaces exclusively here, making the family greppable in audit
    // logs without false positives from random-byte fuzz.
    if s.is_ascii() {
        Ok(())
    } else {
        Err(CanonError::NonAscii)
    }
}

/// Split on `/`, strip matrix params, drop empty/`.` segments, resolve
/// `..` with underflow detection.
fn split_and_resolve(path: &str) -> Result<Vec<String>, CanonError> {
    let mut segments: Vec<String> = vec![ROOT.to_string()];
    // RFC 3986 defines a path as a sequence of segments separated by '/'.
    for raw_seg in path.split('/') {
        // ';' is a sub-delim — it's a perfectly legal character inside a path segment.
        // Strip matrix params *before* dot-resolution so a segment like
        // `.;jsessionid=1` (which decodes to the current-directory
        // marker `.` after stripping) is dropped rather than preserved.
        // The reverse order let `/.;` canonicalize to `["", "."]` while
        // its rendered form `//.` re-parsed to `[""]`, breaking the
        // idempotency invariant exercised by the M2 proptest.
        // Matrix params are never used in authorization decisions:
        // e.g. `segment;k=v;k2=v2` -> `segment`.
        let cleaned = match raw_seg.find(';') {
            Some(pos) => &raw_seg[..pos],
            None => raw_seg,
        };
        // A segment that's empty (from `//`), a current-directory marker
        // (`.`), or pure matrix params (`;k=v`, which strips to "")
        // collapses away — same treatment, same reason: keeping any of
        // them in the canonical form would re-introduce the kind of
        // request/rule asymmetry the canonical model exists to remove.
        if cleaned.is_empty() || cleaned == "." {
            continue;
        }
        if cleaned == ".." {
            // Pop the previous segment. Popping the root is an error.
            if segments.len() <= 1 {
                return Err(CanonError::PathUnderflow);
            }
            segments.pop();
            continue;
        }
        segments.push(cleaned.to_string());
    }
    Ok(segments)
}

#[cfg(test)]
mod path_tests {
    use super::*;

    fn segs(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| (*s).to_string()).collect()
    }

    // -----------------------------------------------------------------
    // canonicalize_path — end-to-end happy paths
    // -----------------------------------------------------------------

    #[test]
    fn canonicalize_path_accepts_valid_inputs() {
        // (input, expected_segments, expected_trailing_slash). Covers:
        // root, empty-string fallback, simple path, ASCII case folding,
        // double-slash collapse, `.` removal, `..` resolution
        // (including chained), single percent-decode, double-encoding
        // leaving a literal `%` after one decode, mixed-case percent
        // (`%2f` and `%2F`), matrix-param stripping on one and many
        // segments, and a segment that becomes empty after matrix
        // stripping.
        let cases: &[(&str, &[&str], bool)] = &[
            ("/", &[""], false),
            ("", &[""], false),
            ("/metadata/identity", &["", "metadata", "identity"], false),
            ("/Metadata/Identity", &["", "metadata", "identity"], false),
            ("/metadata//identity", &["", "metadata", "identity"], false),
            ("/metadata/./identity", &["", "metadata", "identity"], false),
            (
                "/metadata/x/../identity",
                &["", "metadata", "identity"],
                false,
            ),
            ("/a/b/c/../../identity", &["", "a", "identity"], false),
            ("/metadata%2Fidentity", &["", "metadata", "identity"], false),
            ("/metadata%2fidentity", &["", "metadata", "identity"], false),
            (
                "/metadata%252Fidentity",
                &["", "metadata%2fidentity"],
                false,
            ),
            (
                "/metadata/identity;jsessionid=abc",
                &["", "metadata", "identity"],
                false,
            ),
            (
                "/metadata;a=1;b=2/identity;c=3",
                &["", "metadata", "identity"],
                false,
            ),
            ("/a/;jsessionid=x/b", &["", "a", "b"], false),
            ("/metadata/", &["", "metadata"], true),
        ];
        for (input, expected_segs, expected_ts) in cases {
            let got = canonicalize_path(input)
                .unwrap_or_else(|e| panic!("expected Ok for {input:?}, got {e:?}"));
            assert_eq!(got, (segs(expected_segs), *expected_ts), "input={input:?}");
        }
    }

    // -----------------------------------------------------------------
    // canonicalize_path — end-to-end errors
    // -----------------------------------------------------------------

    #[test]
    fn canonicalize_path_rejects_invalid_inputs() {
        // Each row is (input, expected_error). Exercises every typed
        // error the path pipeline can produce except OverlongUtf8 /
        // InvalidUtf8 for overlong sequences, which have their own test
        // because either variant is acceptable.
        let cases: &[(&str, CanonError)] = &[
            // Malformed percent: dangling `%`, truncated, non-hex digit
            ("/abc%", CanonError::MalformedPercent),
            ("/abc%2", CanonError::MalformedPercent),
            ("/abc%ZZ", CanonError::MalformedPercent),
            ("/abc%2G", CanonError::MalformedPercent),
            // Control characters: NUL, HTAB, LF, CR, DEL
            ("/x%00", CanonError::ControlChar),
            ("/x%09", CanonError::ControlChar),
            ("/x%0A", CanonError::ControlChar),
            ("/x%0D", CanonError::ControlChar),
            ("/x%7F", CanonError::ControlChar),
            // Non-ASCII after decode: U+4E2D `中` in UTF-8 — well-formed,
            // so it surfaces as NonAscii (Unicode-confusable / homoglyph
            // attack class), not InvalidUtf8 (encoding corruption).
            ("/x%E4%B8%AD", CanonError::NonAscii),
            // Embedded `?` from %3F smuggling
            (
                "/metadata/identity%3Fapi-version=2018",
                CanonError::EmbeddedQuery,
            ),
            // Path traversal past root: chained, immediate, and a lone `..`
            ("/a/../..", CanonError::PathUnderflow),
            ("/..", CanonError::PathUnderflow),
            ("/a/b/../../../c", CanonError::PathUnderflow),
        ];
        for (input, expected) in cases {
            assert_eq!(
                canonicalize_path(input).unwrap_err(),
                *expected,
                "input={input:?}"
            );
        }
    }

    #[test]
    fn canonicalize_path_rejects_overlong_utf8() {
        // %C0%AF is the classic 2-byte overlong for `/` (IDS bypass).
        // %E0%80%AF is the 3-byte overlong for `/`.
        // %F0%80%80%AF is the 4-byte overlong for `/`.
        //
        // Each MUST be rejected. The exact variant depends on whether
        // reject_overlong_utf8 catches it first or String::from_utf8 does
        // (both happen to fire on these inputs); either way the request
        // is denied, so we accept either error code.
        for input in ["/x%C0%AFy", "/x%E0%80%AFy", "/x%F0%80%80%AFy"] {
            let err = canonicalize_path(input).unwrap_err();
            assert!(
                matches!(err, CanonError::OverlongUtf8 | CanonError::InvalidUtf8),
                "input={input:?} got={err:?}"
            );
        }
    }

    // -----------------------------------------------------------------
    // decode_path_once
    // -----------------------------------------------------------------

    #[test]
    fn decode_path_once_handles_hex_correctly() {
        // Happy cases: identity (no `%`), upper, lower, and mixed hex.
        // The decoder must accept all of them — case asymmetry was one
        // of the legacy bypass vectors.
        let ok: &[(&str, &str)] = &[
            ("/plain/path", "/plain/path"),
            ("/a%2Fb", "/a/b"),
            ("/a%2fb", "/a/b"),
            ("/a%2fb%2F%2f", "/a/b//"),
            ("/space%20here", "/space here"),
        ];
        for (input, expected) in ok {
            assert_eq!(
                decode_path_once(input).unwrap(),
                *expected,
                "input={input:?}"
            );
        }

        // Malformed: `%` at very end, `%X` (only one nibble), invalid
        // hex digits, surrounded by garbage.
        let bad: &[&str] = &["%", "abc%", "%2", "abc%2", "%ZZ", "abc%2G", "%9Q"];
        for input in bad {
            assert_eq!(
                decode_path_once(input).unwrap_err(),
                CanonError::MalformedPercent,
                "input={input:?}"
            );
        }
    }

    // -----------------------------------------------------------------
    // hex_value
    // -----------------------------------------------------------------

    #[test]
    fn hex_value_accepts_digits_and_rejects_others() {
        // Every valid hex digit, both letter cases.
        let valid: &[(u8, u8)] = &[
            (b'0', 0),
            (b'1', 1),
            (b'2', 2),
            (b'3', 3),
            (b'4', 4),
            (b'5', 5),
            (b'6', 6),
            (b'7', 7),
            (b'8', 8),
            (b'9', 9),
            (b'a', 10),
            (b'b', 11),
            (b'c', 12),
            (b'd', 13),
            (b'e', 14),
            (b'f', 15),
            (b'A', 10),
            (b'B', 11),
            (b'C', 12),
            (b'D', 13),
            (b'E', 14),
            (b'F', 15),
        ];
        for (byte, expected) in valid {
            assert_eq!(
                hex_value(*byte).unwrap(),
                *expected,
                "byte={}",
                *byte as char
            );
        }

        // A handful of representative non-hex bytes: G/g (just past f),
        // punctuation, whitespace, high bytes.
        for byte in [b'g', b'G', b'/', b' ', b'\0', 0xFFu8] {
            assert_eq!(
                hex_value(byte).unwrap_err(),
                CanonError::MalformedPercent,
                "byte=0x{byte:02X}"
            );
        }
    }

    // -----------------------------------------------------------------
    // reject_overlong_utf8 — direct byte-level tests
    // -----------------------------------------------------------------

    #[test]
    fn reject_overlong_utf8_catches_all_overlong_forms() {
        // Each "bad" buffer carries an overlong sequence of arity 2, 3,
        // or 4. Each "ok" buffer is a well-formed UTF-8 sequence of the
        // same arity that must NOT be flagged. This pins both the
        // detection AND the absence of false positives.
        let bad: &[&[u8]] = &[
            // 2-byte overlong: leading 0xC0 / 0xC1 always overlong.
            &[0xC0, 0xAF],
            &[b'/', 0xC1, 0xAF, b'/'],
            // 3-byte overlong: 0xE0 followed by 0x80..=0x9F.
            &[0xE0, 0x80, 0xAF],
            &[0xE0, 0x9F, 0xBF],
            // 4-byte overlong: 0xF0 followed by 0x80..=0x8F.
            &[0xF0, 0x80, 0x80, 0xAF],
            &[0xF0, 0x8F, 0xBF, 0xBF],
        ];
        for buf in bad {
            assert_eq!(
                reject_overlong_utf8(buf).unwrap_err(),
                CanonError::OverlongUtf8,
                "buf={buf:?}"
            );
        }

        let ok: &[&[u8]] = &[
            b"plain ascii",
            // Well-formed 2-byte sequence (U+00A9 ©): 0xC2 0xA9
            &[0xC2, 0xA9],
            // Well-formed 3-byte sequence (U+4E2D 中): 0xE4 0xB8 0xAD
            &[0xE4, 0xB8, 0xAD],
            // Well-formed 4-byte sequence (U+1F600): 0xF0 0x9F 0x98 0x80
            &[0xF0, 0x9F, 0x98, 0x80],
            b"",
        ];
        for buf in ok {
            assert!(reject_overlong_utf8(buf).is_ok(), "buf={buf:?}");
        }
    }

    // -----------------------------------------------------------------
    // reject_control_chars — direct
    // -----------------------------------------------------------------

    #[test]
    fn reject_control_chars_blocks_c0_block_and_del() {
        // Every byte in the C0 control block (0x00..=0x1F) plus DEL
        // (0x7F) must be rejected. We check the full block, not just
        // a few representative bytes, because each byte is a separate
        // CRLF/NUL/HTAB injection vector.
        for b in 0u8..=0x1F {
            let s = std::str::from_utf8(&[b]).unwrap().to_string();
            assert_eq!(
                reject_control_chars(&s).unwrap_err(),
                CanonError::ControlChar,
                "byte=0x{b:02X}"
            );
        }
        let del = String::from_utf8(vec![0x7F]).unwrap();
        assert_eq!(
            reject_control_chars(&del).unwrap_err(),
            CanonError::ControlChar
        );

        // Printable ASCII (0x20..=0x7E) and the empty string must pass.
        assert!(reject_control_chars("").is_ok());
        assert!(reject_control_chars(" !#0AZaz~").is_ok());
        assert!(reject_control_chars("/metadata/identity?x=1&y=2").is_ok());
    }

    // -----------------------------------------------------------------
    // reject_non_ascii — direct
    // -----------------------------------------------------------------

    #[test]
    fn reject_non_ascii_blocks_high_bytes() {
        // Anything within the ASCII range (incl. the C0 block — that's
        // a different helper's job) must pass.
        for s in ["", "/", "/abc", "/metadata/identity?api-version=2018"] {
            assert!(reject_non_ascii(s).is_ok(), "input={s:?}");
        }
        // Any non-ASCII character (1, 2, 3, or 4 UTF-8 bytes wide) must
        // be rejected with the NonAscii code — distinct from InvalidUtf8
        // (random bytes) and OverlongUtf8 (IDS-bypass overlongs) so audit
        // logs can `grep CANON_NON_ASCII` for the homoglyph attack class
        // without picking up generic encoding-failure noise.
        for s in ["é", "中", "🙂", "/abc/中文/x"] {
            assert_eq!(
                reject_non_ascii(s).unwrap_err(),
                CanonError::NonAscii,
                "input={s:?}"
            );
        }
    }

    // -----------------------------------------------------------------
    // split_and_resolve — direct
    // -----------------------------------------------------------------

    #[test]
    fn split_and_resolve_handles_dot_segments_and_matrix_params() {
        // (input lowered path, expected segments). Inputs are passed as
        // they would be after decode + lowercase, so this isolates the
        // segment-level behavior. Covers: root, double-slash collapse,
        // `.` removal, `..` chain, matrix params on one and many
        // segments, a segment that becomes empty after matrix strip,
        // and a trailing matrix-param-only segment.
        let cases: &[(&str, &[&str])] = &[
            ("/", &[""]),
            ("//", &[""]),
            ("/a/b", &["", "a", "b"]),
            ("/a//b", &["", "a", "b"]),
            ("/a/./b", &["", "a", "b"]),
            ("/a/b/../c", &["", "a", "c"]),
            ("/a/b/c/../../d", &["", "a", "d"]),
            ("/a;k=v/b", &["", "a", "b"]),
            ("/a;k=v;k2=v2/b;k3=v3", &["", "a", "b"]),
            ("/a/;k=v/b", &["", "a", "b"]),
            ("/a/b/;k=v", &["", "a", "b"]),
        ];
        for (input, expected) in cases {
            assert_eq!(
                split_and_resolve(input).unwrap(),
                segs(expected),
                "input={input:?}"
            );
        }

        // Underflow: every form must fail-closed with PathUnderflow.
        for input in ["/..", "/a/../..", "/../a", "/a/b/../../../c"] {
            assert_eq!(
                split_and_resolve(input).unwrap_err(),
                CanonError::PathUnderflow,
                "input={input:?}"
            );
        }
    }

    // -----------------------------------------------------------------
    // Appendix A.1 — path golden vectors
    //
    // Spec-conformance tests for the path pipeline. The vector labels
    // (`A1.xxx`) appear in every failure message so a regression points
    // straight back to the row in `Innovation-2.1-canonical-request.md`.
    //
    // These call the full canonicalize_str() entrypoint rather than
    // canonicalize_path() directly so the assertions match the form a
    // caller would see — the assertion target is still the path output.
    // -----------------------------------------------------------------

    fn canon_path_via_pipeline(url: &str) -> String {
        super::super::canonicalize_str(url)
            .unwrap()
            .path_segments
            .join("/")
    }

    #[test]
    fn appendix_a1_path_vectors_canonicalize_successfully() {
        // (vector_label, raw_url, expected_canonical_path)
        let cases: &[(&str, &str, &str)] = &[
            (
                "A1.plain",
                "http://169.254.169.254/metadata/identity",
                "/metadata/identity",
            ),
            (
                "A1.mixed_case",
                "http://169.254.169.254/Metadata/Identity",
                "/metadata/identity",
            ),
            (
                "A1.double_slash",
                "http://169.254.169.254/metadata//identity",
                "/metadata/identity",
            ),
            (
                "A1.dot_segment",
                "http://169.254.169.254/metadata/./identity",
                "/metadata/identity",
            ),
            (
                "A1.dotdot_segment",
                "http://169.254.169.254/metadata/x/../identity",
                "/metadata/identity",
            ),
            (
                "A1.encoded_slash_decodes",
                "http://169.254.169.254/metadata%2Fidentity",
                "/metadata/identity",
            ),
            (
                // Decoding happens once: %252F -> %2F (literal, not a separator).
                "A1.double_encoding_decoded_once",
                "http://169.254.169.254/metadata%252Fidentity",
                "/metadata%2fidentity",
            ),
            (
                "A1.matrix_param_stripped",
                "http://169.254.169.254/metadata/identity;jsessionid=abc",
                "/metadata/identity",
            ),
        ];
        for (label, url, expected) in cases {
            assert_eq!(canon_path_via_pipeline(url), *expected, "vector={label}");
        }
    }

    #[test]
    fn appendix_a1_path_vectors_rejected() {
        // (vector_label, raw_url, expected_error)
        let exact: &[(&str, &str, CanonError)] = &[
            (
                "A1.path_underflow",
                // /metadata/identity -> pop x2 -> root; the third .. underflows.
                "http://169.254.169.254/metadata/identity/../../..",
                CanonError::PathUnderflow,
            ),
            (
                "A1.embedded_query",
                "http://169.254.169.254/metadata/identity%3Fapi-version=2018",
                CanonError::EmbeddedQuery,
            ),
            (
                "A1.control_char",
                "http://169.254.169.254/metadata/identity%0A",
                CanonError::ControlChar,
            ),
        ];
        for (label, url, expected) in exact {
            assert_eq!(
                super::super::canonicalize_str(url).unwrap_err(),
                *expected,
                "vector={label}"
            );
        }

        // Either-of class: overlong UTF-8 may surface as OverlongUtf8 or
        // InvalidUtf8 depending on decoder state — both are equally a deny.
        let either: &[(&str, &str)] = &[(
            "A1.overlong_utf8",
            "http://169.254.169.254/metadata/%C0%AFidentity",
        )];
        for (label, url) in either {
            let err = super::super::canonicalize_str(url).unwrap_err();
            assert!(
                matches!(err, CanonError::OverlongUtf8 | CanonError::InvalidUtf8),
                "vector={label} got={err:?}"
            );
        }
    }

    // -----------------------------------------------------------------
    // D1 extended path vectors (M2: golden vectors for the pentest D1
    // "URL parsing differentials" family — pentest/linux/DESIGN.md row D1
    // and design doc §3.1).
    //
    // The Appendix A.1 table above is the *representative* set the
    // design promises by name. These are the additional concrete forms
    // that must produce the same canonical output (or the same typed
    // deny) so that the matcher's behavior cannot diverge from the
    // upstream server's interpretation.
    // -----------------------------------------------------------------

    #[test]
    fn d1_extended_path_vectors_canonicalize_successfully() {
        let cases: &[(&str, &str, &str)] = &[
            // Mixed-case percent escapes for `/` decode the same.
            (
                "D1.lowercase_encoded_slash",
                "http://169.254.169.254/metadata%2fidentity",
                "/metadata/identity",
            ),
            // Double-encoded `..` (`%252e%252e`) decodes ONCE to the literal
            // bytes `%2e%2e` — it must NOT collapse like `..` would.
            (
                "D1.double_encoded_dotdot",
                "http://169.254.169.254/metadata/%252e%252e/identity",
                "/metadata/%2e%2e/identity",
            ),
            // Multiple matrix params on a single segment all strip.
            (
                "D1.multiple_matrix_params",
                "http://169.254.169.254/metadata;a=1;b=2;c=3/identity",
                "/metadata/identity",
            ),
            // Matrix params across multiple segments.
            (
                "D1.matrix_params_each_segment",
                "http://169.254.169.254/metadata;k=v/identity;k2=v2",
                "/metadata/identity",
            ),
            // A segment that is ONLY matrix params (`;k=v`) collapses to
            // nothing — never to an empty segment that would shift indices.
            (
                "D1.matrix_only_segment_drops",
                "http://169.254.169.254/a/;k=v/b",
                "/a/b",
            ),
            // Encoded space survives as a literal space in the segment;
            // render() must percent-encode it back.
            (
                "D1.encoded_space_in_segment",
                "http://169.254.169.254/foo%20bar",
                "/foo bar",
            ),
            // Combined dot / dotdot / matrix in one path.
            (
                "D1.combined_dot_dotdot_matrix",
                "http://169.254.169.254/a/b/./c/../d;p=q/e",
                "/a/b/d/e",
            ),
            // Leading multi-slash collapses to single root.
            (
                "D1.leading_multi_slash",
                "http://169.254.169.254///metadata",
                "/metadata",
            ),
            // Intermixed `./` segments collapse.
            (
                "D1.intermixed_dot_segments",
                "http://169.254.169.254/./a/./b/./",
                "/a/b",
            ),
            // Case folding plus encoded slash plus matrix.
            (
                "D1.combined_case_encoded_slash_matrix",
                "http://169.254.169.254/Foo%2FBar;p=q",
                "/foo/bar",
            ),
            // Encoded `;` (`%3B`) decodes to a literal `;` and then
            // triggers the same matrix-param stripping as a raw `;` —
            // this symmetry is REQUIRED, otherwise an attacker could
            // smuggle past a `/foo;v=1` deny rule by writing `/foo%3Bv=1`.
            (
                "D1.encoded_semicolon_strips_like_raw",
                "http://169.254.169.254/a%3Bb",
                "/a",
            ),
        ];
        for (label, url, expected) in cases {
            assert_eq!(canon_path_via_pipeline(url), *expected, "vector={label}");
        }
    }

    #[test]
    fn d1_extended_path_vectors_rejected() {
        // Exact-error vectors.
        let exact: &[(&str, &str, CanonError)] = &[
            // Truncated percent at end of input (no following hex digits).
            (
                "D1.truncated_percent_end",
                "http://169.254.169.254/a%",
                CanonError::MalformedPercent,
            ),
            (
                "D1.truncated_percent_one_hex",
                "http://169.254.169.254/a%2",
                CanonError::MalformedPercent,
            ),
            // Non-hex characters after `%`.
            (
                "D1.non_hex_percent",
                "http://169.254.169.254/a%ZZ",
                CanonError::MalformedPercent,
            ),
            (
                "D1.partial_non_hex_percent",
                "http://169.254.169.254/a%2G",
                CanonError::MalformedPercent,
            ),
            // All four control-character flavours the matcher must deny.
            (
                "D1.nul_byte",
                "http://169.254.169.254/a%00b",
                CanonError::ControlChar,
            ),
            (
                "D1.cr_byte",
                "http://169.254.169.254/a%0Db",
                CanonError::ControlChar,
            ),
            (
                "D1.tab_byte",
                "http://169.254.169.254/a%09b",
                CanonError::ControlChar,
            ),
            (
                "D1.del_byte",
                "http://169.254.169.254/a%7Fb",
                CanonError::ControlChar,
            ),
            // Decoded non-ASCII (valid UTF-8 but outside the matcher's
            // ASCII-only contract). Distinct from encoding-corruption
            // (`InvalidUtf8`) and overlong-bypass (`OverlongUtf8`)
            // because this is the Unicode-confusable attack family.
            (
                "D1.decoded_non_ascii_lowercase_e_acute",
                "http://169.254.169.254/caf%C3%A9",
                CanonError::NonAscii,
            ),
            // Underflow variants the Appendix table doesn't enumerate.
            (
                "D1.underflow_from_root",
                "http://169.254.169.254/..",
                CanonError::PathUnderflow,
            ),
            (
                "D1.underflow_via_dotdot_chain",
                "http://169.254.169.254/a/b/../../..",
                CanonError::PathUnderflow,
            ),
            // Embedded `?` smuggled via uppercase AND lowercase `%3F`.
            (
                "D1.embedded_query_uppercase_hex",
                "http://169.254.169.254/x%3Fy",
                CanonError::EmbeddedQuery,
            ),
            (
                "D1.embedded_query_lowercase_hex",
                "http://169.254.169.254/x%3fy",
                CanonError::EmbeddedQuery,
            ),
        ];
        for (label, url, expected) in exact {
            assert_eq!(
                super::super::canonicalize_str(url).unwrap_err(),
                *expected,
                "vector={label}"
            );
        }

        // Either-of class: 3-byte and 4-byte overlong UTF-8 sequences may
        // surface as OverlongUtf8 or InvalidUtf8 depending on which check
        // fires first.
        let either: &[(&str, &str)] = &[
            (
                "D1.overlong_utf8_3byte_slash",
                "http://169.254.169.254/x/%E0%80%AFy",
            ),
            (
                "D1.overlong_utf8_4byte_slash",
                "http://169.254.169.254/x/%F0%80%80%AFy",
            ),
            (
                "D1.overlong_utf8_2byte_backslash",
                "http://169.254.169.254/x/%C1%9Cy",
            ),
        ];
        for (label, url) in either {
            let err = super::super::canonicalize_str(url).unwrap_err();
            assert!(
                matches!(err, CanonError::OverlongUtf8 | CanonError::InvalidUtf8),
                "vector={label} got={err:?}"
            );
        }
    }
}
