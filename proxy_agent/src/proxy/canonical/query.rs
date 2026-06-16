// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

//! Query string canonicalization.
//!
//! - Split on `&`, then on the first `=` (additional `=` characters
//!   become part of the value).
//! - Single percent-decode of both key and value.
//! - Lowercase the key (case-insensitive matching).
//! - Reject control characters and malformed UTF-8 in both key and value.
//!   Unlike the path pipeline, well-formed non-ASCII UTF-8 is **allowed**
//!   here: query *values* legitimately carry it (e.g. an IMDS
//!   `msi_res_id` / `resource` ARM id whose resource-group name contains
//!   Unicode letters, which Azure naming rules permit). The path stays
//!   ASCII-only because IMDS / WireServer / HGAP paths never contain
//!   non-ASCII and a confusable path segment could slip past a deny rule.
//! - Fold into a `BTreeMap<String, Vec<String>>`: deterministic key
//!   ordering, insertion order preserved within a key.

use std::collections::BTreeMap;

use super::CanonError;

/// Canonicalize a raw query string (the part after `?`, without it).
pub fn canonicalize_query(raw: &str) -> Result<BTreeMap<String, Vec<String>>, CanonError> {
    let mut map: BTreeMap<String, Vec<String>> = BTreeMap::new();
    if raw.is_empty() {
        return Ok(map);
    }
    for pair in raw.split('&') {
        if pair.is_empty() {
            // `?a=1&&b=2` -> skip empty pairs.
            continue;
        }
        let (k_raw, v_raw) = match pair.find('=') {
            Some(pos) => (&pair[..pos], &pair[pos + 1..]),
            None => (pair, ""),
        };
        let k = decode_query_component(k_raw)?;
        let v = decode_query_component(v_raw)?;
        if k.is_empty() {
            // `?=foo` is malformed — silently drop instead of injecting a
            // ghost empty key into the map.
            continue;
        }
        map.entry(k.to_ascii_lowercase()).or_default().push(v);
    }
    Ok(map)
}

fn decode_query_component(raw: &str) -> Result<String, CanonError> {
    // `+` in a query component is a legacy form for space (application/x-www-form-urlencoded).
    // IMDS / WireServer don't use form-encoded queries, but normalize it so a rule author
    // can't tell the difference between `?key=a+b` and `?key=a%20b`.
    let bytes = raw.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        match b {
            b'%' => {
                if i + 2 >= bytes.len() {
                    return Err(CanonError::MalformedPercent);
                }
                let h = hex_value(bytes[i + 1])?;
                let l = hex_value(bytes[i + 2])?;
                out.push((h << 4) | l);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            _ => {
                out.push(b);
                i += 1;
            }
        }
    }
    // `String::from_utf8` still rejects malformed byte sequences
    // (`InvalidUtf8`), so smuggling via broken encodings is closed. We
    // deliberately do NOT reject well-formed non-ASCII here the way the
    // path pipeline does: query values legitimately carry Unicode (e.g.
    // an ARM `msi_res_id` whose resource-group name has Unicode letters),
    // and a confusable in a query value cannot slip past a path-prefix
    // deny rule. Control characters stay forbidden in both halves.
    let s = String::from_utf8(out).map_err(|_| CanonError::InvalidUtf8)?;
    for b in s.bytes() {
        if b < 0x20 || b == 0x7F {
            return Err(CanonError::ControlChar);
        }
    }
    Ok(s)
}

fn hex_value(b: u8) -> Result<u8, CanonError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(10 + b - b'a'),
        b'A'..=b'F' => Ok(10 + b - b'A'),
        _ => Err(CanonError::MalformedPercent),
    }
}

#[cfg(test)]
mod query_tests {
    use super::*;

    #[test]
    fn empty() {
        assert!(canonicalize_query("").unwrap().is_empty());
    }

    #[test]
    fn single_pair() {
        let q = canonicalize_query("api-version=2018-02-01").unwrap();
        assert_eq!(q.get("api-version"), Some(&vec!["2018-02-01".to_string()]));
    }

    #[test]
    fn key_lowercased() {
        let q = canonicalize_query("API-Version=2018").unwrap();
        assert_eq!(q.get("api-version"), Some(&vec!["2018".to_string()]));
        assert!(!q.contains_key("API-Version"));
    }

    #[test]
    fn percent_decoded_once() {
        let q = canonicalize_query("resource=https%3A%2F%2Fmanagement.azure.com%2F").unwrap();
        assert_eq!(
            q.get("resource"),
            Some(&vec!["https://management.azure.com/".to_string()])
        );
    }

    #[test]
    fn plus_to_space() {
        let q = canonicalize_query("k=a+b").unwrap();
        assert_eq!(q.get("k"), Some(&vec!["a b".to_string()]));
    }

    #[test]
    fn repeated_key_preserves_order() {
        let q = canonicalize_query("k=1&k=2&k=3").unwrap();
        assert_eq!(
            q.get("k"),
            Some(&vec!["1".to_string(), "2".to_string(), "3".to_string()])
        );
    }

    #[test]
    fn no_value() {
        let q = canonicalize_query("foo").unwrap();
        assert_eq!(q.get("foo"), Some(&vec!["".to_string()]));
    }

    #[test]
    fn malformed_percent_rejected() {
        assert_eq!(
            canonicalize_query("k=%2").unwrap_err(),
            CanonError::MalformedPercent
        );
    }

    #[test]
    fn empty_key_dropped() {
        let q = canonicalize_query("=value&k=v").unwrap();
        assert!(!q.contains_key(""));
        assert_eq!(q.get("k"), Some(&vec!["v".to_string()]));
    }

    #[test]
    fn control_char_rejected() {
        assert_eq!(
            canonicalize_query("k=%0A").unwrap_err(),
            CanonError::ControlChar
        );
    }

    #[test]
    fn non_ascii_allowed_in_query_value_and_key() {
        // Unlike the path pipeline, well-formed non-ASCII UTF-8 is
        // accepted in the query so legitimate ARM ids (e.g. an
        // `msi_res_id` whose resource-group name has Unicode letters) are
        // not rejected. The decoded codepoints survive verbatim.
        // Value side: U+4E2D `中`.
        let q = canonicalize_query("k=%E4%B8%AD").unwrap();
        assert_eq!(q.get("k"), Some(&vec!["\u{4e2d}".to_string()]));
        // Key side: U+00E9 `é` (only A–Z is ASCII-lowercased, so the
        // non-ASCII key is preserved as-is).
        let q = canonicalize_query("caf%C3%A9=1").unwrap();
        assert_eq!(q.get("caf\u{e9}"), Some(&vec!["1".to_string()]));
        // Both halves non-ASCII.
        let q = canonicalize_query("%C3%A9=%C3%A9").unwrap();
        assert_eq!(q.get("\u{e9}"), Some(&vec!["\u{e9}".to_string()]));
    }

    #[test]
    fn malformed_utf8_still_reports_invalid_utf8() {
        // Lone continuation byte (0x80 with no lead byte) is genuine
        // encoding corruption, not a homoglyph attack. It must stay on
        // `InvalidUtf8` / `CANON_UTF8` so the two audit-log classes
        // remain separable.
        assert_eq!(
            canonicalize_query("k=%80").unwrap_err(),
            CanonError::InvalidUtf8
        );
    }
}
