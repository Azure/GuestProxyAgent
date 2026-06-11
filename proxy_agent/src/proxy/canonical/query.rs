// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

//! Query string canonicalization.
//!
//! - Split on `&`, then on the first `=` (additional `=` characters
//!   become part of the value).
//! - Single percent-decode of both key and value.
//! - Lowercase the key (case-insensitive matching).
//! - Reject control characters and non-ASCII in both key and value
//!   (same rationale as for the path).
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
    let s = String::from_utf8(out).map_err(|_| CanonError::InvalidUtf8)?;
    for b in s.bytes() {
        if b < 0x20 || b == 0x7F {
            return Err(CanonError::ControlChar);
        }
    }
    if !s.is_ascii() {
        return Err(CanonError::InvalidUtf8);
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
}
