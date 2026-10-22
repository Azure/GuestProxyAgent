// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

//! Query string canonicalization.
//!
//! - Split on `&`, then on the first `=` (additional `=` characters
//!   become part of the value).
//! - Single percent-decode of both key and value.
//! - ASCII-lowercase **both** key and value (case-insensitive matching).
//!   Values are folded too because the constrained query values GPA
//!   matches on — ARM resource ids (`mi_res_id`, `resource`) — are
//!   case-insensitive, and the legacy matcher lowercased values as well
//!   (`key.rs::Privilege::is_match`: `decoded_v.to_lowercase() == value`).
//!   Preserving value case here would reject valid requests that only
//!   differ in casing from the rule (shadow-mode divergence KD-2).
//!   ASCII folding leaves any non-ASCII bytes untouched, so the
//!   non-ASCII-value allowance below still holds.
//! - Reject control characters and malformed UTF-8 in both key and value.
//!   Incoming requests have one compatibility exception: trailing `\r`
//!   characters are trimmed from `client_id` values because established
//!   clients and the host endpoint treat them as line-ending contamination.
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
    canonicalize_query_impl(raw, true, false)
}

/// Canonicalize the ordinary query portion of an incoming request.
pub(super) fn canonicalize_request_query(
    raw: &str,
) -> Result<BTreeMap<String, Vec<String>>, CanonError> {
    canonicalize_query_impl(raw, true, true)
}

/// Canonicalize a query that was embedded in a path via `%3F`.
///
/// The path decoder has already percent-decoded this string once, so this
/// entrypoint performs query parsing and validation without a second decode
/// or `+`-to-space conversion, preserving literal plus signs from `%2B`.
pub(super) fn canonicalize_decoded_query(
    raw: &str,
) -> Result<BTreeMap<String, Vec<String>>, CanonError> {
    canonicalize_query_impl(raw, false, true)
}

fn canonicalize_query_impl(
    raw: &str,
    decode_percent: bool,
    allow_client_id_trailing_cr: bool,
) -> Result<BTreeMap<String, Vec<String>>, CanonError> {
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
        let k = decode_query_component(k_raw, decode_percent)?;
        reject_control_chars(&k)?;
        if k.is_empty() {
            // `?=foo` is malformed — silently drop instead of injecting a
            // ghost empty key into the map.
            continue;
        }
        let key = k.to_ascii_lowercase();
        let mut v = decode_query_component(v_raw, decode_percent)?;
        if allow_client_id_trailing_cr && key == "client_id" {
            v.truncate(v.trim_end_matches('\r').len());
        }
        reject_control_chars(&v)?;
        // ASCII-lowercase the value as well as the key: the rule side runs
        // through this same function, so folding both sides keeps the
        // `av == rv` comparison in `rule::CanonicalPattern::matches`
        // case-insensitive — matching legacy semantics for case-insensitive
        // ARM ids (KD-2).
        map.entry(key).or_default().push(v.to_ascii_lowercase());
    }
    Ok(map)
}

fn decode_query_component(raw: &str, decode_percent: bool) -> Result<String, CanonError> {
    // Raw query components treat `+` as a legacy form for space. Already-decoded
    // embedded queries must preserve `+`, which may have originated as `%2B`.
    let bytes = raw.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        match b {
            b'%' if decode_percent => {
                if i + 2 >= bytes.len() {
                    return Err(CanonError::MalformedPercent);
                }
                let h = hex_value(bytes[i + 1])?;
                let l = hex_value(bytes[i + 2])?;
                out.push((h << 4) | l);
                i += 3;
            }
            b'+' if decode_percent => {
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
    // deny rule.
    String::from_utf8(out).map_err(|_| CanonError::InvalidUtf8)
}

fn reject_control_chars(s: &str) -> Result<(), CanonError> {
    for b in s.bytes() {
        if b < 0x20 || b == 0x7F {
            return Err(CanonError::ControlChar);
        }
    }
    Ok(())
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
    fn value_ascii_lowercased() {
        // KD-2 regression: query VALUES are ASCII-lowercased (like keys) so
        // matching is case-insensitive. ARM resource ids are case-insensitive
        // and the legacy matcher lowercased values too; preserving case here
        // produced a `legacy=allow` / `canon=deny` shadow divergence.
        let q = canonicalize_query(
            "mi_res_id=/subscriptions/AB/resourceGroups/RG/providers/Microsoft.ManagedIdentity/userAssignedIdentities/My-Id",
        )
        .unwrap();
        assert_eq!(
            q.get("mi_res_id"),
            Some(&vec![
                "/subscriptions/ab/resourcegroups/rg/providers/microsoft.managedidentity/userassignedidentities/my-id"
                    .to_string()
            ])
        );
    }

    #[test]
    fn value_non_ascii_preserved_under_ascii_fold() {
        // ASCII folding must leave non-ASCII bytes untouched (the query
        // pipeline allows Unicode in values). Only the ASCII `R` folds.
        let q = canonicalize_query("resource=Rés").unwrap();
        assert_eq!(q.get("resource"), Some(&vec!["rés".to_string()]));
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
        for canonicalize in [canonicalize_query, canonicalize_request_query] {
            let q = canonicalize(concat!("k+key=a+b&literal%2B", "key=a%2Bb")).unwrap();
            assert_eq!(q.get("k key"), Some(&vec!["a b".to_string()]));
            assert_eq!(q.get("literal+key"), Some(&vec!["a+b".to_string()]));
        }
    }

    #[test]
    fn decoded_query_preserves_plus_in_keys_and_values() {
        let q = canonicalize_decoded_query("k+key=a+b").unwrap();
        assert_eq!(q.get("k+key"), Some(&vec!["a+b".to_string()]));
    }

    #[test]
    fn decoded_query_is_not_percent_decoded_twice() {
        let q = canonicalize_decoded_query("k=%26&other=value").unwrap();
        assert_eq!(q.get("k"), Some(&vec!["%26".to_string()]));
        assert_eq!(q.get("other"), Some(&vec!["value".to_string()]));
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
        // KD-3: a trailing carriage return (`%0D` -> `\r`) on a query value
        // (observed as a contaminated `client_id`) must fail closed.
        assert_eq!(
            canonicalize_query("client_id=292e4c16-1d25-4666-a60a-52d441e9ee5b%0D").unwrap_err(),
            CanonError::ControlChar
        );
    }

    #[test]
    fn request_trims_trailing_cr_from_client_id_only() {
        let q = canonicalize_request_query("client_id=292e4c16-1d25-4666-a60a-52d441e9ee5b%0D%0D")
            .unwrap();
        assert_eq!(
            q.get("client_id"),
            Some(&vec!["292e4c16-1d25-4666-a60a-52d441e9ee5b".to_string()])
        );

        assert_eq!(
            canonicalize_request_query(concat!("client_id=value%0D", "extra")).unwrap_err(),
            CanonError::ControlChar
        );
        assert_eq!(
            canonicalize_request_query("resource=value%0D").unwrap_err(),
            CanonError::ControlChar
        );
        assert_eq!(
            canonicalize_request_query("client%0Did=value").unwrap_err(),
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
