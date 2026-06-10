// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

//! Canonical form of a rule pattern.
//!
//! Rules go through the same pipeline as requests, with two
//! differences:
//!
//! 1. There is no scheme/method on a rule (the matcher inherits those
//!    from the request).
//! 2. A rule's destination is `RuleDestination`, which adds an `Any`
//!    variant for rules that intentionally span endpoints.
//!
//! Matching is then a pure structural comparison:
//!
//! - `Destination` must equal the rule's destination (or the rule is
//!   `Any`).
//! - The rule's path is a **prefix** of the request's canonical path,
//!   compared segment-by-segment (not character-by-character — this is
//!   what prevents `starts_with("/metadata")` from matching
//!   `/metadata-attacker`).
//! - For each query key constrained by the rule, the request must
//!   have at least one matching value (case-insensitive after the
//!   canonical pipeline already lowercased both sides).

use std::collections::BTreeMap;

use crate::key_keeper::key::Privilege;

use super::destination::Destination;
use super::path::canonicalize_path;
use super::query::canonicalize_query;
use super::{CanonError, CanonicalRequest};

/// Destination constraint on a rule.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum RuleDestination {
    /// Rule applies to a single classified destination.
    Only(Destination),
    /// Rule applies regardless of destination (used for the per-endpoint
    /// rule files where the file itself already partitions the rules).
    Any,
}

/// Canonical form of an authorization rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalPattern {
    pub destination: RuleDestination,
    /// Segments to prefix-match against [`CanonicalRequest::path_segments`].
    /// Always starts with the root marker (empty string).
    pub path_prefix: Vec<String>,
    /// Required query parameters. Empty map means "no query constraint".
    /// All present keys must match at least one of the supplied values.
    pub required_query: BTreeMap<String, Vec<String>>,
}

impl CanonicalPattern {
    /// Build from a raw `Privilege` (the on-disk rule format).
    ///
    /// The privilege's path is run through the canonical path pipeline,
    /// and its query parameters are run through the canonical query
    /// pipeline. Rules that fail canonicalization are **rejected** by
    /// the loader — fail-closed.
    pub fn from_privilege(p: &Privilege) -> Result<Self, CanonError> {
        let (segments, _trailing) = canonicalize_path(&p.path)?;
        let required_query = match &p.queryParameters {
            None => BTreeMap::new(),
            Some(qp) => {
                let mut joined = String::new();
                for (k, v) in qp.iter() {
                    if !joined.is_empty() {
                        joined.push('&');
                    }
                    joined.push_str(k);
                    joined.push('=');
                    joined.push_str(v);
                }
                canonicalize_query(&joined)?
            }
        };
        Ok(CanonicalPattern {
            destination: RuleDestination::Any,
            path_prefix: segments,
            required_query,
        })
    }

    /// Structural match against a canonical request.
    pub fn matches(&self, req: &CanonicalRequest) -> bool {
        // Destination
        if let RuleDestination::Only(d) = &self.destination {
            if d != &req.destination {
                return false;
            }
        }

        // Path: segment-by-segment prefix match.
        if req.path_segments.len() < self.path_prefix.len() {
            return false;
        }
        for (i, seg) in self.path_prefix.iter().enumerate() {
            if &req.path_segments[i] != seg {
                return false;
            }
        }

        // Query: every required key must be present and at least one
        // of its required values must appear among the request's values
        // for that key.
        for (k, required_values) in &self.required_query {
            let actual = match req.query.get(k) {
                Some(v) => v,
                None => return false,
            };
            let any_match = required_values
                .iter()
                .any(|rv| actual.iter().any(|av| av == rv));
            if !any_match {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod rule_tests {
    use std::collections::HashMap;

    use hyper::{Method, Uri};

    use super::*;
    use crate::proxy::canonical::canonicalize;

    // ---------- helpers ----------

    fn priv_of(path: &str, qp: Option<&[(&str, &str)]>) -> Privilege {
        Privilege {
            name: "test".to_string(),
            path: path.to_string(),
            queryParameters: qp.map(|pairs| {
                pairs
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect::<HashMap<_, _>>()
            }),
        }
    }

    fn req_of(uri: &str, method: &Method) -> CanonicalRequest {
        let u: Uri = uri.parse().unwrap();
        canonicalize(&u, method).unwrap()
    }

    fn segs(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    fn pat(
        destination: RuleDestination,
        prefix: &[&str],
        query: &[(&str, &[&str])],
    ) -> CanonicalPattern {
        let mut required = BTreeMap::new();
        for (k, vs) in query {
            required.insert(
                (*k).to_string(),
                vs.iter().map(|v| (*v).to_string()).collect(),
            );
        }
        CanonicalPattern {
            destination,
            path_prefix: segs(prefix),
            required_query: required,
        }
    }

    // ---------- from_privilege ----------

    #[test]
    fn from_privilege_canonicalizes_and_normalizes() {
        // (raw_path, raw_query_pairs) -> (expected_path_prefix, expected_required_query as sorted pairs)
        let cases: &[(&str, Option<&[(&str, &str)]>, &[&str], &[(&str, &[&str])])] = &[
            // case folding + leading-slash root marker preserved.
            ("/Metadata", None, &["", "metadata"], &[]),
            // dot-segments collapse on the rule side too.
            ("/a/./b/../c", None, &["", "a", "c"], &[]),
            // trailing slash on rule is dropped from segments (same as request side).
            (
                "/metadata/identity/",
                None,
                &["", "metadata", "identity"],
                &[],
            ),
            // None vs Some(empty) both yield an empty required_query.
            ("/x", None, &["", "x"], &[]),
            ("/x", Some(&[]), &["", "x"], &[]),
            // single query param canonicalized (key case-folded).
            (
                "/m",
                Some(&[("Api-Version", "2018-02-01")]),
                &["", "m"],
                &[("api-version", &["2018-02-01"])],
            ),
            // value with encoded specials kept literal (not re-split on '=').
            (
                "/m",
                Some(&[("k", "a%3Db")]),
                &["", "m"],
                &[("k", &["a=b"])],
            ),
            // root-only rule.
            ("/", None, &[""], &[]),
        ];

        for (path, qp, expect_segs, expect_q) in cases {
            let p = CanonicalPattern::from_privilege(&priv_of(path, *qp)).unwrap();
            assert_eq!(
                p.destination,
                RuleDestination::Any,
                "from_privilege must default to Any (input path={path:?})"
            );
            assert_eq!(p.path_prefix, segs(expect_segs), "path={path:?}");
            let actual: Vec<(String, Vec<String>)> = p.required_query.into_iter().collect();
            let expected: Vec<(String, Vec<String>)> = expect_q
                .iter()
                .map(|(k, vs)| {
                    (
                        (*k).to_string(),
                        vs.iter().map(|v| (*v).to_string()).collect(),
                    )
                })
                .collect();
            assert_eq!(actual, expected, "path={path:?}");
        }
    }

    #[test]
    fn from_privilege_rejects_invalid_inputs() {
        // Garbage propagates from the canonical pipeline as a CanonError;
        // the loader is expected to drop the rule rather than admit it.
        let bad: &[(&str, Option<&[(&str, &str)]>)] = &[
            // Malformed percent in rule path.
            ("/bad%ZZ", None),
            // Control byte in rule path.
            ("/bad\x01path", None),
            // Non-ASCII in rule path.
            ("/café", None),
            // Malformed percent in rule query value.
            ("/x", Some(&[("k", "%ZZ")])),
            // Control byte in rule query key.
            ("/x", Some(&[("k\x01", "v")])),
            // Non-ASCII in rule query value.
            ("/x", Some(&[("k", "café")])),
        ];
        for (path, qp) in bad {
            let r = CanonicalPattern::from_privilege(&priv_of(path, *qp));
            assert!(
                r.is_err(),
                "expected canonical rejection for path={path:?} qp={qp:?}"
            );
        }
    }

    // ---------- destination matching ----------

    #[test]
    fn matches_destination_constraint() {
        // Any always matches; Only matches only its own classified destination.
        let any = pat(RuleDestination::Any, &[""], &[]);
        let only_imds = pat(RuleDestination::Only(Destination::Imds), &[""], &[]);
        let only_ws = pat(RuleDestination::Only(Destination::WireServer), &[""], &[]);

        let imds_req = req_of("http://169.254.169.254/x", &Method::GET);
        let ws_req = req_of("http://168.63.129.16/x", &Method::GET);
        let unk_req = req_of("http://10.0.0.1/x", &Method::GET);

        let cases: &[(&CanonicalPattern, &CanonicalRequest, bool, &str)] = &[
            (&any, &imds_req, true, "Any+Imds"),
            (&any, &ws_req, true, "Any+WireServer"),
            (&any, &unk_req, true, "Any+Unknown"),
            (&only_imds, &imds_req, true, "Only(Imds)+Imds"),
            (&only_imds, &ws_req, false, "Only(Imds)+WireServer rejects"),
            (&only_imds, &unk_req, false, "Only(Imds)+Unknown rejects"),
            (&only_ws, &ws_req, true, "Only(WS)+WireServer"),
            (&only_ws, &imds_req, false, "Only(WS)+Imds rejects"),
        ];
        for (rule, req, expected, label) in cases {
            assert_eq!(rule.matches(req), *expected, "{label}");
        }
    }

    // ---------- path matching ----------

    #[test]
    fn matches_path_prefix_semantics() {
        // (rule_path, request_uri, expected, label)
        // Method is intentionally varied to confirm it is NOT part of rule matching.
        let cases: &[(&str, &str, &Method, bool, &str)] = &[
            // Segment-boundary safety: /metadata must not match /metadata-attacker.
            (
                "/metadata",
                "http://169.254.169.254/metadata/identity",
                &Method::GET,
                true,
                "rule shorter than request matches at boundary",
            ),
            (
                "/metadata",
                "http://169.254.169.254/metadata-attacker/identity",
                &Method::GET,
                false,
                "rule must not bleed across segment boundary",
            ),
            // Exact match.
            (
                "/metadata/identity",
                "http://169.254.169.254/metadata/identity",
                &Method::POST,
                true,
                "exact path equality (method irrelevant)",
            ),
            // Request strictly shorter than rule prefix -> reject.
            (
                "/metadata/identity/oauth2/token",
                "http://169.254.169.254/metadata/identity",
                &Method::GET,
                false,
                "request shorter than rule rejects",
            ),
            // Mid-segment differ (not just at the end).
            (
                "/a/b/c",
                "http://169.254.169.254/a/X/c",
                &Method::GET,
                false,
                "differing mid segment rejects",
            ),
            // Case-insensitive (both rule and request lowercased by pipeline).
            (
                "/Metadata",
                "http://169.254.169.254/METADATA/Identity",
                &Method::GET,
                true,
                "case-insensitive path match",
            ),
            // Percent-encoded slash decoded once -> rule that includes the slash matches.
            (
                "/metadata/identity",
                "http://169.254.169.254/metadata%2Fidentity/oauth2/token",
                &Method::GET,
                true,
                "encoded slash in request decodes to rule path",
            ),
            // Root-only rule matches any request path.
            (
                "/",
                "http://169.254.169.254/anything/at/all",
                &Method::GET,
                true,
                "root-only rule is universal on path",
            ),
            (
                "/",
                "http://169.254.169.254/",
                &Method::GET,
                true,
                "root-only rule on root request",
            ),
        ];
        for (rule_path, uri, method, expected, label) in cases {
            let p = CanonicalPattern::from_privilege(&priv_of(rule_path, None)).unwrap();
            let r = req_of(uri, method);
            assert_eq!(p.matches(&r), *expected, "{label}");
        }
    }

    // ---------- query matching ----------

    #[test]
    fn matches_query_constraint_semantics() {
        // Across keys: AND. Within a key: OR over the rule's allowed values.
        // Build patterns directly so we can exercise multiple values per key
        // (the on-disk Privilege format only supports a single value per key).
        let multi_value = pat(RuleDestination::Any, &["", "m"], &[("v", &["a", "b"])]);
        let multi_key = pat(
            RuleDestination::Any,
            &["", "m"],
            &[("a", &["1"]), ("b", &["2"])],
        );
        let no_query = pat(RuleDestination::Any, &["", "m"], &[]);

        let cases: &[(&CanonicalPattern, &str, bool, &str)] = &[
            // No required_query -> any query (including none) matches.
            (
                &no_query,
                "http://169.254.169.254/m",
                true,
                "no constraint + no query",
            ),
            (
                &no_query,
                "http://169.254.169.254/m?anything=here",
                true,
                "no constraint + extra query",
            ),
            // OR within a key.
            (
                &multi_value,
                "http://169.254.169.254/m?v=a",
                true,
                "OR within key, first value",
            ),
            (
                &multi_value,
                "http://169.254.169.254/m?v=b",
                true,
                "OR within key, second value",
            ),
            (
                &multi_value,
                "http://169.254.169.254/m?v=c",
                false,
                "value outside allowed set rejects",
            ),
            (
                &multi_value,
                "http://169.254.169.254/m",
                false,
                "missing required key rejects",
            ),
            // Request supplies the same key twice; rule accepts if ANY request value matches.
            (
                &multi_value,
                "http://169.254.169.254/m?v=c&v=b",
                true,
                "request-side repeat: any value matches rule",
            ),
            // Extra request keys are allowed (rule is a minimum requirement, not an exact match).
            (
                &multi_value,
                "http://169.254.169.254/m?v=a&extra=zzz",
                true,
                "extra request keys allowed",
            ),
            // AND across keys.
            (
                &multi_key,
                "http://169.254.169.254/m?a=1&b=2",
                true,
                "AND across keys satisfied",
            ),
            (
                &multi_key,
                "http://169.254.169.254/m?a=1",
                false,
                "AND across keys: missing second key rejects",
            ),
            (
                &multi_key,
                "http://169.254.169.254/m?a=1&b=9",
                false,
                "AND across keys: wrong value on one key rejects",
            ),
            // Case folding on keys (Api-Version vs api-version) via canonical pipeline.
            (
                &CanonicalPattern::from_privilege(&priv_of(
                    "/metadata/identity",
                    Some(&[("Api-Version", "2018-02-01")]),
                ))
                .unwrap(),
                "http://169.254.169.254/metadata/identity?API-VERSION=2018-02-01",
                true,
                "case-insensitive key fold both sides",
            ),
            // Encoded value on the request side decodes once to match the rule.
            (
                &CanonicalPattern::from_privilege(&priv_of("/m", Some(&[("k", "a b")]))).unwrap(),
                "http://169.254.169.254/m?k=a%20b",
                true,
                "request value decoded once matches rule value",
            ),
        ];
        for (rule, uri, expected, label) in cases {
            let r = req_of(uri, &Method::GET);
            assert_eq!(rule.matches(&r), *expected, "{label}");
        }
    }
}
