// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

//! Property tests for the canonical pipeline (Innovation 2.1, M2).
//!
//! These are *invariants*, not example tables: every test draws inputs
//! from a [`proptest`] strategy and asserts a relationship that must hold
//! for **all** survivors of that strategy. They complement the hand-rolled
//! Appendix A / D1 / C7 golden vectors by exercising shapes nobody
//! enumerated.
//!
//! The three properties — taken verbatim from §10.2 of the design doc —
//! are:
//!
//! 1. **`idempotent`**: `canonicalize(canonicalize(x).render()) == canonicalize(x)`.
//!    Forms the contract that lets us cache canonicalized rules and reuse
//!    them across requests without re-deriving on every match.
//!
//! 2. **`no_panics`**: `canonicalize_str` returns `Result`, never panics,
//!    for *any* string short of those that fail `Uri::parse`. This is the
//!    M2 fuzz-target exit criterion expressed as a property so we get the
//!    same coverage with one tool (no separate cargo-fuzz crate yet —
//!    see the TODO in `mod.rs` for the binary-crate blocker).
//!
//! 3. **`host_form_equivalence`**: every numeric IPv4 spelling of the same
//!    address (dotted, decimal-u32, hex-u32, IPv4-mapped IPv6) classifies
//!    to the same [`Destination`]. This is the *positive* counterpart of
//!    the C7 host-smuggling vectors.

use super::{canonicalize, canonicalize_str, Destination};
use hyper::{Method, Uri};
use proptest::prelude::*;
use std::net::Ipv4Addr;

// ---------------------------------------------------------------------------
// Strategies
// ---------------------------------------------------------------------------

/// Characters that survive a `path_segment` round-trip without being
/// reinterpreted as a delimiter. We pick a curated subset so the strategy
/// stays focused on shapes the canonicalizer is supposed to normalize
/// (case, percent-encoding, dot resolution, matrix params) rather than
/// degenerating into a hyper-parser-rejection generator.
///
/// Intentionally includes `%` and `;` so the strategy exercises the
/// percent-decode and matrix-strip stages.
const SEG_BYTES: &str = "abcXY01-._~/%;:@&=+$,";

fn arb_segment() -> impl Strategy<Value = String> {
    // 0..16 keeps the search space tight enough to drive ~1000 cases
    // through every code path without blowing the default proptest budget.
    proptest::collection::vec(proptest::sample::select(SEG_BYTES.as_bytes()), 0..16)
        .prop_map(|bs| String::from_utf8(bs).expect("ASCII subset is always valid UTF-8"))
}

const QKV_BYTES: &str = "abcXY01-._~%+";

fn arb_qkv() -> impl Strategy<Value = String> {
    proptest::collection::vec(proptest::sample::select(QKV_BYTES.as_bytes()), 0..8)
        .prop_map(|bs| String::from_utf8(bs).expect("ASCII subset is always valid UTF-8"))
}

/// Build a syntactically reasonable URL whose authority we control (so
/// `Destination` is stable across round-trips) but whose path/query are
/// drawn from broad strategies.
fn arb_url() -> impl Strategy<Value = String> {
    let path_strat = proptest::collection::vec(arb_segment(), 0..4);
    let query_strat = proptest::collection::vec((arb_qkv(), arb_qkv()), 0..4);
    let trailing_slash = any::<bool>();

    (path_strat, query_strat, trailing_slash).prop_map(|(segs, kvs, ts)| {
        let mut url = String::from("http://169.254.169.254");
        if segs.is_empty() {
            url.push('/');
        } else {
            for s in &segs {
                url.push('/');
                url.push_str(s);
            }
        }
        if ts && !url.ends_with('/') {
            url.push('/');
        }
        if !kvs.is_empty() {
            url.push('?');
            for (i, (k, v)) in kvs.iter().enumerate() {
                if i > 0 {
                    url.push('&');
                }
                url.push_str(k);
                url.push('=');
                url.push_str(v);
            }
        }
        url
    })
}

// ---------------------------------------------------------------------------
// Properties
// ---------------------------------------------------------------------------

proptest! {
    /// Re-canonicalizing a rendered canonical request yields the same
    /// request. This is the *load-bearing* invariant: every cache, every
    /// audit-log signature, and every "rule equals request" comparison
    /// in the matcher assumes this holds.
    ///
    /// We only assert the property on inputs that canonicalize
    /// successfully on the first pass; rejected inputs are out of scope
    /// (covered by `no_panics`).
    #[test]
    fn idempotent(url in arb_url()) {
        let c1 = match canonicalize_str(&url) {
            Ok(c) => c,
            Err(_) => return Ok(()),
        };
        // render() omits the authority by design — re-attach the same
        // host we built the input from so the destination doesn't
        // change between rounds.
        let url2 = format!("http://169.254.169.254{}", c1.render());
        let c2 = canonicalize_str(&url2)
            .map_err(|e| TestCaseError::fail(format!(
                "second pass failed: input={url:?} rendered={url2:?} err={e:?}"
            )))?;
        prop_assert_eq!(
            &c1, &c2,
            "non-idempotent: input={:?} rendered={:?}", url, url2
        );
    }

    /// `canonicalize_str` is *total* on any input that survives
    /// `Uri::parse` — it returns a typed error rather than panicking.
    /// Random printable-ASCII strings give the parser plenty to choke
    /// on, and the canonicalizer plenty of weird-but-valid `Uri` shapes
    /// to chew through.
    #[test]
    fn no_panics(s in r"[\x20-\x7E]{0,80}") {
        // proptest catches panics across the FFI boundary automatically;
        // the test "passes" iff this call returns (Ok or Err) without
        // unwinding.
        let _ = canonicalize_str(&s);
    }

    /// Same target — different spelling. All four well-formed numeric
    /// forms of an IPv4 address must classify to the same Destination.
    /// This is the positive contract behind the C7 host-shape rejection
    /// vectors: the canonicalizer is allowed to *deny* exotic forms,
    /// but if it *accepts* them they must collapse onto the same
    /// classification as the dotted form.
    #[test]
    fn host_form_equivalence(raw in any::<u32>()) {
        let v4 = Ipv4Addr::from(raw);
        // Don't run the property on the dual-stack any-address; hyper
        // happens to reject the bracketed `[::ffff:0.0.0.0]` form, which
        // would unbalance the comparison. The fix isn't shape-changing,
        // so skipping is safe.
        if raw == 0 {
            return Ok(());
        }

        let dotted = format!("http://{}/x", v4);
        let decimal = format!("http://{}/x", raw);
        let hex = format!("http://0x{:x}/x", raw);
        let mapped = format!("http://[::ffff:{}]/x", v4);

        let dotted_dest = classify_or_none(&dotted);
        let decimal_dest = classify_or_none(&decimal);
        let hex_dest = classify_or_none(&hex);
        let mapped_dest = classify_or_none(&mapped);

        // Forms the canonicalizer accepts must all agree. Forms it
        // rejects are out of scope (we don't require it to accept any
        // particular alternative spelling — only that acceptance is
        // self-consistent).
        //
        // `Destination::Unknown` carries `host_text` so audit logs can
        // show the *originally requested* spelling; that field is
        // intentionally form-dependent and we strip it for the
        // equivalence comparison. Known destinations (IMDS, WireServer,
        // HostGAPlugin) have no host_text and compare directly.
        let accepted: Vec<(&str, Destination)> = [
            ("dotted", dotted_dest),
            ("decimal", decimal_dest),
            ("hex", hex_dest),
            ("mapped", mapped_dest),
        ]
        .into_iter()
        .filter_map(|(n, d)| d.map(|d| (n, normalize_for_equivalence(d))))
        .collect();

        if let Some((_, first)) = accepted.first() {
            let first = first.clone();
            for (name, d) in accepted.iter().skip(1) {
                prop_assert_eq!(
                    d, &first,
                    "host-form mismatch for {}: {} -> {:?} vs dotted -> {:?}",
                    v4, name, d, first
                );
            }
        }
    }
}

/// Helper: parse + canonicalize, returning only the destination. Used by
/// `host_form_equivalence` so a parse failure on one spelling doesn't
/// short-circuit the comparison.
fn classify_or_none(url: &str) -> Option<Destination> {
    let uri: Uri = url.parse().ok()?;
    canonicalize(&uri, &Method::GET).ok().map(|c| c.destination)
}

/// Strip `host_text` from `Destination::Unknown` so two equivalent
/// numeric spellings (e.g. `0.0.0.1` and `1`) compare equal. Known
/// destinations are returned unchanged.
fn normalize_for_equivalence(d: Destination) -> Destination {
    match d {
        Destination::Unknown {
            family,
            ip,
            port,
            host_text: _,
        } => Destination::Unknown {
            family,
            ip,
            port,
            host_text: None,
        },
        other => other,
    }
}
