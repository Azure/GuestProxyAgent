## Sections

1.  [1. Overview & Goals](#overview)
2.  [2. Today's Behavior](#today)
3.  [3. Threats & Bypass Patterns](#threats)
4.  [4. CanonicalRequest Model](#model)
5.  [5. Normalization Pipeline](#pipeline)
6.  [6. Public API & Rust Sketch](#api)
7.  [7. Error Taxonomy & Fail-Closed](#errors)
8.  [8. Integration Points](#integration)
9.  [9. Shadow-Mode Rollout](#shadow)
10. [10. Test Strategy](#tests)
11. [11. Performance Budget](#perf)
12. [12. Telemetry & Observability](#telemetry)
13. [13. Risks & Open Questions](#risks)
14. [14. Milestones](#milestones)
15. [Appendix A — Vector Table](#appendix)

**GPA** · **Direction 2.1** · **Security-critical refactor**

# Detailed Design — Canonical Request Model

A single, total, well-tested normalization step shared by rule loading and request matching, designed to eliminate the rule/request asymmetry that produces SSRF-style AuthZ bypasses.

**Primary files affected:** `proxy_agent/src/proxy/authorization_rules.rs`, `proxy_agent/src/key_keeper/key.rs`, new module `proxy_agent/src/proxy/canonical/`.

> **Prerequisites:** None — foundational request-normalization layer. Required by [1.4](Innovation-1.4-capability-scopes.md), [2.2](Innovation-2.2-typed-policy-cedar.md), [2.4](Innovation-2.4-differential-testing.md), [5.2](Innovation-5.2-gate-more-endpoints.md), [5.3](Innovation-5.3-cross-cloud-port.md), [6.1](Innovation-6.1-policy-simulator.md).

## 1. Overview & Goals

| Impact                        | Effort                  | Risk                        | Scope          |
|-------------------------------|-------------------------|-----------------------------|----------------|
| **High** closes a vuln family | **Medium** ~2–3 sprints | **Low** shadow-mode rollout | **agent only** |

### 1.1 Problem statement

Today the rule-matching pipeline performs ad-hoc, partial normalization in *two different places* — once when rules are loaded and once when requests are matched. The two normalizations are not byte-identical, which creates a class of bypass where the attacker crafts a URL that the agent considers different from the rule pattern but that the upstream metadata service treats as semantically equivalent.

### 1.2 Goals

- **One normalizer, one type.** Both rules and requests are reduced to a single canonical form (`CanonicalRequest`) before they ever meet the matcher.
- **Total function with explicit failure.** The normalizer either returns a fully-canonical value or a typed error; the matcher never sees ambiguous input.
- **Fail-closed semantics.** Any normalization error denies the request and logs a structured event.
- **Byte-stable output.** Round-tripping a canonical form through the normalizer yields the same bytes (idempotent). This is the property property-tests will enforce.
- **Zero behavior change at cutover.** Shadow-mode dual-evaluation must show 0 divergences for N days before flipping enforcement.

### 1.3 Non-goals

- Replacing the policy language itself (that is Direction 2.2 — Cedar).
- Identity normalization for users/processes (Direction 1.3 — measured identity).
- Changing the on-wire request format sent upstream. We canonicalize for *matching*; the request forwarded to IMDS / WireServer is the original.

## 2. Today's Behavior (and why it's fragile)

### 2.1 Normalization in `authorization_rules.rs`

At rule load time (`ComputedAuthorizationItem::from_authorization_item`), each privilege's path and query parameters are lowercased:

    let normalized = Privilege {
        name: privilege.name,
        path: privilege.path.to_lowercase(),
        queryParameters: privilege.queryParameters.map(|qp| {
            qp.into_iter()
              .map(|(k, v)| (k.to_lowercase(), v.to_lowercase()))
              .collect()
        }),
    };

At request time (`ComputedAuthorizationItem::is_allowed`), the request URL is percent-decoded once then lowercased:

    let decoded_path = percent_encoding::percent_decode_str(request_url.path())
        .decode_utf8_lossy();
    let lowered_request_path = decoded_path.to_lowercase();

The actual match (`Privilege::is_match` in `key.rs`) does:

- `actual_path.starts_with(&self.path)`
- splits on `?` in the *decoded* path to harvest extra query pairs (handles `%3F` trick)
- compares query parameters case-insensitively with one more percent-decode on the key

### 2.2 The asymmetries

| Step                                | Rule side                | Request side                          | Risk                                                                                                                                    |
|-------------------------------------|--------------------------|---------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------|
| Percent decoding                    | Not applied to rule path | Applied once to request path          | A rule containing `%2F` by accident becomes unreachable; a request can introduce decoded characters the rule author did not anticipate. |
| Path segment collapsing (`..`, `.`) | None                     | None                                  | `/metadata/identity/../identity/oauth2/token` bypasses a deny on `/metadata/identity/oauth2`.                                           |
| Trailing slash                      | Author-controlled        | Author-controlled                     | Prefix `starts_with` means rule `/metadata` matches `/metadata-attacker`.                                                               |
| Matrix params `;foo=bar`            | Not handled              | Not handled                           | Some HTTP stacks strip them, some don't.                                                                                                |
| Host normalization                  | N/A (no host in rule)    | N/A                                   | Pentest C7: `0xa9fea9fe`, `2852039166`, `[::ffff:169.254.169.254]` reach the same IMDS.                                                 |
| UTF-8 validity                      | Assumed                  | `decode_utf8_lossy` silently replaces | Lossy substitution may yield matches the rule author didn't intend.                                                                     |
| Query key/value decoding            | Lowercased only          | Decoded again at match time           | Double-encoding (`%2525`) yields different views.                                                                                       |

## 3. Threats & Bypass Patterns

The canonical model targets, at minimum, every pattern in pentest scenarios `D1` and `C7`.

### 3.1 URL-encoding differentials (pentest D1)

- `%2F` vs `/`, mixed case `%2f`.
- Double-encoding: `%252e%252e`.
- Overlong UTF-8 for `/`.
- Semicolon matrix params on path segments.
- Trailing dot or whitespace in path.
- Embedded `?` via `%3F` that re-introduces query parameters into the path string.

### 3.2 Host-form differentials (pentest C7)

- IPv4 dotted: `169.254.169.254`
- IPv4 decimal: `2852039166`
- IPv4 hex: `0xa9fea9fe`
- IPv4 octal: `0251.0376.0251.0376`
- IPv4-mapped IPv6: `[::ffff:169.254.169.254]`, `[::ffff:a9fe:a9fe]`
- Uppercased hostnames, trailing dots: `METADATA.azure.internal.`
- Userinfo smuggling: `http://attacker@169.254.169.254/`
- Port-form smuggling: `http://169.254.169.254:80@evil/`

### 3.3 Header / line smuggling (out of scope, but related)

Request smuggling at the HTTP framing layer is handled separately by Hyper config + pentest A3/A4. The canonical model assumes Hyper produced a well-formed `hyper::Uri`.

## 4. The CanonicalRequest Model

### 4.1 Type

    // proxy_agent/src/proxy/canonical/mod.rs
    #[derive(Clone, Debug, PartialEq, Eq, Hash)]
    pub struct CanonicalRequest {
        /// HTTP method, uppercased ASCII (GET, POST, ...).
        pub method: Method,

        /// Canonical destination (already classified as one of GPA's known endpoints).
        pub destination: Destination,

        /// Canonical path segments: percent-decoded, NFC-normalized, lowercased,
        /// with `.` collapsed, `..` resolved against earlier segments, matrix params stripped.
        /// Always begins with the empty root segment; never contains empty segments
        /// except the final one when the original ended with `/`.
        pub path_segments: Vec<String>,

        /// Whether the original path had a trailing slash (preserved as a single bit so
        /// rules can opt to be slash-sensitive without re-introducing string-level asymmetry).
        pub trailing_slash: bool,

        /// Query parameters in a canonical multi-map form: keys lowercased + decoded once,
        /// values decoded once, preserved order is not significant (BTreeMap of Vec).
        pub query: BTreeMap<String, Vec<String>>,
    }

    #[derive(Clone, Debug, PartialEq, Eq, Hash)]
    pub enum Destination {
        Imds,         // 169.254.169.254 in any encoding, port 80
        WireServer,   // 168.63.129.16:80
        HostGaPlugin, // 168.63.129.16:32526
        Unknown {     // anything else; matcher will deny unless an explicit rule allows
            family: AddrFamily,
            ip: IpAddr,
            port: u16,
            host_text: Option<String>, // original host text for audit, never used for matching
        },
    }

### 4.2 Invariants (checked by debug asserts and property tests)

- **Idempotent:** `canonicalize(canonicalize(x)) == canonicalize(x)`.
- **Total:** for every `hyper::Uri`, the function returns either `Ok(CanonicalRequest)` or a typed `CanonError`; it never panics.
- **Round-trip-stable rendering:** a debug `Display` impl produces a string that, when re-parsed and canonicalized, yields the same value.
- **UTF-8 strict:** invalid UTF-8 in path or query is an error, not a lossy replacement.
- **No host text in matching:** the matcher only sees the typed `Destination` enum, never the raw host string.

## 5. The Normalization Pipeline

Each step is a small pure function with its own unit tests.

hyper::Uri │ ▼ parse_scheme_method (must be http; reject https/ws/...; method allow-list) │ ▼ classify_destination (IP/host -\> Destination enum; covers numeric forms) │ ▼ validate_userinfo (must be empty; reject \`user@host\`) │ ▼ decode_path_once (single percent-decode; reject malformed %XY; reject overlong UTF-8) │ ▼ reject_control_chars (no CR/LF/NUL/HTAB after decode) │ ▼ nfc_normalize (Unicode NFC) │ ▼ ascii_lowercase_path (path is matched case-insensitively) │ ▼ split_segments (split on '/'; collapse \`.\`; resolve \`..\`; error on underflow) │ ▼ strip_matrix_params (drop \`;k=v\` suffix on each segment, preserve segment text only) │ ▼ decode_query_once (k/v percent-decode once; error on malformed; lowercase keys) │ ▼ reject_embedded_query (if decoded path now contains '?' -\> error: ambiguous) │ ▼ fold_into_btreemap (group by key; values preserve insertion order within a key) │ ▼ CanonicalRequest

### 5.1 Step details

#### 5.1.1 `classify_destination`

- If host is a bracketed IPv6, parse with `std::net::Ipv6Addr`; if it is IPv4-mapped, project to IPv4 and continue.
- If host parses as `Ipv4Addr` directly, use it.
- Else attempt the historic numeric forms manually: dotted-quad with any base per octet (octal-leading-zero, hex-leading-`0x`, plain decimal), and 32-bit packed forms. A small dedicated parser, not `inet_aton`, because `inet_aton` behavior is libc-dependent.
- Map the resolved IP+port to `Destination` via a constant table; unknown destinations land in `Destination::Unknown`.
- Hostnames that are not IPs (e.g. `metadata.azure.internal`) are *not* resolved at this layer — DNS is a confused-deputy surface. They are returned as `Unknown { host_text: Some(...) }` and require an explicit allow rule keyed on host text.

#### 5.1.2 `decode_path_once`

- One pass of percent decoding. A second pass is never attempted — that is exactly the asymmetry we want to remove.
- Malformed sequences (`%2`, `%ZZ`) → `CanonError::MalformedPercent`.
- Detect overlong UTF-8 encodings of ASCII (e.g. `%C0%AF` for `/`) → `CanonError::OverlongUtf8`.

#### 5.1.3 `split_segments` + dot-segment resolution (RFC 3986 §5.2.4)

- Empty segments collapsed (treat `//` as `/`).
- `.` dropped.
- `..` pops the previous segment; popping past root is an error (`CanonError::PathUnderflow`) rather than a no-op, because a real client would never produce it.

#### 5.1.4 `strip_matrix_params`

- For each segment, drop everything after the first `;`.
- Document this clearly: matrix params are **never** used in authorization decisions.

#### 5.1.5 `reject_embedded_query`

- If the decoded-and-rebuilt path contains a literal `?`, the request is ambiguous: an attacker may have used `%3F` to smuggle query into the path. Today's matcher tries to rescue this; the new model rejects it as an error and logs.

## 6. Public API & Rust Sketch

### 6.1 Module layout

    proxy_agent/src/proxy/canonical/
    ├── mod.rs            // CanonicalRequest, Destination, CanonError, canonicalize()
    ├── destination.rs    // IP/host classification + numeric-form parser
    ├── path.rs           // decode + dot-segment + matrix-strip
    ├── query.rs          // decode + fold into BTreeMap
    ├── rule.rs           // canonicalize a rule pattern into CanonicalPattern
    └── tests/
        ├── vectors.rs    // 300+ golden vectors from pentest D1 / C7
        ├── proptests.rs  // proptest invariants
        └── differential.rs // dual-evaluate against legacy matcher in shadow mode

### 6.2 Public surface

    pub fn canonicalize(uri: &hyper::Uri, method: &hyper::Method)
        -> Result<CanonicalRequest, CanonError>;

    /// Canonical form of a rule pattern. Same pipeline, but path segments may end
    /// in a "*" sentinel to mark prefix match, and `Destination` may be `Any` for
    /// rules that intentionally span endpoints.
    pub struct CanonicalPattern { /* ... */ }

    pub fn canonicalize_pattern(raw: &RawPrivilege) -> Result<CanonicalPattern, CanonError>;

    /// Matching is now a pure structural comparison on canonical forms.
    impl CanonicalPattern {
        pub fn matches(&self, req: &CanonicalRequest) -> bool;
    }

### 6.3 Error type

    #[derive(Debug, thiserror::Error)]
    pub enum CanonError {
        #[error("scheme not http")]                SchemeNotHttp,
        #[error("method not allowed")]             MethodNotAllowed,
        #[error("userinfo present in URL")]        UserinfoPresent,
        #[error("malformed percent-encoding")]     MalformedPercent,
        #[error("overlong UTF-8 in path/query")]   OverlongUtf8,
        #[error("invalid UTF-8 in path/query")]    InvalidUtf8,
        #[error("control character in path/query")]ControlChar,
        #[error("path traversal past root")]       PathUnderflow,
        #[error("embedded '?' after decoding")]    EmbeddedQuery,
        #[error("unparseable host")]               BadHost,
        #[error("unparseable port")]               BadPort,
    }

    impl CanonError {
        /// All variants are fail-closed; this is here so callers can record a
        /// stable string for telemetry / pentest assertions.
        pub fn code(&self) -> &'static str { /* ... */ }
    }

### 6.4 Matcher call site (after the change)

    // Replaces ComputedAuthorizationItem::is_allowed's URL handling.
    let canon = match canonical::canonicalize(&request.uri(), request.method()) {
        Ok(c) => c,
        Err(e) => {
            logger.write(LoggerLevel::Warn,
                format!("Canonicalization failed: {} ({})", e, e.code()));
            return false; // fail-closed
        }
    };
    for pattern in self.compiled_patterns.iter() {
        if pattern.matches(&canon) { /* identity check ... */ }
    }

## 7. Error Taxonomy & Fail-Closed Semantics

| Error              | Likely cause                          | Action    | Audit event code  |
|--------------------|---------------------------------------|-----------|-------------------|
| `SchemeNotHttp`    | WS upgrade probe (pentest A4)         | Deny; 405 | `CANON_SCHEME`    |
| `MethodNotAllowed` | CONNECT / TRACE                       | Deny; 405 | `CANON_METHOD`    |
| `UserinfoPresent`  | Host smuggling attempt                | Deny; 400 | `CANON_USERINFO`  |
| `MalformedPercent` | Truncated / non-hex `%XX`             | Deny; 400 | `CANON_PCT`       |
| `OverlongUtf8`     | Classic IDS-bypass payload            | Deny; 400 | `CANON_OVERLONG`  |
| `InvalidUtf8`      | Random bytes or wrong codec           | Deny; 400 | `CANON_UTF8`      |
| `NonAscii`         | Unicode confusable / homoglyph attack in **path** (query allows non-ASCII values) | Deny; 400 | `CANON_NON_ASCII` |
| `ControlChar`      | CRLF injection attempt                | Deny; 400 | `CANON_CTRL`      |
| `PathUnderflow`    | Too many `..`                         | Deny; 400 | `CANON_UNDERFLOW` |
| `EmbeddedQuery`    | `%3F` smuggling                       | Deny; 400 | `CANON_EMBQ`      |
| `BadHost`          | Mixed numeric forms that fail parsing | Deny; 400 | `CANON_HOST`      |
| `BadPort`          | Out-of-range port                     | Deny; 400 | `CANON_PORT`      |

**Fail-closed rule:** every `CanonError` path returns `false` from the matcher and emits a structured audit entry that includes the error code, the original (redacted) URL, the caller cgroup id, and the active `policy_epoch`. There is no "best effort" branch.

## 8. Integration Points

| File                                           | Today                                                                                                               | After change                                                                                                             |
|------------------------------------------------|---------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------|
| `proxy_agent/src/proxy/authorization_rules.rs` | Lowercases privilege path/query during `from_authorization_item`; percent-decodes request path during `is_allowed`. | Calls `canonical::canonicalize_pattern` at load time, `canonical::canonicalize` at request time; *no* ad-hoc string ops. |
| `proxy_agent/src/key_keeper/key.rs`            | `Privilege::is_match` does `starts_with` + embedded-query rescue + per-key percent-decode.                          | Method removed (or wraps `CanonicalPattern::matches` for back-compat callers).                                           |
| `proxy_agent/src/proxy/proxy_authorizer.rs`    | Calls `is_allowed(uri, claims)`.                                                                                    | Calls `canonicalize` once, then `is_allowed(canon, claims)`; logs `CanonError` on failure.                               |
| `proxy_agent/src/proxy/proxy_server.rs`        | Hands raw `Uri` down.                                                                                               | Unchanged; canonical form is computed once inside the authorizer and cached on the connection context.                   |
| `proxy_agent/src/key_keeper/local_rules.rs`    | Lowercases rule fields during merge.                                                                                | Calls `canonicalize_pattern`; rejects rules that fail canonicalization (fail-closed).                                    |

## 9. Shadow-Mode Rollout

The canonicalizer ships before the matcher cuts over.

### 9.1 Mode flag

    // In GuestProxyAgent.linux.json / .windows.json
    "canonicalRequest": {
        "mode": "shadow"   // "off" | "shadow" | "enforce"
    }

- **off** — legacy path only (default in first release).
- **shadow** — legacy decides; canonical runs in parallel; divergences logged.
- **enforce** — canonical decides; legacy still computes for divergence telemetry.

### 9.2 Divergence record

    {
      "ts": "2026-06-01T12:34:56Z",
      "policy_epoch": 174,
      "request_uri_redacted": "/metadata/identity/oauth2/token?api-version=2018-02-01",
      "legacy_decision": "allow",
      "canon_decision":  "deny",
      "canon_error":     null,
      "matched_rule_id": "imds.identity.read",
      "caller_cgroup":   "/sys/fs/cgroup/system.slice/walinuxagent.service",
      "delta_reason":    "trailing_slash_difference"
    }

### 9.3 Cutover criteria

- ≥ 14 consecutive days with zero divergences across the production fleet sample.
- All pentest D1 and C7 vectors PASS in enforcement mode in the CI canary.
- p99 added latency \< 100 µs (measured during shadow mode).
- One full release in **shadow** behind a feature flag before any region flips to **enforce**.

## 10. Test Strategy

### 10.1 Golden vectors

A frozen table of `(input_uri, expected_canonical | expected_error)`. The seed set comes from:

- Every `D1` and `C7` case in `pentest/linux/DESIGN.md`.
- OWASP URL-canonicalization corpus.
- Hand-curated IMDS / WireServer real-world URLs harvested from production logs (redacted).

### 10.2 Property tests (`proptest`)

    proptest! {
        #[test]
        fn idempotent(uri in any_uri()) {
            if let Ok(c1) = canonicalize_uri(&uri) {
                let c2 = canonicalize_uri(&c1.render()).unwrap();
                prop_assert_eq!(c1, c2);
            }
        }

        #[test]
        fn no_panics(uri_bytes in any::<Vec<u8>>()) {
            let _ = std::panic::catch_unwind(|| {
                if let Ok(uri) = hyper::Uri::try_from(uri_bytes) {
                    let _ = canonicalize(&uri, &hyper::Method::GET);
                }
            }).unwrap();
        }

        #[test]
        fn host_form_equivalence(ip in any::<Ipv4Addr>()) {
            let dotted  = format!("http://{}/x", ip);
            let decimal = format!("http://{}/x", u32::from(ip));
            let hex     = format!("http://0x{:x}/x", u32::from(ip));
            prop_assert_eq!(
                canonicalize_str(&dotted).map(|c| c.destination),
                canonicalize_str(&decimal).map(|c| c.destination),
            );
            prop_assert_eq!(
                canonicalize_str(&dotted).map(|c| c.destination),
                canonicalize_str(&hex).map(|c| c.destination),
            );
        }
    }

### 10.3 Differential test against legacy matcher

Bound the legacy matcher and the new canonical matcher to the same rule set and the same request stream (harvested from production logs). Any divergence is a CI failure during the enforce-prep window.

### 10.4 Fuzzing

- `cargo fuzz` target on `canonicalize(bytes)` — must never panic.
- Second target on `CanonicalPattern::matches` — must never panic; pattern produced from random rule JSON.
- Run for ≥ 1 CPU-day before each release; record corpora in `proxy_agent/src/proxy/canonical/tests/corpus/`.

### 10.5 Pentest re-runs

Add a new pentest phase in `pentest/linux/phase4_rules_fuzz/`:

- **S20** — every D1 vector must return identical decisions in legacy and canonical modes (or canonical-strictly-stricter).
- **S21** — every C7 host form must resolve to the same `Destination` as the dotted form.
- **S22** — invalid UTF-8, overlong UTF-8, and embedded `?` must produce `CanonError` and a deny.

## 11. Performance Budget

| Operation                         | Target p50 | Target p99 | Notes                                                                        |
|-----------------------------------|------------|------------|------------------------------------------------------------------------------|
| `canonicalize` (typical IMDS GET) | ≤ 5 µs     | ≤ 30 µs    | One pass each over path and query; no allocations beyond small Vec/BTreeMap. |
| `CanonicalPattern::matches`       | ≤ 1 µs     | ≤ 5 µs     | Slice-equality over pre-sized segment vec.                                   |
| Total added latency vs legacy     | —          | ≤ 100 µs   | Measured end-to-end during shadow mode.                                      |

### 11.1 Allocation strategy

- Use `SmallVec<[Cow<'a, str>; 8]>` for path segments; most IMDS paths are ≤ 6 segments.
- Borrow from the source `Uri` wherever the decode is a no-op (no `%` in the segment).
- BTreeMap is acceptable here because query maps are tiny (typical: 1–3 keys); benchmark before optimizing.

### 11.2 Hot path caching

- Compiled patterns are stored once at rule load, swapped via `arc_swap::ArcSwap<Vec<CanonicalPattern>>` (this also satisfies the TOCTOU concern from pentest `D5`).

## 12. Telemetry & Observability

### 12.1 Metrics

- `gpa_canon_calls_total{result="ok|error"}`
- `gpa_canon_errors_total{code="CANON_PCT|CANON_OVERLONG|..."}`
- `gpa_canon_divergence_total{reason="trailing_slash|embedded_query|host_form|..."}` (shadow mode only)
- `gpa_canon_latency_microseconds` (histogram)

### 12.2 Audit log fields

New fields appended to each entry in `ProxyAgent.Connection.log`:

- `canon_path` — rendered canonical path (redacted: identifiers replaced with placeholder).
- `canon_dest` — `imds|wireserver|hostga|unknown`.
- `canon_error` — error code or null.
- `policy_epoch` — snapshot id used for this request.

### 12.3 Operator-visible signal

A non-zero divergence rate after the first week of shadow mode is the single most important signal: it directly identifies rules whose authors implicitly relied on the legacy normalization quirks. Surface this in `gpa-doctor` (Direction 6.2) so operators can fix their rules *before* enforce mode is enabled.

## 13. Risks & Open Questions

### 13.1 Risks

- **Existing rules may rely on quirks.** Mitigation: shadow mode + divergence reporting + a one-release overlap period.
- **Hostname rules.** If a customer has a rule keyed on a hostname rather than an IP, our refusal to DNS-resolve at the matcher means the rule will only match if the client also uses that exact hostname text. Document clearly; provide a migration tool.
- **IPv6 link-local zone IDs** (`fe80::1%eth0`) — decide whether to strip or reject; current proposal is to reject (fail-closed).
- **Performance regression** on tiny VMs with high IMDS QPS. Mitigation: benchmark suite gated in CI; SmallVec; borrow-when-possible decoding.

### 13.2 Open questions

1.  Should `CanonicalPattern` support glob/regex on segments, or only exact + prefix? Recommendation: exact + prefix only; richer matching is the policy-language work in Direction 2.2.
2.  Do we expose the canonical form on `/.well-known/gpa/attestation` (Direction 3.3) for diagnostic use? Recommendation: yes, but redact identifiers.
3.  For unknown destinations, do we ever forward, or strictly deny? Current proposal: strictly deny.

## 14. Milestones

| M   | Deliverable                                                        | Exit criteria                                                                       |
|-----|--------------------------------------------------------------------|-------------------------------------------------------------------------------------|
| M1  | Module skeleton + types + error taxonomy                           | Compiles; unit tests for each helper at \> 90% line coverage                        |
| M2  | Golden vectors + property tests + fuzz target                      | Zero panics in 1 CPU-day of fuzzing; all D1/C7 vectors pass                         |
| M3  | Shadow-mode integration in `proxy_authorizer.rs`                   | Divergence telemetry visible in dev/test; behavior unchanged for production traffic |
| M4  | Rule-loader uses canonical patterns; legacy `Privilege` deprecated | All existing rule files still load; old API marked `#[deprecated]`                  |
| M5  | Region-by-region cutover to enforce mode                           | Zero divergence for 14 days per region; pentest S20–S22 pass                        |
| M6  | Removal of legacy matcher                                          | All call sites migrated; legacy code deleted; codebase reduction recorded           |

## AAppendix — Representative Vector Table

A sample of the golden vectors. The full table lives in `proxy_agent/src/proxy/canonical/tests/vectors.rs`.

### A.1 Path vectors

| Input path                              | Canonical              | Or error               |
|-----------------------------------------|------------------------|------------------------|
| `/metadata/identity`                    | `/metadata/identity`   | —                      |
| `/Metadata/Identity`                    | `/metadata/identity`   | —                      |
| `/metadata//identity`                   | `/metadata/identity`   | —                      |
| `/metadata/./identity`                  | `/metadata/identity`   | —                      |
| `/metadata/x/../identity`               | `/metadata/identity`   | —                      |
| `/metadata%2Fidentity`                  | `/metadata/identity`   | —                      |
| `/metadata%252Fidentity`                | `/metadata%2fidentity` | — (single decode only) |
| `/metadata/%C0%AFidentity`              | —                      | `OverlongUtf8`         |
| `/metadata/identity/../../..`           | —                      | `PathUnderflow`        |
| `/metadata/identity;jsessionid=abc`     | `/metadata/identity`   | —                      |
| `/metadata/identity%3Fapi-version=2018` | —                      | `EmbeddedQuery`        |
| `/metadata/identity%0A`                 | —                      | `ControlChar`          |

### A.2 Host vectors (all should map to `Destination::Imds`)

| Host text                     | Result                                          |
|-------------------------------|-------------------------------------------------|
| `169.254.169.254`             | `Imds`                                          |
| `2852039166`                  | `Imds`                                          |
| `0xa9fea9fe`                  | `Imds`                                          |
| `0251.0376.0251.0376`         | `Imds`                                          |
| `[::ffff:169.254.169.254]`    | `Imds`                                          |
| `[::ffff:a9fe:a9fe]`          | `Imds`                                          |
| `user@169.254.169.254`        | `CanonError::UserinfoPresent`                   |
| `169.254.169.254:80@evil.com` | `CanonError::BadHost`                           |
| `metadata.azure.internal`     | `Destination::Unknown { host_text: Some(...) }` |

Detailed design for direction 2.1 of the GPA innovation plan. Parent doc: [Innovation-Directions.md](Innovation-Directions.md). Source-of-truth files: `proxy_agent/src/proxy/authorization_rules.rs`, `proxy_agent/src/key_keeper/key.rs`, `pentest/linux/DESIGN.md`.
