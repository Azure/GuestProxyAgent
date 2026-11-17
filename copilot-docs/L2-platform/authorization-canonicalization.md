**TL;DR:** Authorization canonicalization normalizes destinations, paths, queries, and privilege patterns consistently across Windows and Linux. Typed errors reject malformed input, while explicit request-decoding and final-path-prefix exceptions preserve compatibility.

# Authorization Canonicalization


<!-- TIER2-POINTER:BEGIN (managed by step8_inject_tier2_pointer.py) -->
> **Need a specific class, method, error code, config key, or flow step?**
> Read `intermediate-docs/L2-platform/authorization-canonicalization.content.md` for implementation details; stay here for overviews.
> Search the companion for the source-file heading and range-read that section, starting with Purpose and Functionality.
> Verify behavior in source when needed; do not load the entire companion.
<!-- TIER2-POINTER:END -->
## Why

Equivalent URI spellings should reach the same authorization comparison without
DNS or platform-dependent address parsing. Shared normalization reduces
rule/request asymmetry; strict rule parsing remains separate from incoming-request
compatibility exceptions.

## What

| Representation | Contract |
|---|---|
| `Destination`, `AddrFamily` | IMDS, WireServer, HostGaPlugin, or Unknown; unknown targets retain family, optional parsed IP, port, and original host text |
| Canonical path | Owned segments beginning with an empty root marker, plus a trailing-slash flag |
| Canonical query | `BTreeMap<String, Vec<String>>`: sorted keys, duplicate values in input order |
| `CanonicalPattern`, `RuleDestination` | Normalized privilege path/query constraints with either `Any` or `Only(Destination)` |
| `CanonError` | Typed rejection of invalid input; callers must preserve fail-closed handling |

Helpers are synchronous and platform-independent, with owned local data and no
shared synchronization. `CanonicalPattern::matches` does not check HTTP methods
and is not the complete authorization decision.

### Code Pointers

Paths are repository-relative; Key Classes includes Rust types and functions.

| Component | File Path | Key Classes |
|---|---|---|
| Destination classification | `proxy_agent\src\proxy\canonical\destination.rs` | `Destination`, `AddrFamily`, `classify`, `parse_host_as_ip`, `parse_inet_aton`, `parse_numeric_octet` |
| Path normalization | `proxy_agent\src\proxy\canonical\path.rs` | `canonicalize_path`, `canonicalize_request_path`, `decode_path_once`, `split_and_resolve` |
| Query normalization | `proxy_agent\src\proxy\canonical\query.rs` | `canonicalize_query`, `canonicalize_request_query`, `canonicalize_decoded_query` |
| Rule construction/matching | `proxy_agent\src\proxy\canonical\rule.rs` | `CanonicalPattern::from_privilege`, `CanonicalPattern::matches`, `RuleDestination` |
| Randomized invariants | `proxy_agent\src\proxy\canonical\property_tests.rs` | `idempotent`, `no_panics`, `host_form_equivalence`, `normalize_for_equivalence` |

## How

### Classify destinations without resolution

`classify` inspects the parsed URI host and port, not DNS results. Its numeric
parser accepts legacy one-to-four-part IPv4 forms and decimal, hexadecimal, or
leading-zero octal components. IPv4-mapped IPv6 projects to IPv4 before endpoint
recognition; endpoint ports remain significant.

Userinfo and malformed explicit ports are rejected. An omitted port uses the
IMDS port constant; an origin-form URI yields an information-free Unknown with
port zero. Hostname trailing dots are ignored for validation, but Unknown keeps
the original host text. Invalid numeric components, overflow, and unacceptable
host characters return typed errors.

### Normalize paths before matching

Path processing percent-decodes exactly once, validates UTF-8, rejects controls
and non-ASCII path text, converts backslashes to slashes, and folds ASCII case.
It strips matrix parameters before dropping empty/current-directory segments
and resolving parent-directory segments. Traversal above root returns
`PathUnderflow`; paths collapsing to root lose the trailing-slash flag.

`canonicalize_path` rejects embedded queries in rule paths.
`canonicalize_request_path` can extract a query exposed by decoding an encoded
question mark and passes that owned text to query normalization. Query-specific
validation belongs there, not to the path validator.

Malformed escapes and invalid UTF-8 propagate errors. Strict UTF-8 conversion
precedes the overlong-byte helper, so actual overlong sequences currently report
`InvalidUtf8`, not the more specialized overlong error.

### Keep raw and already-decoded queries distinct

Parsing splits pairs on ampersands and each pair on its first equals sign.
Empty pairs are skipped; absent values become empty strings. Empty decoded keys
are discarded before their values are decoded. Keys and values use ASCII-only
lowercasing, preserving valid non-ASCII UTF-8.

| Entry point | Decoding and compatibility |
|---|---|
| `canonicalize_query` | Strict rule query: decode percent escapes once; literal plus becomes space; reject controls |
| `canonicalize_request_query` | Same raw decoding, but trim trailing carriage returns only from `client_id` values before control validation |
| `canonicalize_decoded_query` | Already-decoded embedded query: preserve percent text and plus signs; retain the request-only `client_id` exception |

Malformed escapes, invalid UTF-8, and remaining C0 controls or DEL return
`CanonError`. Do not send an extracted embedded query through raw decoding again.

### Match normalized privilege patterns

`CanonicalPattern::from_privilege` normalizes the privilege path and optional
query parameters through the strict helpers. It defaults destination to `Any`;
absent or empty query parameters impose no query constraint.

`CanonicalPattern::matches` checks destination and minimum path length first.
Earlier rule segments require exact equality. **Without a rule trailing slash,
the final rule segment may prefix-match the request segment**: a rule ending in
`/metadata` can match `/metadata-attacker`. This compatibility behavior is broader
than the introductory strict-boundary description in `rule.rs`.

A rule trailing slash disables that final-segment exception; it does not require
the request itself to retain a trailing slash. Additional request segments are
allowed. Every required query key must exist and have at least one value equal
to one of that key's required values; extra query keys are allowed.

### Test contracts and limits

Unit and full-pipeline golden tests cover endpoint/port distinctions, hostname
non-resolution, single decoding, matrix stripping, typed failures, destination
isolation, query duplicates, prefix compatibility, and slash boundaries.
Control-character helper tests cover every C0 byte and DEL.

Property tests require test compilation and the optional `proptests` feature:

| Property | Scope |
|---|---|
| `idempotent` | Skip initially rejected inputs; render accepted requests, restore authority, and require identical recanonicalization |
| `no_panics` | Printable ASCII up to 80 characters may succeed or return an error, but must not unwind |
| `host_form_equivalence` | Compare accepted dotted, decimal, hexadecimal, and mapped-IPv6 forms; skip zero/rejected forms and remove only Unknown host spelling |

These are bounded randomized checks, not exhaustive proofs or fuzz-duration evidence.

## Related Components

The [canonical pipeline](..\..\proxy_agent\src\proxy\canonical\mod.rs) owns
`CanonicalRequest`, `CanonError`, `canonicalize`, `canonicalize_str`, and
`CanonicalRequest::render`; use it to trace orchestration and golden vectors.
The [privilege model](..\..\proxy_agent\src\key_keeper\key.rs) supplies the
`Privilege` consumed by `CanonicalPattern::from_privilege`.
