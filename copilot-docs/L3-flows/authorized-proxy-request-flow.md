**TL;DR:** The loopback HTTP/1.1 proxy recovers caller identity and the original destination, validates requests, applies endpoint-specific authorization, and forwards with optional signing. Audit denials continue forwarding; canonical comparisons remain observational, and signing failures do not necessarily block requests.

# Authorized Proxy Request Flow


<!-- TIER2-POINTER:BEGIN (managed by step8_inject_tier2_pointer.py) -->
> **Need a specific class, method, error code, config key, or flow step?**
> Read `intermediate-docs/L3-flows/authorized-proxy-request-flow.content.md` for implementation details; stay here for overviews.
> Search the companion for the source-file heading and range-read that section, starting with Purpose and Functionality.
> Verify behavior in source when needed; do not load the entire companion.
<!-- TIER2-POINTER:END -->
## Why

Redirected host-service traffic must retain its originating process identity and
destination so access policy, host claims, and diagnostics describe the actual
caller. Authorization, signature exemptions, signing availability, and listener
readiness are separate contracts; none implies the others succeeded.

## What

The flow spans TCP audit recovery, HTTP validation, endpoint policy selection,
optional body buffering/signing, upstream response streaming, and summaries.
Local provisioning/status queries branch before ordinary destination checks.

### Code Pointers

Paths are repository-relative; Key Classes includes Rust types and functions.

| Component | File Path | Key Classes |
|---|---|---|
| Listener and request orchestration | `proxy_agent\src\proxy\proxy_server.rs` | `ProxyServer`, `start`, `handle_new_http_request`, `handle_request_with_signature`, `forward_response` |
| Connection identity, transport, diagnostics | `proxy_agent\src\proxy\proxy_connection.rs` | `TcpConnectionContext::new`, `HttpConnectionContext`, `ConnectionLogger`, `send_request` |
| Endpoint authorization | `proxy_agent\src\proxy\proxy_authorizer.rs` | `Authorizer`, `AuthorizeResult`, `get_authorizer`, `get_access_control_rules`, `authorize` |
| Rule compilation and evaluation | `proxy_agent\src\proxy\authorization_rules.rs` | `AuthorizationMode`, `ComputedAuthorizationItem`, `CanonicalDecision`, `AuthorizationRulesForLogging` |
| Request and aggregate records | `proxy_agent\src\proxy\proxy_summary.rs` | `ProxySummary`, `ProxySummary::to_key_string`, `ProxyConnectionSummary::from` |
| Windows identity acquisition | `proxy_agent\src\proxy\windows.rs` | `get_user`, `get_process_full_name`, `get_process_cmd`, `LsaBuffer`, `NetApiBuffer` |

## How

### 1. Accept a connection and recover its origin

`ProxyServer` accepts loopback connections on a dedicated configurable Tokio
runtime; `JoinSet` owns connection tasks. Bind retries cover address-in-use
failures. Startup failure publishes stopped status and readiness failure.
Managed listener readiness is one-shot and distinct from provisioning approval:
approval does not gate acceptance.

`TcpConnectionContext::new` looks up and removes redirector audit data. Removal
failure aborts audit acquisition. Windows can recover from lookup failure using
socket identity; non-Windows returns an audit error. Audit failure leaves the
destination absent and stores a setup error. Claim extraction failure is logged
and leaves claims absent, although upstream sender creation still proceeds.

On Windows, `get_user` resolves sessions and indirect local groups, with SYSTEM
and built-in-account handling. Group lookup failure warns but retains the
username. LSA/NetAPI allocations use drop guards; process handles remain
caller-owned. Library loading failure logs and panics; symbol/process queries
return typed errors. Account-name helpers take low bytes rather than fully
decoding UTF-16. Command lines are UTF-16 decoded and limited to four arguments,
including quoted arguments: **truncation is not comprehensive secret redaction**.

### 2. Validate HTTP input and branch local queries

Tower caps ordinary request bodies at **100 KiB** and signature-exempt bodies at
**100 MiB**. `HttpConnectionContext` retains request metadata, timing, and trace
stages. Validation precedes endpoint authorization:

| Condition | Result |
|---|---|
| Unsupported HTTP method | 405 with an explicit method response |
| Nested percent encoding after one lossy decode | 404 |
| Raw repeated slashes or decoded parent-directory traversal | 403 |
| Ordinary forwarded request missing destination or claims | 421 |
| Access-control state retrieval failure | 500, not an absent-rules fallback |

Single-dot segments, matrix parameters, and non-nested escapes are not rejected
by these path helpers alone. Local provisioning/status handlers require request
metadata; aggregate status additionally requires elevated claims.

### 3. Select policy and preserve authorization semantics

`get_authorizer` selects by destination IP and port, not merely URI text.
`get_access_control_rules` retrieves endpoint rules asynchronously and propagates
state errors; unknown destinations have no rules.

| Authorizer or outcome | Forwarding contract |
|---|---|
| `WireServer`, `GAPlugin` | Require elevated claims before optional rule evaluation |
| `Imds` | No elevation prerequisite; evaluate rules when present |
| Recognized endpoint with absent rules | Permit after any elevation prerequisite |
| `Default` | Permit regardless of supplied rules |
| Rule denial in Audit mode | `OkWithAudit`: record denial but continue |
| Other rule denial | `Forbidden`: return 403 |

Before endpoint selection, `authorize` permits an elevated caller whose exact
method/URI combination is signature-exempt. Exemption alone does not grant
non-elevated callers this authorization bypass.

`ComputedAuthorizationItem::from_authorization_item` requires all four rule
collections. Paths and query keys/values are lowercased; names remain
case-sensitive. Undefined roles log errors; missing privileges/identities are
skipped. Invalid mode strings log and become Disabled, which allows immediately.
Otherwise a matching privilege without an assigned matching identity denies;
unmatched requests use default access.

Canonical pattern compilation failures warn and omit cached patterns while
retaining legacy privileges; omitted patterns can expose default access.
`canonical_decision` errors project to denial through
`CanonicalDecision::allowed_or_fail_closed`. However, `authorize` returns the
**legacy result even in canonical Enforce mode**: `shadow_compare` only supplies
comparison diagnostics here. Divergence logs contain path/query, not authority.

### 4. Add claims, optionally sign, and forward

The server adds host-claims and date headers. Signature-exempt bodies stream
directly; other bodies are buffered by `handle_request_with_signature`.
Missing signing keys or signature-computation errors still permit forwarding;
do not describe this path as requiring a successful signature.

Cloned TCP contexts share an upstream HTTP/1 sender behind an asynchronous
mutex, held throughout each send. Stored setup errors, closed connections, and
Hyper failures propagate. Responses stream; host-connection failures map to
502 and other forwarding failures to 503.

### 5. Record outcomes and retire connections

Authorization denials are summarized even when Audit mode permits forwarding.
`ProxySummary` owns identity, destination/address family, process information,
request details, status, elapsed time, and error details. Older serialized
records without address family default to IPv4.

`ProxySummary::to_key_string` groups by username, client/destination addresses and
port, address family, executable path, command line, and response status; it
excludes request ID, method, URL, timing, and error details. Conversion to
`ProxyConnectionSummary` starts count at one and uses lossy path conversion.
System/event logging is immediate; eligible file messages and HTTP trace stages
flush on drop. Logger clones keep correlation IDs but start with empty queues.

Cancellation closes the listener, requests graceful HTTP shutdown, and drains
connection tasks for **30 seconds** before aborting survivors.

## Related Components

- [Authorization canonicalization](..\L2-platform\authorization-canonicalization.md): normalized matching, typed errors, and final-segment prefix compatibility.
- [Shared-state access](..\L1-conceptual\agent-shared-state-access.md): endpoint rules, signing keys, provisioning, identity caches, redirector references, and aggregates.
- [eBPF socket redirection](..\L2-platform\ebpf-socket-redirection.md): traffic interception and origin/destination evidence consumed by connection setup.

## Test Navigation

Embedded tests cover endpoint/mode/exemption outcomes, canonical agreement and
fail-closed errors, cache omission, traversal/nested encoding, body limits,
unsupported methods, unauthenticated status, and shutdown/drain deadlines.
Windows tests cover session/process lookup and command-line truncation.
`proxy_summary.rs` has no dedicated tests in the supplied summaries; these are
test-location pointers, not evidence that tests were executed.
