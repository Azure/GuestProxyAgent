# Compose Content for: L3-flows/authorized-proxy-request-flow.md

Total files: 6

---

## proxy_agent/src/proxy/authorization_rules.rs

### Purpose and Functionality
Computes authorization rules from privileges, identities, roles, and assignments; evaluates HTTP requests; and writes diagnostic rule snapshots.
### Key Components
AuthorizationMode parses case-insensitively; invalid modes log errors and become Disabled. ComputedAuthorizationItem owns lookup maps and a serialization-skipped canonical-pattern cache. Rule population requires all four rule collections. Privilege paths and query keys/values are lowercased; names remain case-sensitive. Undefined roles log errors; undefined privileges and identities are skipped. Canonical compilation failures warn and omit cached patterns, retaining legacy privileges.
### Behavior and Interactions
Legacy evaluation consumes URI and claims, percent-decodes paths lossily, and delegates privilege/identity matching. Disabled allows immediately; Audit and Enforce share evaluation here. Any matched privilege without a matching assigned identity denies; otherwise unmatched requests use default access. Canonical evaluation borrows inputs and returns errors that project to denial. Shadow comparison returns the canonical verdict and logs disagreements with path/query, excluding authority. Dropped patterns can lead to default access. Snapshot rotation logs filesystem failures. Tests assert mode handling, case-insensitive paths, identity rejection, encoded-slash protection, retention limits, canonical agreement, final-segment prefix compatibility, fail-closed errors, and cache omission. Production logic is synchronous; async tests use Tokio. Executable fixtures use Unix device/inode metadata versus Windows zeros.

---

## proxy_agent/src/proxy/proxy_authorizer.rs

### Purpose and Functionality
Selects endpoint-specific authorizers and combines claims with optional access-control rules. AuthorizeResult distinguishes permission, permission with an audit denial, and prohibition.
### Key Components
The Authorizer trait exposes authorization and diagnostic descriptions. WireServer and GAPlugin own claims and require elevation before evaluating rules; Imds has no elevation prerequisite. Default permits requests regardless of supplied rules. get_authorizer returns a boxed implementation selected by destination address and port. get_access_control_rules asynchronously retrieves endpoint rules from shared state, propagates errors, and returns no rules for unrecognized destinations.
### Behavior and Interactions
Recognized authorizers permit requests when rules are absent. A rule denial becomes OkWithAudit in audit mode and Forbidden otherwise. The top-level authorize function first permits signature-exempt method/URI combinations when claims are elevated, bypassing subsequent authorization. Otherwise it computes the legacy result. With canonical mode enabled and rules available, it separately evaluates the rules-only legacy predicate and performs a canonical shadow comparison. Even canonical Enforce mode retains the legacy outcome here. Tests assert endpoint selection, disabled/audit/enforced rule outcomes, and exemption behavior for elevated callers, non-elevated callers, mismatched methods, and ordinary requests. No platform-specific branches appear here.

---

## proxy_agent/src/proxy/proxy_connection.rs

### Purpose and Functionality
Maintains TCP and HTTP contexts, serializes upstream HTTP/1 sends, and buffers diagnostics.
### Key Components
TcpConnectionContext is cloneable and holds optional claims, IPv4 destination details, address family, and either an Arc-shared Tokio Mutex<Client> or a stored connection error. HttpConnectionContext owns request metadata, timing, trace stages, and a TCP context. ConnectionLogger records correlated messages.
### Behavior and Interactions
Construction looks up and removes redirector audit data; removal failure aborts audit acquisition. Windows attempts socket-based recovery when lookup fails; non-Windows returns an audit error. Claim extraction failure is logged and leaves claims absent, while sender creation proceeds. Audit failure leaves destination metadata absent and stores an error. Sending holds the async mutex through the upstream send, propagating closed-connection, stored setup, and Hyper errors.
Logging immediately writes system messages and optionally events, buffering eligible file messages until drop. Logger clones retain identifiers but start empty queues. HTTP tracing accumulates stages and flushes them on drop. Path helpers detect raw repeated slashes, dot-dot after one lossy percent decode, and remaining valid percent escapes indicating nested encoding. Tests assert traversal and nested-encoding detection, while allowing clean paths, single-dot segments, matrix parameters, and non-nested escapes.

---

## proxy_agent/src/proxy/proxy_server.rs

### Purpose and Functionality
Runs a loopback HTTP/1.1 proxy with authorization, optional signing, provisioning queries, and elevated-only aggregate status access.
### Key Components
ProxyServer clones shared-state handles and cancellation tokens. Managed construction separates mutex-protected one-shot readiness from provisioning approval; approval does not gate acceptance. A dedicated thread owns a configurable Tokio runtime. Binding retries address-in-use failures; startup errors publish stopped status and readiness failure. JoinSet owns connection tasks.
### Behavior and Interactions
Cancellation closes the listener, gracefully shuts down HTTP connections, and drains tasks for 30 seconds before aborting survivors. Windows additionally captures raw socket identity. Tower limits ordinary bodies to 100 KiB and signature-exempt bodies to 100 MiB. Requests reject unsupported methods with 405, nested encoding with 404, traversal with 403, and missing destinations or claims with 421. Authorization failures are summarized; only Forbidden blocks forwarding. Metadata is required for local queries, and status also requires elevated claims. Signed-path bodies are buffered; missing keys or signature-computation errors still permit forwarding. Exempt bodies and responses stream. Host-connection errors become 502; other forwarding errors become 503. Summaries record outcomes. Tests assert drain completion/deadlines, idle shutdown, cancellation, unauthenticated status rejection, malformed paths, oversized bodies, and unsupported-method status lines.

---

## proxy_agent/src/proxy/proxy_summary.rs

### Purpose and Functionality
Defines an owned, serializable record of a proxied request and converts it into the smaller connection-summary representation used for aggregate status reporting. This file contains data and conversion logic, not networking or asynchronous synchronization.
### Key Components
ProxySummary derives serialization, deserialization, and cloning. Its fields retain request identity, method and URL, client and destination addresses, address family, user and group information, executable path and command line, elevation, response status, elapsed time, and error details. default_address_family supplies IPv4 when deserializing records lacking the addressFamily field.
### Behavior and Interactions
to_key_string concatenates user name, client IP, destination IP and port, address family, executable path, command line, and response status with spaces. It excludes request ID, method, URL, timing, and error details. Conversion into ProxyConnectionSummary consumes the original record, moves selected strings and groups, wraps groups and the converted path in Some, and initializes count to one. Both path conversions replace invalid Unicode lossily. There are no explicit error-returning operations, platform-specific branches, or tests in this file.

---

## proxy_agent/src/proxy/windows.rs

### Purpose and Functionality
This Windows-only proxy module retrieves account names, local group membership, executable paths, and shortened command lines for authorization claims.
### Key Components
LsaBuffer and NetApiBuffer release returned API allocations on drop; process handles remain caller-owned. A lazily loaded library supplies local-group enumeration and buffer-free functions. Loading the library logs and panics on failure, while symbol resolution and process-query failures return typed Windows errors. User lookup special-cases SYSTEM sessions, queries other sessions through LSA, and includes indirect local groups. Empty session usernames produce a warning and an undefined name; group enumeration failure warns but still returns the username. Built-in account names override retrieved names. Account-string helpers take low bytes of wide characters rather than performing full UTF-16 decoding.
### Behavior and Interactions
Command-line retrieval first queries buffer size, then decodes the returned UTF-16 string and retains at most four arguments, recognizing arguments beginning with double quotes. This limits later-argument capture, not comprehensive secret redaction. Tests assert nonempty session usernames and current-process details, plus empty-input, short-input, truncation, and quoted-argument behavior.

---
