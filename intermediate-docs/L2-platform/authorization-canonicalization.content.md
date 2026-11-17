# Compose Content for: L2-platform/authorization-canonicalization.md

Total files: 5

---

## proxy_agent/src/proxy/canonical/destination.rs

### Purpose and Functionality
Classifies URI destinations as IMDS, WireServer, HostGaPlugin, or Unknown using the parsed host and port, without DNS resolution. A hand-written numeric parser avoids platform-dependent address interpretation, giving Windows and Linux the same behavior; there are no OS-specific branches or asynchronous operations.
### Key Components
Destination represents recognized endpoints or an unknown target with address family, optional parsed IP, port, and owned host text. AddrFamily distinguishes IPv4, IPv6, and names. classify borrows a Hyper URI and returns an owned destination or CanonError. Supporting functions recognize endpoint addresses, parse IP literals, assemble legacy one-to-four-part IPv4 forms, and interpret decimal, hexadecimal, or leading-zero octal components.
### Behavior and Interactions
Classification rejects userinfo and malformed explicit ports instead of silently assigning a default. Missing ports use the IMDS port constant; origin-form URIs produce an information-free Unknown with port zero. IPv4-mapped IPv6 projects to IPv4 before endpoint recognition. Hostname trailing dots are ignored during validation, while Unknown retains the original host text. Invalid numeric components, overflow, and unacceptable host characters propagate typed errors. Tests assert numeric-form equivalence, endpoint port distinctions, unknown-target fields, hostname non-resolution, adversarial rejection, and stable display labels.

---

## proxy_agent/src/proxy/canonical/path.rs

### Purpose and Functionality
Normalizes URI paths into owned, root-prefixed string segments and a trailing-slash flag for authorization matching. Separate entrypoints distinguish strict rule paths from request paths containing percent-encoded query delimiters.
### Key Components
The pipeline decodes percent escapes exactly once, validates UTF-8, checks for overlong encodings, rejects controls and non-ASCII path text, converts backslashes to slashes, and folds ASCII case. Segment processing strips matrix parameters before removing empty or current-directory segments and resolving parent-directory segments. Traversal above root returns PathUnderflow. Paths collapsing to root cannot retain the trailing-slash flag.
### Behavior and Interactions
Request processing extracts an owned embedded query after decoding and leaves query-specific validation to the query pipeline; strict path processing rejects embedded queries. Malformed escapes, invalid UTF-8, controls, and non-ASCII paths propagate typed CanonError results. Strict UTF-8 conversion precedes the overlong-byte helper, so actual overlong inputs currently fail as InvalidUtf8. Platform-independent synchronous helpers use local allocations without shared synchronization. Unit and full-pipeline golden tests verify normalization, single decoding, matrix stripping, backslashes, embedded-query compatibility, typed failures, and overlong rejection; helper tests cover every C0 byte and DEL.

---

## proxy_agent/src/proxy/canonical/property_tests.rs

### Purpose and Functionality
Defines randomized canonical-pipeline invariant tests complementing golden vectors. The parent module includes this file only during test compilation with the optional proptests feature; there is no Windows/Linux split.
### Key Components
Owned-string strategies generate short path segments, query keys and values, and URLs with a fixed destination and optional trailing slash. Character sets include percent signs, matrix delimiters, and plus signs to exercise normalization. Helpers classify a parsed URI using GET and remove original host spelling from unknown destinations before comparison.
### Behavior and Interactions
The idempotent property skips inputs rejected on their first canonicalization, renders successful requests, restores the same authority, and requires the second pass to succeed with an identical canonical request. The no_panics property calls canonicalize_str on printable-ASCII strings up to eighty characters; either result is acceptable, but unwinding fails the test. Host-form equivalence generates IPv4 addresses and compares accepted dotted, decimal, hexadecimal, and mapped-IPv6 spellings. Rejected forms are excluded, zero is skipped, and unknown destinations retain family, address, and port while discarding host_text. These synchronous tests perform no shared-state synchronization.

---

## proxy_agent/src/proxy/canonical/query.rs

### Purpose and Functionality
Canonicalizes query parameters into an owned BTreeMap of string keys to ordered value vectors. Deterministic key ordering and preserved duplicate-value order support canonical request representation and case-insensitive rule comparisons.
### Key Components
Three entrypoints share one implementation: strict raw-query canonicalization, ordinary incoming-request canonicalization, and parsing of embedded queries already decoded by the path pipeline. Parsing splits on ampersands and the first equals sign, skips empty pairs, treats absent values as empty strings, and drops empty decoded keys before decoding their values. Keys and values undergo ASCII-only lowercasing; valid non-ASCII UTF-8 remains intact.
### Behavior and Interactions
Raw queries decode percent escapes once and convert literal plus signs to spaces. Already-decoded embedded queries preserve both percent text and plus signs, avoiding double interpretation. Request entrypoints trim trailing carriage returns only from client_id values before control validation; strict queries reject them. Malformed escapes, invalid UTF-8, and remaining C0 controls or DEL propagate typed CanonError failures. Helpers are synchronous and platform-independent, with no shared synchronization. Unit tests assert case folding, Unicode preservation, duplicate ordering, missing values, empty-key removal, decoding distinctions, strict rejection, and the narrowly scoped request compatibility exception.

---

## proxy_agent/src/proxy/canonical/rule.rs

### Purpose and Functionality
Defines owned canonical authorization patterns and compares them with canonical requests. Construction normalizes privilege paths and query parameters through shared helpers, propagating CanonError on invalid input.
### Key Components
RuleDestination restricts a pattern to one classified destination or permits any destination. CanonicalPattern stores path segments, a sorted map of required query values, and a trailing-slash flag. from_privilege defaults the destination to Any and assembles optional query parameters for canonicalization; absent or empty parameters impose no query constraint.
### Behavior and Interactions
matches first checks destination and minimum path length. Earlier path segments must match exactly, but the final rule segment may prefix-match when the rule lacks a trailing slash. This compatibility exception is broader than the introductory strict-boundary description. A trailing slash disables that exception without requiring the request to retain its slash. Every required query key must exist, with at least one equal value; extra keys are allowed. Method is not matched here. Tests assert normalization, malformed-input rejection, destination isolation, prefix compatibility, trailing-slash boundaries, repeated query values, encoded delimiters, and case-insensitive query-value matching after canonicalization. No platform-specific branches or asynchronous synchronization appear here.

---
