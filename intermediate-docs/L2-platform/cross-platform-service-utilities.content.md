# Compose Content for: L2-platform/cross-platform-service-utilities.md

Total files: 27

---

## proxy_agent_shared/src/common_state.rs

### Purpose and Functionality
Maintains shared VM metadata, string-keyed state, cancellation, and telemetry notification through an asynchronous actor rather than direct shared-map access.
### Key Components
Cloneable CommonState handles contain an mpsc sender and CancellationToken. start_new spawns a task owning optional metadata, a HashMap, and an Arc-wrapped Notify. CommonStateAction variants carry owned inputs and oneshot response senders. A bounded channel with capacity 100 serializes operations; cancellation or channel closure stops the task.
### Behavior and Interactions
Getters clone stored values; setters await acknowledgements. Channel send and receive failures become typed errors, while abandoned response receivers generate warnings. Notification retrieval shares the same Notify, and notify_telemetry_event wakes one waiter. update_vm_meta_data treats secure-key lookup errors as absent values, then sequentially fetches goal state, shared configuration, and IMDS information. Fetch and metadata-update errors propagate. Token access clones the token; cancellation affects shared token users. Tests assert missing-key behavior, insertion, replacement, independent retained values, repeated operations, and mock-backed metadata population with nonempty container and role fields.

---

## proxy_agent_shared/src/current_info.rs

### Purpose and Functionality
Exposes cached information about the running system and executable for reuse across the shared library's consumers. Values are initialized lazily rather than refreshed on each call.
### Key Components
Three once_cell Lazy statics store memory and processor count, architecture and long operating-system description, and current executable version. Public getters return numeric values directly or owned copies of cached strings. Architecture, operating-system text, and executable version are obtained through misc_helpers.
### Behavior and Interactions
Windows initialization queries shared Windows helpers; memory-query failure is logged and represented as zero while processor count is still collected. Non-Windows initialization constructs a sysinfo System with memory and CPU refresh settings, converts total memory from bytes to megabytes, and counts CPU entries. Lazy initialization provides synchronized process-wide caching, so subsequent reads do not refresh system measurements. The unit test requires more than 100 megabytes of memory, at least one CPU, and an architecture value other than the unknown sentinel. It does not assert operating-system text or executable version.

---

## proxy_agent_shared/src/error.rs

### Purpose and Functionality
Defines typed shared-library failures and their human-readable formatting using thiserror. The file classifies errors; it does not perform retries, recovery, or logging.
### Key Components
Error covers HTTP operations, signing, URL and version parsing, wire-server requests, I/O, JSON, regular expressions, commands, asynchronous channel exchanges, datetime parsing, file decoding, aggregate-status retrieval, telemetry enqueueing, and invalid input. HyperErrorType distinguishes connection, request construction, response-body, status, deserialization, and header failures. ParseVersionErrorType, CommandErrorType, and WireServerErrorType provide narrower categories. I/O and JSON conversions preserve underlying display text, while regex conversion adds context.
### Behavior and Interactions
Windows-only variants retain service, Windows API, or native signature failures. The non-Windows signature variant exists only with the signing feature and carries an OpenSSL error stack. Channel receive failures retain the oneshot receive error; aggregate-status failure retains both server and file diagnostics. Tests verify platform-specific missing-file text and formatting for telemetry, regex, version, command, HTTP status, and header errors. These assertions check representation, not recovery behavior.

---

## proxy_agent_shared/src/host_clients/goal_state.rs

### Purpose and Functionality
Models wire-server goal-state and shared-configuration XML documents with Serde serialization and deserialization. Public accessors extract the deployment information used when assembling VM metadata.
### Key Components
GoalState contains version, incarnation, machine information, and container role instances. Private nested structures represent expected machine state, optional load-balancer probe ports, role state, and configuration references. SharedConfig models deployment, role, and instance collections; Serde attribute mappings distinguish XML attributes from elements. Shared-configuration structures also derive equality support.
### Behavior and Interactions
Getters return owned strings for container identity, shared-configuration URI, deployment name, role name, and role-instance name. GoalState selects the first role instance by direct indexing, so an empty collection panics. SharedConfig instead uses a checked first-element lookup and returns an empty string when no instance exists. The optional probe-port field is omitted during serialization when absent. XML fixture tests assert container extraction, decoded shared-configuration URI, deployment name, role name, and first instance name. This module performs no network requests and does not wrap deserialization errors.

---

## proxy_agent_shared/src/host_clients/imds_client.rs

### Purpose and Functionality
Implements a small asynchronous client for retrieving VM instance information from the instance metadata service. The caller supplies the host and port rather than the client selecting a fixed network destination.
### Key Components
ImdsClient owns a copy of the supplied IP string and stores its port. new constructs that configuration, while the private endpoint helper creates a HostEndpoint for a requested path. get_imds_instance_info targets the instance metadata resource with a fixed API-version query and adds the required Metadata header.
### Behavior and Interactions
The async retrieval method borrows the client and accepts optional owned signing-key identifier and key values. It forwards those options, endpoint, headers, and the warning logger to the shared hyper_client::get helper, returning its Result containing InstanceInfo directly. Consequently, request transport and response decoding failures propagate without an IMDS-specific wrapper in this module. The client stores no persistent connection, retry state, or synchronization primitive. No platform-specific branches or tests are declared in this file.

---

## proxy_agent_shared/src/host_clients/instance_info.rs

### Purpose and Functionality
Defines the subset of instance metadata needed for VM identification and image-origin reporting. It models response data rather than contacting the metadata service.
### Key Components
Public InstanceInfo wraps a private ComputeInfo structure. Both derive Serde serialization and deserialization. ComputeInfo stores location, VM name, resource group, subscription identifier, VM identifier, VM size, and an optional image offer. The optional offer field is omitted from serialized output when absent; the remaining modeled fields are required for deserialization.
### Behavior and Interactions
Accessors return owned strings for subscription identifier, VM identifier, and resource group. get_image_origin classifies a present, nonempty offer as platform origin with numeric value one; absent or empty offers produce custom origin with value zero. It does not inspect other image-reference fields. A large JSON fixture exercises deserialization despite many unmodeled properties and asserts the three identifying getters plus platform-origin classification. There are no separate assertions for missing or empty offers. This file contains no explicit error conversion, platform gating, asynchronous work, or external resource ownership.

---

## proxy_agent_shared/src/host_clients/wire_server_client.rs

### Purpose and Functionality
Implements asynchronous wire-server operations for telemetry submission, goal-state retrieval, and shared-configuration retrieval. WireServerClient owns its configured host string and port; its endpoint helper constructs request destinations.
### Key Components
send_telemetry_data returns success immediately for empty input. Otherwise it builds an unsigned XML POST with protocol-version and content-type headers, sends it through hyper_client, and accepts any successful HTTP status without decoding the response body. get_goalstate requests the goal-state resource and returns GoalState. get_shared_config parses a supplied full URI, constructs its endpoint, and returns SharedConfig; its destination therefore comes from that URI rather than the stored client address.
### Behavior and Interactions
Both retrieval methods forward optional signing inputs and the warning logger to the shared GET helper. Retrieval failures receive operation-specific WireServer error categories. Invalid URI syntax becomes ParseUrl; endpoint-construction errors propagate directly. Telemetry request-building errors also propagate directly, whereas send failures and unsuccessful statuses become telemetry-category errors. The file defines no retries, persistent connections, platform branches, or tests.

---

## proxy_agent_shared/src/host_clients.rs

### Purpose and Functionality
Declares the public host_clients module hierarchy. This tiny file contains module declarations only, with no request-processing or data-conversion implementation.
### Key Components
The goal_state and instance_info submodules provide response models. The imds_client and wire_server_client submodules provide the corresponding host-service clients.
### Behavior and Interactions
The declarations expose those four submodules through the shared crate's host_clients namespace so consumers can address their public types and functions. This file itself creates no client instances, owns no network resources, and introduces no platform gating, asynchronous synchronization, error handling, or tests. Those behaviors belong to the declared submodule implementations.

---

## proxy_agent_shared/src/hyper_client.rs

### Purpose and Functionality
Provides asynchronous HTTP/1 requests, deserialization, endpoint parsing, and signature canonicalization. HostEndpoint owns host, port, and path/query; HTTPS selects port 443, but transport remains plain TCP and Display emits HTTP.
### Key Components
Request construction adds date, host, root-claim, and content-length headers, copies bytes into an owned boxed body, and signs when the signing feature and both keys are present. Canonicalization uses raw body bytes, sorted lowercase headers with trimmed values, excludes authorization, and rejects duplicate or non-text headers. Query parsing preserves encoding; canonicalization lowercases names and sorts concatenated name/value keys, potentially collapsing collisions.
### Behavior and Interactions
A spawned task owns the connection and reports failures through a callback. GET rejects unsuccessful statuses. Decoding uses lossy UTF-8 by default, little-endian UTF-16 without guarding odd chunk lengths, and rejects UTF-32; content type selects XML, otherwise JSON. Errors propagate, with deserialization errors including response text. Date synchronization prefers the custom header; valid header text containing an invalid date prevents fallback. Tests cover canonicalization, header rejection, raw queries, method-specific signature exemptions, mock host-client exchanges, and date precedence.

---

## proxy_agent_shared/src/lib.rs

### Purpose and Functionality
Defines the public module surface of the proxy_agent_shared library crate. This file contains module declarations only, rather than executable initialization, request handling, or resource management.
### Key Components
Unconditionally exports common state, constants, current information, error and result definitions, host clients, HTTP helpers, logging, miscellaneous helpers, aggregate status, secret redaction, service helpers, telemetry, time buckets, and version support. It also publicly exposes server_mock, described as supporting unit tests and local development, without a test-only compilation gate.
### Behavior and Interactions
Windows builds expose windows and windows_events through cfg(windows). The linux module is selected by cfg(not(windows)), so its declaration applies to all non-Windows targets rather than an explicit Linux-only condition. Consumers reach implementations through these module paths; this root does not re-export individual functions or types. It declares no tests, synchronization objects, error-handling branches, or owned runtime resources.

---

## proxy_agent_shared/src/linux.rs

### Purpose and Functionality
Implements non-Windows operating-system identification, cgroup discovery, service CPU quota configuration, process memory inspection, Unix permissions, and optional signing. OS information is cached in a process-wide Lazy value.
### Key Components
OS helpers use cached platform information, consulting the OS release file when the detected type is generic Linux. Read failures produce warnings and return Unknown. FileMount and FileSystem deserialize findmnt JSON; discovery returns the first filesystem target, propagating execution and JSON errors and rejecting unsuccessful or empty results. MemStatus owns optional resident, swapped, and peak-resident memory measurements parsed from process status; missing or malformed numeric fields remain None.
### Behavior and Interactions
CPU quota configuration invokes systemctl and propagates command-execution errors, but does not inspect the returned exit status. File permissions are applied through Unix PermissionsExt with filesystem errors propagated. With signing enabled, OpenSSL computes a hex-encoded HMAC-SHA256 from a decoded hexadecimal key; decoding and cryptographic failures become shared errors. Tests check nonempty OS version, long-version formatting, architecture against lowercase unknown, and permission bits. Cgroup discovery tests validate a successful path but merely print discovery errors, accommodating environments without a mount.

---

## proxy_agent_shared/src/logger/logger_manager.rs

### Purpose and Functionality
Routes messages to named or default rolling loggers and independently filtered system output. Process-wide Tokio OnceCell values own the logger map, default key, and severity limits; synchronous APIs use no awaited initialization or write lock.
### Key Components
set_loggers establishes the file level once, ignores later logger-map replacements, and panics if a newly supplied map lacks its default key. Failed cell assignments use system logging. File filtering defaults to Trace; system filtering defaults to Error. Windows-only setup retains a WindowsEventWriter and reports initialization failures.
### Behavior and Interactions
Single-message logging attempts system output before file filtering. Unknown keys or an absent map omit file output; rolling-write failures go to stderr. write_many sends raw batches directly to the selected logger, bypassing severity filtering and system output. System messages use stderr for Error and stdout otherwise; Windows also forwards to its event writer or reports it uninitialized. Linux console capture depends on the environment. Tests initialize once, register exit cleanup, emit repeated messages across levels, and assert six retained files. Separate cells are not initialized atomically.

---

## proxy_agent_shared/src/logger/rolling_logger.rs

### Purpose and Functionality
Implements synchronous filesystem logging with size-triggered archival and retention. RollingLogger owns directory, filename, extension, size threshold, and file-count configuration, without persistent handles or synchronization locks.
### Key Components
Constructors only store configuration. Opening creates the directory if needed and returns a LineWriter over an appended or new file. Single-message writes add timestamp/severity headers; batches write supplied strings unchanged, each newline-terminated. Rotation is checked before writing, so messages or batches can exceed the threshold. Although a comment says kilobytes, the configured threshold is compared directly with metadata length in bytes.
### Behavior and Interactions
Rotation renames the active file using timestamp and nanosecond suffixes, sorts matching paths, and removes oldest entries while reserving room for the new active file. Discovery primarily filters by filename prefix; its metadata/extension condition does not reliably exclude directories or unrelated extensions. Rotation and write/flush errors propagate, but a second open failure inside a write is silently ignored after the initial rotation check succeeds. Local writers release handles when dropped. Tests exercise successful creation, five files before retention pressure, and six afterward.

---

## proxy_agent_shared/src/logger.rs

### Purpose and Functionality
Provides the shared logging facade's initialization helper and timestamped severity headers. It exposes logger_manager and rolling_logger as public submodules and aliases LoggerLevel to log::Level rather than declaring a separate severity enumeration.
### Key Components
init_loggers accepts an owned log directory, logger-key and filename pairs, a primary key, size and retention limits, and a maximum file severity. It constructs a HashMap of RollingLogger configurations, cloning the directory for each entry, then transfers ownership of the map and primary key into logger_manager::set_loggers. Repeated keys replace earlier configurations during map construction. A missing primary key preserves the manager's documented panic contract.
### Behavior and Interactions
Initialization itself does not open files; persistence is handled by the rolling logger. get_log_header obtains a millisecond timestamp from miscellaneous helpers, formats it with severity, and delegates to a private helper that truncates by characters and pads using string byte length to target 34. Tests assert severity parsing and ordering and exact INFO, ERROR, and WARN header spacing for supplied timestamps. This file contains no platform-specific branches or asynchronous operations.

---

## proxy_agent_shared/src/misc_helpers.rs

### Purpose and Functionality
Provides utilities for timestamps, JSON persistence, filesystem discovery, process execution, environment expansion, versions, XML escaping, and UTF-8-safe truncation.
### Key Components
HostTimeSyncState stores host UTC and a monotonic Instant behind a synchronous RwLock. RFC1123 output advances synchronized time by elapsed duration; unavailable state or duration-conversion failure falls back to local UTC. Synchronization returns false for invalid input or lock failure; unavailable synchronization is considered stale. ISO timestamps use local UTC. TextEncoding and DetectedEncoding support UTF-8, UTF-16, and UTF-32, including byte-order variants and optional BOMs; BOM-less detection assumes initial ASCII. UTF-8 decoding borrows input; wider encodings allocate.
### Behavior and Interactions
Synchronous and Tokio JSON writers use temporary files followed by rename; reads propagate filesystem, decoding, and JSON errors. Invalid scalars, unpaired surrogates, and truncated code units are rejected. Directory existence-check failure panics. CommandOutput owns exit status and lossy-decoded streams. Executable-version probing reports unsuccessful commands. Windows uses metadata with Cargo-version fallback; non-Windows uses Cargo versions. Signing is re-exported on Windows and feature-gated elsewhere. Tests assert encoding round trips, malformed-input errors, timestamp parsing, synchronization staleness, command streams, sorted searches, cloning, environment expansion, and signing results.

---

## proxy_agent_shared/src/proxy_agent_aggregate_status.rs

### Purpose and Functionality
Defines serializable aggregate-status models and retrieves status over HTTP with JSON-file fallback. Windows expands an environment-based status directory; non-Windows uses a fixed logging directory.
### Key Components
ModuleState distinguishes unknown, starting, running, and stopped states; only running and stopped are ultimate states. OverallState represents success, error, or unknown. ProxyAgentDetailStatus carries a message and optional state map omitted from serialization when absent. ProxyAgentStatus combines module reports, audit-fallback information, version, and connection count. ProxyConnectionSummary owns identity, address, process, response, and count data; missing address-family fields deserialize as IPv4. Manual Clone duplicates owned fields, and Countable updates the count. GuestProxyAgentAggregateStatus groups timestamp, agent status, connection summaries, and failed-authentication summaries; timestamp parsing delegates to misc_helpers.
### Behavior and Interactions
Asynchronous retrieval first calls the shared HTTP client with a metadata header, then synchronously reads the supplied file after HTTP failure. Success includes a server-or-file source enum. If both attempts fail, one error preserves both descriptions. The Tokio mock-server test checks version, successful overall state, empty summary lists, and zero connections, then cancels the server.

---

## proxy_agent_shared/src/result.rs

### Purpose and Functionality
Provides the shared crate's Result type alias, fixing the error parameter to the Error type declared in the sibling error module while leaving the success type generic.
### Key Components
Result is an alias for Rust's core result type, not a wrapper or a separately implemented error container.
### Behavior and Interactions
Callers can express fallible operations using the crate's common error vocabulary without repeating its error type. This file contains only an import and the alias declaration; it implements no conversions, logging, recovery, resource ownership, platform-specific behavior, asynchronous synchronization, or tests.

---

## proxy_agent_shared/src/secrets_redactor.rs

### Purpose and Functionality
Redacts credential-like logging and telemetry text through a blocking String-in/String-out interface. Indicator scanning, including URL user-information detection, bypasses regexes for unlikely inputs; several indicators are case-sensitive.
### Key Components
RedactionPattern owns a regex and mutable search cache. Replacement borrows unchanged text or allocates marked output, advancing empty matches at UTF-8 boundaries. RedactionRequest transfers owned text and a response sender to a lazily started dedicated thread. Initialization silently skips regexes that fail compilation.
### Behavior and Interactions
A zero-capacity synchronous request channel serializes callers against the worker; each request has a buffered response channel. Patterns apply sequentially, reusing the original String when unchanged. Caches reset hourly, including while idle, and when individual cache usage reaches 2.5 MB, with warning logs. Request-channel disconnection stops the worker; thread startup and public send/receive failures panic, while worker response-send errors are ignored. The blocking API is documented for noncritical consumer paths, not proxied requests. Tests assert replacements, unchanged borrowed results, URL handling, correctness after cache reset, and independent results for eight concurrent callers. There are no platform-specific branches or async primitives.

---

## proxy_agent_shared/src/server_mock.rs

### Purpose and Functionality
Provides an asynchronous HTTP mock for WireServer and instance-metadata interactions during tests and local development, optionally accepting a caller-supplied secure-channel status body.
### Key Components
The public start functions share start_internal, which binds a Tokio TCP listener and returns its actual port. An address-in-use error triggers an ephemeral-port retry; other bind errors propagate. handle_request dispatches using the method and path including its query string. Responses cover secure-channel status and key retrieval, aggregate status, goal state, shared configuration, instance metadata, and telemetry submission. Goal-state links incorporate the listener address. set_secure_channel_state changes process-global state, affecting default status and whether key responses use an empty or generated identifier.
### Behavior and Interactions
A spawned accept loop owns the listener and cancellation token. Each accepted connection receives a separate HTTP/1 task with cloned response configuration; cancellation stops acceptance without joining or explicitly cancelling existing connections. Accept errors are logged and connection errors printed. Shared mutable channel state uses unsafe access without synchronization. All requests, including unmatched routes, receive HTTP 200; unmatched bodies remain empty. Response construction and address extraction use unwrap. This file contains no tests.

---

## proxy_agent_shared/src/service/linux_service.rs

### Purpose and Functionality
Implements the non-Windows backend using synchronous systemctl commands and filesystem inspection. Installation unmasks, reloads systemd, and enables; uninstall disables and attempts unit-file removal.
### Key Components
Lifecycle helpers log command output. start_service explicitly rejects unsuccessful command results, whereas stop, unmask, enable, disable, and daemon reload do not independently check exit success. query_service_executable_path parses the path field from ExecStart output, retrying unsuccessful results or unparseable text up to three attempts with blocking one-second delays. Command-execution errors propagate immediately; exhausted attempts return a command error. Unit-file removal failure is logged but returns success; successful removal triggers daemon reload.
### Behavior and Interactions
Installation detection requires a regular unit file in the configured service directory. Runtime checks return not-installed immediately when it is absent; otherwise they query is-active and is-enabled. Active means running, activating means transitioning, and deactivating is already down. Enablement states map to cross-platform start-type vocabulary, with unfamiliar text capitalized and empty output unknown. Execution errors are logged and yield unknown fields. Pure mapping tests assert healthy, stopped, failed, transitional, disabled, masked, static, and unfamiliar states; another test verifies missing-service status.

---

## proxy_agent_shared/src/service/windows_service.rs

### Purpose and Functionality
Implements Windows-only service management through owned SCM handles. ServiceStatusInfo stores state, start type, optional executable path, and cached version, with summary/message formatting.
### Key Components
Installation updates an existing service or attempts creation after any status-query error. Both configure an automatic-start, own-process LocalSystem service with supplied dependencies and no launch arguments. Creation installs restart actions after 15, 60, and 120 seconds, resetting failure counts after 30 minutes. SCM failures are wrapped with the last OS error.
### Behavior and Interactions
Startup accepts already-running services; otherwise it starts, sleeps asynchronously for one second, and queries status. The retry wrapper requires Running and returns an error on exhaustion. Stop acts only on Running, logs stop-request failures, then re-queries; deletion follows successful completion without verifying Stopped. Binary-path normalization strips the NT device prefix and resolves relative paths against the Windows directory. Runtime classification treats start/continue pending as transitioning and other non-running states as down. Tests cover classification, path normalization including non-ASCII input, status formatting, installation/update paths, failed startup of a non-service executable, stopped status, and deletion. Async sleeps coexist with synchronous SCM calls.

---

## proxy_agent_shared/src/service.rs

### Purpose and Functionality
Defines the shared service-management facade, selecting private Windows or non-Windows implementations through conditional compilation. Public operations install, start, stop, remove, update, and inspect system services while exposing a common runtime-status representation.
### Key Components
ServiceRuntimeStatus owns the service name, installation/running/transition flags, and display strings. Its summary and message methods produce human-readable status text. Windows-only exports additionally expose detailed status, state classification, and failure-action configuration. check_service_status combines Windows runtime state with configuration, normalizes the executable path, and caches an optional product version.
### Behavior and Interactions
Windows operations delegate to SCM helpers, including asynchronous startup retries. Non-Windows installation ignores executable, display-name, and dependency arguments; starting ignores retry parameters. Non-Windows deletion stops before uninstalling, while update only prints an unsupported message and returns success. Windows stop discards the returned detailed status. A failed Windows status query becomes not-installed; configuration failure retains runtime state with unknown start type, and unreadable product version becomes absent. Tests assert non-Windows update/install success, missing-service status, and Windows installation, stopped-state, automatic-start, and cleanup behavior. Although some facade functions are async, non-Windows delegates execute synchronously.

---

## proxy_agent_shared/src/telemetry.rs

### Purpose and Functionality
Defines shared telemetry payloads and filename conventions, and exposes the logger, reader, sender, span, and telemetry-event submodules. Generic filenames use Unix nanoseconds followed by a JSON suffix; extension filenames add an extension prefix. Lazily compiled, anchored regular expressions distinguish the two filename families. Regex initialization unwraps compilation of fixed patterns.
### Key Components
Event is a serializable and deserializable generic-log record whose capitalized field names are retained. Its constructor takes ownership of severity, message, task name, and operation identifier, then supplies executable version, process and thread identities, and a millisecond-resolution timestamp. Extension describes extension identity and classification. OperationStatus groups outcome, operation, task, message, and signed duration. ExtensionStatusEvent owns both records and adds process, thread, and timestamp metadata; these extension-related types also support cloning.
### Behavior and Interactions
Filename helpers obtain timestamps through misc_helpers, while payload construction uses current_info and process metadata. There are no platform-specific branches or asynchronous operations here. Tests assert preservation of caller-supplied generic-event fields and extension identity plus selected operation-status fields; they do not validate generated metadata or filename matching.

---

## proxy_agent_shared/src/time_buckets.rs

### Purpose and Functionality
Implements a time-windowed count accumulator that expires entire buckets. It uses SystemTime and caller-provided bucket duration and maximum age.
### Key Components
Countable defines a count setter. TimeBucketedItem owns the original item and a VecDeque of bucket-start timestamps and u64 counts. Construction creates one bucket with count one, independently of the item's stored count. to_item requires Clone and Countable.
### Behavior and Interactions
add_one prunes expired front buckets, then increments the newest bucket while its age is below the bucket duration; otherwise it appends a bucket and returns true. Pruning removes buckets whose age is at least the maximum age. If the clock moves backward, pruning treats the duration error as maximum age and expires that front bucket; the increment check instead treats an error as zero elapsed time. Count lookup and is_empty also prune, requiring mutable access. to_item clones the base item and replaces its count with the surviving total. Tests assert initial count, same-bucket increments, rollover, expiration, emptiness, clone field preservation, and accumulation across buckets. There are no asynchronous or platform-gated paths.

---

## proxy_agent_shared/src/version.rs

### Purpose and Functionality
Defines a platform-independent version value with required unsigned major and minor components and optional unsigned build and revision components. Version supports cloning, debugging, equality, construction, parsing, and display; it does not implement full version ordering.
### Key Components
Version constructors progressively accept additional components. major_at_least compares only the major component against its argument, deliberately ignoring minor, build, and revision. from_string consumes an owned string and accepts two through four dot-separated components. Invalid component counts produce InvalidString errors; invalid major or minor values produce their respective ParseVersion errors through the crate's Result type.
### Behavior and Interactions
Malformed optional build or revision components become None rather than failing parsing. Revision parsing is independent of build validity, so a parsed revision can exist without a build. Display always emits major and minor, appends build when present, and emits revision only when build is also present. Consequently, display can omit a stored revision. Unit tests assert two-component and three-component parsing, rejection of a single-component input, and major-only threshold behavior for equal, greater, and smaller major versions.

---

## proxy_agent_shared/src/windows.rs

### Purpose and Functionality
Provides Windows-only registry, system-information, service, executable-version, signing, and process-resource utilities; non-Windows builds exclude this module.
### Key Components
Registry helpers operate under HKLM, creating keys for writes and enumerating names. Integer reads print errors and return supplied defaults; string reads silently return defaults. Child-key deletion ignores deletion failures after opening its parent. OS-version discovery requires parseable major/minor values but tolerates missing build/revision; product naming adjusts Windows 10 branding for Windows 11 builds. Helpers report architecture, processor count, and physical memory, extract product versions from existing absolute files, and start stopped services without waiting for readiness.
### Behavior and Interactions
Signing hex-decodes a key, computes HMAC-SHA256 through BCrypt, destroys hash handles, and returns hex or typed errors. Resource limiting validates CPU percentages, configures a 3% minimum and requested maximum, optionally sets working-set and committed-memory limits, rejects already-jobbed processes, and assigns a job. Failure paths attempt handle cleanup; callers own successful job/process handles and must close them. Tests assert registry operations, system/version results, and file product major version. The resource-limit test logs failures without failing. Native failures generally propagate through crate errors.

---

## proxy_agent_shared/src/windows_events.rs

### Purpose and Functionality
Serves as the Windows eventing module root, declaring submodules for real-time ETW listening, Windows Event Log subscriptions, queries, writing, and shared event models. The crate exposes this module only when compiling for Windows; this file supplies no Linux implementation.
### Key Components
Besides module declarations and imports, its only function is to_wide. This helper borrows a Rust string and returns an owned vector of UTF-16 code units using Windows OsStrExt encoding, with a terminating zero appended for native Windows APIs.
### Behavior and Interactions
The returned vector owns the backing storage, so callers must retain it while native APIs use pointers into it. Conversion has no Result-based error path and does not reject embedded zero characters. The file contains no event-processing implementation, asynchronous synchronization, or tests; those responsibilities reside in its declared submodules.

---
