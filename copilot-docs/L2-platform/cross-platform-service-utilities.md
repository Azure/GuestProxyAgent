**TL;DR:** `proxy_agent_shared` supplies common service lifecycle, host metadata/HTTP, state, logging, telemetry models, and OS utilities. Its Windows SCM and non-Windows systemd backends share a facade but differ in readiness, error handling, and resource ownership.

# Cross-platform service utilities

<!-- TIER2-POINTER:BEGIN (managed by step8_inject_tier2_pointer.py) -->
> **Need a specific class, method, error code, config key, or flow step?**
> Read `intermediate-docs/L2-platform/cross-platform-service-utilities.content.md` for implementation details; stay here for overviews.
> Search the companion for the source-file heading and range-read that section, starting with Purpose and Functionality.
> Verify behavior in source when needed; do not load the entire companion.
<!-- TIER2-POINTER:END -->

## Why

Agent consumers need consistent service inspection, host identity, diagnostics, and persistence without duplicating platform integration. This crate centralizes those primitives; it does not make all operations asynchronous, enforce retries everywhere, or guarantee equivalent platform behavior.

## What

| Responsibility | Shared contract |
|---|---|
| Service lifecycle | Install, start, stop, remove, update, and inspect through `service`; expose `ServiceRuntimeStatus`. |
| Host communication | Fetch goal state, shared configuration, and IMDS models; submit telemetry through shared HTTP helpers. |
| Shared state | Serialize VM metadata and string-keyed values in a cancellable actor; share telemetry notification. |
| Diagnostics | Named rolling loggers, independently filtered system output, blocking secret redaction, and telemetry payloads. |
| System utilities | Cached machine information, OS integration, signing, encoding, atomic-style JSON replacement, timestamps, and versions. |
| Status and counts | HTTP-first aggregate-status retrieval with file fallback; expiring bucketed connection counts. |

### Code Pointers

Paths are repository-relative. Key Classes includes Rust types, modules, and function entry points.

| Component | File Path | Key Classes |
|---|---|---|
| Crate surface | `proxy_agent_shared\src\lib.rs` | `common_state`, `service`, `host_clients`, `telemetry`, `windows_events` |
| Actor state | `proxy_agent_shared\src\common_state.rs` | `CommonState`, `CommonStateAction`, `CommonState::start_new`, `CommonState::update_vm_meta_data` |
| Cached system facts | `proxy_agent_shared\src\current_info.rs` | `current_info` getters |
| Errors and result | `proxy_agent_shared\src\error.rs`; `proxy_agent_shared\src\result.rs` | `Error`, `HyperErrorType`, `CommandErrorType`, `WireServerErrorType`, `ParseVersionErrorType`, `Result<T>` |
| Host module surface | `proxy_agent_shared\src\host_clients.rs` | `goal_state`, `instance_info`, `imds_client`, `wire_server_client` |
| XML models | `proxy_agent_shared\src\host_clients\goal_state.rs` | `GoalState`, `SharedConfig` |
| IMDS model | `proxy_agent_shared\src\host_clients\instance_info.rs` | `InstanceInfo`, `ComputeInfo`, `InstanceInfo::get_image_origin` |
| IMDS client | `proxy_agent_shared\src\host_clients\imds_client.rs` | `ImdsClient`, `ImdsClient::get_imds_instance_info` |
| Wire-server client | `proxy_agent_shared\src\host_clients\wire_server_client.rs` | `WireServerClient`, `send_telemetry_data`, `get_goalstate`, `get_shared_config` |
| HTTP and signing input | `proxy_agent_shared\src\hyper_client.rs` | `HostEndpoint`, `hyper_client::get` |
| Service facade | `proxy_agent_shared\src\service.rs` | `ServiceRuntimeStatus`, `check_service_status` |
| systemd backend | `proxy_agent_shared\src\service\linux_service.rs` | `start_service`, `query_service_executable_path` |
| SCM backend | `proxy_agent_shared\src\service\windows_service.rs` | `ServiceStatusInfo` |
| Non-Windows integration | `proxy_agent_shared\src\linux.rs` | `FileMount`, `FileSystem`, `MemStatus` |
| Windows integration | `proxy_agent_shared\src\windows.rs` | `windows` registry, signing, system-information, and resource-limit helpers |
| Windows eventing surface | `proxy_agent_shared\src\windows_events.rs` | `windows_events`, `to_wide` |
| Logging facade | `proxy_agent_shared\src\logger.rs` | `LoggerLevel`, `init_loggers`, `get_log_header` |
| Logger routing | `proxy_agent_shared\src\logger\logger_manager.rs` | `set_loggers`, `write_many` |
| File logging | `proxy_agent_shared\src\logger\rolling_logger.rs` | `RollingLogger` |
| General helpers | `proxy_agent_shared\src\misc_helpers.rs` | `HostTimeSyncState`, `TextEncoding`, `DetectedEncoding`, `CommandOutput` |
| Aggregate status | `proxy_agent_shared\src\proxy_agent_aggregate_status.rs` | `GuestProxyAgentAggregateStatus`, `ProxyAgentStatus`, `ProxyConnectionSummary`, `ModuleState`, `OverallState` |
| Redaction | `proxy_agent_shared\src\secrets_redactor.rs` | `RedactionPattern`, `RedactionRequest` |
| Local HTTP fixture | `proxy_agent_shared\src\server_mock.rs` | `start_internal`, `handle_request`, `set_secure_channel_state` |
| Telemetry contracts | `proxy_agent_shared\src\telemetry.rs` | `Event`, `Extension`, `OperationStatus`, `ExtensionStatusEvent` |
| Expiring counts | `proxy_agent_shared\src\time_buckets.rs` | `Countable`, `TimeBucketedItem`, `TimeBucketedItem::to_item` |
| Version values | `proxy_agent_shared\src\version.rs` | `Version`, `Version::from_string`, `Version::major_at_least` |

## How

### Select and operate the service backend

`lib.rs` exposes Windows modules only under `cfg(windows)`; `linux` and the non-Windows service backend use `cfg(not(windows))`, not an explicit Linux-only gate. Async facade signatures do not imply nonblocking backend work.

| Operation | Windows SCM | Non-Windows systemd |
|---|---|---|
| Install | Update existing service or attempt creation after any status-query error; automatic-start LocalSystem own-process service, supplied dependencies, no arguments. | Unmask, daemon-reload, enable; ignore executable, display name, and dependency inputs. |
| Start | Accept already-running; otherwise start, asynchronously wait one second, and query. Retry wrapper requires Running and errors on exhaustion. | Synchronous `systemctl`; reject unsuccessful start status; ignore facade retry parameters. |
| Stop/remove | Stop only Running services; log stop-request failures and re-query. Delete without proving Stopped; facade discards detailed stop status. | Stop before uninstall; disable and remove unit file. Removal failure logs but returns success; successful removal triggers reload. |
| Update | Reconfigure through SCM. Creation also configures restart delays of 15/60/120 seconds with a 30-minute reset. | Print unsupported-operation message and return success. |
| Inspect | Query failure becomes not-installed; configuration failure retains runtime state with unknown start type. Normalize binary path and cache optional product version. | Require a regular unit file, then query active/enabled state. Execution errors log and yield unknown fields. |

Windows start/continue-pending states are transitioning; other non-running states are down. Non-Windows `activating` is transitioning and `deactivating` is already down. Do not equate an installed service, a successful command invocation, and readiness.

Non-Windows stop/unmask/enable/disable/reload do not independently reject unsuccessful exit statuses. Executable-path inspection retries failed results or unparseable `ExecStart` output three times with blocking one-second delays; execution errors propagate immediately.

### Fetch host identity and coordinate consumers

1. `CommonState::start_new` spawns an actor owning optional VM metadata, a string map, and shared `Notify`. A bounded 100-message channel and oneshot acknowledgements serialize access; getters clone values.
2. Cancellation or channel closure stops the actor. Send/receive failures become typed errors; abandoned response receivers warn. Token access clones the shared cancellation token; telemetry notification wakes one waiter.
3. `CommonState::update_vm_meta_data` treats secure-key lookup errors as absent keys, then sequentially fetches goal state, shared configuration, and IMDS. Fetch/update failures propagate.
4. Clients accept host/port inputs. IMDS requests use the required `Metadata` header; shared-configuration destinations come from the supplied full URI, not necessarily the wire-server client's address.
5. Wire-server retrieval wraps failures by operation. Telemetry is an unsigned XML POST, accepts any successful status, and skips requests for empty input. These clients add no retries or persistent connection state.

`GoalState` directly indexes the first role instance and can panic on an empty list; `SharedConfig` returns an empty instance name instead. `InstanceInfo::get_image_origin` reports platform origin only for a present, nonempty offer.

### Preserve HTTP, signing, and decoding semantics

| Boundary | Behavior and caution |
|---|---|
| Transport | `HostEndpoint` selects port 443 for HTTPS URIs, but transport remains plain TCP and display emits HTTP; this is not TLS support. A spawned task drives each HTTP/1 connection and reports failures through a callback. |
| Request construction | Add date, host, root-claim, and content-length headers; copy raw body bytes into an owned body. Sign only with the signing feature and both key inputs. |
| Canonicalization | Sort lowercase headers with trimmed values, omit authorization, and reject duplicate/non-text headers. Preserve query encoding; lowercase query names and sort concatenated name/value keys, with possible collisions. |
| Response handling | GET rejects unsuccessful status; content type selects XML, otherwise JSON. Deserialization errors include response text. |
| HTTP text decoding | Default UTF-8 is lossy; little-endian UTF-16 does not guard odd chunk lengths; UTF-32 is rejected. This differs from strict filesystem decoding in `misc_helpers`. |
| Host time | Prefer the custom date header; valid header text containing an invalid date prevents fallback. `HostTimeSyncState` advances host UTC using monotonic elapsed time, falling back to local UTC when unavailable. |

### Emit diagnostics and status

Logger initialization stores configuration without opening files. Process-wide cells initialize once and non-atomically; later map replacements are ignored, and a supplied map missing its default key panics. File filtering defaults to Trace and system filtering to Error. Unknown logger keys omit file output.

Single-message logging attempts system output before file filtering; `write_many` bypasses severity filtering and system output. Windows additionally uses its event writer. `RollingLogger` checks rotation before writes, compares limits in **bytes**, and can overshoot on a message/batch. It owns no persistent handles or synchronization locks; a second open failure during writing can be silently ignored.

Secret redaction is a **blocking**, serialized worker-thread API for noncritical consumer paths, not proxied requests. Indicator scans may bypass regexes and include case-sensitive checks. Regex compilation failures are skipped; public worker startup/channel failures panic. Caches reset hourly or at 2.5 MB per cache.

Telemetry models add executable version, process/thread identity, and timestamps to caller-owned fields. Generic and extension filenames use distinct anchored nanosecond-based JSON patterns; sending, reading, and span implementations reside in exposed submodules, not this model file.

Aggregate-status retrieval tries HTTP with a metadata header, then synchronously reads the supplied JSON file. Success identifies server versus file; failure preserves both diagnostics. Missing connection address-family fields default to IPv4. `ModuleState` considers only Running and Stopped ultimate.

### Use platform and data helpers deliberately

| Utility | Contract to preserve |
|---|---|
| Cached information | `current_info` lazily caches machine facts and executable version process-wide; Windows memory-query failure logs and becomes zero. These getters do not refresh measurements. |
| Non-Windows helpers | Cache OS information; parse `findmnt` JSON and process memory fields. Missing/malformed memory values remain `None`; CPU-quota command execution errors propagate, but exit status is not checked. Unix permission failures propagate. |
| Windows helpers | Registry reads may return caller defaults; child deletion failures are ignored. Successful resource-limit job/process handles belong to callers and require closing; failure paths attempt cleanup. Starting a stopped service here does not wait for readiness. |
| Signing | Windows BCrypt and feature-gated non-Windows OpenSSL implement hex-key HMAC-SHA256 with hex output and typed failures. |
| Persistence/encoding | Sync and Tokio JSON writers write temporary files then rename. File decoding rejects invalid scalars, unpaired surrogates, and truncated units; BOM-less detection assumes initial ASCII. Directory existence-check failure can panic. |
| Commands/versions | `CommandOutput` owns status and lossy streams; version probing rejects unsuccessful commands. `Version` accepts 2-4 unsigned components, tolerates malformed optional fields, and compares only major in `major_at_least`; a revision without build is omitted by display. |
| Counts | `TimeBucketedItem` begins at one regardless of stored item count, expires whole buckets, and prunes on reads. Backward clock movement expires front buckets during pruning but counts as zero elapsed during increment checks. |
| Windows eventing | The root only declares event submodules and `to_wide`; retain returned UTF-16 storage while native pointers are used. Embedded zeros are not rejected. |
| Errors | `Error`/`Result<T>` classify and format failures; they provide no automatic logging, retry, or recovery. |

### Existing test evidence and limits

The companion describes assertions, not executed results: actor state/metadata, HTTP canonicalization and mock exchanges, strict encoding/time helpers, logger retention, status fallback models, redaction concurrency/cache reset, service mappings, versions, and bucket expiration.

Some checks are weaker: cgroup discovery and Windows resource-limit tests can log failures without failing. `server_mock` is publicly exported outside test builds; it returns HTTP 200 even for unmatched routes, uses unsynchronized unsafe global channel state, and cancels acceptance without joining existing connections. Mock success does not establish production transport, lifecycle, or concurrency safety.

## Related components

| Component | Relationship |
|---|---|
| [Agent platform utilities](agent-platform-utilities.md) | Agent-side configuration and diagnostic wrappers consume shared logging, errors, and OS helpers. |
| [Agent shared-state access](../L1-conceptual/agent-shared-state-access.md) | Agent actors coordinate runtime/signing state alongside shared `CommonState` metadata and notification. |
| [Authorization canonicalization](authorization-canonicalization.md) | Related request-identity component; do not assume its canonical form is interchangeable with shared HTTP signing canonicalization. |
| [Telemetry submodules](..\..\proxy_agent_shared\src\telemetry) | Follow here for logger, reader, sender, span, and telemetry-event implementation beyond payload contracts. |
| [Windows eventing submodules](..\..\proxy_agent_shared\src\windows_events) | Follow here for ETW listening, Event Log subscription/query/writing, and event models. |
