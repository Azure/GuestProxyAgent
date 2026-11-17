**TL;DR:** The agent runs secure-channel polling alongside an owned listener/redirector pair, coordinating keys, authorization policy, provisioning, and reporting through shared state. Runtime ownership, listener health, desired port, and provisioning readiness are separate states; cancellation initiates cleanup rather than guaranteeing synchronous shutdown.

# Agent Runtime Orchestration


<!-- TIER2-POINTER:BEGIN (managed by step8_inject_tier2_pointer.py) -->
> **Need a specific class, method, error code, config key, or flow step?**
> Read `intermediate-docs/L3-flows/agent-runtime-orchestration.content.md` for implementation details; stay here for overviews.
> Search the companion for the source-file heading and range-read that section, starting with Purpose and Functionality.
> Verify behavior in source when needed; do not load the entire companion.
<!-- TIER2-POINTER:END -->
## Why

Host policy and secure-channel state can change while the agent is serving
traffic. Orchestration must reconcile listener ports and soft-audit transitions
without losing resource ownership, prematurely enabling redirection, or tying
service-wide reporting to a replaceable listener runtime.

## What

| Responsibility | Owner and boundary |
|---|---|
| Process/service entry | `main`, `async_main`, and service adapters select CLI, console, or OS-service operation |
| Shared state | `SharedState` supplies cloned handles and shared cancellation, not transactional updates or worker joins |
| Secure-channel control | `KeyKeeper` polls WireServer, persists/attests keys, resolves policy, and publishes desired runtime settings |
| Runtime pair | `RuntimeCoordinator` owns listener threads and redirector tasks, including replacement and teardown |
| Readiness/reporting | Provisioning combines redirector, key-latch, and listener readiness; reporting uses the service runtime |
| Kernel integration | `Redirector` manages platform BPF objects, policies, audits, and alert tasks |

### Code Pointers

Paths are repository-relative; Key Classes includes Rust types and functions.

| Component | File Path | Key Classes |
|---|---|---|
| Executable dispatch | `proxy_agent\src\main.rs` | `main`, `async_main` |
| Service lifecycle | `proxy_agent\src\service.rs` | `start_service`, `start_service_wait`, `stop_service` |
| Windows SCM adapter | `proxy_agent\src\service\windows_main.rs` | `run_service` |
| Runtime pair ownership | `proxy_agent\src\runtime_coordinator.rs` | `RuntimeCoordinator`, `PairAction`, `evaluate_status`, `starting_timed_out` |
| Shared handles | `proxy_agent\src\shared_state.rs` | `SharedState`, `EventThreadsSharedState` |
| Common module routing | `proxy_agent\src\common.rs` | Module exports only; Windows key-storage re-exports |
| Key/policy controller | `proxy_agent\src\key_keeper.rs` | `KeyKeeper`, `KeyKeeper::poll_secure_channel_status` |
| Host payloads and matching | `proxy_agent\src\key_keeper\key.rs` | `Key`, `KeyStatus`, `Privilege`, `RuleIdDescriptor` |
| Local policy overlay | `proxy_agent\src\key_keeper\local_rules.rs` | `LocalRuleTarget`, `LocalRuleFileState`, `LocalRuleMonitorState`, `LocalAuthorizationRulesFile` |
| Readiness and status query | `proxy_agent\src\provision.rs` | `ProvisionFlags`, `ProvisionStateInternal`, `ProvisionQuery`, `start_event_threads` |
| Health reporting | `proxy_agent\src\proxy_agent_status.rs` | `ProxyAgentStatusTask` |
| Process/user claims | `proxy_agent\src\proxy.rs` | `Claims`, `Process`, `User`, `get_user` |
| Canonical request pipeline | `proxy_agent\src\proxy\canonical\mod.rs` | `CanonicalRequest`, `CanonError`, `CanonicalMode`, `canonicalize` |
| Redirector lifecycle | `proxy_agent\src\redirector.rs` | `Redirector`, `AuditEntry`, `EventTaskRuntime` |
| Linux BPF backend | `proxy_agent\src\redirector\linux.rs` | `BpfObject`, `LinuxAuditMapValue` |
| Shared Rust BPF layouts | `proxy_agent\src\redirector\shared_ebpf.rs` | `_destination_entry`, `sock_addr_audit_key`, `sock_addr_audit_entry`, `alert_only_event` |
| Windows BPF facade | `proxy_agent\src\redirector\windows.rs` | `BpfObject`, `AuditKeyEntry`, `AuditValueEntry` |
| Windows DLL bindings | `proxy_agent\src\redirector\windows\bpf_api.rs` | `try_load_ebpf_api`; dynamic API wrappers |
| Native declarations | `proxy_agent\src\redirector\windows\bpf_obj.rs` | `ebpf_link_t`, `ring_buffer`; native layout declarations |
| Windows BPF operations | `proxy_agent\src\redirector\windows\bpf_prog.rs` | `BpfObject` loading, attachment, map, and alert operations |
| Directory hardening dispatch | `proxy_agent\src\acl.rs` | `acl_directory` |
| Linux directory hardening | `proxy_agent\src\acl\linux_acl.rs` | `acl_directory` |
| Windows directory hardening | `proxy_agent\src\acl\windows_acl.rs` | `acl_directory` |

## How

### 1. Enter and launch independent control loops

`main` creates a multithreaded Tokio runtime; `async_main` initializes elapsed
time and dispatches CLI options. Provisioning queries exit 1 when unfinished,
2 when finished with an error, and normally on success. Console mode starts
shared state and waits synchronously for Enter before requesting shutdown.

`start_service` initializes logging, spawns `KeyKeeper` polling, and starts the
coordinator without retaining their join handles. Non-Windows service mode
waits indefinitely. Windows saves the runtime handle for its synchronous service
callback; `run_service` starts workers before registering SCM controls.
ETW setup and default service-failure-action errors are logged, not fatal.

### 2. Acquire keys and resolve effective policy

`KeyKeeper` selects polling, notifications, and cancellation. Unknown state
retries every second during the first five minutes; provisioning has a two-minute
timeout. Disabled/unknown notifications reset readiness and timing, while stable
notifications preserve remaining sleep. Disabled transitions clear the shared key.

For a changed key, local loading is attempted first. Newly acquired keys must be
persisted, read back, checked, and attested before readiness. Persistence errors
propagate into polling retries, but some shared-state publication failures only
warn before readiness proceeds. Windows uses encrypted storage and also hardens
the executable directory; non-Windows persists owner-only JSON.

Local WireServer/IMDS JSON rules refresh on remote, enablement, metadata, or
previous-failure changes. Disabled or missing files retain normalized remote
policy; metadata/parse failures instead deny default access and remove explicit
rules, retaining mode or choosing enforce without remote policy. Reads retry
three times with 50-millisecond delays; semantic validation fails immediately.
Merging preserves remote mode and prefixes local references when both sets exist.
HostGA remains server-only. Descriptors publish desired listener ports and gate
soft audit; malformed descriptors fall back to legacy identifiers.

Status validation is version-dependent; scheme/delivery mismatches accumulate
messages rather than failing validation. Acquisition and signed attestation
require HTTP 200. Redirect-policy updates require proxy provisioning and retry
on failure; identical status events are suppressed.

### 3. Reconcile runtime ownership, ports, and soft audit

The coordinator starts the default pair and reconciles watch updates or a
one-second timer. Port changes take priority over STARTING timeouts and soft
audit; `starting_timed_out` applies a sixty-second limit.

`RuntimeCoordinator::handoff_proxy_server` waits for candidate readiness, but
bind failure or readiness timeout does not itself prevent candidate selection.
With a running redirector, failure to stage its local port discards the candidate;
later policy-update failure does **not** roll selection back. Commit enables
provisioning notifications, replaces the owned runtime, then cancels and joins
the old listener through `spawn_blocking`.

Soft-audit decisions can stop a non-running pair and restart it when disabled;
they do not suppress desired-port reconciliation. Stopped-module messages supply
the fallback reason. Redirector shutdown awaits its startup task before closure.
Coordinator cancellation or status-publisher loss stops both owned modules.

### 4. Attach redirection and correlate caller identity

`Redirector` retries startup up to five times with ten-millisecond delays, loads
and attaches BPF programs, excludes the agent process, stores the object behind
`Arc<Mutex<_>>`, and signals readiness. Provisioning owns destination-policy
activation. Subscription/publication failures can log without failing startup.

| Platform | Resource and compatibility behavior |
|---|---|
| Linux | Aya owns attachments; system BTF is attempted and cgroup discovery can fall back to configuration. Ring-buffer reading uses `AsyncFd`; dropping `Ebpf` detaches links before awaiting event-task shutdown outside the mutex. Policy map mutations can log failure yet return true after successful map conversion. |
| Windows | DLL loading prefers the installation path, then system DLL search; version-matched programs are preferred when present. IPv4 attachment is required; absent IPv6 only warns. Canonical and released legacy audit layouts are size-selected; socket redirect context validates returned length. |

Shared peer keys normalize mapped IPv4 and retain full source addresses.
Destination ports use network order; source-port encoding differs by platform.
Linux extended audit records carry executable device/inode validity; legacy
Windows records do not. Preserve layout sizes and decoding boundaries.
Windows native declarations do not enforce pointer lifetime or cleanup; program
load-error paths can leave a newly opened pointer unclosed.

Alert tasks enrich records into `Claims` and rate-limit by user, process,
destination, and family for fifteen minutes. Enrichment failures log unavailable
details. Process command lines remain unredacted for authorization; redaction
belongs before logging. Linux executable matching denies missing identity data.
Canonicalization owns normalized request data and typed failures; parsing
`CanonicalMode` here does not execute rollout decisions.

### 5. Publish readiness and keep reporting independent

Provisioning combines redirector, key-latch, and listener flags. Disabled/unknown
channels are unlatched; key resets recompute completion. Full readiness updates
endpoint policies, records completion, writes tags, and starts reporting.
Missing authorization rules disable redirection; soft audit suppresses
provisioning error messages rather than proving readiness.

Tags use a compatibility marker and temporary-file rename with XML-escaped
errors; filesystem failures log. Five owned reporting-task handles target the
service runtime and survive listener-runtime shutdown; initialization suppresses
repeat startup. Deferred limits apply 15% CPU and, on Windows, 20 MB memory.

`ProvisionQuery` polls localhost with metadata/timestamp/first-attempt headers,
trying a WireServer-discovered port after failure. Expiration returns unfinished.
`ProxyAgentStatusTask` requires key keeper, redirector, and listener running for
overall success; telemetry-logger health is informational. Failed summary reads
log and substitute zero/empty data. Non-Windows status writes attempt mode 0640.

### 6. Cancel without assuming synchronous service teardown

`stop_service` cancels the shared token and stops ETW/event logging, but does not
join workers. Windows SCM Stop reports Stopped immediately without awaiting
cleanup; a missing global status handle can cause successful process exit.
`EventTaskRuntime::shutdown` cancels and joins all owned tasks, returning the first
join error; drop cancels and aborts remaining tasks. Platform redirector teardown
extracts event resources under lock and awaits outside it.

Directory ACL success is not a universal hardening guarantee: the facade skips
missing/non-directory paths; Linux independently attempts root ownership and
0700 permissions but logs failures and returns success. Windows grant/setup
errors propagate after potentially partial modification, while individual
removal failures warn; no rollback exists.

### Evidence boundaries

The supplied summaries describe tests for handoff ownership/old-port reuse,
soft-audit transitions, timeout boundaries, key persistence, local-rule failure
handling, provisioning tags/custom-port queries, reporting survival, audit
layout compatibility, and identity matching. Linux attachment tests require
`test-with-root`; canonical property tests require `proptests`.
Service entry/SCM and Windows binding/program files declare no tests. ACL and
status tests have limited assertions. These are described checks, not test-run
results or proof of end-to-end shutdown/security.

## Related Components

| Component | Navigation | Relationship |
|---|---|---|
| State actors | [Agent shared-state access](..\L1-conceptual\agent-shared-state-access.md) | Async state ownership, runtime snapshots, and captured service-runtime handle |
| Kernel interception | [eBPF socket redirection](..\L2-platform\ebpf-socket-redirection.md) | Kernel policy/audit ABI consumed by user-mode loaders |
| Authorization normalization | [Authorization canonicalization](..\L2-platform\authorization-canonicalization.md) | Destination/path/query normalization and privilege matching |
| Platform facilities | [Agent platform utilities](..\L2-platform\agent-platform-utilities.md) | Configuration, logging, identity, and key-storage support |
| Telemetry | [Telemetry event delivery](..\L2-platform\telemetry-event-delivery.md) | Event/status reporting downstream of provisioning |
