**TL;DR:** Seven Tokio actors serialize shared authorization, signing, health, provisioning, connection-summary, identity-cache, and redirector state. Cloneable handles expose asynchronous requests; serialization is per request, not a transaction across reads, writes, or wrappers.

# Agent Shared-State Access


<!-- TIER2-POINTER:BEGIN (managed by step8_inject_tier2_pointer.py) -->
> **Need a specific class, method, error code, config key, or flow step?**
> Read `intermediate-docs/L1-conceptual/agent-shared-state-access.content.md` for implementation details; stay here for overviews.
> Search the companion for the source-file heading and range-read that section, starting with Purpose and Functionality.
> Verify behavior in source when needed; do not load the entire companion.
<!-- TIER2-POINTER:END -->
## Why

Concurrent agent tasks must exchange mutable state without directly sharing maps,
keys, or lifecycle flags. Each actor exclusively owns its state. These wrappers
store and expose data; they do not authorize requests, fetch keys, provision
resources, or load traffic-filtering programs.

## What

### Code Pointers

Paths are repository-relative; Key Classes includes Rust structs and enums.

| Component | File Path | Key Classes |
|---|---|---|
| Endpoint authorization rules | `proxy_agent\src\shared_state\access_control_wrapper.rs` | `AccessControlSharedState`, `AccessControlAction` |
| Health and runtime snapshots | `proxy_agent\src\shared_state\agent_status_wrapper.rs` | `AgentStatusSharedState`, `AgentStatusAction`, `AgentStatusModule`, `ModuleStatus`, `RuntimeStatusSnapshot` |
| Connection aggregates | `proxy_agent\src\shared_state\connection_summary_wrapper.rs` | `ConnectionSummarySharedState`, `ConnectionSummaryAction` |
| Signing and secure-channel state | `proxy_agent\src\shared_state\key_keeper_wrapper.rs` | `KeyKeeperSharedState`, `KeyKeeperAction` |
| Provisioning readiness | `proxy_agent\src\shared_state\provision_wrapper.rs` | `ProvisionSharedState`, `ProvisionAction` |
| Logon-identity cache | `proxy_agent\src\shared_state\proxy_server_wrapper.rs` | `ProxyServerSharedState`, `ProxyServerAction`, `CachedUser` |
| Redirector references | `proxy_agent\src\shared_state\redirector_wrapper.rs` | `RedirectorSharedState`, `RedirectorAction` |

## How

### Shared actor contract

Each wrapper's `start_new` spawns a task with a bounded, 100-request Tokio MPSC queue.
Awaited sends provide backpressure. Most operations await a typed oneshot reply;
connection-summary additions acknowledge enqueueing only, not processing.
Actors process messages sequentially and end when all senders are dropped and
the queue drains; do not assume an explicit cancellation-token branch.

Submission and reply failures generally propagate as contextual `Error::SendError`
and `Error::RecvError`. Actors warn on abandoned reply receivers and continue.
Status aggregation is an exception: `AgentStatusSharedState::get_module_status`
logs failures and returns unknown status instead of propagating an error.
These wrappers have no production OS-specific branches; referenced platform
resources can still have platform-specific behavior.

### Authorization and signing state

Rules, keys, and rule identifiers live in separate actors; updating one does not
atomically update the others.

| State owner | Initial state | Operations and constraints |
|---|---|---|
| `AccessControlSharedState` | WireServer, IMDS, and HostGAPlugin rules absent | `set_wireserver_rules`, `set_imds_rules`, and `set_hostga_rules` convert `AuthorizationItem` to `ComputedAuthorizationItem` before enqueueing and await replacement. `None` clears rules; getters return clones. |
| `KeyKeeperSharedState` | No key, unknown channel state, empty rule identifiers | Key reads clone stored data; `clear_key` removes it. `update_current_secure_channel_state` reports change; endpoint rule-ID updates also return the previous identifier. These helpers use separate reads/writes, not atomic compare-and-set. `get_notify` shares `Notify`; `notify` wakes one waiter. |

WireServer and HostGA rule setters currently label receive errors with their
corresponding get-action names.

### Health and readiness

`AgentStatusSharedState` tracks module health, listener states, independently
wrapping HTTP/TCP counters, soft-audit mode, and fallback reasons.
`AgentStatusModule::ProxyServer` aliases the desired listener. Reads never insert
entries; non-desired listeners are retained only while STARTING or RUNNING.
Untracked messages are logged without retention, and port changes prune inactive
listeners. Changed messages emit warning telemetry.

`AgentStatusSharedState::subscribe_runtime_status` exposes a watch receiver of `RuntimeStatusSnapshot`,
including desired-port listener/redirector states and readiness predicates such
as `RuntimeStatusSnapshot::both_running`. Fallback reasons require soft-audit mode and reset when it is
disabled. Status messages longer than 1024 bytes are byte-sliced, which can panic
at a non-UTF-8 boundary; do not assume Unicode-safe truncation.

`ProvisionSharedState` retains the runtime handle captured at construction so
service-wide work can target that runtime rather than a listener runtime.
Readiness flags start empty: `ProvisionSharedState::update_one_state` ORs flags
in, while `reset_one_state` removes supplied bits; both return the resulting flags.
Event-log initialization starts false and can only be marked true.
`set_provision_finished` records current Unix nanoseconds on every true call or
zero on false; `get_provision_finished` returns a timestamp, not a Boolean.

### Connection reporting and identity caching

`ConnectionSummarySharedState` maintains separate success/failure maps keyed by
`ProxySummary::to_key_string`, using 15-minute buckets and a four-hour maximum
age. The actor redacts possible command-line secrets before key generation or
storage. Existing keys increment bucket counts; new buckets emit informational
connection telemetry only if JSON serialization succeeds. Serialization failures
silently omit that event. Collection removes empty aggregates and materializes
current summaries; `clear_all_summary` empties both maps.

`ProxyServerSharedState` caches owned `User` records by logon identifier for five
minutes from insertion. `add_user` replaces the entry and refreshes its timestamp;
`get_user` returns a clone only while elapsed time is strictly below the TTL.
Expired entries are removed on lookup, with no periodic sweep or sliding expiry.
`clear_users` removes all cached users.

### Redirector ownership

`RedirectorSharedState` starts with port zero and no BPF object. It stores an
optional `Arc<Mutex<BpfObject>>` but never locks that mutex itself.
`get_bpf_object` clones the reference; `take_bpf_object` empties the stored slot
and transfers its reference. Previously cloned references remain valid. A failed
take reply still leaves the slot empty. Updating replaces the stored reference;
clearing or actor shutdown drops it without invalidating other owners.

### Existing evidence and gaps

The supplied summaries describe tests for WireServer/IMDS rule conversion; listener retention, aliasing,
snapshots, counters and fallback reset; success/failure summaries, IPv4/IPv6 keys
and clearing; key round-trips and rule changes; and user-cache expiry/group retention.
They do not establish HostGA rule conversion, authorization clearing/channel
failures, or complete lifecycle coverage. Provision and redirector wrappers have
no executable unit-test modules in the supplied summaries. This is coverage
description, not evidence that tests were run for this document.

## Related Components

| Component | Navigation | Boundary |
|---|---|---|
| Authorization | [Authorization rules](..\..\proxy_agent\src\proxy\authorization_rules.rs), [authorizer](..\..\proxy_agent\src\proxy\proxy_authorizer.rs) | Rule computation and evaluation, distinct from state storage |
| Key maintenance | [Key keeper](..\..\proxy_agent\src\key_keeper.rs) | Fetches and maintains signing/secure-channel data |
| Proxy consumers | [Proxy server](..\..\proxy_agent\src\proxy\proxy_server.rs), [connection handling](..\..\proxy_agent\src\proxy\proxy_connection.rs) | Consume identity, authorization, signing, and reporting state |
| Runtime lifecycle | [Runtime coordinator](..\..\proxy_agent\src\runtime_coordinator.rs) | Coordinates listener/redirector lifecycle rather than just storing references |
| Secret handling | [Secrets redactor](..\..\proxy_agent_shared\src\secrets_redactor.rs) | Sanitizes command-line data used by connection summaries |
