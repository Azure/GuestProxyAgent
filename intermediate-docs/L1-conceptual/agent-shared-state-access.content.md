# Compose Content for: L1-conceptual/agent-shared-state-access.md

Total files: 7

---

## proxy_agent/src/shared_state/access_control_wrapper.rs

### Purpose and Functionality
Serializes storage and retrieval of computed authorization rules for WireServer, IMDS, and HostGAPlugin endpoints through an asynchronous actor.
### Key Components
AccessControlAction defines endpoint-specific set and get messages with typed oneshot replies. AccessControlSharedState is a clonable bounded MPSC sender. start_new spawns a task that exclusively owns three optional rule values, initially absent, and processes messages sequentially through a channel with capacity one hundred.
### Behavior and Interactions
Setters convert optional AuthorizationItem values into ComputedAuthorizationItem before enqueueing and await acknowledgement after replacement; passing None clears the selected endpoint. Getters request cloned computed rules, preserving actor ownership. Awaited sends provide backpressure. Sending failures become Error::SendError, and lost replies become Error::RecvError. The WireServer and HostGA setters label receive errors with their corresponding get-action names. The actor logs warnings if a response receiver has disappeared and continues processing; it exits when all senders are dropped and the channel drains. There is no explicit cancellation-token branch. The Tokio test checks WireServer allow/audit conversion, matching identifiers, and empty computed collections, then IMDS deny/enforce conversion. It does not exercise HostGA, clearing, or channel failures.

---

## proxy_agent/src/shared_state/agent_status_wrapper.rs

### Purpose and Functionality
Maintains module health, listener status, connection counters, soft-audit mode, and fallback reasons through a platform-independent asynchronous actor. Conditional compilation adds tests and status counting.
### Key Components
AgentStatusSharedState holds a bounded Tokio mpsc sender and watch receiver. The spawned task exclusively owns mutable state; oneshot channels carry replies. AgentStatusAction defines requests, AgentStatusModule identifies modules, and ModuleStatus defaults to unknown. RuntimeStatusSnapshot exposes desired-port listener and redirector states, audit mode, and readiness predicates.
### Behavior and Interactions
ProxyServer aliases the desired listener. Reads never insert entries. Non-desired listeners survive only while STARTING or RUNNING; untracked messages are logged without retention. Port changes prune inactive listeners and update snapshots. Changed messages emit warning telemetry. HTTP and TCP counters wrap independently. Fallback reasons require soft-audit mode and reset when disabled. Channel failures become SendError or RecvError; abandoned replies are logged. Aggregate status reads instead log failures and return unknown. Messages exceeding 1024 bytes are sliced there, potentially panicking across UTF-8 boundaries. Tests assert bounded retention, listener restart, alias consistency during concurrent port switching, snapshot notifications, counter increments, and fallback reset.

---

## proxy_agent/src/shared_state/connection_summary_wrapper.rs

### Purpose and Functionality
Collects successful and failed proxy connection summaries in separate time-bucketed aggregates for later status reporting. Both paths use fifteen-minute buckets with a four-hour maximum age. Production behavior has no Windows/Linux conditional branches; tests are compiled separately.
### Key Components
ConnectionSummaryAction describes additions, collection requests, and explicit clearing. ConnectionSummarySharedState is a cloneable bounded Tokio mpsc sender. A spawned task exclusively owns two hash maps keyed by ProxySummary::to_key_string, each containing TimeBucketedItem<ProxyConnectionSummary> values. Reads and clearing use oneshot replies; additions acknowledge only successful enqueueing.
### Behavior and Interactions
Before computing keys or storing summaries, the actor redacts possible secrets from process command lines. New keys initialize aggregates; existing keys increment bucket counts. New buckets emit informational connection telemetry when JSON serialization succeeds; serialization failures silently omit that event. Collection removes empty aggregates and materializes current summaries. Clearing empties both maps. Public methods propagate channel send and receive errors using repository error types; failed response delivery logs warnings. The test asserts an initial successful count, failed-summary retrieval, different keys for IPv4 versus IPv6, IPv6 address-family serialization, and an empty successful-summary collection after clearing.

---

## proxy_agent/src/shared_state/key_keeper_wrapper.rs

### Purpose and Functionality
Provides asynchronous access to the signing key, secure-channel state, and WireServer, IMDS, and HostGA rule identifiers. This platform-independent wrapper stores state rather than fetching keys or evaluating rules.
### Key Components
KeyKeeperSharedState is a cloneable sender handle. KeyKeeperAction describes requests processed by a spawned Tokio task through a bounded, 100-entry MPSC channel. The task owns an optional Key, an initially unknown channel state, initially empty rule identifiers, and an Arc-backed Notify. Each request carries a oneshot response channel.
### Behavior and Interactions
Key reads clone the stored key and expose its value, identifier, or optional incarnation; clearing removes it. Channel-state updates report whether a change occurred, while rule updates also return the previous identifier. These operations perform separate read and write requests, not atomic compare-and-set operations. Notification obtains the shared Notify and wakes one waiter. Send and receive failures become contextual SendError or RecvError results; abandoned responses generate warnings. The actor exits when its sender channel closes. Tests assert key round-tripping and clearing, channel-state retrieval, and rule changes from initially empty identifiers.

---

## proxy_agent/src/shared_state/provision_wrapper.rs

### Purpose and Functionality
Serializes provisioning readiness, event-log initialization, and completion timestamps. It retains the Tokio runtime handle captured at creation, allowing service-wide work to target that runtime rather than a listener runtime.
### Key Components
ProvisionSharedState contains a cloneable MPSC sender and runtime Handle. ProvisionAction defines requests with typed oneshot replies. A spawned task exclusively owns mutable state and processes a bounded queue of 100 requests. Initial values are no readiness flags, event logging uninitialized, and a zero completion timestamp.
### Behavior and Interactions
Updating readiness ORs in supplied flags; resetting removes supplied flags using bitwise AND with their complement. Both return the resulting flags. Event-log initialization can be marked true and queried, but has no reset action. Marking provisioning finished records the current Unix nanosecond timestamp on each call; marking it unfinished stores zero. Getters return the timestamp, not a boolean. Requests propagate contextual SendError and RecvError values, while failed actor replies are logged as warnings. The task terminates when all senders disappear. This file has no platform gates or executable unit-test module.

---

## proxy_agent/src/shared_state/proxy_server_wrapper.rs

### Purpose and Functionality
Implements an asynchronous proxy-server user cache keyed by logon identifier. Entries expire after five minutes by default, limiting reuse of old user-group information.
### Key Components
ProxyServerSharedState is a cloneable sender to an actor with a bounded, 100-entry Tokio MPSC queue. The actor owns a HashMap of CachedUser records, each containing an owned User and insertion Instant. ProxyServerAction represents insertion, lookup, clearing, and test-only entry counting. A private constructor accepts an alternate lifetime for deterministic expiration tests.
### Behavior and Interactions
Adding a user replaces its logon-identifier entry and refreshes the insertion time. Lookup returns a cloned User only while elapsed time is strictly less than the configured lifetime. Expired entries are removed on lookup; there is no periodic sweep or sliding expiration. Clearing removes every entry. Each operation awaits a oneshot reply and maps channel failures to contextual SendError or RecvError results. Abandoned replies produce warnings, and channel closure ends the actor. Tests assert that zero-lifetime entries return no user and are removed, while unexpired entries preserve group membership and remain counted. No operating-system-specific branches are present.

---

## proxy_agent/src/shared_state/redirector_wrapper.rs

### Purpose and Functionality
Provides asynchronous access to the redirector's local port and optional BPF object. It manages references, not traffic filtering or program loading.
### Key Components
RedirectorSharedState is a cloneable MPSC sender. RedirectorAction carries requests and typed oneshot reply channels. A spawned Tokio actor owns the port, initially zero, and an optional Arc containing a standard Mutex-protected redirector BpfObject, initially absent. The actor processes a bounded queue of 100 requests.
### Behavior and Interactions
Port setters and getters serialize through the actor. Updating the BPF object replaces the stored reference; clearing drops it. Getting clones the Arc without removing the stored object. Taking moves the stored Arc into the reply and replaces the slot with None, but does not invalidate references previously cloned elsewhere. If the take reply cannot be delivered, the slot has already been cleared. The wrapper never locks the BPF object's mutex itself. Channel submission and reply failures propagate as contextual SendError and RecvError results; failed actor replies generate warnings. Closing all senders terminates the task and releases its state. There are no platform gates or unit tests here.

---
