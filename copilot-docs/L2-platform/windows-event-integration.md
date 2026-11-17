**TL;DR:** Windows-only shared eventing consumes real-time ETW and Windows Event Log subscriptions, queries historical Event Log records, and writes redacted messages through a worker thread. Consumers share owned event models, but cancellation, handle ownership, and delivery guarantees differ by backend.

# Windows Event Integration

<!-- TIER2-POINTER:BEGIN (managed by step8_inject_tier2_pointer.py) -->
> **Need a specific class, method, error code, config key, or flow step?**
> Read `intermediate-docs/L2-platform/windows-event-integration.content.md` for implementation details; stay here for overviews.
> Search the companion for the source-file heading and range-read that section, starting with Purpose and Functionality.
> Verify behavior in source when needed; do not load the entire companion.
<!-- TIER2-POINTER:END -->

## Why

Agent diagnostics need Windows-native capture and output without blocking Tokio
workers on trace processing or Event Log writes. Shared models normalize records
for callbacks and telemetry; they do not make tracing, subscriptions, historical
queries, and logging interchangeable or guarantee delivery.

## What

### Code Pointers

Paths are repository-relative; Key Classes includes Rust types and functions.

| Component | File Path | Key Classes |
|---|---|---|
| Real-time ETW | `proxy_agent_shared\src\windows_events\etw_listener.rs` | `EtwListener`, `EtwProvider`, `parse_guid_string`, `resolve_provider_name`, `parse_level` |
| Event Log subscriptions | `proxy_agent_shared\src\windows_events\evt_listener.rs` | `EvtListener`, `SourceFilter`, `SubscriptionContext`, `xpath_literal` |
| Historical Event Log queries | `proxy_agent_shared\src\windows_events\evt_query.rs` | `WindowsEventReader`, `build_query` |
| Event Log output | `proxy_agent_shared\src\windows_events\evt_writer.rs` | `WindowsEventWriter`, `EventLogMessage`, `run_event_writer` |
| Normalized and XML records | `proxy_agent_shared\src\windows_events\models.rs` | `WindowsEvent`, `EvtEvent`, `System`, `Provider`, `EventData`, `Data`, `UserData` |

### Choose the appropriate surface

| Need | Entry points | Execution and ownership |
|---|---|---|
| Live ETW providers | `EtwListener::add_provider`, `add_provider_by_event_ids`, `run`, `run_with_handler` | Named OS thread; process-global stop flag and active consumer handle |
| Live channel events, optionally replaying existing records | `EvtListener::subscribe_with_handler`, `subscribe_by_sources_with_handler`, `subscribe_by_sources` | OS thread-pool callbacks; subscriptions retained in a process-wide registry |
| Historical records | `WindowsEventReader::new`, `Iterator::next` | Synchronous, newest-first iteration; query and current record handles owned by reader |
| Local Event Log writes | `WindowsEventWriter::new`, `write`, `write_with_event_id` | Nonblocking enqueue to a dedicated worker; writer drop drains and joins |

The enclosing `windows_events` module is excluded on non-Windows platforms.
`WindowsEvent` is the normalized consumer record; `EvtEvent` and its supporting
types represent Event Log XML.

## How

### Capture and normalize

ETW resolves providers from GUID strings or case-insensitive registered names.
Configuration includes levels and optional event-ID filters capped at 64 entries.
`EtwListener::run_with_handler` clones configuration into a worker; no providers
or thread-spawn failure returns an immediate error, while later tracing failures
are logged. Startup stops a stale same-named session. Provider-enable failures
are logged, and unexpectedly ended consumers reopen after a delay.

ETW callbacks recover a boxed handler through native context and catch panics at
the FFI boundary. TDH supplies names, typed JSON properties, and positional
message substitution. Structures and failed properties are skipped; missing
schemas fall back to hexadecimal payloads. Decoding handles timestamps, SIDs,
strings, numbers, and pointer-width-dependent values.

Event Log subscriptions combine `SourceFilter` publisher/event-ID predicates
with OR; empty filters select all events. `xpath_literal` escapes embedded
quotation marks and is reused by historical queries. Subscription options
distinguish existing-record replay from future-only delivery.

Subscription callbacks render XML, deserialize `EvtEvent`, flatten named or
positional `EventData` and provider-defined `UserData`, then attempt publisher
manifest message formatting. Conversion supplies channel, timestamp, keyword,
and identity fallbacks. Handlers receive owned `WindowsEvent` values; default
routing can enqueue them for telemetry.

`WindowsEvent::get_message` selects nonempty formatted text, then nonempty
properties, then raw user data, otherwise an empty string. A sole string property
is returned directly; other maps use compact JSON, with serialization failure
yielding no property message. `get_level_string` maps severity to standard Windows
names or an unknown fallback. XML Serde defaults accommodate absent classic-event
metadata; `UserData` preserves nested ordered fields, including attributes.

### Query historical records

`WindowsEventReader::new` accepts a channel, publisher, and optional UTC start/end
bounds. `build_query` applies publisher filtering and inclusive timestamp bounds
at millisecond precision inside the Event Log service, not after fetching.

Each `WindowsEventReader::next` closes the previous record and requests one event.
XML rendering probes buffer size, allocates UTF-16 storage, and deserializes
`EvtEvent`. Exhaustion returns `None`; other fetch/render failures appear as
iterator errors. Malformed XML becomes an `InvalidData` I/O error, including when
an empty render buffer produces an empty string.

### Write without blocking producers

`WindowsEventWriter::new` configures the source registry message-file entry,
creates a bounded 1,024-message channel, and starts a worker. A rendezvous channel
confirms event-source registration before construction succeeds. Registry,
thread creation, registration, and startup-channel errors propagate.

Writes own their text, truncate at a character boundary within a 32-KiB byte
limit, and enqueue without blocking. Queue failures print to standard error.
Trace, debug, and info map to informational Event Log severity. The worker
serially redacts secrets, converts messages to UTF-16, and calls `ReportEventW`;
its return value is not checked. Successful enqueueing is not proof of OS delivery.

### Preserve backend-specific shutdown

| Backend | Shutdown and failure contract |
|---|---|
| ETW | `etw_listener::stop` uses process-global sequentially consistent atomics and closes the active consumer without joining. Do not treat listeners as independently cancellable. Cleanup disables providers and stops the session. |
| Subscriptions | Subscription failure reclaims context and returns a Windows API error; delivery/render/parse failures warn. `evt_listener::stop` drains the registry, recovering poisoned locks, and drops listeners outside the mutex. Drop closes each subscription before reclaiming callback context; publisher metadata handles are also closed. |
| Historical reader | Drop closes the outstanding event and query handles; at most one current event handle is retained. |
| Writer | Drop disconnects the sender and joins the worker, allowing queued messages to drain before event-source deregistration. |

### Existing evidence and limits

The companion describes ETW helper tests for GUIDs, level fallback, numeric and
Unicode decoding, message substitution, and epoch formatting, not live tracing
or cancellation. Model tests cover classic positional data, named payloads,
provider/correlation/security identities, and generic `UserData`.

The writer integration test asserts subscription delivery and historical reads
with unbounded, start-only, end-only, and bounded time queries, then attempts
registry cleanup. The query module defines no tests of its own. These are source
test descriptions, not evidence that Windows integration tests ran for this doc.

## Related Components

| Component | Navigation | Relationship |
|---|---|---|
| Telemetry delivery | [Telemetry event delivery](telemetry-event-delivery.md) | Listener defaults can forward normalized Windows events into the shared telemetry queue. |
| Shared platform utilities | [Cross-platform service utilities](cross-platform-service-utilities.md) | Windows-only module exposure, UTF-16 helper, and diagnostic logging integration. |
| Secret redaction | [Secrets redactor](..\..\proxy_agent_shared\src\secrets_redactor.rs) | Blocking sanitation occurs on the Event Log writer backend before OS output. |
