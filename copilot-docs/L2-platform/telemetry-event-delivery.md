**TL;DR:** Shared telemetry buffers generic logs and extension status in memory or JSON files, then enriches, redacts, and batches them into WireServer XML. Delivery is best-effort: bounded queues, file cleanup, retry exhaustion, and cancellation can lose events.

# Telemetry Event Delivery


<!-- TIER2-POINTER:BEGIN (managed by step8_inject_tier2_pointer.py) -->
> **Need a specific class, method, error code, config key, or flow step?**
> Read `intermediate-docs/L2-platform/telemetry-event-delivery.content.md` for implementation details; stay here for overviews.
> Search the companion for the source-file heading and range-read that section, starting with Purpose and Functionality.
> Verify behavior in source when needed; do not load the entire companion.
<!-- TIER2-POINTER:END -->
## Why

Agent and extension producers need a common reporting path without performing
host requests themselves. Disk-only startup supports callers without a direct
sender; direct-send startup can deliver without disk write permission when the
sender queue accepts events. Disk fallback is not a durable delivery guarantee.

## What

### Code Pointers

Paths are repository-relative; Key Classes includes Rust structs and enums.

| Component | File Path | Key Classes |
|---|---|---|
| Producer buffering and disk fallback | `proxy_agent_shared\src\telemetry\event_logger.rs` | `DirectSendConfig`; module functions `start`, `start_with_direct_send`, `write_event`, `report_extension_status_event` |
| Disk replay | `proxy_agent_shared\src\telemetry\event_reader.rs` | `EventReader`, `EventReaderLimits` |
| Host delivery | `proxy_agent_shared\src\telemetry\event_sender.rs` | `EventSender` |
| Elapsed-time messages | `proxy_agent_shared\src\telemetry\span.rs` | `SimpleSpan`, `ElapsedMessage` |
| Owned records and XML | `proxy_agent_shared\src\telemetry\telemetry_event.rs` | `TelemetryEvent`, `TelemetryGenericLogsEvent`, `TelemetryExtensionEventsEvent`, `TelemetryProvider`, `TelemetryData`, `VmMetaData`, `TelemetryEventVMData`, `KeywordName` |

### Ownership and limits

| Boundary | Contract |
|---|---|
| Logger queue | Global concurrent queue, at most 1,000 generic events; separate from the sender queue |
| Logger configuration | Tokio `OnceCell` directory and direct-send configuration; repeated initialization warns |
| Sender queue | Process-wide concurrent queue, at most 1,000 owned generic/extension records |
| Disk storage | Configurable generic-file cap; extension status capped at 1,000 files |
| Generic replay | Optional file-size and per-round event limits through consuming `EventReaderLimits` builders |
| Wire payload | Serialized XML strictly below 64 KiB; record messages truncated to at most 4,096 bytes at a UTF-8 boundary |

## How

### Produce, route, and persist

`event_logger::write_event` also forwards the original message to file logging;
telemetry producers truncate messages at character boundaries.
`event_logger::start` drains generic events to JSON arrays without referencing
the direct-sender path. `event_logger::start_with_direct_send` first attempts
sender enqueueing and persists only rejected events, preserving their order.
Accepted events trigger a `CommonState` notification; notification failure does
not put them back into disk fallback.

The logger loop invokes asynchronous status callbacks, creates the event
directory, and drains owned events. A zero interval becomes 60 seconds.
At the generic-file cap, drained batches are dropped. File-search errors warn
but permit writing; write failures warn without requeueing.
`event_logger::report_extension_status_event` similarly tries direct enqueueing,
then writes one prefixed JSON file if needed.

Windows-only `event_logger::push_windows_event` requires provider and task names
and preserves Windows event identities and timestamp. Reader, sender, span, and
record logic have no platform-specific branches in the supplied summaries.

### Replay files

`EventReader::start` defaults to a 300-second generic replay interval;
`EventReader::start_extension_status_event_processor` defaults to 60 seconds.
An optional initial 60-second delay precedes cancellation monitoring.
Separate filename regexes keep generic arrays and individual extension-status
records isolated. `EventReader::process_once` exposes one generic replay round.

Generic limits are checked between files, so one file can exceed the round event
limit. Counts measure deserialized events, not successful enqueues. Metadata
failures retain files; oversized generic files are deleted. Generic array
events are popped in reverse order, so disk replay is not end-to-end FIFO.
Extension counts measure accepted events and do not apply generic limits.

Successful enqueueing triggers sender notification. Read, enqueue, notification,
search, and deletion errors are logged. Read and enqueue failures still lead to
file deletion attempts: replay does not retain those files for retry.

### Enrich, redact, batch, and send

`event_sender::try_enqueue_generic_event` and
`event_sender::try_enqueue_extension_event` convert borrowed input into owned
records and return `EnqueueEvent` errors when full or closed. They do not notify;
callers must signal through `CommonState`.

`EventSender::start` waits for notification or cancellation.
`EventSender::process_event_queue` refreshes VM metadata through
`WireServerClient` and `ImdsClient`, logging refresh failures. Sending requires
available metadata; a failed refresh alone does not preclude using available
metadata. Endpoint overrides apply to both clients.

The sequential consumer redacts only message-bearing fields before XML batching,
not producer buffers or disk files. `TelemetryEventVMData` combines cloned host
metadata with OS, memory, CPU count, and lazily generated architecture JSON.
Generic version overrides also append the source version to the event name.
Invalid numeric process/thread IDs become zero; extension duration is cast to
`u64`. `KeywordName::to_json` returns an empty string on serialization failure.

`TelemetryData` groups generic event ID 7 and extension event ID 1 into distinct
providers and maintains serialized byte counts incrementally. XML escapes string
parameters and emits typed values and CDATA-wrapped events. Removal takes the
first equal event in its provider and retains empty providers.

An event making a batch reach 64 KiB is removed and requeued when other events
fit; an event too large to fit alone is discarded with a warning.
Requeue failure is also logged. `EventSender::send_data_to_wire_server`
serializes each nonempty batch once and makes five attempts, sleeping 15 seconds
after every failure, including the last. Exhaustion logs XML at trace level
without requeueing the batch.

### Shutdown and timing helpers

`event_logger::stop` sets an atomic shutdown flag; the logger observes it after
sleeping, closes its queue, and drains it. Sender cancellation instead permanently
closes the sender queue without flushing. In-progress processing finishes before
cancellation is observed; do not assume immediate interruption or safe restart
of these process-global queues.

`SimpleSpan` owns a monotonic `Instant`; `start_new` resets it and
`get_elapsed_time_in_millisec` returns whole milliseconds as `u128`.
`SimpleSpan::write_event` captures one elapsed value, logs at Info through
`event_logger`, and returns the corresponding display message.
`get_elapsed_json_message` manually formats JSON-shaped text without escaping:
quotes and control characters can make it invalid JSON despite `ElapsedMessage`
having Serde derives. Neither formatting nor writing exposes a `Result`.

### Existing test evidence

The supplied summaries describe tests for disk caps, logger stopping, extension
persistence, direct-send empty/partial/full fallback and notification failure;
reader limits, file isolation, cleanup and cancellation; sender capacity, FIFO,
metadata conversion, XML variants, mock-server draining and cancellation closure;
record mappings, grouping, size accounting, versions, booleans, extension
redaction and UTF-8 truncation; and span elapsed/reset behavior.
These are described assertions, not a claim that tests ran for this document.
Sender FIFO tests do not establish FIFO across reversed generic-file replay.

## Related Components

| Component | Navigation | Boundary |
|---|---|---|
| Shared cancellation, metadata, notifications | [CommonState](..\..\proxy_agent_shared\src\common_state.rs) | Coordinates reader/sender wakeups, cancellation, and metadata availability |
| Host clients | [WireServerClient](..\..\proxy_agent_shared\src\host_clients\wire_server_client.rs), [ImdsClient](..\..\proxy_agent_shared\src\host_clients\imds_client.rs) | Fetch metadata; WireServer receives telemetry |
| Secret handling | [Secrets redactor](..\..\proxy_agent_shared\src\secrets_redactor.rs) | Message sanitation in the background consumer, not producer-side persistence |
| Local logging and utilities | [Platform utilities](agent-platform-utilities.md) | Related diagnostic logging surface; local logging and host delivery are distinct |
