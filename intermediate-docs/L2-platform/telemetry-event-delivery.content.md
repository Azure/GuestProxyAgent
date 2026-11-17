# Compose Content for: L2-platform/telemetry-event-delivery.md

Total files: 5

---

## proxy_agent_shared/src/telemetry/event_logger.rs

### Purpose and Functionality
Buffers generic telemetry in a global, bounded 1,000-event concurrent queue. Disk-only startup avoids referencing the direct sender; direct-send startup attempts in-memory enqueueing first and persists rejected events.
### Key Components
DirectSendConfig owns routing strings, optional version, and CommonState. Tokio OnceCells retain the directory and direct-send configuration; repeated initialization warns. An atomic shutdown flag requests queue closure after sleeping, followed by draining. A zero interval becomes 60 seconds.
### Behavior and Interactions
The loop invokes asynchronous status callbacks, creates the directory, drains owned events, and writes JSON batches. Reaching the generic-file cap drops batches; search errors warn but allow writing. Write failures warn without requeueing. Successful direct enqueueing triggers notification; notification failure does not restore accepted events. Producers truncate messages at character boundaries; write_event also forwards the original message to file logging. Windows-only ingestion requires provider and task names and preserves Windows event identities and timestamp. Extension status reporting tries direct enqueueing, otherwise writes one prefixed JSON file, capped at 1,000 files. Tests assert disk caps, stopping, extension payload persistence, empty direct input, complete and partial fallback ordering, and no fallback after notification failure.

---

## proxy_agent_shared/src/telemetry/event_reader.rs

### Purpose and Functionality
Reads disk-buffered generic and extension-status telemetry into event_sender queues and removes processed files. EventReader owns directory and routing configuration plus CommonState. EventReaderLimits provides optional generic-file size, per-round event count, and version settings through consuming builders.
### Key Components
Generic and extension processors use separate filename regexes and deserialize arrays of Event or individual ExtensionStatusEvent records. Their asynchronous loops default to 300-second and 60-second intervals respectively, with an optional initial 60-second delay before cancellation monitoring. CommonState supplies cancellation tokens and sender notifications. No platform-specific branches appear.
### Behavior and Interactions
Generic limits are checked between files, so one file can exceed the round count. Metadata failures retain files; oversized files are deleted. Generic counts reflect deserialized events, not successful enqueues. Events are popped in reverse array order; successful enqueueing triggers notification. Read, enqueue, notification, search, and deletion errors are logged. Read failures and enqueue failures still lead to deletion attempts, without retry retention. Extension counts reflect accepted events and do not apply generic limits. Tests assert round-limited retention, unlimited draining, filename exclusion, extension cleanup, cancellation completion, and isolation between generic and extension files.

---

## proxy_agent_shared/src/telemetry/event_sender.rs

### Purpose and Functionality
Sends generic-log and extension-status telemetry to the wire server. A process-wide concurrent queue owns up to 1,000 events.
### Key Components
EventSender owns CommonState and asynchronously waits for notification or cancellation. The try_enqueue functions convert borrowed events into owned records and return EnqueueEvent errors when the queue is full or closed; they do not notify the sender. Endpoint overrides apply to both host clients.
### Behavior and Interactions
Processing refreshes metadata through wire-server and IMDS clients, logs refresh failures, and sends only when metadata is available. The sequential consumer redacts messages before constructing XML batches strictly below 64 KiB. An event reaching the batch limit is requeued when other events fit, or discarded with a warning when it cannot fit alone. Each nonempty batch is serialized once and attempted five times, sleeping 15 seconds after every failure; exhaustion logs XML at trace level without requeuing the batch. Cancellation permanently closes the queue without flushing; in-progress processing finishes before cancellation is observed. Tests assert bounded capacity, FIFO order, metadata conversion, both XML variants, mock-server queue draining, and cancellation closure. There are no platform-specific branches.

---

## proxy_agent_shared/src/telemetry/span.rs

### Purpose and Functionality
Provides elapsed-time telemetry messages. SimpleSpan owns a monotonic Instant and reports elapsed whole milliseconds as u128 without managing tasks or external resources.
### Key Components
SimpleSpan supports explicit and Default construction, resetting, reading elapsed milliseconds, formatting a message, and writing an event. The private ElapsedMessage pairs an elapsed value with an owned string, derives Serde serialization and deserialization, and implements Display for a message followed by elapsed time.
### Behavior and Interactions
get_elapsed_json_message returns manually formatted JSON-shaped text. Despite the Serde derives, formatting does not invoke a JSON serializer or escape message content, so quotes or control characters can produce invalid JSON. write_event captures one elapsed value, forwards the formatted text to event_logger at Info level with the supplied method, module, and logger identifiers, then returns the corresponding Display string. Neither operation exposes a Result. The asynchronous test sleeps between measurements, deserializes a simple formatted message, checks its text and elapsed duration, and verifies resetting produces a smaller positive measurement. Production logic is synchronous and has no Windows/Linux cfg branches.

---

## proxy_agent_shared/src/telemetry/telemetry_event.rs

### Purpose and Functionality
Defines owned telemetry records and wire-server XML serialization for generic logs and extension operation status, including shared VM and machine information.
### Key Components
VmMetaData holds host metadata; TelemetryEventVMData clones it and adds OS, memory, CPU count, and lazily generated architecture JSON. TelemetryEvent wraps generic or extension records. TelemetryProvider owns grouped events; TelemetryData owns providers, VM data, and an incrementally maintained serialized byte count. KeywordName serializes architecture, returning an empty string on serialization failure.
### Behavior and Interactions
Constructors clone source fields, truncate messages to at most 4,096 bytes at a UTF-8 boundary, and default invalid numeric process/thread IDs to zero. A supplied generic agent version also appends the source version to the event name; extension duration is cast to u64. Explicit background-consumer redaction replaces only the message-bearing field. XML escapes string parameters, emits typed values and CDATA-wrapped events, and separates event IDs 7 and 1 into distinct providers. Removal finds the first equal event in its provider and retains empty providers while updating size. Tests assert mappings, provider grouping, XML structure, byte-count accuracy, version selection, booleans, extension-message redaction, and UTF-8 truncation. No platform-specific branches or asynchronous synchronization occur here.

---
