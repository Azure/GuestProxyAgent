# Compose Content for: L2-platform/windows-event-integration.md

Total files: 5

---

## proxy_agent_shared/src/windows_events/etw_listener.rs

### Purpose and Functionality
Implements a Windows-only real-time ETW consumer producing WindowsEvent values for telemetry or callbacks. Providers resolve from GUID text or case-insensitive registered names, with levels and optional event-ID filters capped at 64 entries.
### Key Components
EtwListener clones configuration into a named OS thread, avoiding blocking Tokio workers. Empty-provider and thread-spawn failures return errors immediately; later trace errors are logged. Process-global sequentially consistent atomics track stopping and the active consumer handle, not independent per-listener cancellation. stop closes that handle without joining.
### Behavior and Interactions
Tracing stops a same-named stale session, starts a real-time session, logs provider-enable failures, and reopens unexpectedly ended consumers after a delay. Cleanup disables providers and stops the session. A boxed handler outlives processing; callbacks recover it through ETW context and catch panics at the FFI boundary. TDH supplies names, typed JSON properties, and positional message substitution; structures and failed properties are skipped, while missing schemas yield hexadecimal payloads. Helpers decode timestamps, SIDs, strings, numbers, and pointer-width-dependent values. Tests assert GUID parsing/formatting, level fallback, integer/Unicode conversion, message substitution, and epoch formatting, but not live tracing or cancellation.

---

## proxy_agent_shared/src/windows_events/evt_listener.rs

### Purpose and Functionality
Implements Windows-only subscriptions to local Windows Event Log channels through EvtSubscribe, converting delivered XML into owned WindowsEvent values for caller handlers or the telemetry queue. Subscriptions can replay existing records or receive only future events.
### Key Components
EvtListener owns the subscription handle and heap-allocated SubscriptionContext containing the channel and a Send + Sync handler. SourceFilter combines a publisher name with optional event IDs. Query construction ORs sources together; empty filters select all events, and xpath_literal handles embedded quotation marks.
### Behavior and Interactions
OS thread-pool callbacks render XML, deserialize EvtEvent, flatten named or positional payloads and UserData fields, and attempt publisher-manifest message formatting. Conversion supplies channel, timestamp, keyword, and identity fallbacks. Subscription failures reclaim context and return Windows API errors; delivery, rendering, and parsing failures produce warnings. Successful listeners enter a process-wide mutex-protected registry that recovers poisoned locks. stop drains the registry and drops listeners outside the lock. Drop closes each subscription before reclaiming its callback context; publisher metadata handles are also closed. The enclosing module is excluded on non-Windows platforms.

---

## proxy_agent_shared/src/windows_events/evt_query.rs

### Purpose and Functionality
Provides a synchronous WindowsEventReader iterator over local Windows Event Log records, newest first. Filtering is delegated to the Event Log service rather than performed after fetching records. This module is compiled only through the Windows-gated windows_events module.
### Key Components
WindowsEventReader owns a query handle and at most one current event handle. Its constructor accepts a channel, publisher name, and optional UTC start and end bounds. build_query combines an escaped publisher predicate with inclusive timestamp comparisons formatted to millisecond precision, reusing the listener module's XPath literal helper.
### Behavior and Interactions
Each iterator step closes the previous record, requests one event with EvtNext, renders its XML through a size-probe and UTF-16 buffer allocation, then deserializes EvtEvent. Exhaustion returns None; other fetch failures become Windows API errors. Rendering errors also propagate through iterator items, while malformed XML becomes an InvalidData I/O error. An empty render buffer produces an empty string that subsequently fails XML parsing. Drop closes both any outstanding event and the query handle. No asynchronous synchronization or tests are defined here.

---

## proxy_agent_shared/src/windows_events/evt_writer.rs

### Purpose and Functionality
Implements Windows-only Event Log writing with blocking redaction and operating-system calls isolated on a dedicated backend thread. WindowsEventWriter exposes ordinary writes and writes with an explicit event ID.
### Key Components
Construction configures the source's registry message-file entry, creates a bounded 1,024-message channel, and starts a worker. A separate rendezvous channel confirms event-source registration before construction succeeds. EventLogMessage carries severity, event ID, and owned text; severity conversion maps trace, debug, and info to informational events.
### Behavior and Interactions
Writes truncate text at a character boundary within a 32-KiB byte limit and use nonblocking enqueueing. Queue failures are printed to standard error. The single worker redacts secrets, converts messages to UTF-16, and calls ReportEventW; its return value is not checked. Registry, thread creation, registration, and startup-channel failures propagate as errors. Drop disconnects the sender and joins the worker, allowing queued messages to drain before deregistration. The integration test asserts listener delivery and reader results for unbounded, start-only, end-only, and bounded time queries, then attempts registry cleanup.

---

## proxy_agent_shared/src/windows_events/models.rs

### Purpose and Functionality
Defines owned event representations shared by Windows tracing and Event Log processing. WindowsEvent serializes normalized metadata and optional formatted messages, decoded properties, or raw payloads. EvtEvent and supporting structures serialize and deserialize Event Log XML. The enclosing module is Windows-only.
### Key Components
System captures publisher, severity, timing, record identity, execution, channel, correlation, and security metadata. Provider supports optional source names and GUIDs. EventData contains optional positional or named Data entries. UserData is a nested ordered-map alias for provider-defined wrapper elements and text fields, including attribute-prefixed entries. Serde annotations map XML attributes and text explicitly and default metadata commonly absent from classic events.
### Behavior and Interactions
WindowsEvent message selection prefers nonempty formatted text, then nonempty properties, then raw user data, finally an empty string. A sole string property is returned directly; other property maps become compact JSON, with serialization failure yielding no property message. Severity values map to standard Windows names, with an unknown fallback. Tests assert classic positional payload parsing, named payloads with provider and correlation/security identifiers, and generic UserData extraction. The file performs no OS calls or asynchronous synchronization.

---
