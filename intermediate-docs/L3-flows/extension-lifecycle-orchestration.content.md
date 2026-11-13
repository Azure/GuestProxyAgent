# Compose Content for: L3-flows/extension-lifecycle-orchestration.md

Total files: 14

---

## proxy_agent_extension/src/common.rs

### Purpose and Functionality
Provides extension environment loading, reporting, sequence tracking, executable discovery, telemetry control, and health transitions.
### Key Components
Reporting serializes one-element JSON arrays; status adds a timestamp and sequence-derived filename. StatusState owns consecutive outcome counters. Path helpers select Windows or non-Windows agent and setup executables.
### Behavior and Interactions
Environment loading exits on unreadable or empty input, returning the first environment otherwise. Reporting errors are logged without propagation. Sequence updates return whether content changed and propagate write errors; reads log failures and return an empty string. Service-path lookup logs failures and returns an empty path. A spawned task starts event logging only with a specified, existing events directory, using a 60-second interval and 50-file limit; stopping invokes the shared logger. Health starts transitioning, succeeds after one success, leaves success after one failure, and errors after 20 consecutive failures. Error recovery requires a success to transition, then another to succeed; counters cap at 10,000. Tests cover environment variants, reporting envelopes, path construction, sequence changes and failures, state transitions, and counter saturation.

---

## proxy_agent_extension/src/constants.rs

### Purpose and Functionality
Centralizes compile-time declarations used by extension reporting, service management, platform compatibility checks, and diagnostics. This file contains constants, a shared service-name re-export, and a conditional module; it performs no runtime work or validation.
### Key Components
Declarations cover plugin and substatus names, handler/log/sequence filenames, file suffixes, enable-operation and language markers, reporting format version, status and exit codes, retry limits, stale-status timing, eBPF service labels, and diagnostic state keys. Limits bound connection summaries to 100 entries, failed-authentication summaries to 50 entries, and connection-related substatus data to 80 KB.
### Behavior and Interactions
Windows selects an executable process name and capitalized status labels; non-Windows selects the extension process name without an executable suffix and lowercase status labels. Windows compatibility declarations encode the minimum supported build and an invalid-version sentinel. The non-Windows linux module declares minimum major versions for Mariner, Ubuntu, Azure Linux, Red Hat, and Rocky, plus a major/minor requirement for SUSE. Status becomes stale after five minutes according to the declared threshold. These declarations do not themselves enforce limits or compatibility. No tests or error-handling logic appear here.

---

## proxy_agent_extension/src/error.rs

### Purpose and Functionality
Declares the extension's common error enum for wrapping failures from operating-system I/O, shared proxy-agent helpers, and Windows service operations. It contains error-type declarations only, with no logging, retries, recovery policy, or runtime control flow.
### Key Components
Error derives Debug and thiserror::Error. Its Io variant owns a standard I/O error, while ProxyAgentShared owns the shared crate's error type. A WindowsService variant owns a windows_service error and is compiled only on Windows.
### Behavior and Interactions
Every variant uses transparent error formatting and a generated From conversion. Callers can therefore propagate supported underlying errors through the extension error type without manually constructing wrappers, while retaining the wrapped error's display and source behavior. Non-Windows builds omit the service-specific dependency reference and variant but retain both cross-platform variants. The file declares no tests or custom conversion functions.

---

## proxy_agent_extension/src/handler_main.rs

### Purpose and Functionality
Implements extension lifecycle commands, initializing logging and rejecting unsupported operating systems with status reporting and a dedicated exit code. A lazy handler environment supplies directories. Windows support requires a minimum build; Linux uses distribution-specific major-version thresholds, plus a minor-version check for SUSE.
### Key Components
program_start validates the OS before dispatching install, uninstall, enable, disable, reset, or update. Helpers locate the executable parent, manage an update marker, and identify Linux extension processes by exact name and a single command-line argument. Windows tests assert acceptance above the build threshold and rejection below it or without a build.
### Behavior and Interactions
Enable persists the configuration sequence, optionally reports status, and exits on persistence failure. Windows delegates service operations; Linux checks process presence once and retries failed spawns with asynchronous delays, dropping the child handle after launch. Disable sends SIGKILL on Linux. Uninstall skips setup-tool removal while the update marker exists and logs subprocess output without checking exit success. Reset removes marker and sequence files. Update requires a target-version environment variable on Windows and retries marker writes; exhaustion only logs. Filesystem, decoding, spawn, and signal failures are logged.

---

## proxy_agent_extension/src/linux.rs

### Purpose and Functionality
Provides the non-Windows service entry helper that keeps the extension process alive after starting its background service work. The root module and this function are both gated to non-Windows builds.
### Key Components
start_service_wait is an asynchronous function that invokes service_main::run once, then enters an unconditional loop.
### Behavior and Interactions
Each iteration awaits a one-second Tokio timer rather than blocking a thread. There is no shutdown condition, result propagation, join handle, or explicit cancellation handling in this file; despite the comment about waiting until service stop, the loop itself never checks service state.

---

## proxy_agent_extension/src/logger.rs

### Purpose and Functionality
Adapts the shared logging subsystem for the extension, configuring its log destination and exposing initialization, key retrieval, and informational writes.
### Key Components
init_logger converts an owned folder string into a PathBuf and initializes a single named logger using the same name as its key and default destination. Configuration enables Trace-level logging with a 20 MiB size setting and a retention parameter of 30. A static Tokio OnceCell owns the logger-key string. get_logger_key returns a cloned string and panics if initialization has not set the key.
### Behavior and Interactions
Initialization configures the shared loggers on every call but only attempts to populate the key when the cell is uninitialized. A failed set is printed to standard error. write forwards its owned message to logger_manager at Info level rather than looking up the stored key. Test-only constructor and destructor hooks initialize logging in a temporary directory and remove that directory afterward, explicitly ignoring cleanup errors. These hooks contain no test assertions.

---

## proxy_agent_extension/src/main.rs

### Purpose and Functionality
Defines the extension executable's module layout and command-line entry point. Clap parses an optional lifecycle subcommand; providing one runs the handler, while omitting it starts service mode under a multithreaded Tokio runtime.
### Key Components
Cli holds the optional ExtensionCommand enumeration, whose variants cover enable, disable, uninstall, install, update, and reset. Common modules are always exposed; linux and windows are selected by platform configuration. Windows additionally declares a service callback and a process-wide Tokio OnceCell containing a runtime handle.
### Behavior and Interactions
Command mode obtains the configuration sequence from an environment variable, substitutes a textual placeholder if unavailable, and awaits handler_main::program_start. Service mode reads the handler environment beside the executable, initializes service-file logging, and awaits event-logger startup. Windows dispatches through the service manager and logs dispatch failures. Its synchronous callback retrieves the stored handle, blocks on the asynchronous Windows service runner, and logs returned errors; missing handle initialization panics. Non-Windows service mode awaits linux::start_service_wait. Setting the Windows runtime handle also uses unwrap, making initialization failure fatal.

---

## proxy_agent_extension/src/result.rs

### Purpose and Functionality
Contains only the extension's shared result-type alias and an import of its local error type.
### Key Components
Result<T> aliases core::result::Result with a generic success value and crate::error::Error as the fixed error type.
### Behavior and Interactions
The alias introduces no wrapper, conversion, logging, runtime behavior, platform gating, or tests. Callers retain standard Rust result semantics while sharing the extension's error representation.

---

## proxy_agent_extension/src/service_main/service_state.rs

### Purpose and Functionality
Tracks repeated extension-service observations so callers can distinguish new or changed state from repeated values. ServiceState owns a private map from string keys to an owned string value and an observation counter. It derives Clone and Default, allowing independent copies and initially empty state.
### Key Components
The update_service_state_entry method accepts borrowed key and value strings plus a maximum repetition count, mutates the map, and returns a Boolean notification decision. New entries start at count one and return true.
### Behavior and Interactions
An existing entry returns true when its value changes or its previous count has reached the supplied maximum; either condition replaces the value and resets the count to one. Otherwise, the method increments the count and returns false. The threshold check precedes the increment, which determines when repeated observations become reportable again. Strings are copied into owned map entries. Mutation requires exclusive access through a mutable reference; this file supplies no asynchronous synchronization, persistence, platform-specific behavior, or tests.

---

## proxy_agent_extension/src/service_main/windows_main.rs

### Purpose and Functionality
Connects the extension's background service work to Windows Service Control Manager reporting. This module is included only on Windows and exposes an asynchronous run_service entry point; its service arguments are unused.
### Key Components
A process-global Tokio OnceCell owns the registered ServiceStatusHandle. The synchronous control callback accesses that handle without awaiting. run_service invokes the shared service launcher, registers the callback, reports an own-process Running state accepting STOP, and then stores the handle.
### Behavior and Interactions
Registration and initial status-reporting errors propagate through the extension's Result type. Storing the handle uses unwrap, so repeated initialization can panic. A Stop notification stops the event logger and attempts to report Stopped with a successful Windows exit code. Status-reporting failures are logged. If the callback runs before the global handle is available, it logs the fallback and exits the process successfully. Interrogate succeeds without further action; unsupported controls return NotImplemented. The callback does not explicitly cancel or await the monitor and heartbeat tasks launched through service_main. No tests are declared here.

---

## proxy_agent_extension/src/service_main.rs

### Purpose and Functionality
Runs extension monitoring and heartbeats through two spawned Tokio tasks whose handles are discarded. Heartbeats repeat every five minutes; monitoring repeats every fifteen seconds.
### Key Components
UpdateAction distinguishes file-version changes from interrupted updates. Sequence changes trigger comparison, backup for mismatched files, and synchronous setup-tool installation; matching files with missing or mismatched runtime status trigger reinstall without backup. Aggregate status retrieval uses HTTP with file fallback, or direct file reading when endpoint arguments are absent. Helpers mutate borrowed status objects, debounce failures, select highest-count connection records, and drop connection summaries before truncating oversized authentication details.
### Behavior and Interactions
Unreadable bundled versions retry; stale timestamps, timestamp parsing errors, and version mismatches update error messages. Failure helpers retain an OK code while transitioning; install failures preserve process exit codes. Restore or purge is marked attempted even when command execution fails. Windows checks matching eBPF driver versions and requires eBPFSvc from version 1.0; Windows/Linux service health distinguishes startup from confirmed failure. Error details override only an already-error top-level status, with Windows eBPF errors taking priority. Tests assert update selection, debounce/code coupling, stale-status messaging, summary limits, platform health classification, and override precedence.

---

## proxy_agent_extension/src/structs.rs

### Purpose and Functionality
Defines owned data models for the extension's handler environment, status reports, and heartbeat JSON. Serde derives support serialization and deserialization while retaining the declared mixed-case field names used by these payloads.
### Key Components
Handler wraps HandlerEnvironment, which contains required folder and heartbeat paths alongside optional deployment, role, instance, resolver, and event-folder metadata. HandlerEnvironment implements field-by-field cloning. StatusObj owns operation metadata, an integer result code, a formatted message, and a vector of SubStatus entries. FormattedMessage owns language and message strings. TopLevelStatus adds version and timestamp fields; TopLevelHeartbeat wraps HeartbeatObj, whose code is a string rather than an integer.
### Behavior and Interactions
StatusObj, FormattedMessage, and SubStatus are cloneable. SubStatus defaults to empty strings, zero code, and an empty formatted message. These are data declarations, not file readers or report writers. Tests deserialize fixture JSON and assert selected handler paths and optional metadata, top-level status version and timestamp plus status fields, and heartbeat version, status, and string code. Despite comments mentioning round trips, the tests do not serialize the parsed objects.

---

## proxy_agent_extension/src/windows/service_ext.rs

### Purpose and Functionality
Implements Windows extension-service lifecycle wrappers around the shared service helpers. Service identity, display name, executable name, retry count, and failure exit codes come from extension constants rather than caller configuration.
### Key Components
install_extension_service locates the extension executable beneath the current executable directory and requests installation with an empty dependency list. update_extension_service takes ownership of a supplied root PathBuf, joins the extension executable name, logs the target, and requests an update with the same service identity and empty dependencies. Startup, shutdown, and uninstall are asynchronous functions.
### Behavior and Interactions
Startup delegates retry handling to the shared helper using the configured retry count and a fifteen-second duration. Uninstall awaits stop-and-delete; stop awaits the shared stop operation. Every wrapper logs success. On failure it logs the error, writes a diagnostic to standard error, and terminates the process using the operation-specific exit code instead of returning an error to its caller. The uninstall standard-error diagnostic labels the operation as an update even though its logging and exit code identify uninstall. No tests or additional synchronization are declared.

---

## proxy_agent_extension/src/windows.rs

### Purpose and Functionality
Provides the extension's Windows module boundary. The crate root includes this file only for Windows builds.
### Key Components
Its only declaration publicly exposes the service_ext child module.
### Behavior and Interactions
This file contains no executable logic, resource ownership, error handling, or tests. Service installation, update, startup, shutdown, and removal behavior resides in the child module rather than here.

---
