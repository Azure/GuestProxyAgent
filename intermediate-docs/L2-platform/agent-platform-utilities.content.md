# Compose Content for: L2-platform/agent-platform-utilities.md

Total files: 8

---

## proxy_agent/src/common/cli.rs

### Purpose and Functionality
This module defines the agent's clap-based command-line interface and a lazily parsed global instance. Cli derives Parser, while Commands derives Subcommand and currently offers only Console.
### Key Components
Public options include Boolean status and version flags, an optional unsigned wait duration, and an optional command. Each option has short and long forms. The wait argument requires status, making clap responsible for rejecting unsupported combinations and malformed values. Test builds additionally accept private test_threads and nocapture options.
### Behavior and Interactions
Cli::is_console_mode returns whether any subcommand is present; with the current enum, that means Console. The global CLI uses once_cell::sync::Lazy to parse process arguments on first access and share the initialized value safely. Parsing is synchronous; clap handles command-line diagnostics and exit behavior rather than returning an agent Result. This file defines argument shape only, not service startup, version output, or provision-status polling. It contains no test assertions.

---

## proxy_agent/src/common/config.rs

### Purpose and Functionality
Loads JSON service configuration into a process-wide, lazily initialized Config and exposes directory, timing, logging, eBPF, runtime-sizing, and canonical-request settings. Config supports Serde serialization and deserialization; optional fields are omitted when absent during serialization.
### Key Components
Config::default selects a platform-specific filename. Non-Windows builds first try the system configuration directory; otherwise configuration comes from the executable directory. Config::from_json_file panics on read or deserialization failure and resolves environment variables once in the log, event, and key directory fields. Module-level accessors use the shared immutable configuration and return owned paths, strings, durations, or setting values.
### Behavior and Interactions
Event retention and proxy worker counts have constant defaults; worker counts are clamped between one and available CPUs. Non-Windows builds expose the configurable cgroup root. Missing or invalid file log levels become Info; absent event thresholds remain None. HTTP tracing defaults to false. Canonical mode defaults to Off when absent, and invalid values produce a warning before falling back to Off. Tests assert directory resolution, timing values, optional settings, defaults, and explicit worker-count bounds.

---

## proxy_agent/src/common/error.rs

### Purpose and Functionality
Defines the agent's typed error vocabulary using thiserror, preserving contextual data and producing human-readable diagnostics. The top-level Error enum covers I/O, HTTP, shared-library errors, keys, URL parsing, ACLs, eBPF, invalid values, channel failures, and audit-entry lookup failures.
### Key Components
KeyErrorType distinguishes status validation, key requests and responses, URL construction, and local key operations. AclErrorType identifies ACL-object, SID, entry-enumeration, and entry-addition failures. BpfErrorType covers map operations, object and API loading, program conversion and attachment, cgroup opening, string conversion, and exhausted redirector startup retries.
### Behavior and Interactions
Windows builds additionally expose WindowsApiErrorType and top-level Windows API and service variants. Their payloads retain operating-system or dynamic-library errors for system information, identity, sockets, cryptography, and process access. Shared errors and Windows service errors support automatic conversion and transparent display. Send failures retain action and diagnostic strings; receive failures retain the oneshot receive error. The formatting test asserts both an HTTP server diagnostic and its exact nested presentation inside a key-request error. No recovery or retry execution occurs here.

---

## proxy_agent/src/common/helpers.rs

### Purpose and Functionality
Provides small process-wide helpers for startup timing, startup-event emission, and sizing the main Tokio runtime. Both retained values use once_cell's synchronized Lazy initialization rather than mutable per-call state.
### Key Components
A shared SimpleSpan is created on first use. get_elapsed_time_in_millisec delegates elapsed-time measurement to that span. write_startup_event forwards the task, method, module, and logger identifiers to the span and returns its generated message. A separate lazy value obtains the available CPU count and clamps the main runtime worker count between one and four.
### Behavior and Interactions
On non-Windows builds, startup-event emission also clones the returned message into the serial-console logger, using its default destination. Windows builds omit that console call. get_tokio_main_worker_threads returns the cached count by value; it is distinct from the configurable proxy-server runtime sizing. These synchronous helpers neither create a runtime nor spawn asynchronous work. This file contains no tests or explicit error-returning interfaces.

---

## proxy_agent/src/common/linux.rs

### Purpose and Functionality
Supplies non-Windows filesystem-device helpers for comparing executable identity with device identifiers reported by eBPF. The parent common module excludes this file on Windows. The implementation distinguishes userspace stat device encoding from the kernel's superblock device encoding.
### Key Components
kernel_dev_from_st_dev extracts major and minor components through libc and combines them using the kernel's twenty-bit major shift. mount_id_from_fdinfo extracts a trimmed mount identifier. sb_dev_from_mountinfo locates that exact mount record, parses its device components, and produces the kernel-format value. sb_dev_of_path connects these operations by opening the path and reading descriptor and mount information from procfs.
### Behavior and Interactions
The path descriptor uses O_PATH to avoid blocking on FIFOs or devices and O_CLOEXEC to prevent inheritance across execution; the owned File closes automatically. Open, read, missing-field, and parse failures become None. Comments note differing Btrfs behavior across distributions rather than promising universal equivalence with eBPF observations. Tests cover ordinary and large-minor device encoding, mount-record selection, missing mounts, fdinfo parsing, a live executable lookup, and a nonexistent path.

---

## proxy_agent/src/common/logger.rs

### Purpose and Functionality
Wraps the shared logging manager with the agent logger key and convenience functions for Trace, Info, Warn, and Error messages. It also provides non-Windows serial-console output designed to avoid blocking indefinitely on a stalled console.
### Key Components
The internal log function optionally duplicates messages into telemetry events when the configured event threshold compares greater than or equal to the message level, then always submits the owned message to logger_manager. write_serial_console_log adds a timestamp, package identity, version, and process identifier, opening either the supplied destination or the default console without creating it.
### Behavior and Interactions
Console descriptors are nonblocking and close-on-exec. write_all_with_timeout handles partial writes, retries interrupted writes, and polls for writability after WouldBlock against a two-second deadline supplied by the caller. Zero-byte writes, exhausted waits, polling failures, and other I/O failures return errors; console open or write failures are reported through warning logging. Files are owned locally and closed on return. Non-Windows tests verify formatted output at a supplied file path and a TimedOut result for a filled nonblocking pipe. No asynchronous task is created.

---

## proxy_agent/src/common/result.rs

### Purpose and Functionality
Declares the agent-wide Result<T> type alias, fixing the error parameter of core::result::Result to the sibling common::error::Error type.
### Key Components
The sole public declaration is the generic Result alias; its success value remains caller-selected.
### Behavior and Interactions
Consumers share a consistent error type while retaining standard Result propagation and ownership semantics. This tiny file contains no executable logic, platform gates, synchronization, resource management, conversions, or tests.

---

## proxy_agent/src/common/windows.rs

### Purpose and Functionality
Implements Windows system-information queries and local key persistence through DPAPI. The parent module includes it only on Windows and re-exports key-storage functions, plus mock inspection helpers during tests.
### Key Components
get_processor_count reads SYSTEM_INFO; get_memory_in_mb initializes MEMORYSTATUSEX's size and returns physical memory in mebibytes, mapping API failure to the agent's Windows error type. Production store_key_data protects the supplied string using CryptProtectData with no optional entropy and zero flags, copies the allocated output, frees it with LocalFree, and writes encrypted bytes to the requested file.
### Behavior and Interactions
Production fetch_key_data reads the file, calls CryptUnprotectData, copies and frees its output, and returns a lossy UTF-8 conversion. Filesystem failures retain operation and path context; cryptographic failures retain the last operating-system error. Test builds replace persistence with a lazily initialized mutex-protected path-to-string map, avoiding DPAPI and disk writes. Store and fetch report poisoned locks; inspection helpers fall back to false or zero, and cleanup skips poisoned locks. Tests assert positive processor and memory values and a mock key round trip with no encrypted file created. Operations are synchronous.

---
