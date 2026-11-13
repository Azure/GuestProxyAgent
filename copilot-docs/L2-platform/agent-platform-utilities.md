**TL;DR:** Agent platform utilities centralize command-line parsing, immutable configuration, diagnostics, typed errors, and OS-specific identity/key helpers. They provide synchronous building blocks for agent startup and runtime consumers, not service orchestration or request handling.

# Agent platform utilities

<!-- TIER2-POINTER:BEGIN (managed by step8_inject_tier2_pointer.py) -->
> **Need a specific class, method, error code, config key, or flow step?**
> Read `intermediate-docs/L2-platform/agent-platform-utilities.content.md` for implementation details; stay here for overviews.
> Search the companion for the source-file heading and range-read that section, starting with Purpose and Functionality.
> Verify behavior in source when needed; do not load the entire companion.
<!-- TIER2-POINTER:END -->

## Why

Agent subsystems need consistent startup inputs, logging, error propagation, and platform-specific operations. This layer shares those contracts without creating runtimes, spawning asynchronous work, or implementing recovery policies.

## What

| Responsibility | Contract |
|---|---|
| Startup inputs | Clap validates arguments; JSON configuration is loaded lazily into a process-wide immutable value. |
| Runtime sizing and timing | Cache a startup span and main-runtime worker count; expose separately configured proxy-runtime sizing. |
| Diagnostics | Route agent logs through the shared logger manager, optionally mirror telemetry events, and bound non-Windows console writes. |
| Error vocabulary | Preserve operation context in `Error` and specialized enums; `Result<T>` fixes the error type for callers. |
| Non-Windows device identity | Translate userspace device encoding and resolve procfs mount information for comparison with eBPF observations. |
| Windows system/key utilities | Query CPU/memory and persist local key strings through DPAPI; test builds substitute an in-memory store. |

### Code Pointers

Paths are repository-relative. The Key Classes column includes Rust types and function entry points.

| Component | File Path | Key Classes |
|---|---|---|
| CLI | `proxy_agent\src\common\cli.rs` | `Cli`, `Commands`, `Cli::is_console_mode`, `CLI` |
| Configuration | `proxy_agent\src\common\config.rs` | `Config`, `Config::default`, `Config::from_json_file`, `get_canonical_request_mode`, `get_proxy_server_runtime_worker_threads` |
| Error taxonomy | `proxy_agent\src\common\error.rs` | `Error`, `KeyErrorType`, `AclErrorType`, `BpfErrorType`, Windows-only `WindowsApiErrorType` |
| Startup helpers | `proxy_agent\src\common\helpers.rs` | `get_elapsed_time_in_millisec`, `write_startup_event`, `get_tokio_main_worker_threads` |
| Device identity | `proxy_agent\src\common\linux.rs` | `kernel_dev_from_st_dev`, `mount_id_from_fdinfo`, `sb_dev_from_mountinfo`, `sb_dev_of_path` |
| Logging | `proxy_agent\src\common\logger.rs` | `write`, `write_information`, `write_warning`, `write_error`, `write_serial_console_log`, `write_all_with_timeout` |
| Result alias | `proxy_agent\src\common\result.rs` | `Result<T>` |
| Windows helpers | `proxy_agent\src\common\windows.rs` | `get_processor_count`, `get_memory_in_mb`, `store_key_data`, `fetch_key_data`, `has_mock_key_data`, `mock_key_data_count`, `clear_mock_key_data` |

## How

### Initialize and consume shared settings

1. First access to `CLI` parses process arguments through synchronized `Lazy` initialization. Status, version, wait, and an optional `Console` subcommand define the public interface; wait requires status. Clap owns malformed-argument diagnostics and exit behavior.
2. `Cli::is_console_mode` checks for any subcommand, currently equivalent to `Console`. Test builds additionally accept private test-runner options. This module does not perform status polling, version output, or service startup.
3. First configuration access invokes `Config::default`. It selects the platform filename, first tries the system configuration directory on non-Windows, and otherwise uses the executable directory.
4. `Config::from_json_file` reads/deserializes JSON and resolves environment variables once in log, event, and key directory fields. Read or deserialization failure **panics**; accessors do not provide live reload. `Config` supports Serde serialization, omitting absent optional fields.
5. Consumers obtain owned paths/strings, durations, eBPF settings, and other values through accessors. Event retention and proxy worker counts have constant defaults; proxy workers are clamped to one through available CPUs. Main-runtime sizing is a separate cached count clamped to one through four.

| Optional setting | Fallback |
|---|---|
| Missing or invalid file log level | `Info` |
| Absent event thresholds | `None` |
| HTTP tracing | Disabled |
| Canonical-request mode | `Off` when absent; invalid values warn and fall back to `Off` |
| Cgroup root | Configurable only on non-Windows |

### Emit diagnostics without owning lifecycle

`write_startup_event` uses the shared `SimpleSpan`, returns its generated message, and also forwards it to the default serial-console destination on non-Windows. The span starts on first use, not necessarily process creation.

Logger wrappers submit owned messages under the agent logger key. The internal `log` function additionally emits telemetry when the configured event threshold compares greater than or equal to the message level; logger-manager submission occurs regardless.

Non-Windows `write_serial_console_log` prefixes timestamp, package identity/version, and process ID. It opens an existing destination with nonblocking and close-on-exec flags. `write_all_with_timeout` handles partial writes, retries interruptions, and polls after `WouldBlock` against a two-second deadline. Zero writes, timeout, polling errors, and other I/O failures return errors; console open/write failures produce warning logs. Locally owned files close on return.

### Respect platform and failure boundaries

| Boundary | Behavior to preserve |
|---|---|
| Platform selection | The parent common module includes `linux.rs` only on non-Windows and `windows.rs` only on Windows; serial-console support is also non-Windows. |
| Device encoding | `kernel_dev_from_st_dev` extracts major/minor components with libc and uses the kernel's twenty-bit major shift; userspace stat encoding is not directly interchangeable with superblock encoding. |
| Mount lookup | `sb_dev_of_path` opens with `O_PATH` and `O_CLOEXEC`, reads descriptor mount ID and mount records from procfs, and selects the exact mount. Open/read/missing-field/parse failures yield `None`; Btrfs equivalence varies across distributions. |
| Windows system information | CPU count comes from `SYSTEM_INFO`; physical memory is returned in MiB. Memory-query failure maps to the Windows error vocabulary. |
| Production key storage | `store_key_data` protects strings with `CryptProtectData`, no optional entropy, and zero flags, then writes encrypted bytes. `fetch_key_data` reads and unprotects bytes, returning lossy UTF-8. Both copy API output and free it with `LocalFree`. |
| Windows failures | File errors retain operation/path context; cryptographic errors retain the last OS error. These calls are synchronous, not background persistence. |
| Test key storage | A lazy mutex-protected path/string map replaces DPAPI and disk writes. Store/fetch report poisoned locks; inspection helpers return false/zero on poisoning, and cleanup skips poisoned locks. |
| Error propagation | `Error` covers I/O, HTTP, shared, key, URL, ACL, eBPF, invalid-value, channel, and audit-entry failures, with additional Windows API/service variants. Selected shared/service errors convert automatically; enums execute no retry or recovery. |

### Existing test evidence

The supplied summaries describe the following assertions, not executed results:

| Area | Existing coverage and limits |
|---|---|
| Configuration and errors | Directory/timing/optional-setting defaults, explicit worker bounds, and exact nested HTTP/key-request error formatting. |
| Non-Windows identity | Ordinary/large-minor encoding, exact mount selection, missing mounts, fdinfo parsing, live executable lookup, and nonexistent paths. |
| Serial console | Formatted output to a supplied file and `TimedOut` for a filled nonblocking pipe. |
| Windows utilities | Positive CPU/memory values and mock key round trips without an encrypted file; production DPAPI and disk persistence are not exercised. |
| CLI, startup helpers, result alias | No test assertions described in these files. |

## Related components

| Component | Relationship |
|---|---|
| [Shared utilities](..\..\proxy_agent_shared\src) | Supplies the logger manager, telemetry/startup span support, and shared errors consumed by this layer. |
| [Authorization canonicalization](authorization-canonicalization.md) | Documents the canonical-request component; its `CanonicalMode` is selected through configuration accessors. |
| [Common module](..\..\proxy_agent\src\common.rs) | Owns platform inclusion and Windows key-storage re-exports, including test-only inspection helpers. |
