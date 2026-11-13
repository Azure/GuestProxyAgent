**TL;DR:** `proxy_agent_extension` translates extension lifecycle commands into platform-specific service operations and continuously reconciles the bundled agent with runtime health. Sequence tracking, update markers, setup-tool actions, and debounced status reports coordinate upgrades and recovery, but do not guarantee transactional updates or graceful task shutdown.

# Extension lifecycle orchestration

<!-- TIER2-POINTER:BEGIN (managed by step8_inject_tier2_pointer.py) -->
> **Need a specific class, method, error code, config key, or flow step?**
> Read `intermediate-docs/L3-flows/extension-lifecycle-orchestration.content.md` for implementation details; stay here for overviews.
> Search the companion for the source-file heading and range-read that section, starting with Purpose and Functionality.
> Verify behavior in source when needed; do not load the entire companion.
<!-- TIER2-POINTER:END -->

## Why

The extension must bridge host-issued lifecycle commands, the installed agent, and host-readable status across Windows and Linux. It separates short-lived command handling from long-running monitoring so configuration changes can trigger installation while health and heartbeats continue independently.

## What

| Responsibility | Contract |
|---|---|
| Command entry | An optional Clap subcommand selects enable, disable, install, uninstall, update, or reset; no subcommand selects service mode. |
| Compatibility gate | `handler_main::program_start` rejects unsupported operating systems with status reporting and a dedicated exit code before command dispatch. Windows uses a minimum build; Linux uses distribution-specific versions, including SUSE major/minor checks. |
| Reconciliation | Sequence changes drive bundled/installed version comparison and setup-tool installation; runtime status detects interrupted updates. |
| Reporting | Heartbeats repeat every five minutes; monitoring repeats every fifteen seconds. Aggregate status combines runtime evidence, service health, and bounded connection/authentication summaries. |
| Platform integration | Windows uses SCM service wrappers and a service callback. Linux launches or kills the extension process and keeps service mode alive with an asynchronous wait loop. |

### Code Pointers

Paths are repository-relative. Key Classes includes Rust types, modules, and function entry points.

| Component | File Path | Key Classes |
|---|---|---|
| CLI and service entry | `proxy_agent_extension\src\main.rs` | `Cli`, `ExtensionCommand`, `main`, `proxy_agent_extension_windows_service_main` |
| Lifecycle dispatch | `proxy_agent_extension\src\handler_main.rs` | `program_start`, `handle_command`, `enable_handler`, `disable_handler`, `update_handler`, `reset_handler` |
| Environment, reports, health | `proxy_agent_extension\src\common.rs` | `get_handler_environment`, `update_current_seq_no`, `report_status`, `report_heartbeat`, `StatusState`, `start_event_logger` |
| Policy declarations | `proxy_agent_extension\src\constants.rs` | `constants`, `linux` (non-Windows compatibility constants) |
| Monitoring and recovery | `proxy_agent_extension\src\service_main.rs` | `run`, `monitor_thread`, `heartbeat_thread`, `UpdateAction`, `determine_update_action`, `restore_purge_proxy_agent` |
| Observation deduplication | `proxy_agent_extension\src\service_main\service_state.rs` | `ServiceState::update_service_state_entry` |
| Windows service runner | `proxy_agent_extension\src\service_main\windows_main.rs` | `run_service` |
| Windows module boundary | `proxy_agent_extension\src\windows.rs` | `service_ext` |
| Windows lifecycle wrappers | `proxy_agent_extension\src\windows\service_ext.rs` | `install_extension_service`, `update_extension_service`, `start_extension_service`, `stop_extension_service`, `uninstall_extension_service` |
| Non-Windows service wait | `proxy_agent_extension\src\linux.rs` | `start_service_wait` |
| Report payloads | `proxy_agent_extension\src\structs.rs` | `Handler`, `HandlerEnvironment`, `StatusObj`, `SubStatus`, `TopLevelStatus`, `TopLevelHeartbeat`, `HeartbeatObj`, `FormattedMessage` |
| Logging adapter | `proxy_agent_extension\src\logger.rs` | `init_logger`, `get_logger_key`, `write` |
| Error representation | `proxy_agent_extension\src\error.rs` | `Error::Io`, `Error::ProxyAgentShared`, `Error::WindowsService` (Windows only) |
| Result alias | `proxy_agent_extension\src\result.rs` | `Result<T>` |

## How

### Enter command or service mode

Command mode reads the configuration sequence from an environment variable, substituting a textual placeholder when unavailable, then awaits `program_start`. The handler initializes logging and loads a lazily held handler environment.

Service mode reads the handler environment beside the executable, initializes service-file logging, and starts optional event logging. Environment loading exits for unreadable or empty input; otherwise it selects the first environment. Event logging requires a specified, existing events directory and uses a sixty-second interval with a fifty-file limit.

| Command | Orchestration and caveat |
|---|---|
| Install | Dispatches extension installation; Windows delegates service registration to `install_extension_service`. |
| Enable | Persists the configuration sequence, optionally reports enable status, and exits if persistence fails. Windows starts the service; Linux checks process presence once and retries failed spawns with asynchronous delays, dropping the child handle after launch. |
| Disable | Windows stops the service; Linux sends SIGKILL to the matching extension process. Linux identification requires the exact process name and a single command-line argument. |
| Uninstall | Skips setup-tool removal while the update marker exists. Setup subprocess output is logged without checking successful exit; Windows also delegates extension-service removal. |
| Update | Windows requires a target-version environment variable. Update-marker writes are retried, but exhaustion only logs. |
| Reset | Removes update-marker and sequence files. |

Windows service wrappers use fixed service identity, executable names, retry limits, and operation-specific failure exit codes. They log success; failures log, write stderr diagnostics, and terminate rather than returning errors. Startup delegates retries to shared helpers with a fifteen-second duration.

### Reconcile agent deployment

`service_main::run` spawns independent heartbeat and monitor tasks and discards their handles. The monitor retries unreadable bundled versions rather than treating them as a completed comparison.

| Observation | Action |
|---|---|
| Sequence change with bundled/installed file-version mismatch | Back up the installed agent, then invoke synchronous setup-tool installation. |
| Matching file versions but missing or mismatched runtime status | Treat as an interrupted update and reinstall without backup. |
| Installation failure | Preserve the setup process exit code in status. |
| Restore or purge selected | Invoke the setup tool; mark the action attempted even if command execution fails. |

`UpdateAction` distinguishes file-version replacement from interrupted-update recovery. Setup execution is synchronous inside the monitor path; an attempted recovery is not proof of successful restore or purge.

### Derive bounded, debounced status

`get_proxy_agent_aggregate_status` uses HTTP with file fallback when endpoint arguments are available; otherwise it reads the file directly. Stale timestamps, timestamp parsing errors, and agent-version mismatches affect error messages. The declared stale threshold is five minutes.

| Health observation | `StatusState` behavior |
|---|---|
| Initial state | Transitioning. |
| One success from transitioning | Success. |
| One failure from success | Leave success for transitioning. |
| Twenty consecutive failures | Error. |
| Success while in error | Transitioning; another success is required to reach success. |

Outcome counters saturate at 10,000. Failure helpers retain an OK code while transitioning; do not infer terminal failure from the message alone.

Windows eBPF health requires matching driver versions and, from version 1.0, `eBPFSvc`. Windows/Linux service health distinguishes startup from confirmed failure. Service-detail overrides apply only to an already-error top-level status; Windows eBPF errors take precedence.

Connection summaries select highest-count records and are bounded to 100 entries; failed-authentication summaries are bounded to fifty entries, with an 80 KB limit for connection-related substatus data. Trimming drops connection summaries before truncating oversized authentication details.

`ServiceState::update_service_state_entry` reports new or changed observations immediately. Repeated values become reportable when the previous count has reached the supplied maximum; the threshold check happens before increment, then a report resets the count to one.

### Preserve reporting and shutdown boundaries

Status and heartbeat writers serialize one-element JSON arrays. Status adds a timestamp and uses a sequence-derived filename; write failures log without propagation. Serde models preserve mixed-case payload names; status codes are integers, but heartbeat codes are strings.

Sequence writes return whether content changed and propagate write errors. Sequence reads log failures and return an empty string; service-path lookup similarly logs and returns an empty path. `Error` transparently wraps supported underlying failures; `Result<T>` adds no recovery policy.

| Platform | Service lifetime and limitation |
|---|---|
| Windows | The entry point stores a Tokio runtime handle and dispatches through SCM. `run_service` launches background work, registers control handling, reports Running accepting STOP, then stores the status handle. Registration/status errors propagate; repeated handle initialization can panic. |
| Windows STOP | Stops event logging and attempts to report Stopped with success. Status failures log; if the handle is not yet available, the callback logs and exits successfully. It does not explicitly cancel or await monitor/heartbeat tasks. Interrogate succeeds; unsupported controls return NotImplemented. |
| Non-Windows | `start_service_wait` starts background work once, then awaits one-second timers forever. It has no shutdown condition, cancellation handling, or join ownership. |

The Windows entry callback logs service-runner errors; missing runtime-handle initialization can panic. Shared file logging uses Trace configuration, a 20 MiB size setting, and retention parameter thirty. `get_logger_key` panics before initialization; `logger::write` forwards Info messages directly to the shared logger manager.

### Evidence boundaries

Source-described tests cover environment parsing, reporting envelopes, path/sequence behavior, health transitions and counter saturation, update selection, stale-status messaging, summary limits, platform health classification, and override precedence. Windows handler tests cover supported/unsupported build checks. Payload tests assert deserialization fields, not serialization round trips; these checks do not establish end-to-end upgrade recovery or graceful shutdown.

## Related components

| Component | Relationship |
|---|---|
| [Agent installation and recovery](agent-installation-and-recovery.md) | Setup-tool implementation behind install, backup, restore, purge, and removal actions. |
| [Cross-platform service utilities](..\L2-platform\cross-platform-service-utilities.md) | Shared lifecycle helpers used by extension service wrappers and health checks. |
| [Telemetry event delivery](..\L2-platform\telemetry-event-delivery.md) | Shared event-logging infrastructure started and stopped by the extension. |
| [eBPF socket redirection](..\L2-platform\ebpf-socket-redirection.md) | Related datapath whose Windows driver/service health contributes to extension status. |
