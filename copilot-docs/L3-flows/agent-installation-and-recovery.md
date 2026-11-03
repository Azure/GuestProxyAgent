**TL;DR:** `proxy_agent_setup` installs, backs up, restores, and removes the agent through shared service APIs and platform-specific file placement. Recovery is explicit and best-effort: copy/stop failures can be logged without aborting, and restore checks only for a backup executable.

# Agent installation and recovery

<!-- TIER2-POINTER:BEGIN (managed by step8_inject_tier2_pointer.py) -->
> **Need a specific class, method, error code, config key, or flow step?**
> Read `intermediate-docs/L3-flows/agent-installation-and-recovery.content.md` for implementation details; stay here for overviews.
> Search the companion for the source-file heading and range-read that section, starting with Purpose and Functionality.
> Verify behavior in source when needed; do not load the entire companion.
<!-- TIER2-POINTER:END -->

## Why

Deployment needs a common entry point for replacing the running agent, preserving a recovery package, and controlling its service across Windows and non-Windows builds. This flow coordinates those operations; it does not provide transactional installation, automatic rollback, or complete backup validation.

## What

The Tokio entry point initializes setup logging, parses a required Clap subcommand, logs the operation, and dispatches it.

| Command | Flow and boundary |
|---|---|
| `Install` | Attempt stop, copy staged package, install/update service, then start. Does not automatically back up the previous package. |
| `Backup` | Copy installed files into the setup-relative backup layout; does not stop the service. |
| `Restore` | Skip if the backup executable is absent; otherwise attempt stop, copy backup, install/update and start, then optionally delete backup. |
| `Uninstall` | Stop/delete service; remove installed files only in `Package` mode. Default mode is `Service`. |
| `Purge` | Delete the backup tree, not the installed package or service. |

`Restore.delete_backup` has a declared default of `true`; it and `Uninstall.uninstall_mode` are positional Clap fields, not named flags. Clap owns parsing and invalid-input handling.

### Code Pointers

Paths are repository-relative. Key Classes includes Rust types and function entry points.

| Component | File Path | Key Classes |
|---|---|---|
| Command model | `proxy_agent_setup\src\args.rs` | `Cli`, `Command`, `UninstallMode`, `Display::fmt` |
| Lifecycle coordinator | `proxy_agent_setup\src\main.rs` | `main`, `copy_proxy_agent`, `backup_proxy_agent`, `restore_proxy_agent`, `setup_service`, `uninstall_service`, `check_backup_exists`, `failing_ebpf_deps_message` |
| Staged package paths | `proxy_agent_setup\src\setup.rs` | `proxy_agent_folder_in_setup`, `proxy_agent_exe_in_setup`, `proxy_agent_exe_path`, `ebpf_setup_script_file` |
| Backup paths | `proxy_agent_setup\src\backup.rs` | `proxy_agent_backup_folder`, `proxy_agent_backup_package_folder` |
| Installed/versioned paths | `proxy_agent_setup\src\running.rs` | `proxy_agent_running_folder`, `proxy_agent_parent_folder`, `proxy_agent_version_target_folder` |
| Non-Windows artifacts | `proxy_agent_setup\src\linux.rs` | `setup_service`, `backup_files`, `copy_files`, `delete_files` |
| Setup diagnostics | `proxy_agent_setup\src\logger.rs` | `init_logger`, `force_init_logger`, `write`, `write_error` |
| Error wrapper | `proxy_agent_setup\src\error.rs` | `Error::Io` |
| Result alias | `proxy_agent_setup\src\result.rs` | `Result<T>` |

## How

### Resolve package and recovery locations

`setup` resolves the package adjacent to the setup executable and selects the platform's agent filename. `backup` places `Backup` beneath that staged package directory, with payload files under `Backup\Package`; neither module validates or creates those paths.

| Platform | Running and target directory |
|---|---|
| Windows | Query the service executable's parent. Query failure logs and falls back to `%SYSTEMDRIVE%\WindowsAzure\ProxyAgent\Package`; a missing parent also falls back. New targets use `Package_<version>` under the same installation root. |
| Non-Windows | Use the shared fixed executable directory for both running and target paths. The Windows installation-root helper panics if called here. |

`proxy_agent_version_target_folder` probes the selected executable's version on both platforms. Probe failure logs and panics, even though non-Windows targets are not version-suffixed.

### Install or restore

1. `stop_service` awaits the shared stop operation but logs failures and continues.
2. `copy_proxy_agent` selects staged files; `restore_proxy_agent` selects `Backup\Package`. Both resolve the destination from the selected executable's version.
3. Windows copies enumerated package files into the target directory. Non-Windows delegates artifact placement to `linux::copy_files`.
4. `setup_service` removes a differing existing running directory on Windows; on non-Windows it installs the service unit and optional manual page from the selected service-config folder.
5. Register/update the service through `service::install_service`, then await `service::start_service` with retry inputs of five and fifteen seconds. Actual backend retry/readiness semantics belong to the shared service implementation.
6. After restore setup returns, delete the backup tree if requested. A missing backup executable instead logs a skip and returns without stopping the service.

Restore uses `Backup` for service configuration; install uses the setup executable's directory. The executable-presence check does not prove that configuration, eBPF artifacts, or service files are complete.

### Preserve platform-specific ordering

| Concern | Windows | Non-Windows |
|---|---|---|
| File placement | Package files stay together in a version-selected directory. | Executable, configuration, eBPF object, and manual page have separate destinations. |
| Service configuration | Register with `EbpfCore` and `NetEbpfExt` dependencies. | Copy the named unit to the shared service-config directory and set permissions to `0644`. |
| eBPF setup | Register agent service **before** invoking an optional adjacent PowerShell eBPF setup script. If `eBPFSvc` exists, re-register with that additional dependency. | Copy the eBPF object as part of package placement; no Windows setup script. |
| Permissions | File copying is handled by the Windows branch. | Set executable to `0755`, configuration to `0644`, and optional manual page to `0644`. |
| Backup shape | Copy running package files into `Backup\Package`. | Put executable, configuration, and eBPF object in `Backup\Package`; put unit and manual page beside it in `Backup`. |
| Package deletion | Delete the captured running directory. | Delete executable, configuration, eBPF object, and manual page; `linux::delete_files` does not remove the service unit. |

The manual page is optional when absent from installation input. Its copying/permission errors are logged, unlike service-unit copying/permission errors.

### Handle failures and cleanup deliberately

| Outcome | Behavior |
|---|---|
| Logged, continue | Stop failure; file enumeration/copy or directory creation/deletion failures; non-Windows payload permission failures; optional eBPF script invocation failure. |
| Exit with failure | Non-Windows unit setup failure; service installation, dependency update, uninstall, or startup failure. |
| Panic | Executable version lookup failure; calling the Windows installation-root helper on non-Windows. |
| Restore skip | Backup executable absent; logs and returns without reporting a failing exit. |

File-copy helpers do not aggregate a success result. A successful service start therefore does not prove that every payload file was copied, and subsequent backup deletion can remove recovery material after a partial copy. There is no automatic restoration of the previous running directory if a later service step fails.

`uninstall_service` captures the running directory before stop/delete so `Package` mode can remove it afterward. `Service` mode retains payload files; neither uninstall mode purges the backup tree.

### Diagnostics and evidence

`logger::write` mirrors Info output to stdout; `write_error` mirrors Error output to stderr. Both use shared logging with a fixed setup identity, the executable directory, a 20 MiB size limit, count 30, and Trace configuration; setup wrappers return no logging errors.

`Error::Io` transparently wraps and converts I/O errors; `Result<T>` only supplies the common error type. Neither adds retries or recovery.

Windows-only tests in `main.rs` cover `failing_ebpf_deps_message`: both core dependencies running yields no diagnostic; missing/stopped combinations include exactly the failing dependency names. These are diagnostic assertions, not end-to-end evidence for installation, backup integrity, or rollback.

## Related components

| Component | Relationship |
|---|---|
| [Cross-platform service utilities](..\L2-platform\cross-platform-service-utilities.md) | Owns SCM/systemd lifecycle behavior, readiness, shared path/version helpers, and logging infrastructure used by setup. |
| [eBPF socket redirection](..\L2-platform\ebpf-socket-redirection.md) | Related runtime datapath; setup distributes its object/package and coordinates Windows eBPF service dependencies. |
