# Compose Content for: L3-flows/agent-installation-and-recovery.md

Total files: 9

---

## proxy_agent_setup/src/args.rs

### Purpose and Functionality
Defines the setup tool's command-line interface using Clap derives, together with human-readable formatting for startup logging. The crate-visible Cli requires a subcommand rather than allowing an omitted operation.
### Key Components
Command represents backup, restore, uninstall, install, and purge operations. Restore carries a Boolean delete_backup argument with a declared default of true. Uninstall carries an UninstallMode argument defaulting to Service. UninstallMode derives ValueEnum, Clone, Debug, and PartialEq and distinguishes removing only the service from removing the package as well.
### Behavior and Interactions
The command fields are positional Clap arguments because they do not declare long or short option names. Parsing and invalid-input handling are supplied by Clap rather than handwritten validation here. Display for Cli forwards to its command. Command formatting emits the operation and includes the restore deletion choice or uninstall mode when applicable. UninstallMode formatting emits its lowercase service or package representation. This module declares argument structure and formatting only; it performs no service operations, file changes, asynchronous work, or tests.

---

## proxy_agent_setup/src/backup.rs

### Purpose and Functionality
Centralizes the setup tool's backup-directory layout without performing backup operations itself.
### Key Components
proxy_agent_backup_folder obtains the staged agent directory from the setup module and returns its Backup child. proxy_agent_backup_package_folder returns the Package child beneath that backup directory.
### Behavior and Interactions
Both functions return owned PathBuf values assembled through path joins. They do not create directories, inspect files, copy packages, or report filesystem errors. There are no platform gates, asynchronous operations, or tests in this file.

---

## proxy_agent_setup/src/error.rs

### Purpose and Functionality
Declares the setup crate's error wrapper.
### Key Components
Error derives Debug and thiserror::Error and has a single Io variant owning a standard-library I/O error.
### Behavior and Interactions
The variant's transparent error annotation preserves the wrapped error's display and source behavior. Its conversion annotation generates conversion from std::io::Error, supporting propagation into the setup error type. This file contains declarations only, with no logging, recovery logic, platform gates, or tests.

---

## proxy_agent_setup/src/linux.rs

### Purpose and Functionality
Handles non-Windows installation, backup, restoration copying, and deletion of agent files, the systemd unit, and the manual page. Both this file and its parent module declaration exclude Windows builds.
### Key Components
setup_service copies the named unit into the shared service-config directory, sets permissions to 0644, and then attempts manual-page installation. Unit copying and permission failures become contextual I/O errors propagated through Result. The manual page is optional when absent from the source directory; copying and permission failures are logged instead of propagated.
### Behavior and Interactions
backup_files copies configuration, the eBPF object, and the running executable into the backup package directory; the manual page and unit are backed up beside that directory. copy_files installs the executable, configuration, and eBPF object to their separate destinations, applying 0755 to the executable and 0644 to configuration. Its shared copying helper attempts parent-directory creation, logs failures, and still attempts copying. File deletion likewise logs failures without returning them. delete_files removes the executable, configuration, eBPF object, and manual page, but not the service unit. No tests or asynchronous operations are declared.

---

## proxy_agent_setup/src/logger.rs

### Purpose and Functionality
Provides setup-specific initialization and output helpers over the shared logging infrastructure. Messages are mirrored to the console so setup progress and errors remain visible outside the log file.
### Key Components
init_logger selects the current executable directory and the fixed setup log identity. The private force_init_logger function passes the folder and log name to the shared initializer, using the same name as lookup key and default logger. Its configuration supplies a twenty-mebibyte size limit, a count of thirty, and Trace-level logging.
### Behavior and Interactions
write takes ownership of a String, prints it to standard output, and forwards it to logger_manager at Info level. write_error similarly prints to standard error and forwards the owned message at Error level. Both use the fixed setup logger key. The module does not return initialization or write errors, implement rotation itself, or introduce asynchronous synchronization. There are no platform-specific branches or tests; directory discovery and logging mechanics are delegated to shared helpers.

---

## proxy_agent_setup/src/main.rs

### Purpose and Functionality
Coordinates the Tokio-based setup executable's install, backup, restore, uninstall, and purge commands after initializing logging and parsing arguments. Restore checks only that the backup executable exists, skips when absent, and optionally deletes the backup after setup.
### Key Components
Install and restore await service stopping, copy their selected package, install or update the service, and start it. Stop failures and file-copy or directory-deletion failures are logged without aborting. Uninstall removes the service and optionally its package; purge deletes the backup tree.
### Behavior and Interactions
Windows copies enumerated files into version-selected directories and removes a differing existing running directory before installation. Service registration precedes optional eBPF setup-script execution; script invocation failures are logged. If the additional eBPF service exists, registration is repeated with that dependency. Non-Windows paths delegate file placement and unit installation to linux. Unit setup, service installation, dependency update, uninstall, and startup failures exit with failure. Startup uses five retries with a fifteen-second duration. Windows startup diagnostics identify missing or non-running core dependencies. Windows-only tests verify no diagnostic when both dependencies run and inclusion of exactly the failing dependency names across missing and stopped combinations.

---

## proxy_agent_setup/src/result.rs

### Purpose and Functionality
Defines the setup crate's common result type. This is a tiny type-alias declaration, not an implementation of setup operations or error handling.
### Key Components
The public generic Result alias specializes the standard core result type with the setup crate's own Error type while leaving the successful value type generic.
### Behavior and Interactions
Callers can share one error type across fallible setup functions without repeating the full result signature. The alias does not introduce conversions, logging, recovery, resource ownership, or platform-specific behavior; those remain the responsibility of the error definition and calling implementation. No tests are declared in this file.

---

## proxy_agent_setup/src/running.rs

### Purpose and Functionality
Resolves the installed proxy agent's running directory and the destination directory for a versioned installation. These helpers return owned paths rather than creating directories or copying files.
### Key Components
proxy_agent_running_folder queries the Windows service executable location and uses its parent directory. Query failures are logged and fall back to the default package directory; an executable without a parent uses the same fallback. Non-Windows builds return the shared Linux executable directory instead. proxy_agent_parent_folder expands the system-drive environment variable into the Windows installation root and explicitly panics on non-Windows platforms.
### Behavior and Interactions
proxy_agent_version_target_folder reads the supplied executable's version through shared helpers, logs it, and selects a version-suffixed package directory on Windows. Non-Windows builds retain the fixed executable directory, but still perform the version lookup first. Failure to obtain the version is logged and causes a panic rather than allowing installation to proceed. No tests are defined here.

---

## proxy_agent_setup/src/setup.rs

### Purpose and Functionality
Provides path-construction helpers for files distributed alongside the setup executable. It locates the packaged proxy agent and the Windows eBPF setup script without performing installation, validating existence, or reading package contents.
### Key Components
proxy_agent_folder_in_setup joins the current executable directory with the proxy agent package subdirectory. proxy_agent_exe_in_setup composes that result with proxy_agent_exe_path. The latter accepts a borrowed package directory and chooses the Windows executable filename under cfg(windows), or the Linux-style executable filename under cfg(not(windows)). The private ebpf_folder helper resolves the adjacent eBPF distribution directory, and ebpf_setup_script_file appends its PowerShell setup filename.
### Behavior and Interactions
All helpers return owned PathBuf values and reuse the shared current-executable-directory resolver. The eBPF path helpers themselves are not Windows-gated, despite referring to a Windows package. This file contains no explicit error handling, asynchronous work, filesystem mutations, or tests.

---
