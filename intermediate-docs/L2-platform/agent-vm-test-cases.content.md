# Compose Content for: L2-platform/agent-vm-test-cases.md

Total files: 15

---

## e2etest/GuestProxyAgentTest/TestCases/AddLinuxVMExtensionCase.cs

### Purpose and Functionality
Installs the Linux test VM extension through Azure Resource Manager and records provisioning evidence in the execution context. Despite its introductory comment, this case deploys an extension rather than rebooting the VM.
### Key Components
AddLinuxVMExtensionCase derives from TestCaseBase and supports default or caller-supplied names. StartAsync constructs extension data using the configured region, selects the handler type from the scenario's ARM64 flag, disables both upgrade mechanisms, and supplies empty settings.
### Behavior and Interactions
The result initially indicates failure. A completed create-or-update operation succeeds immediately when its provisioning state is Succeeded, with formatted extension data captured as custom output. Exceptions are retained in standard error before fallback polling. The non-success formatting expression contains an invalid composite-format placeholder, so that path also reaches the catch. Fallback queries expanded instance-view data, accepting only the first status's provisioning-success display text. It retries approximately every ten seconds for five minutes and preserves failure on timeout. Azure operations receive context cancellation, but delays do not; polling exceptions propagate outside the initial catch.

---

## e2etest/GuestProxyAgentTest/TestCases/EnableProxyAgentCase.cs

### Purpose and Functionality
Changes a VM's proxy-agent security settings through an Azure Resource Manager patch. The internal EnableProxyAgentCase supports enabling or disabling the agent, controlling Linux extension addition, and choosing local-file rules versus configured endpoint access-control profiles.
### Key Components
Constructors default to enabling the agent without explicitly adding the Linux extension. StartAsync builds VirtualMachinePatch, SecurityProfile, and ProxyAgentSettings objects. The AddProxyAgentExtension field is populated only when the platform helper identifies Linux.
### Behavior and Interactions
When enabling, WireServer and IMDS settings are chosen independently. Local-file rules or a missing profile reference select enforce mode with the local-rule flag; otherwise, only the profile reference is supplied. This avoids combining profile references with endpoint mode. Disabling omits endpoint configuration. The update waits for completion and receives the execution-context cancellation token. A subsequent instance-view request does not explicitly receive that token. Success records serialized instance-view output and a non-blob result; it does not inspect endpoint behavior or instance-view status. No local catch converts update or retrieval exceptions into results.

---

## e2etest/GuestProxyAgentTest/TestCases/GuestProxyAgentExtensionValidationCase.cs

### Purpose and Functionality
Runs the configured guest proxy agent extension validation script and interprets its structured output as end-to-end assertions about extension health. The implementation delegates in-VM inspection to the script rather than checking services directly in C#.
### Key Components
GuestProxyAgentExtensionValidationCase supports a default name or an explicit name with expected agent version. The default expected version is empty. StartAsync passes that expectation as a script parameter and converts the Run Command response into TestResultDetails using the context logger. GuestProxyAgentExtensionValidationDetails supplies six Boolean fields matching the script's output.
### Behavior and Interactions
Additional assertions run only when the converted result already succeeds and custom output is non-null. Safe deserialization uses the logger. A non-null decoded object must confirm service existence, process existence, service status, status-object generation, version validation, and extension instance-view validation. Any false field or null decoded object marks failure. An initially failed command remains failed; an initially successful result without custom output is left unchanged. This file defines no polling, local exception handling, or independent version comparison.

---

## e2etest/GuestProxyAgentTest/TestCases/GuestProxyAgentLoadedModulesValidationCase.cs

### Purpose and Functionality
Validates the guest proxy agent's loaded modules against a baseline through a PowerShell script. The case prepares the baseline artifact and interprets the returned comparison, rather than enumerating modules within the C# process.
### Key Components
GuestProxyAgentLoadedModulesValidationCase resolves the baseline text file beneath the configured resources directory. It uploads that file to shared blob storage under the scenario's storage prefix and passes the returned access URL as a UTF-8, Base64-encoded script parameter. LoadedModulesValidationDetails contains missing-baseline modules, newly added modules, and an overall match flag.
### Behavior and Interactions
The Run Command response is converted into context result details. If it succeeds and supplies custom output, safe deserialization is attempted with logging. A non-null object passes when the overall match flag is true, the new-module list is null, or that list is empty. Missing-baseline modules alone do not cause failure. Null deserialization or unmatched output containing new modules fails. Successful command results lacking custom output are unchanged. Upload and execution exceptions are not caught here.

---

## e2etest/GuestProxyAgentTest/TestCases/GuestProxyAgentValidationCase.cs

### Purpose and Functionality
Validates the installed guest proxy agent by running the configured in-VM validation script and checking structured service, process, log, and secure-channel evidence.
### Key Components
GuestProxyAgentValidationCase initializes its expected service status once: Running for Windows and enabled otherwise, as determined by the platform helper. The secure-channel expectation defaults to disabled and can be overridden with the named constructor. GuestProxyAgentValidationDetails models three Boolean checks plus service-status and secure-channel strings.
### Behavior and Interactions
StartAsync supplies the expected secure-channel state to the script and converts its response through the shared result extension. When the initial result succeeds and custom output exists, safe deserialization must produce an object confirming service installation, process startup, and log generation. Service status and secure-channel state must also match expectations using ordinal, case-insensitive comparisons. Missing or false evidence marks failure. An initially successful command without custom output is not reclassified. The string properties are initialized with null-forgiving declarations rather than runtime defaults; comparisons assume non-null values. Script execution and comparison exceptions are not caught locally.

---

## e2etest/GuestProxyAgentTest/TestCases/IMDSPingTestCase.cs

### Purpose and Functionality
Defines a script-backed end-to-end case for probing IMDS connectivity with specified secure-channel and IPv6 dual-stack expectations. The file is a small orchestration wrapper, not an implementation of HTTP requests or network probing.
### Key Components
IMDSPingTestCase derives from TestCaseBase. Its constructor requires a case name and secure-channel-enabled flag, and defaults the IPv6 dual-stack-supported flag to true. Both flags are retained as private properties.
### Behavior and Interactions
StartAsync converts each Boolean to its string representation and supplies the two named parameters to the configured IMDS ping script through RunScriptViaRunCommandV2Async. The helper's final Boolean argument is explicitly false. The awaited response is converted to TestResultDetails with the execution-context logger and assigned to the context. This class adds no structured-output assertions, retry loop, timeout, or local exception handling. Connectivity assertions and interpretation of the supplied expectations are delegated to the script and shared execution helpers.

---

## e2etest/GuestProxyAgentTest/TestCases/InstallOrUpdateGuestProxyAgentCase.cs

### Purpose and Functionality
Coordinates installation or update of the guest proxy agent through the configured MSI installation script on the scenario VM. It stages the installation archive in shared storage and delegates actual guest-side installation to RunCommandRunner.
### Key Components
InstallOrUpdateGuestProxyAgentCase derives from TestCaseBase with a fixed default name. StartAsync constructs a RunCommandSettingBuilder containing the scenario settings, an MSI-specific command name, and a script path beneath the configured scripts directory.
### Behavior and Interactions
The execution call receives the context logger, VM resource, and cancellation token. A builder callback uploads the configured archive to the shared MSI container using the scenario storage prefix. It encodes the returned access URL as UTF-8 Base64 and adds it as the archive script parameter. After completion, the case copies success, standard error, and standard output into a new result and marks it as blob-backed. There is no custom-output copying, separate installed-version verification, reboot, cleanup, or local exception handling; upload and execution failures can propagate.

---

## e2etest/GuestProxyAgentTest/TestCases/InstallOrUpdateGuestProxyAgentExtensionCase.cs

### Purpose and Functionality
Installs or updates a development guest proxy agent extension using a script executed on the scenario VM. Although its comment mentions MSI installation, the selected script and parameter specifically handle the extension artifact.
### Key Components
InstallOrUpdateGuestProxyAgentExtensionCase builds a Run Command request from scenario settings, an extension-install command name, and the configured extension installation script path. Its builder callback uploads the configured archive to shared MSI storage under the scenario prefix and supplies the returned access URL as a UTF-8 Base64-encoded development-extension parameter.
### Behavior and Interactions
Execution uses the context logger, VM resource, and cancellation token. The result copies command success and standard streams and is marked blob-backed. On non-Windows platforms, the case then awaits a completed VM restart with cancellation, allowing sequential Linux VM extension processing to unpack, install, and enable the replacement. Restart is attempted regardless of the command's success flag. Windows skips that restart. There is no local catch or post-restart health check, so restart errors propagate after the command result has already been stored.

---

## e2etest/GuestProxyAgentTest/TestCases/InstallOrUpdateGuestProxyAgentPackageCase.cs

### Purpose and Functionality
Runs the configured Linux guest proxy agent package installation or update script against the scenario VM. Despite an MSI-oriented comment, the implementation selects the Linux package script explicitly.
### Key Components
InstallOrUpdateGuestProxyAgentPackageCase derives from TestCaseBase with its own default name. StartAsync constructs RunCommandSettingBuilder with scenario settings, a package-install command name, and the script path assembled from the configured scripts directory and Linux package script constant.
### Behavior and Interactions
RunCommandRunner receives the logger, VM resource, and context cancellation token. Its builder callback uploads the configured archive to the shared MSI container using the scenario storage prefix, encodes the resulting access URL as UTF-8 Base64, and adds the archive parameter. The awaited command's success flag and standard streams become a new blob-backed TestCaseResultDetails object. No platform guard prevents invocation elsewhere; script selection is the Linux-specific behavior in this file. There is no local retry, exception conversion, package-version assertion, restart, or staged-artifact cleanup.

---

## e2etest/GuestProxyAgentTest/TestCases/LocalIPBindingCase.cs

### Purpose and Functionality
Defines a script-backed network test for ping behavior while binding a local IP address. This class configures the requested IMDS mode and delegates the actual binding and connectivity checks to the configured in-VM script.
### Key Components
LocalIPBindingCase derives from TestCaseBase and offers a default constructor, a named constructor, and a constructor accepting both a name and IMDS mode. Its private mode property defaults to enforce; constructors without an explicit mode retain that setting.
### Behavior and Interactions
StartAsync creates a single named script parameter carrying the selected mode and invokes RunScriptViaRunCommandV2Async with the local-IP-binding ping script constant. The helper's final Boolean argument is explicitly false. The awaited response is converted into TestResultDetails using the context logger and stored in the execution context. The wrapper does not validate the mode string, inspect custom output, or add assertions beyond the shared conversion. It contains no local retry, cancellation logic, resource disposal, or exception handling.

---

## e2etest/GuestProxyAgentTest/TestCases/RebootVMCase.cs

### Purpose and Functionality
Restarts a scenario VM and records management-plane evidence, with a fallback status-polling path when restart or immediate instance-view retrieval throws.
### Key Components
RebootVMCase derives from TestCaseBase and accepts default or caller-supplied names. StartAsync first installs an unsuccessful, non-blob result with empty standard streams in the execution context.
### Behavior and Interactions
The primary path awaits restart completion with the context cancellation token, retrieves instance view without explicitly passing that token, and records success with serialized output. It does not inspect status values on this path. Exceptions are saved in standard error before polling instance view for approximately five minutes. Polling accepts either provisioning-success or running display text, but examines only the first status entry. Success updates the existing result and retains the earlier error text. Timeout stores the latest view while leaving failure intact. Poll requests receive cancellation, whereas ten-second delays do not. Polling exceptions are outside the catch and propagate. Status recovery does not independently prove a reboot occurred or guest applications became ready.

---

## e2etest/GuestProxyAgentTest/TestCases/RunPenTestCase.cs

### Purpose and Functionality
RunPenTestCase prepares inputs and an output destination for the penetration-test script, then delegates execution to the shared VM Run Command helper. Its constructor supplies the fixed test-case name used by the harness.
### Key Components
StartAsync uploads the configured ZIP package to shared package storage under the scenario's storage prefix. It creates an empty temporary file with a scenario-specific penetration-test log archive name, closes the writer immediately, and uploads that placeholder to shared test-output storage.
### Behavior and Interactions
The package and log-upload SAS URLs are UTF-8 encoded and converted to base64 script parameters. The script runs without the helper's optional custom JSON output parameter. After execution, the case sets CustomOut to the log archive's SAS URL and converts the command output into context.TestResultDetails using the scenario logger. It contains no local assertion, exception handler, or temporary-file cleanup; upload, file, and command failures propagate to the scenario harness.

---

## e2etest/GuestProxyAgentTest/TestCases/SetupCGroup2TestCase.cs

### Purpose and Functionality
SetupCGroup2TestCase is a small adapter that schedules the configured cgroup-v2 setup script through the common test-case infrastructure. The caller supplies its test-case name.
### Key Components
The constructor forwards that name to TestCaseBase. StartAsync invokes RunScriptViaRunCommandV2Async with the setup-script constant, no explicit script parameters, and custom JSON output disabled.
### Behavior and Interactions
The awaited command result is converted into TestResultDetails without passing a logger to the conversion method, then stored on the execution context. VM selection, cancellation, and command construction are inherited from the helper. This file neither implements cgroup configuration nor checks the platform, reboots the VM, or catches execution errors; those responsibilities lie outside this wrapper.

---

## e2etest/GuestProxyAgentTest/TestCases/TCPPortScalabilityCase.cs

### Purpose and Functionality
TCPPortScalabilityCase wraps execution of the PowerShell script that configures TCP port scalability on a scenario VM. Its constructor assigns ConfigTCPPortScalability as the harness-visible test-case name.
### Key Components
StartAsync awaits RunScriptViaRunCommandV2Async for ConfigTCPPortScalability.ps1, passing no explicit parameters and disabling the optional custom JSON output destination. It converts the returned command output into context.TestResultDetails with the context logger.
### Behavior and Interactions
The class declares a private ImdsSecureChannelEnabled property but never reads or sets it. It performs no platform check, reboot, connectivity assertion, or scalability measurement itself. Command setup and cancellation come from the base helper, while exceptions propagate to the enclosing scenario. The separate scalability scenario schedules the reboot and subsequent IMDS connectivity case.

---

## e2etest/GuestProxyAgentTest/TestCases/TestCaseBase.cs

### Purpose and Functionality
TestCaseBase defines the shared contract and VM-script execution support for individual end-to-end cases. TestCaseResult represents NotStarted, Running, Succeed, Failed, and Aborted states. Each case has a constructor-assigned name, a mutable result initially NotStarted, and an abstract asynchronous StartAsync method.
### Key Components
RunScriptViaRunCommandV2Async optionally creates an empty temporary JSON file, disposes its writer, and uploads it as customOutputJson.json under the scenario storage prefix. It builds a RunCommandSettingBuilder using the scenario settings, case name, and script path beneath the configured scripts folder.
### Behavior and Interactions
The helper passes the context VM, logger, cancellation token, custom-output SAS, and caller-supplied parameters to RunCommandRunner. Disabling custom JSON output leaves its SAS value null. File, storage, and execution errors are not caught here, and temporary files are not deleted. Three formatting helpers produce diagnostic strings for extension data, extension instance views, and status lists. Null inputs yield a literal null marker; non-null status entries are concatenated with their code, level, display status, and message.

---
