**TL;DR:** VM test cases provide reusable deployment, configuration, health-validation, and connectivity steps for the E2E harness. Most delegate guest operations to scripts through Azure Run Command; management-plane completion and script success are not independent proof of guest readiness.

# Agent VM test cases

<!-- TIER2-POINTER:BEGIN (managed by step8_inject_tier2_pointer.py) -->
> **Need a specific class, method, error code, config key, or flow step?**
> Read `intermediate-docs/L2-platform/agent-vm-test-cases.content.md` for implementation details; stay here for overviews.
> Search the companion for the source-file heading and range-read that section, starting with Purpose and Functionality.
> Verify behavior in source when needed; do not load the entire companion.
<!-- TIER2-POINTER:END -->

## Why: separate operations from scenario composition

Scenarios need reusable steps for installing artifacts, enabling proxy endpoints,
restarting VMs, and interpreting guest evidence. Cases own those operations and
local assertions; scenario orchestration owns ordering, execution-state changes,
reporting, and teardown. A configured test step is not evidence that it passed.

## What: operation and assertion boundaries

| Case family | Responsibility | Important limit |
|---|---|---|
| Agent MSI and Linux package installation | Stage the configured archive and invoke the selected installation script. | Command success and standard streams only; no installed-version assertion, restart, or artifact cleanup. The package case has no platform guard. |
| Development extension update | Stage the extension archive and invoke its installation script. | Non-Windows restarts afterward, even when command success is false; Windows skips restart. No post-restart health check. |
| Linux VM extension addition | Create/update the ARM extension with architecture-selected handler type, empty settings, and both upgrade mechanisms disabled. | Provisioning evidence only; fallback accepts the first instance-view status's provisioning-success display text. |
| Proxy-agent enablement | Patch VM security settings, optionally controlling Linux extension addition. | Completion and serialized instance view do not verify endpoint behavior or status values. |
| Agent and extension health | Decode script-produced JSON and apply case-specific assertions. | Assertions run only after successful command conversion with non-null custom output. Missing custom output leaves success unchanged. |
| Loaded-module validation | Upload a baseline and interpret the script's module comparison. | Missing-baseline modules alone do not fail; overall match or no newly added modules passes. |
| IMDS and local-IP binding | Pass secure-channel/IPv6 expectations or IMDS mode to connectivity scripts. | No additional C# connectivity assertions or custom JSON destination. |
| cgroup-v2 and TCP configuration | Run setup scripts with custom JSON output disabled. | No local platform check, reboot, or readiness assertion; TCP configuration does not measure scalability. |
| Penetration-test execution | Stage the ZIP and a log-archive destination, then invoke the script. | Exposes the log archive through custom output; no local assertion or temporary-file cleanup. |
| VM reboot | Request restart and record instance view, falling back to status polling after an exception. | A recovered status does not independently prove a reboot or application readiness. |

## How: execution, evidence, and recovery

### Shared case contract

`TestCaseBase` assigns the case name and initializes its mutable result to
`TestCaseResult.NotStarted`. The enum also provides `Running`, `Succeed`, `Failed`,
and `Aborted`; `StartAsync` is the case-specific entry point, not an automatic
state machine.

`TestCaseBase.RunScriptViaRunCommandV2Async` builds settings from the scenario,
case name, and configured script directory. By default it creates an empty
temporary JSON file, uploads it as `customOutputJson.json` beneath the scenario
storage prefix, and passes its SAS destination with caller parameters to
`RunCommandRunner`. Disabling custom JSON output leaves that destination null.
The helper forwards VM, logger, and cancellation token; file, upload, and command
errors propagate. Temporary files are not deleted here.

MSI, package, and extension installation use `RunCommandSettingBuilder` directly.
Their callbacks upload archives to shared MSI storage and pass UTF-8/Base64 access
URLs as script parameters; extension installation uses its distinct development
extension parameter. Results copy command success and standard streams with
`FromBlob` set, without copying custom output.

Baseline validation similarly uploads a resource-file baseline. `RunPenTestCase`
uploads its package and an empty log-archive placeholder, passes both URLs encoded
as parameters, disables the default JSON destination, and assigns the log URL to
`CustomOut` before result conversion.

### Interpret structured validation precisely

| Entry point | Assertions after successful conversion and available custom output |
|---|---|
| `GuestProxyAgentValidationCase.StartAsync` | Requires installed service, running process, and generated logs; service status must match `Running` on Windows or `enabled` otherwise. Secure-channel expectation defaults to `disabled`; both string comparisons are ordinal, case-insensitive. |
| `GuestProxyAgentExtensionValidationCase.StartAsync` | Requires six true fields: service existence, process existence, service status, status-object generation, version validation, and extension instance-view validation. Expected version is passed to the script and defaults to empty. |
| `GuestProxyAgentLoadedModulesValidationCase.StartAsync` | Requires decoded output and either overall match, a null new-module list, or an empty new-module list. Missing-baseline entries alone are accepted. |

Null decoded objects fail these validations; initially failed commands remain
failed. Successful commands without custom output are not reclassified.
Agent status strings have null-forgiving declarations rather than runtime
defaults; comparisons assume non-null values. No local catch handles comparison
or script errors, and extension version comparison belongs to the script.

`IMDSPingTestCase` passes Boolean strings for secure-channel and IPv6 dual-stack
expectations; IPv6 defaults to true. `LocalIPBindingCase` defaults IMDS mode to
`enforce` without validating caller-supplied mode strings. Both rely on script
and shared result interpretation. `SetupCGroup2TestCase` converts output without
a logger; the other thin configuration/connectivity wrappers supply one.

### Management-plane transitions and fallback limits

`EnableProxyAgentCase.StartAsync` defaults to enabling without explicitly adding
the Linux extension. When enabling, it selects WireServer and IMDS independently:
local-file rules or a missing profile reference choose enforce mode with local
rules; otherwise only the profile reference is supplied. Disabling omits endpoint
configuration. Extension addition is set only for Linux. VM update receives
cancellation; subsequent instance-view retrieval does not explicitly receive it.

`AddLinuxVMExtensionCase.StartAsync` begins failed and accepts immediate
provisioning success. Initial exceptions are retained in standard error before
fallback polling; the non-success formatting expression has an invalid composite
placeholder and also enters that catch. `RebootVMCase.StartAsync` likewise begins
failed, but its primary path marks success after restart and instance-view
retrieval without inspecting statuses.

Both fallback loops run approximately five minutes with ten-second delays and
inspect only the first display status. Extension addition accepts provisioning
success; reboot accepts provisioning success or running. Poll requests receive
cancellation but delays do not; polling exceptions propagate outside the initial
catch. Reboot recovery retains the earlier error text, and timeout records the
latest view while leaving failure intact.

## Code Pointers

All paths are repository-relative. Each concrete case implements `StartAsync`.

| Component | File Path | Key Classes |
|---|---|---|
| Shared contract and script helper | `e2etest\GuestProxyAgentTest\TestCases\TestCaseBase.cs` | `TestCaseBase`, `TestCaseResult` |
| ARM extension addition | `e2etest\GuestProxyAgentTest\TestCases\AddLinuxVMExtensionCase.cs` | `AddLinuxVMExtensionCase` |
| VM security configuration | `e2etest\GuestProxyAgentTest\TestCases\EnableProxyAgentCase.cs` | `EnableProxyAgentCase` |
| Extension health assertions | `e2etest\GuestProxyAgentTest\TestCases\GuestProxyAgentExtensionValidationCase.cs` | `GuestProxyAgentExtensionValidationCase`, `GuestProxyAgentExtensionValidationDetails` |
| Module baseline assertions | `e2etest\GuestProxyAgentTest\TestCases\GuestProxyAgentLoadedModulesValidationCase.cs` | `GuestProxyAgentLoadedModulesValidationCase`, `LoadedModulesValidationDetails` |
| Agent health assertions | `e2etest\GuestProxyAgentTest\TestCases\GuestProxyAgentValidationCase.cs` | `GuestProxyAgentValidationCase`, `GuestProxyAgentValidationDetails` |
| IMDS connectivity | `e2etest\GuestProxyAgentTest\TestCases\IMDSPingTestCase.cs` | `IMDSPingTestCase` |
| MSI installation/update | `e2etest\GuestProxyAgentTest\TestCases\InstallOrUpdateGuestProxyAgentCase.cs` | `InstallOrUpdateGuestProxyAgentCase` |
| Extension installation/update | `e2etest\GuestProxyAgentTest\TestCases\InstallOrUpdateGuestProxyAgentExtensionCase.cs` | `InstallOrUpdateGuestProxyAgentExtensionCase` |
| Linux package installation/update | `e2etest\GuestProxyAgentTest\TestCases\InstallOrUpdateGuestProxyAgentPackageCase.cs` | `InstallOrUpdateGuestProxyAgentPackageCase` |
| Bound-local-IP connectivity | `e2etest\GuestProxyAgentTest\TestCases\LocalIPBindingCase.cs` | `LocalIPBindingCase` |
| Restart and status recovery | `e2etest\GuestProxyAgentTest\TestCases\RebootVMCase.cs` | `RebootVMCase` |
| Penetration-test adapter | `e2etest\GuestProxyAgentTest\TestCases\RunPenTestCase.cs` | `RunPenTestCase` |
| cgroup-v2 setup | `e2etest\GuestProxyAgentTest\TestCases\SetupCGroup2TestCase.cs` | `SetupCGroup2TestCase` |
| TCP port configuration | `e2etest\GuestProxyAgentTest\TestCases\TCPPortScalabilityCase.cs` | `TCPPortScalabilityCase` |

## Related components

| Component | Follow for |
|---|---|
| [Deployment test scenarios](agent-deployment-test-scenarios.md) | Case ordering, platform branches, `TestCaseExecutionContext`, lifecycle, and cleanup. The TCP scenario schedules reboot and IMDS after configuration. |
| [Cloud test utilities](agent-cloud-test-utilities.md) | `RunCommandRunner`, `RunCommandSettingBuilder`, storage uploads, platform helpers, script constants, and logging. |
| [E2E test runner](agent-e2e-test-runner.md) | Shared result conversion, output materialization, dispatch, and reporting. |
| [E2E test models](agent-e2e-test-models.md) | `TestCaseResultDetails`, `RunCommandOutputDetails`, and blob-versus-inline output contracts. |
