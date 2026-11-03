**TL;DR:** Deployment scenarios compose ordered VM test cases for agent installation, extension updates, enablement, and reboot connectivity across Linux and Windows. `TestScenarioBase` owns provisioning, sequential execution, reporting, artifacts, and cleanup; individual cases implement operations and assertions.

# Agent deployment test scenarios

<!-- TIER2-POINTER:BEGIN (managed by step8_inject_tier2_pointer.py) -->
> **Need a specific class, method, error code, config key, or flow step?**
> Read `intermediate-docs/L2-platform/agent-deployment-test-scenarios.content.md` for implementation details; stay here for overviews.
> Search the companion for the source-file heading and range-read that section, starting with Purpose and Functionality.
> Verify behavior in source when needed; do not load the entire companion.
<!-- TIER2-POINTER:END -->

## Why: exercise deployment transitions

These scenarios check deployment paths and selected connectivity expectations before and after VM restarts. Case ordering encodes prerequisites: enablement precedes enforced-state validation, extension updates precede target-version validation, and reboot precedes persistence checks.

Scenario composition is not proof of successful deployment or complete security coverage. Assertions belong to the registered cases; actual outcomes belong to runner results and artifacts.

## What: scenario selection and platform boundaries

| Scenario | Platform contract | Ordered coverage |
|---|---|---|
| `BakedInScenario` | Linux only; throws on Windows | Start disabled; validate disabled state and IMDS without secure channel; enable; validate WireServer/IMDS/HostGA enforcement; secure-channel IMDS before and after reboot. No install/update; IPv6 dual-stack pings disabled throughout. |
| `BVTScenario` | Windows and non-Windows branches | Non-Windows: cgroup-v2 setup and reboot. All: install/update and validate. Windows: loaded-module validation. Non-Windows: enable and validate all three enforcement targets. IMDS before/after installation reboot; secure channel and local-IP binding only on non-Windows. |
| `LinuxImplicitExtension` | Linux only; throws on Windows | Enable with implicit extension addition; validate extension with version argument zero; update; validate configured target version; secure-channel IMDS and local-IP binding before/after reboot. |
| `LinuxPackageScenario` | Linux-specific cases, but no explicit platform guard | cgroup-v2 setup and reboot; package install/update; default validation; enable; validate all three enforcement targets; secure-channel IMDS and local-IP binding before/after another reboot. |
| `ProxyAgentExtension` | Windows and non-Windows branches | Non-Windows: cgroup-v2 setup, reboot, explicit VM extension addition, enablement. Windows: request enablement during provisioning. Both: version-zero validation, update, target-version validation, secure-channel IMDS before/after reboot. No local-IP binding cases. |
| `PenTestScenario` | No explicit platform guard | Provision with enablement, extension addition, and local-file rules requested; version-zero validation; extension update; target-version validation; `RunPenTestCase`. No reboot or separate IMDS ping. |
| `TCPPortScalabilityScenario` | Windows only; throws on non-Windows | Request enablement during provisioning; extension install/update; target-version validation; `TCPPortScalabilityCase`; reboot; secure-channel IMDS ping. No numeric port-count threshold asserted by this scenario. |

### Configuration and interpretation

- `TestScenarioSetup` registers cases rather than executing them. Settings such as `GuestProxyAgentSettings.Enabled`, `AddProxyAgentExtension`, and `UseLocalFileRules` are consumed during provisioning.
- Extension scenarios read and log the configured target agent version. A pre-update version argument of zero is passed to the validation case, not interpreted by the scenario itself.
- BVT comments explain Windows omissions: enablement could replace the private package through extension installation; local-IP binding awaits an officially signed system eBPF file. Do not silently equalize platform branches.
- Secure-channel flags express expectations for IMDS cases, not independent evidence that a secure channel was established.

## How: shared execution and recovery

1. **Construct and configure:** `TestScenarioBase` initializes logging and agent settings, then calls subclass setup. Fluent methods supply scenario settings and builders; `PreCheck` rejects missing prerequisites.
2. **Provision under a scenario timeout:** `StartAsync` supplies cancellation. Allocation failures try parsed alternative VM sizes or an available-size fallback. A non-allocation error during retries stops alternatives but still proceeds to instance-view polling.
3. **Recover provisioning status:** polling examines only the first display status for provisioning success or running, for up to five minutes with uncancelled ten-second delays. This is a limited status check, not an application-readiness assertion.
4. **Execute registered cases sequentially:** cases check cancellation, receive `TestCaseExecutionContext`, resolve blob output, and produce timed JUnit results. Ordinary case failures do not stop later cases; registration order alone is not fail-fast dependency enforcement.
5. **Persist outcomes:** case-finalization paths update state and save outputs by blob download or direct write. `DoStartAsync` catches scenario exceptions and marks failure and completion; escaping exceptions are mapped to case results by `StartAsync`.
6. **Attempt teardown independently:** finalization collects guest-agent logs without cancellation and attempts Azure cleanup separately, logging failures from either operation. Log placeholders are uploaded and populated through Run Command.

### Lifecycle limits to preserve

`TestCaseExecutionContext` carries the VM, settings, logger, cancellation token, and mutable results. Keep orchestration separate from case-specific remote scripts and assertions. Cleanup is attempted, not guaranteed; the base class does not dispose its cancellation source or delete temporary files here.

## Code Pointers

All paths are repository-relative. Scenario entry points are `TestScenarioSetup`; shared lifecycle entry points are `PreCheck`, `StartAsync`, and `DoStartAsync`.

| Component | File Path | Key Classes |
|---|---|---|
| Baked-in image enablement | `e2etest\GuestProxyAgentTest\TestScenarios\BakedInScenario.cs` | `BakedInScenario` |
| Basic install and reboot coverage | `e2etest\GuestProxyAgentTest\TestScenarios\BVTScenario.cs` | `BVTScenario` |
| Implicit Linux extension addition | `e2etest\GuestProxyAgentTest\TestScenarios\LinuxImplicitExtension.cs` | `LinuxImplicitExtension` |
| Linux package deployment | `e2etest\GuestProxyAgentTest\TestScenarios\LinuxPackageScenario.cs` | `LinuxPackageScenario` |
| Penetration-test environment composition | `e2etest\GuestProxyAgentTest\TestScenarios\PenTestScenario.cs` | `PenTestScenario` |
| Cross-platform extension update | `e2etest\GuestProxyAgentTest\TestScenarios\ProxyAgentExtension.cs` | `ProxyAgentExtension` |
| Windows TCP configuration sequence | `e2etest\GuestProxyAgentTest\TestScenarios\TCPPortScalabilityScenario.cs` | `TCPPortScalabilityScenario` |
| Shared scenario lifecycle | `e2etest\GuestProxyAgentTest\TestScenarios\TestScenarioBase.cs` | `TestScenarioBase`, `TestCaseExecutionContext` |

## Related components

Start with adjacent DAGs for component boundaries; use the VM-case companion for operation-specific detail.

| Component | Follow for |
|---|---|
| [Agent VM test cases](..\..\intermediate-docs\L2-platform\agent-vm-test-cases.content.md) | Install/update operations, enablement, extension validation, reboot, IMDS, local-IP binding, penetration-test execution, and TCP configuration. |
| [Agent E2E test runner](agent-e2e-test-runner.md) | Scenario dispatch, scenario settings, and JUnit report construction. |
| [Agent cloud test utilities](agent-cloud-test-utilities.md) | VM provisioning helpers, Run Command, blob output, logging, and test-map loading. |
| [Agent E2E test models](agent-e2e-test-models.md) | Configuration, scenario status, and case-result data contracts. |
