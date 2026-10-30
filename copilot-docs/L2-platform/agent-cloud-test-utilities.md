**TL;DR:** These C# utilities turn end-to-end scenario settings into Azure VMs, blob-backed scripts, managed Run Commands, and cleanup operations. They support the test harness, not the agent's production request path; callers retain responsibility for output interpretation and recovery.

# Agent cloud test utilities

<!-- TIER2-POINTER:BEGIN (managed by step8_inject_tier2_pointer.py) -->
> **Need a specific class, method, error code, config key, or flow step?**
> Read `intermediate-docs/L2-platform/agent-cloud-test-utilities.content.md` for implementation details; stay here for overviews.
> Search the companion for the source-file heading and range-read that section, starting with Purpose and Functionality.
> Verify behavior in source when needed; do not load the entire companion.
<!-- TIER2-POINTER:END -->

## Why

Cloud scenarios need repeatable configuration loading, VM provisioning, script delivery, remote execution, and resource reclamation. This layer centralizes those mechanics so scenario and test-case code can focus on deployment and validation.

## What

| Responsibility | Contract |
|---|---|
| Configuration and maps | YAML configuration initializes shared settings; included test groups flatten into scenario settings carrying image metadata and class names. |
| VM lifecycle | Provision resource groups, networking, and marketplace/shared-gallery VMs; resolve VM handles and remove scenario resources. |
| Remote execution | Upload/select scripts, allocate output blobs, submit managed Run Commands, and return output SAS references plus execution success. |
| Supporting utilities | Discover certificates, deserialize environment tokens, download HTTP content, generate names, log messages, and assert conditions. |

### Code Pointers

Paths are repository-relative. Method names identify behavior entry points without embedding implementation.

| Component | File Path | Key Classes |
|---|---|---|
| Harness setup, downloads, tokens | `e2etest\GuestProxyAgentTest\Utilities\TestCommonUtilities.cs` | `TestCommonUtilities`: `TestSetup`, `DownloadContentAsString`, `DownloadFile`, `GetAccessTokenFromEnv`; `TokenEnvModel` |
| YAML loading | `e2etest\GuestProxyAgentTest\Utilities\YamlUtils.cs` | `YamlUtils.DeserializeYaml<T>` |
| Scenario-map expansion | `e2etest\GuestProxyAgentTest\Utilities\TestMapReader.cs` | `TestMapReader.ReadFlattenTestScenarioSettingFromTestMap`, `TestMapFile` |
| Shared names and host-platform selection | `e2etest\GuestProxyAgentTest\Utilities\Constants.cs` | `Constants`, `IS_WINDOWS` |
| Certificate lookup | `e2etest\GuestProxyAgentTest\Utilities\CertificateUtility.cs` | `CertificateUtility`: `IsCertInstalled`, `GetCertificate`, `CanAccessPrivateKey` |
| Resource-name candidates | `e2etest\GuestProxyAgentTest\Utilities\ResourceNamer.cs` | `ResourceNamer`: `RandomName`, `RandomString` |
| VM provisioning | `e2etest\GuestProxyAgentTest\Utilities\VMBuilder.cs` | `VMBuilder.Build`; `GuestProxyAgentSettings` |
| VM lookup and cleanup | `e2etest\GuestProxyAgentTest\Utilities\VMHelper.cs` | `VMHelper`: `Init`, `GetVMResource`, `CleanupTestResources`, `CleanupOldTestResourcesAndForget` |
| Blob uploads, SAS, cleanup | `e2etest\GuestProxyAgentTest\Utilities\StorageHelper.cs` | `StorageHelper`: `Init`, `Instance` |
| Command preparation | `e2etest\GuestProxyAgentTest\Utilities\RunCommandSettingBuilder.cs` | `RunCommandSettingBuilder`: `Build`, `CustomOutputSas`, `TestScenarioSetting` |
| Command submission | `e2etest\GuestProxyAgentTest\Utilities\RunCommandRunner.cs` | `RunCommandRunner.ExecuteRunCommandOnVM`, `toVMRunCommandData` |
| Console diagnostics | `e2etest\GuestProxyAgentTest\Utilities\TestLogger.cs` | `TestLogger.Log`, `Prefix` |
| Minimal assertions | `e2etest\GuestProxyAgentTest\Utilities\TestAssertUtils.cs` | `TestAssertUtils.AssertIsTrue` |

## How

### Setup and scenario selection

1. `TestCommonUtilities.TestSetup` deserializes YAML into `TestConfig`, initializes `TestSetting` with artifact/result paths and version, then initializes storage and VM helpers.
2. `TestMapReader.ReadFlattenTestScenarioSettingFromTestMap` reads the map beside the executing assembly and expands included groups into `TestScenarioSetting` objects. `YamlUtils.DeserializeYaml<T>` uses camel-case naming and propagates file/YAML errors.
3. `Constants.IS_WINDOWS` selects script names and Windows/Linux-named maps from the **harness host OS**, not a supplied target-VM OS. ARM64 map selection is separate and defaults to false; every non-Windows host takes the Linux-named branch.

### Provision, execute, collect

1. `VMBuilder` loads scenario settings, generates resource names, and builds a cleanup-tagged resource group plus VM networking. Subnet default outbound access is disabled.
2. VM creation supports marketplace or shared-gallery images, purchase plans, managed OS storage, and ARM64 extension tags. Size selection prefers the configured available size, architecture-specific fallbacks, then a two-vCPU architecture match; exhaustion logs and falls back to the configured size.
3. `GuestProxyAgentSettings` starts with enablement, extension installation, and local-file rules disabled. Proxy endpoints use local rules or access-control profile references, defaulting to Enforce when references are absent. Harness OS selects guest configuration; explicit extension control applies only to non-Windows, non-gallery creation.
4. `RunCommandSettingBuilder.Build` prefers an existing script SAS URI over a local script upload and creates standard/error append blobs under the scenario/command prefix. A custom-output URI becomes a UTF-8/base64 script parameter.
5. `RunCommandRunner.ExecuteRunCommandOnVM` optionally transforms the builder, then submits a command using configured location, script URI, output URIs, ordinary parameters, and a one-hour timeout with asynchronous guest execution disabled.
6. Success requires both `Succeeded` execution state and exit code zero. `RunCommandOutputDetails` returns standard/error/custom SAS locations, **not downloaded output**; downstream result-processing code materializes and reports them.

### Cleanup and failure boundaries

| Boundary | Behavior agents must preserve or account for |
|---|---|
| Initialization | `StorageHelper` and `VMHelper` require initialization, keep the first client, ignore supplied tenant/client arguments, and do not synchronize initialization. |
| Cancellation and recovery | Cancellation reaches VM creation and Run Command create/update, not all provisioning calls or the later synchronous InstanceView fetch. Provisioning has no rollback; command submission has no retry or command-resource deletion. |
| Scenario cleanup | `VMHelper.CleanupTestResources` waits for resource-group deletion before deleting scenario-prefixed blobs in two shared containers. An exception can prevent later cleanup steps. |
| Old-resource cleanup | `CleanupOldTestResourcesAndForget` returns an awaitable task. It selects cleanup-tagged groups whose earliest timestamped deployment is at least two days old, requests deletion without waiting for completion, and leaves groups without qualifying deployments alone. |
| Blob scope and lifetime | Uploads overwrite; append blobs are created only if absent. Prefix cleanup deletes every matching blob. SAS grants all container permissions despite a blob-addressed URI; its seven-day expiry exceeds the delegation key's one-day future expiry. |
| Mutable builders | `Build` returns the same settings instance. Repeated builds can repeat storage work and duplicate custom-output parameters; duplicate dictionary keys throw. Missing script or a null command name throws, and missing scenario setup can fail on prefix access. |
| Naming | `ResourceNamer` produces candidates, not guaranteed maximum-length names: oversized prefixes are not truncated and `RandomString` can overshoot. |
| Certificates | `IsCertInstalled` normalizes thumbprints and searches without validity filtering. Convenience lookup searches CurrentUser before LocalMachine, accepting only matches that pass any requested private-key check. Environment loading tries passwordless PKCS#12, then certificate parsing on a cryptographic exception; failures log and return null, not a vault lookup. Returned certificates remain caller-owned; rejected objects are not explicitly disposed. |
| Environment tokens | `GetAccessTokenFromEnv` deserializes token text and expiration into `AccessToken`. Missing data, malformed JSON, and expiration errors propagate; a null-deserialization error includes the original environment text. Constants contain environment-variable names, not token values. |
| Downloads and logging | HTTP helpers are synchronous. File download deletes an existing destination before attempting the request and its catch path dereferences an optional logger. String retries sleep even after the last failure. `TestLogger` writes local timestamps without redaction. |
| Assertions | `TestAssertUtils.AssertIsTrue` invokes its delegate once and throws on false; delegate exceptions propagate without logging or result-record creation. |

## Related components

Follow adjacent DAGs for consumers and shared contracts:

| Component | Relationship |
|---|---|
| [Agent E2E test runner](agent-e2e-test-runner.md) | Owns process-wide/scenario/command settings, environment-backed credential adapters, entry-point orchestration, output materialization, and JUnit reporting. |
| [Agent E2E test models](agent-e2e-test-models.md) | Defines `TestConfig`, test-map shapes, `RunCommandOutputDetails`, and result/status containers consumed by utilities and the runner. |
| [Agent deployment test scenarios](agent-deployment-test-scenarios.md) | Scenario-level consumers of provisioning, remote commands, and cleanup. |
| [Agent VM test cases](..\..\intermediate-docs\L2-platform\agent-vm-test-cases.content.md) | Guest-side validation workflows built on script selection and remote command execution. |
