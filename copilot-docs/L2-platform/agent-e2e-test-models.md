**TL;DR:** `GuestProxyAgentTest.Models` defines the mutable data contracts for E2E environment configuration, test selection, output interpretation, and scenario reporting. These models do not execute tests, provision resources, fetch output, or enforce consistency.

# Agent E2E Test Models


<!-- TIER2-POINTER:BEGIN (managed by step8_inject_tier2_pointer.py) -->
> **Need a specific class, method, error code, config key, or flow step?**
> Read `intermediate-docs/L2-platform/agent-e2e-test-models.content.md` for implementation details; stay here for overviews.
> Search the companion for the source-file heading and range-read that section, starting with Purpose and Functionality.
> Verify behavior in source when needed; do not load the entire companion.
<!-- TIER2-POINTER:END -->
## Why

The E2E harness needs separate representations for what to run, where to run it,
and what happened. Keeping those contracts distinct lets execution and reporting
exchange data without embedding cloud operations or runner behavior in the models.

## What

| Contract | Representation | Important distinction |
|---|---|---|
| Environment | `TestConfig` | Identity/certificate references, subscription/location, VM size, networking, storage, and OS-specific WireServer/IMDS access-control profile references |
| Test selection | `TestMap`, `TestGroupConfig`, `TestGroupDetails`, `TestScenarioConfig` | Outer group references are separate from detailed image metadata and scenario names/class names |
| Remote command output | `RunCommandOutputDetails` | `StdOut`, `StdErr`, and `CustomOut` are SAS URL references, not downloaded text; `Succeed` is an independent flag |
| Test-case output | `TestCaseResultDetails` | The three output channels hold either text or blob SAS URLs, interpreted using `FromBlob` |
| Scenario reporting | `TestScenarioStatusDetails`, `ScenarioTestStatus`, `ScenarioTestResult` | Progress, outcome, scenario-level errors, and failed-case names are separate fields |

### Code Pointers

Paths are relative to the repository root.

| Component | File Path | Key Classes |
|---|---|---|
| Remote output references | `e2etest\GuestProxyAgentTest\Models\RunCommandOutputDetails.cs` | `RunCommandOutputDetails` |
| Case results | `e2etest\GuestProxyAgentTest\Models\TestCaseResultDetails.cs` | `TestCaseResultDetails` |
| Environment configuration | `e2etest\GuestProxyAgentTest\Models\TestConfig.cs` | `TestConfig` |
| Group/image/scenario selection | `e2etest\GuestProxyAgentTest\Models\TestMap.cs` | `TestMap`, `TestGroupConfig`, `TestGroupDetails`, `TestScenarioConfig` |
| Scenario status and outcomes | `e2etest\GuestProxyAgentTest\Models\TestScenarioStatusDetails.cs` | `TestScenarioStatusDetails`; enums `ScenarioTestStatus`, `ScenarioTestResult` |

## How

### Configure and select

`TestConfig` carries tenant/application identity, certificate thumbprint and
Key Vault certificate name, deployment placement, VM sizing, shared storage URL,
and public-IP service tag. Windows and Linux have separate WireServer and IMDS
profile-reference properties; the model does not choose between them.
`CertNameInKV` defaults to `GuestProxyAgentE2ETestCert`.

`TestMap.TestGroupList` contains `TestGroupConfig` references through `Include`.
`TestGroupDetails` holds `GroupName`, publisher/offer/SKU/version image metadata,
`SharedGalleryImageUniqueId`, and `Scenarios`. Each `TestScenarioConfig` supplies
`Name` and `ClassName`. Loading includes, resolving image alternatives, and
instantiating scenario classes are consumer responsibilities.

### Interpret outputs

`RunCommandOutputDetails` describes remote output locations, not downloaded text;
it neither validates URLs nor infers success from the output channels.
For `TestCaseResultDetails`, `FromBlob = true` means consumers must read output
from blob storage; `false` means the channels contain direct content.
Changing `FromBlob` does not fetch or convert output, and assigning output does
not update `Succeed`.

### Track progress and report failures

`TestScenarioStatusDetails.Status` starts at `ScenarioTestStatus.NotStarted`;
the other declared states are `Running` and `Completed`. These are values, not
automatic transitions. `Result` defaults to `ScenarioTestResult.Succeed`, the
enum's first value, so a newly constructed record is not proof of completion.

`ErrorMessage` stores scenario-level errors. `FailedCases` is a getter-only,
eagerly initialized mutable list. `TestCasesErrorMessage` is computed on access:
it is empty when the list is empty; otherwise it includes the scenario name,
comma-separated failed-case names, and a direction to consult test-case logs.
Mutating the list changes subsequent messages but does not update `Result`.

### Consumer invariants

Except for the certificate-name default, string properties use `null!`, which
suppresses compiler warnings without creating runtime values. Test-map lists
also use `null!` and must be populated before enumeration. Both case-result
Booleans and the remote-command success flag default to `false`.

Consumers must validate configuration, keep output representation consistent
with `FromBlob`, and explicitly maintain status/result/failure consistency.
The models provide no synchronization, resource ownership, authentication,
certificate retrieval, provisioning, or general error handling.

## Related Components

Execution, output materialization, and reporting live outside these contracts.

| Related component | Follow for |
|---|---|
| [E2E test runner](agent-e2e-test-runner.md) | Configuration loading, scenario orchestration, output conversion, and summary/JUnit reporting |
| [Scenario implementations](..\..\e2etest\GuestProxyAgentTest\TestScenarios) | Scenario execution consuming configuration and status records |
| [Test cases](..\..\e2etest\GuestProxyAgentTest\TestCases) | Case execution producing result records |
| [Cloud/output utilities](..\..\e2etest\GuestProxyAgentTest\Utilities) | Cloud operations and output retrieval rather than model declarations |
