**TL;DR:** The C# E2E runner initializes shared settings, starts configured scenarios, and converts remote-command outcomes into per-scenario JUnit XML. Timeouts bound waiting, not necessarily execution; report generation and process completion do not guarantee that all work stopped or every scenario passed.

# Agent E2E Test Runner

<!-- TIER2-POINTER:BEGIN (managed by step8_inject_tier2_pointer.py) -->
> **Need a specific class, method, error code, config key, or flow step?**
> Read `intermediate-docs/L2-platform/agent-e2e-test-runner.content.md` for implementation details; stay here for overviews.
> Search the companion for the source-file heading and range-read that section, starting with Purpose and Functionality.
> Verify behavior in source when needed; do not load the entire companion.
<!-- TIER2-POINTER:END -->

## Why

Provide a common entry point, configuration boundary, progress view, and CI-reporting
layer for Guest Proxy Agent scenarios. Scenario implementations and cloud utilities
own VM operations and assertions; this component coordinates them and records supplied
outcomes rather than independently verifying success.

## What

| Responsibility | Contract |
|---|---|
| Console inputs | Four required positional arguments: configuration path, result directory, agent ZIP path, agent version. An optional fifth argument selects ARM64 through a case-insensitive comparison. |
| Process settings | `TestSetting.Init` copies configuration and artifact arguments once; map timeout defaults to three hours. Script/resource paths are assembly-relative; platform selection chooses script folders and access-control references. |
| Scenario settings | `TestScenarioSetting` defaults to the BVT scenario and a two-hour scenario timeout. `ResourceGroupName` combines group, scenario, and a random suffix; `TestScenarioStorageFolderPrefix` returns the same name. |
| Image selection | `VMImageDetails.IsArm64` checks offer/SKU substrings case-insensitively, not shared-gallery identifiers. Each settings getter returns a fresh image-details object. |
| Command settings | `RunCommandSetting` carries command/script references, an eagerly created parameter dictionary, output SAS destinations, and scenario settings. Consumers base64-encode a supplied custom-output SAS reference into a script parameter; this model does not encode or submit anything. |
| Credentials | Separate general/storage `TokenCredential` adapters retrieve environment tokens through `TestCommonUtilities`; requested scopes and cancellation do not change retrieval. Async methods wrap synchronous retrieval. |
| Results | One builder per group, with lazy scenario suites and one XML file per scenario to accommodate the result publisher. |

## How

### Startup and orchestration

1. `Program.Main` calls `TestCommonUtilities.TestSetup`, starts old-resource cleanup
   through `VMHelper.CleanupOldTestResourcesAndForget` in an unawaited task, then
   reads settings with `TestMapReader.ReadFlattenTestScenarioSettingFromTestMap`.
2. `GuestProxyAgentScenarioTests.StartAsync` creates group builders and mutable
   scenario statuses, initially `NotStarted` with a successful result.
3. Reflection resolves each configured class to `TestScenarioBase`, attaches its
   settings and builder, and calls its `StartAsync`. Creation failures and synchronous
   exceptions mark the scenario completed/failed with a message.
4. A background monitor logs aggregate status every five seconds. The runner awaits
   `Task.WhenAll` through `TaskExtensions.TimeoutAfter` using the map timeout.
5. After completion or a logged execution exception, the runner signals the monitor,
   calls `JunitTestResultBuilder.Build`, and logs counts plus completed-failure details.

### Output normalization and reporting

| Stage / pointer | Behavior |
|---|---|
| `ModelExtensions.ToTestResultDetails` | Copies command output/success fields and immediately resolves blob-backed content unless downloading was disabled. |
| `ModelExtensions.DownloadContentIfFromBlob` | Clears `FromBlob` before independently downloading nonempty stdout, stderr, and custom output. Replaces fields with returned text; any reported download failure marks the result unsuccessful and replaces stderr with combined diagnostics. Already-materialized results are unchanged. |
| `ModelExtensions.SafeDeserializedCustomOutAs<T>` | Deserializes custom JSON into a reference type using Newtonsoft.Json; logs exceptions and returns null on failure. |
| `ModelExtensions.WriteJUnitTestResult` | Selects success/failure insertion from the supplied success flag and forwards duration/output. |
| `ExceptionExtensions.UpdateTestCaseResults` | Mutates running cases to failed with a timeout explanation and exception message; mutates not-started cases to aborted. Other states are unchanged. It neither validates a timeout cause nor cancels work. |
| `JunitTestResultBuilder.AddSuccessTestResult` / `AddFailureTestResult` | Adds completed cases, converting milliseconds to seconds. Success can combine stdout/custom output; failure includes stdout, stderr, and an `AssertionException`-typed element with error/custom output. |
| `JunitTestResultBuilder.AddAbortedTestResult` / `Build` | Aborted cases become skipped with zero duration. Saves one scenario-named XML file per scenario in the group's result directory; suites use group-qualified names, UTC timestamps, and outcome counters. |

### Lifecycle and failure boundaries

- `TaskExtensions.TimeoutAfter` races the original task against a delay. If work
  wins, its completion/cancellation/exception propagates. If the delay wins, it
  requests cancellation only when given a source, then throws `TimeoutException`;
  it does not wait for the original work to stop or cancel the unused delay.
- The map-level caller supplies no cancellation source and logs exceptions without
  rethrowing. Timed-out scenarios may still write results during reporting.
  Insertions lock the builder, but `Build` does not take that lock. XML text and
  attributes are populated through DOM APIs.
- Successful scenario tasks are added to the task list twice; these are duplicate
  references, not duplicate scenario starts. The monitoring task is not awaited,
  and its `ManualResetEvent` is not disposed.
- Failure summaries include only completed failures; unfinished scenarios are not
  counted as failed. `Program.Main` sets no explicit failure exit code from outcomes.
  Inspect scenario status and JUnit artifacts rather than relying on the completion log.
- Required arguments are indexed without a count check. Setup/map-reading errors
  propagate; background cleanup errors are logged without blocking startup.
  Download/reporting helpers do not catch exceptions; XML conversion, directory,
  and save failures propagate.
- Settings are not validated. Singleton initialization is unlocked, later calls
  are ignored, and `Instance` does not guard access before initialization.
  The random suffix is below 1,000 and does not guarantee resource-name uniqueness.

## Code Pointers

Paths are repository-relative; class spelling is `JunitTestResultBuilder` even
though its filename begins with `JUnit`.

| Component | File Path | Key Classes |
|---|---|---|
| Entry point | `e2etest\GuestProxyAgentTest\Program.cs` | `Program` (`Main`) |
| Scenario coordinator | `e2etest\GuestProxyAgentTest\GuestProxyAgentScenarioTests.cs` | `GuestProxyAgentScenarioTests` (`StartAsync`) |
| Process settings / credentials | `e2etest\GuestProxyAgentTest\Settings\TestSetting.cs` | `TestSetting`, `GuestProxyAgentE2ETokenCredential`, `GuestProxyAgentE2EStorageAccountTokenCredential` |
| Scenario / image settings | `e2etest\GuestProxyAgentTest\Settings\TestScenarioSetting.cs` | `TestScenarioSetting`, `VMImageDetails` |
| Remote-command settings | `e2etest\GuestProxyAgentTest\Settings\RunCommandSetting.cs` | `RunCommandSetting` |
| Await timeout | `e2etest\GuestProxyAgentTest\Extensions\TaskExtensions.cs` | `TaskExtensions` (`TimeoutAfter`) |
| Exception reconciliation | `e2etest\GuestProxyAgentTest\Extensions\ExceptionExtensions.cs` | `ExceptionExtensions` (`UpdateTestCaseResults`) |
| Output conversion | `e2etest\GuestProxyAgentTest\Extensions\ModelExtensions.cs` | `ModelExtensions` |
| JUnit persistence | `e2etest\GuestProxyAgentTest\Utilities\JUnitTestResultBuilder.cs` | `JunitTestResultBuilder` |

## Related Components

Follow adjacent DAGs for behavior outside this component:

| Component | Follow for |
|---|---|
| [Cloud test utilities](agent-cloud-test-utilities.md) | `TestCommonUtilities`, `TestMapReader`, `VMHelper`, command execution/building, storage, and logging. |
| [Deployment test scenarios](agent-deployment-test-scenarios.md) | `TestScenarioBase` and concrete scenario execution/lifecycle. |
| [E2E test models](agent-e2e-test-models.md) | Configuration/maps, `TestScenarioStatusDetails`, `RunCommandOutputDetails`, and `TestCaseResultDetails`. |
| [VM test cases](..\..\intermediate-docs\L2-platform\agent-vm-test-cases.content.md) | `TestCaseBase` and the operations whose results are reconciled and reported. |
