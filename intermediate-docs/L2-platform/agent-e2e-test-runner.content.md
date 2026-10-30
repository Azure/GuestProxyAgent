# Compose Content for: L2-platform/agent-e2e-test-runner.md

Total files: 9

---

## e2etest/GuestProxyAgentTest/Extensions/ExceptionExtensions.cs

### Purpose and Functionality
Provides an exception extension that reconciles unfinished test cases with JUnit reporting after an execution failure. UpdateTestCaseResults receives the affected cases, a result builder, and the scenario name; it mutates the existing case objects rather than constructing replacement results.
### Key Components
ExceptionExtensions declares UpdateTestCaseResults. The method examines each TestCaseBase.Result and uses TestCaseResult values to distinguish active cases from cases that never started.
### Behavior and Interactions
Running cases become Failed and receive a JUnit failure entry with a timeout explanation, the exception message, empty standard output, and zero duration. NotStarted cases become Aborted and receive an aborted entry explaining that execution never began. Other states remain unchanged. The method does not throw the supplied exception, cancel execution, or determine whether the exception actually represents a timeout.

---

## e2etest/GuestProxyAgentTest/Extensions/ModelExtensions.cs

### Purpose and Functionality
Translates remote command output into test-result details, resolves blob-backed output, emits JUnit results, and deserializes custom output. ToTestResultDetails copies the output fields and success flag into a new result, sets FromBlob from its download option, and immediately invokes the download helper.
### Key Components
ModelExtensions declares ToTestResultDetails, DownloadContentIfFromBlob, WriteJUnitTestResult, and SafeDeserializedCustomOutAs<T>. DownloadContentIfFromBlob mutates and returns the supplied result; an already materialized result is returned unchanged.
### Behavior and Interactions
Blob processing clears FromBlob before independently downloading each nonempty output field through TestCommonUtilities. Every attempted download replaces its field with the returned text. Any reported download failure marks the result unsuccessful and replaces standard error with a combined diagnostic containing all three resulting fields. JUnit output selects success or failure entries and forwards the supplied duration; failure entries additionally include standard error. Generic custom-output deserialization uses Newtonsoft.Json for reference types, logs caught exceptions, and returns null after failure. The download and reporting methods themselves do not catch exceptions.

---

## e2etest/GuestProxyAgentTest/Extensions/TaskExtensions.cs

### Purpose and Functionality
Adds an asynchronous timeout wrapper for an existing Task. TimeoutAfter accepts a millisecond timeout and an optional CancellationTokenSource, allowing callers to bound how long they await work without changing the original task's return type.
### Key Components
TaskExtensions declares TimeoutAfter, which races the supplied task against Task.Delay using Task.WhenAny. It awaits the original task when that task wins, preserving its completion, cancellation, or exception behavior.
### Behavior and Interactions
When the delay wins, the method requests cancellation through the supplied source, if present, and then throws TimeoutException. Cancellation is cooperative: it neither guarantees that the original operation stops nor waits for it to finish. The helper does not dispose the source, cancel the delay when work finishes, or catch errors from the task or cancellation request.

---

## e2etest/GuestProxyAgentTest/GuestProxyAgentScenarioTests.cs

### Purpose and Functionality
Coordinates configured scenario execution, periodic progress logging, and per-group JUnit report generation. The constructor retains a TestLogger. StartAsync creates one result builder per distinct group and a mutable status record for every scenario, initially not started with a successful result.
### Key Components
GuestProxyAgentScenarioTests uses reflection to instantiate configured classes as TestScenarioBase, supplies settings and the group's result builder, and starts each scenario. Creation failures or synchronous exceptions mark that scenario completed and failed with an explanatory message.
### Behavior and Interactions
Started tasks are added both inside the successful creation branch and again in finally, so the collection contains duplicate references, not duplicate scenario starts. A background monitor logs aggregate counts every five seconds until a ManualResetEvent is signaled. Task.WhenAll is awaited through the configured map timeout; exceptions are logged without rethrowing or requesting scenario cancellation. The method then signals the monitor, builds group reports, and logs final counts plus details for completed failures. It does not await the monitoring task or dispose its event. Timed-out work may therefore remain active during reporting, and summaries count failures only for completed scenarios.

---

## e2etest/GuestProxyAgentTest/Program.cs

### Purpose and Functionality
Provides the asynchronous console entry point for end-to-end scenario execution. Main creates a test logger and reads four required positional arguments: configuration path, result directory, agent ZIP path, and agent version. An optional fifth argument enables ARM64 selection through a case-insensitive comparison.
### Key Components
Program.Main initializes the shared test environment through TestCommonUtilities.TestSetup, starts old-resource cleanup through VMHelper, reads flattened scenario settings through TestMapReader, and passes those settings to GuestProxyAgentScenarioTests.StartAsync.
### Behavior and Interactions
Cleanup runs in a discarded Task.Run operation; its exceptions are caught and logged without blocking scenario startup or being awaited before process completion. Scenario execution itself is awaited, followed by a completion log message. Required argument count is not checked before indexing, and setup, map-reading, or runner exceptions are not caught here. The entry point does not inspect scenario outcomes to set an explicit failure exit code.

---

## e2etest/GuestProxyAgentTest/Settings/RunCommandSetting.cs

### Purpose and Functionality
Declares the settings bundle used to describe a Run Command invocation and its output destinations. RunCommandSetting keeps command metadata, script location, parameters, and the associated scenario settings together without implementing command execution.
### Key Components
Internal fields hold the command name, script SAS reference, standard-output and standard-error blob SAS references, optional custom-output SAS reference, and a TestScenarioSetting reference named testCaseSetting. The parameter dictionary is created eagerly; string and scenario fields use null-forgiving initializers.
### Behavior and Interactions
The custom-output field's documentation describes a consumer convention: when present, its value is base64-encoded and supplied under the designated custom-output parameter name so the script can write additional information to a blob. This file does not perform that encoding, upload scripts, create blobs, validate settings, or submit commands. It contains declarations only and no resource cleanup or error handling.

---

## e2etest/GuestProxyAgentTest/Settings/TestScenarioSetting.cs

### Purpose and Functionality
Defines scenario settings and a separate VM-image details model. TestScenarioSetting stores internal group and scenario names, image metadata, a reflection class name, a generated naming suffix, and a scenario timeout. Defaults select the BVT scenario and a two-hour timeout, while image fields and the group name start empty.
### Key Components
The VMImageDetails getter constructs a new object from the current publisher, offer, SKU, version, and shared-gallery identifier fields on every access. ResourceGroupName combines group and scenario names with an underscore and the suffix. TestScenarioStorageFolderPrefix returns that same computed resource-group name.
### Behavior and Interactions
The suffix is generated per settings instance from a random integer below one thousand; uniqueness is not guaranteed. VMImageDetails exposes writable image properties and computes IsArm64 using case-insensitive substring checks of Offer and Sku, treating null values as nonmatches. Shared-gallery identifiers do not participate in architecture detection. Neither class validates image combinations, provisions resources, enforces timeouts, or handles errors.

---

## e2etest/GuestProxyAgentTest/Settings/TestSetting.cs

### Purpose and Functionality
Provides process-wide end-to-end test configuration and two Azure token credential adapters. TestSetting retains resource configuration, artifact locations, expected agent version, platform-specific access-control references, and a three-hour test-map timeout.
### Key Components
TestSetting has a private constructor, a static Instance accessor, and an Init method that copies TestConfig values and explicit artifact arguments. Script and resource directories are resolved relative to the executing assembly. Endpoint access-control properties select Windows or Linux references through the platform helper. The two TokenCredential subclasses separately retrieve general and storage-account access tokens through the environment-token utility.
### Behavior and Interactions
Initialization returns without changes once an instance exists; no locking protects concurrent initialization, and Instance does not enforce initialization before access. Script-directory selection follows the same platform helper. Synchronous credential methods delegate token retrieval rather than acquiring tokens themselves. Asynchronous methods immediately wrap their synchronous results in ValueTask. Neither adapter uses requested scopes or cancellation to alter retrieval, and exceptions are not caught here. No configuration validation or credential disposal is implemented in this file.

---

## e2etest/GuestProxyAgentTest/Utilities/JUnitTestResultBuilder.cs

### Purpose and Functionality
Builds JUnit-style XML reports for end-to-end scenarios, deliberately keeping each scenario in a separate file to accommodate the test-result publisher. Construction creates the group's result directory and retains the root result-folder path.
### Key Components
JunitTestResultBuilder maps scenario names to XML documents and suite elements. Success, failure, and aborted-result methods lazily create suites with group-qualified names, UTC timestamps, and initialized counters. Success can combine standard and custom output. Failures contain standard output, standard error, and an AssertionException-typed failure element combining error and custom output. Aborted tests become skipped cases with zero duration.
### Behavior and Interactions
Result insertion locks the builder instance, increments tests and the relevant outcome counter, and converts millisecond durations to seconds for completed cases. XML text and attributes are populated through DOM APIs. Build saves one scenario-named XML file per map entry and returns the paths; it does not acquire the insertion lock. Numeric conversion, directory creation, and saving errors propagate. The builder reports supplied outcomes rather than executing assertions itself.

---
