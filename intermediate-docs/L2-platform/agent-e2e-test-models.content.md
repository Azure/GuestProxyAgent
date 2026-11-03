# Compose Content for: L2-platform/agent-e2e-test-models.md

Total files: 5

---

## e2etest/GuestProxyAgentTest/Models/RunCommandOutputDetails.cs

### Purpose and Functionality
Declares the data container for remote Run Command execution output. RunCommandOutputDetails carries references to the command's standard output, standard error, and customized output, together with a Boolean indicating whether execution succeeded.
### Key Components
The class exposes four public read/write properties: StdOut, StdErr, CustomOut, and Succeed. Property comments identify the output strings as SAS URLs rather than downloaded command text. The string properties use null-forgiving initializers, which do not supply nonnull runtime values; Succeed has the ordinary false Boolean default.
### Behavior and Interactions
This file contains declarations only. It does not download blobs, interpret command output, validate URLs, infer success from output, or manage external resources. Callers must populate the object and perform any subsequent materialization or reporting themselves.

---

## e2etest/GuestProxyAgentTest/Models/TestCaseResultDetails.cs

### Purpose and Functionality
Defines a mutable test-case result carrying execution status and three output channels. Unlike a container restricted to remote output references, TestCaseResultDetails can represent either materialized text or blob SAS URLs, with FromBlob indicating how consumers should interpret the strings.
### Key Components
StdOut, StdErr, and CustomOut are public read/write string properties initialized with null-forgiving expressions. Succeed records success or failure, while FromBlob identifies whether output must be read from blob storage. Both Boolean properties default to false.
### Behavior and Interactions
This file contains declarations and documentation only. Changing FromBlob does not itself fetch or convert anything, and setting output does not update Succeed. There is no validation, error handling, synchronization, reporting, or resource ownership logic. Consumers are responsible for keeping the interpretation flag consistent with the stored output.

---

## e2etest/GuestProxyAgentTest/Models/TestConfig.cs

### Purpose and Functionality
Declares the configuration model for the end-to-end test environment. TestConfig groups identity and certificate references, subscription and deployment placement, VM sizing, storage location, networking configuration, and operating-system-specific access-control profile references in one mutable object.
### Key Components
Public string properties cover the tenant and application identity, certificate thumbprint and key-vault certificate name, subscription, location, VM size, public-IP service tag, and shared storage account URL. Separate Windows and Linux properties reference WireServer and IMDS access-control profiles. The certificate-name property has a preset default; the other strings use null-forgiving initializers rather than actual nonnull values.
### Behavior and Interactions
This file contains configuration declarations only. It performs no authentication, certificate retrieval, deserialization, field validation, platform selection, or cloud provisioning. It supplies neither required-field enforcement nor error handling; consumers must interpret and validate the supplied configuration.

---

## e2etest/GuestProxyAgentTest/Models/TestMap.cs

### Purpose and Functionality
Defines the data shapes used to describe test maps, referenced groups, VM images, and scenario selections. These classes separate the outer list of group references from the detailed group definition containing image metadata and executable scenario class names.
### Key Components
TestMap exposes TestGroupList as a list of TestGroupConfig objects. TestGroupConfig has an Include string. TestGroupDetails holds GroupName, publisher, offer, SKU, version, a shared-gallery image identifier, and a list of TestScenarioConfig objects. TestScenarioConfig supplies the scenario Name and ClassName.
### Behavior and Interactions
The file contains declarations only, with public read/write properties and null-forgiving initializers for strings and lists. It does not load included files, flatten scenarios, resolve image alternatives, instantiate classes, or validate names. Lists are not constructed automatically, so consumers must populate them before enumeration. No execution, error handling, resource allocation, or platform-specific branches are implemented here.

---

## e2etest/GuestProxyAgentTest/Models/TestScenarioStatusDetails.cs

### Purpose and Functionality
Models scenario progress and outcome separately, together with scenario-level errors and failed-case names. TestScenarioStatusDetails provides the mutable record consumed by execution and summary reporting rather than implementing a scenario runner.
### Key Components
Status defaults to ScenarioTestStatus.NotStarted. GroupName, ScenarioName, and ErrorMessage are writable strings with null-forgiving initializers. Result uses ScenarioTestResult, whose first value is Succeed. FailedCases is a getter-only property exposing an eagerly created, mutable list. ScenarioTestStatus declares NotStarted, Running, and Completed; ScenarioTestResult declares Succeed and Failed.
### Behavior and Interactions
TestCasesErrorMessage is computed on access: it returns an empty string when no cases failed, otherwise formats the scenario name and comma-separated failed-case names with a direction to consult logs. Updating the list changes subsequent messages. The class provides no synchronization, automatic status transitions, failure propagation, or consistency checks between Result and FailedCases.

---
