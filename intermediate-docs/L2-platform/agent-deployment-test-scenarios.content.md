# Compose Content for: L2-platform/agent-deployment-test-scenarios.md

Total files: 8

---

## e2etest/GuestProxyAgentTest/TestScenarios/BakedInScenario.cs

### Purpose and Functionality
BakedInScenario defines a Linux-only sequence for an agent already present in the VM image. TestScenarioSetup throws InvalidOperationException on Windows and does not register any installation or update case.
### Key Components
The scenario initially disables GuestProxyAgentSettings.Enabled. It registers agent validation expecting a disabled state, followed by an IMDS ping with secure-channel support disabled. A separate local flag disables IPv6 dual-stack coverage for every ping in this scenario.
### Behavior and Interactions
After the initial checks, an EnableProxyAgentCase is followed by validation expecting enforcement for WireServer, IMDS, and HostGA. The secure-channel flag is then true for IMDS connectivity checks both before and after a reboot. This ordered sequence is intended to exercise transition from disabled operation to secure-channel connectivity and its persistence across reboot. The file assembles cases and expected states; it leaves provisioning, asynchronous execution, result recording, and cleanup to the base scenario infrastructure.

---

## e2etest/GuestProxyAgentTest/TestScenarios/BVTScenario.cs

### Purpose and Functionality
BVTScenario assembles the basic installation, validation, and reboot-connectivity sequence. TestScenarioSetup registers cases in execution order rather than running them directly.
### Key Components
Non-Windows runs begin with cgroup-v2 setup and a reboot. All runs install or update the agent and schedule its validation. Windows additionally validates loaded modules. Non-Windows runs instead enable the proxy agent and register validation expecting enforcement for WireServer, IMDS, and HostGA.
### Behavior and Interactions
A local secure-channel flag starts false and becomes true only in the non-Windows branch; that value is passed to the IMDS ping cases before and after the installation reboot. Local-IP binding cases likewise run before and after that reboot only on non-Windows systems. Comments explain that Windows enablement could overwrite the private package through extension installation, and local-IP binding is skipped pending an officially signed system eBPF file. Actual assertions and failures belong to the registered cases and base scenario runner.

---

## e2etest/GuestProxyAgentTest/TestScenarios/LinuxImplicitExtension.cs

### Purpose and Functionality
LinuxImplicitExtension composes a Linux-only extension enablement and update scenario. TestScenarioSetup rejects Windows with InvalidOperationException before registering cases.
### Key Components
The method reads and logs the configured target proxy-agent version. It registers EnableProxyAgentCase with both enablement and implicit extension-addition arguments true, then extension validation using a pre-update version argument of zero. Installation or update of the extension is followed by validation against the configured target version.
### Behavior and Interactions
The remaining cases perform secure-channel-enabled IMDS pings and local-IP binding checks before and after a reboot. Registration order ensures initial enablement precedes version validation, the update precedes target-version checking, and both connectivity modes are revisited after restart. The zero value is passed to the validation case rather than interpreted locally. This class defines orchestration only: VM operations, detailed assertions, cancellation, result handling, and cleanup are performed by its test cases and TestScenarioBase.

---

## e2etest/GuestProxyAgentTest/TestScenarios/LinuxPackageScenario.cs

### Purpose and Functionality
LinuxPackageScenario registers a package-based agent installation and connectivity sequence. Despite its Linux-specific name and cases, TestScenarioSetup contains no explicit platform guard or Windows rejection.
### Key Components
The ordered list begins with cgroup-v2 setup and a reboot, followed by InstallOrUpdateGuestProxyAgentPackageCase and default agent validation. It then enables the proxy agent and registers another validation case expecting enforcement for WireServer, IMDS, and HostGA.
### Behavior and Interactions
After enablement, an IMDS ping with the secure-channel argument true and a local-IP binding check run before a second reboot. Matching ping and binding cases run afterward to cover post-restart connectivity. This file does not install packages, configure cgroups, or make assertions directly; it supplies the case ordering and expected secure-channel state. Actual asynchronous operations, failure recording, and resource lifecycle management are provided by the cases and base scenario runner.

---

## e2etest/GuestProxyAgentTest/TestScenarios/PenTestScenario.cs

### Purpose and Functionality
PenTestScenario configures a proxy-agent extension environment and schedules a penetration-test case after extension update validation. It defines scenario composition rather than implementing penetration-test probes.
### Key Components
TestScenarioSetup sets GuestProxyAgentSettings.Enabled, AddProxyAgentExtension, and UseLocalFileRules to true. It reads the configured target proxy-agent version and logs it. The registered sequence starts with extension validation given a pre-update version argument of zero, followed by installation or update and validation against the configured target version.
### Behavior and Interactions
RunPenTestCase is appended last, so its package upload and remote script execution follow the extension validation steps. This setup contains no platform guard, reboot, or separate IMDS ping case. It does not interpret the zero version argument itself or inspect penetration-test results locally. Provisioning consumes the scenario settings, and the inherited runner and registered cases handle execution, reporting, failures, and output artifacts.

---

## e2etest/GuestProxyAgentTest/TestScenarios/ProxyAgentExtension.cs

### Purpose and Functionality
ProxyAgentExtension assembles extension-update coverage with platform-specific preparation and secure-channel connectivity checks around a reboot.
### Key Components
TestScenarioSetup reads and logs the configured target version and supplies zero as the version argument for pre-update extension validation. Non-Windows runs first register cgroup-v2 setup, a reboot, explicit Linux VM extension addition, and proxy-agent enablement. Windows instead sets GuestProxyAgentSettings.Enabled to true for VM provisioning.
### Behavior and Interactions
Both branches then register pre-update extension validation, installation or update, and validation against the configured target version. An IMDS ping with secure-channel support true precedes a reboot, followed by another ping with the same flag. Unlike some other scenario compositions, this one does not add local-IP binding cases. The method establishes sequencing and configuration only; it relies on the registered cases for assertions and operations, and on TestScenarioBase for VM lifecycle, cancellation, result persistence, and cleanup.

---

## e2etest/GuestProxyAgentTest/TestScenarios/TCPPortScalabilityScenario.cs

### Purpose and Functionality
TCPPortScalabilityScenario defines a Windows-only configuration and connectivity sequence. TestScenarioSetup immediately throws InvalidOperationException for non-Windows runs.
### Key Components
The method reads and logs the configured proxy-agent version and sets GuestProxyAgentSettings.Enabled to true so proxy-agent enablement is requested for the new VM. It registers extension installation or update, then extension validation against that configured version.
### Behavior and Interactions
TCPPortScalabilityCase is registered next to run the TCP configuration script. A reboot follows so the configuration can take effect, and a final IMDS ping case receives a true secure-channel argument. The scenario itself does not measure port counts, assert a numeric scalability threshold, or inspect network configuration. It orders configuration, restart, and post-restart connectivity coverage, while the registered cases and inherited runner implement remote execution, validation details, failure reporting, and resource cleanup.

---

## e2etest/GuestProxyAgentTest/TestScenarios/TestScenarioBase.cs

### Purpose and Functionality
TestScenarioBase orchestrates VM provisioning, ordered cases, JUnit reporting, artifacts, and cleanup. Construction initializes logging and agent settings, then calls subclass setup. Fluent methods supply scenario settings and builders; PreCheck rejects missing prerequisites.
### Key Components
StartAsync applies a timeout with a cancellation source, maps escaping exceptions to case results, and finally attempts uncancelled guest-agent log collection and Azure cleanup independently, logging failures. TestCaseExecutionContext carries the VM, settings, logger, token, and mutable results.
### Behavior and Interactions
AllocationFailed provisioning errors trigger parsed alternative-size retries or an available-size fallback. A non-allocation retry error stops alternatives but proceeds to instance-view polling. Recovery checks the first display status for provisioning success or running, for five minutes with uncancelled ten-second delays.
Cases check cancellation, run sequentially, resolve blob output, and record timed JUnit results; ordinary case failures do not stop later cases. Finally blocks update case state and save outputs by download or direct write. DoStartAsync catches scenario exceptions and marks failure and completion. Log placeholders are uploaded and populated through Run Command; the cancellation source and temporary files are not disposed or deleted here.

---
