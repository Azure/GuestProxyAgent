# L2 — Platform Documentation Index

> "How does X work?" — Infrastructure services, build, deployment, telemetry, flighting.


| Document | Description |
|----------|-------------|
| [agent-cloud-test-utilities.md](agent-cloud-test-utilities.md) | **TL;DR:** These C# utilities turn end-to-end scenario settings into Azure VMs, blob-backed scripts, managed Run Commands, and cleanup operations. The |
| [agent-deployment-test-scenarios.md](agent-deployment-test-scenarios.md) | **TL;DR:** Deployment scenarios compose ordered VM test cases for agent installation, extension updates, enablement, and reboot connectivity across Li |
| [agent-e2e-test-models.md](agent-e2e-test-models.md) | **TL;DR:** `GuestProxyAgentTest.Models` defines the mutable data contracts for E2E environment configuration, test selection, output interpretation, a |
| [agent-e2e-test-runner.md](agent-e2e-test-runner.md) | **TL;DR:** The C# E2E runner initializes shared settings, starts configured scenarios, and converts remote-command outcomes into per-scenario JUnit XM |
| [agent-platform-utilities.md](agent-platform-utilities.md) | **TL;DR:** Agent platform utilities centralize command-line parsing, immutable configuration, diagnostics, typed errors, and OS-specific identity/key  |
| [agent-vm-test-cases.md](agent-vm-test-cases.md) | **TL;DR:** VM test cases provide reusable deployment, configuration, health-validation, and connectivity steps for the E2E harness. Most delegate gues |
| [authorization-canonicalization.md](authorization-canonicalization.md) | **TL;DR:** Authorization canonicalization normalizes destinations, paths, queries, and privilege patterns consistently across Windows and Linux. Typed |
| [cross-platform-service-utilities.md](cross-platform-service-utilities.md) | **TL;DR:** `proxy_agent_shared` supplies common service lifecycle, host metadata/HTTP, state, logging, telemetry models, and OS utilities. Its Windows |
| [ebpf-socket-redirection.md](ebpf-socket-redirection.md) | **TL;DR:** Windows and Linux eBPF hooks redirect policy-matched connections while retaining original destinations and process identity for user-mode a |
| [native-build-integration.md](native-build-integration.md) | **TL;DR:** Cargo build scripts configure static VCRuntime and Windows resources for the agent, extension, and setup executables. On non-Windows build  |
| [telemetry-event-delivery.md](telemetry-event-delivery.md) | **TL;DR:** Shared telemetry buffers generic logs and extension status in memory or JSON files, then enriches, redacts, and batches them into WireServe |
| [windows-event-integration.md](windows-event-integration.md) | **TL;DR:** Windows-only shared eventing consumes real-time ETW and Windows Event Log subscriptions, queries historical Event Log records, and writes r |
