# GuestProxyAgent

GuestProxyAgent redirects selected guest network connections through a loopback
HTTP/1.1 proxy on Windows and Linux. Platform-specific eBPF hooks retain original
destinations and process identity for endpoint-specific authorization, while
runtime orchestration coordinates policy, signing, provisioning, and health.

## Documentation

MUST read the documentation index before searching code for any non-trivial task:

- [Master docs-index](../copilot-docs/docs-index.md) — Start here. Contains layer indexes and reading chains.
- [L0 Primer](../copilot-docs/L0-foundations/codebase-primer.md) — Always-loaded architecture foundation.
- [L1 Conceptual Index](../copilot-docs/L1-conceptual/docs-index.md) — Seven Tokio actors and serialized shared-state access.
- [L2 Platform Index](../copilot-docs/L2-platform/docs-index.md) — Redirection, canonicalization, platform utilities, telemetry, native builds, and E2E infrastructure.
- [L3 Flows Index](../copilot-docs/L3-flows/docs-index.md) — Runtime coordination, authorized requests, installation/recovery, and extension lifecycle.

Use the master's reading chains to select documents for request tracing,
runtime-state changes, installation/recovery, diagnostics, or Azure VM scenarios.
L1 explains concepts; L2 explains platform mechanisms; L3 connects end-to-end flows.

## Ownership Table

Doc Area entries are relative to `copilot-docs/`. This table describes navigation,
not maintainer or team ownership.

| Topic | Code Area | Doc Area |
|-------|-----------|----------|
| Runtime orchestration | `proxy_agent/src/` | L3-flows/agent-runtime-orchestration.md |
| Authorized proxy requests | `proxy_agent/src/proxy/` | L3-flows/authorized-proxy-request-flow.md |
| Authorization canonicalization | `proxy_agent/src/proxy/canonical/` | L2-platform/authorization-canonicalization.md |
| eBPF socket redirection | `ebpf/`, `linux-ebpf/`, `shared-ebpf/include/` | L2-platform/ebpf-socket-redirection.md |
| Shared-state actors | `proxy_agent/src/shared_state/` | L1-conceptual/agent-shared-state-access.md |
| Agent platform utilities | `proxy_agent/src/common/` | L2-platform/agent-platform-utilities.md |
| Shared service utilities | `proxy_agent_shared/` | L2-platform/cross-platform-service-utilities.md |
| Installation and recovery | `proxy_agent_setup/` | L3-flows/agent-installation-and-recovery.md |
| Extension lifecycle | `proxy_agent_extension/` | L3-flows/extension-lifecycle-orchestration.md |
| Telemetry delivery | `proxy_agent_shared/src/telemetry/` | L2-platform/telemetry-event-delivery.md |
| Windows event integration | `proxy_agent_shared/src/windows_events/` | L2-platform/windows-event-integration.md |
| Native executable builds | `proxy_agent/`, `proxy_agent_extension/`, `proxy_agent_setup/` | L2-platform/native-build-integration.md |
| Azure VM test utilities | `e2etest/GuestProxyAgentTest/Utilities/` | L2-platform/agent-cloud-test-utilities.md |
| C# E2E runner | `e2etest/GuestProxyAgentTest/` | L2-platform/agent-e2e-test-runner.md |

<!-- AUTO-GENERATED-MAPPING:BEGIN  (managed by step7_inject_routing_table.py) -->

## Component Mapping (auto-generated)

_This section is generated deterministically from `scripts/dag-enrichment/compose_to_dag_mapping-symbols.json` (by `step7_inject_routing_table.py`). Do not hand-edit - it is rewritten on every DAG regeneration. Anything outside the AUTO-GENERATED-MAPPING markers in this file is preserved._

**How to use this table** — the table answers three kinds of lookups, not just path lookups:

1. **Path lookup**: if the question (or your investigation) mentions a source path, find the row whose pattern matches and follow its reading chain.
2. **Symbol / class lookup**: if the question names a class, interface, method, error code, config key, or feature, scan the **What it covers** column for that term. Each description names the symbols and concepts the DAG covers because the cluster was built from those very symbols.
3. **Concept lookup**: for broader concepts (e.g. *goal-state refresh*, *plugin lifecycle*, *cross-platform helpers*), the **What it covers** column groups related areas. Pick the row that best matches; follow the reading chain; use the `(see also: ...)` cross-references to find adjacent DAGs.

Open the compact `copilot-docs/` doc first. For implementation details, locate the relevant source-file section in its `intermediate-docs/{layer}/{name}.content.md` companion using bounded searches and range reads. Stay at tier-1 for overview questions; verify behavior in source when the documentation is insufficient.

| Source path pattern | Reading chain (tier-1 -> tier-2) | What it covers |
|---------------------|----------------------------------|----------------|
| `proxy_agent/src/shared_state/` | `copilot-docs/L1-conceptual/agent-shared-state-access.md` -> `intermediate-docs/L1-conceptual/agent-shared-state-access.content.md` | Defines actor-owned state boundaries, asynchronous handle contracts, and cross-component lifecycle semantics |
| `e2etest/GuestProxyAgentTest/Utilities/` | `copilot-docs/L2-platform/agent-cloud-test-utilities.md` -> `intermediate-docs/L2-platform/agent-cloud-test-utilities.content.md` | Provides VM provisioning, remote commands, storage, certificates, assertions, and logging for agent tests |
| `e2etest/GuestProxyAgentTest/TestScenarios/` | `copilot-docs/L2-platform/agent-deployment-test-scenarios.md` -> `intermediate-docs/L2-platform/agent-deployment-test-scenarios.content.md` | Groups agent test cases into deployment, extension, package, security, and scalability scenarios |
| `e2etest/GuestProxyAgentTest/Models/` | `copilot-docs/L2-platform/agent-e2e-test-models.md` -> `intermediate-docs/L2-platform/agent-e2e-test-models.content.md` | Defines configuration, command outputs, results, and scenario status for agent end-to-end tests |
| `e2etest/GuestProxyAgentTest/`<br>`e2etest/GuestProxyAgentTest/Extensions/`<br>`e2etest/GuestProxyAgentTest/Settings/`<br>`e2etest/GuestProxyAgentTest/Utilities/` | `copilot-docs/L2-platform/agent-e2e-test-runner.md` -> `intermediate-docs/L2-platform/agent-e2e-test-runner.content.md` | Runs agent end-to-end scenarios with test settings, asynchronous helpers, and JUnit reporting |
| `proxy_agent/src/common/` | `copilot-docs/L2-platform/agent-platform-utilities.md` -> `intermediate-docs/L2-platform/agent-platform-utilities.content.md` | Provides agent CLI parsing, configuration, logging, errors, and operating-system helpers |
| `e2etest/GuestProxyAgentTest/TestCases/` | `copilot-docs/L2-platform/agent-vm-test-cases.md` -> `intermediate-docs/L2-platform/agent-vm-test-cases.content.md` | Implements VM test cases for agent installation, validation, networking, reboot, and scalability |
| `proxy_agent/src/proxy/canonical/` | `copilot-docs/L2-platform/authorization-canonicalization.md` -> `intermediate-docs/L2-platform/authorization-canonicalization.content.md` | Normalizes destinations, paths, queries, and rules for authorization, with property-based tests |
| `proxy_agent_shared/src/`<br>`proxy_agent_shared/src/host_clients/`<br>`proxy_agent_shared/src/logger/`<br>`proxy_agent_shared/src/service/` | `copilot-docs/L2-platform/cross-platform-service-utilities.md` -> `intermediate-docs/L2-platform/cross-platform-service-utilities.content.md`<br>*(see also: telemetry-event-delivery, windows-event-integration)* | Provides shared HTTP and host clients, service helpers, logging, status reporting, and secret redaction |
| `ebpf/`<br>`linux-ebpf/`<br>`proxy_agent/src/common/`<br>`proxy_agent_shared/src/`<br>`shared-ebpf/include/` | `copilot-docs/L2-platform/ebpf-socket-redirection.md` -> `intermediate-docs/L2-platform/ebpf-socket-redirection.content.md` | Implements kernel socket redirection with shared socket definitions, cgroup hooks, and audit events |
| `proxy_agent/`<br>`proxy_agent_extension/`<br>`proxy_agent_setup/` | `copilot-docs/L2-platform/native-build-integration.md` -> `intermediate-docs/L2-platform/native-build-integration.content.md` | Runs build-time integration for agent binaries, including eBPF compilation and object staging |
| `proxy_agent_shared/src/telemetry/` | `copilot-docs/L2-platform/telemetry-event-delivery.md` -> `intermediate-docs/L2-platform/telemetry-event-delivery.content.md` | Logs, reads, and sends telemetry events with span tracking and configurable delivery limits. |
| `proxy_agent_shared/src/windows_events/` | `copilot-docs/L2-platform/windows-event-integration.md` -> `intermediate-docs/L2-platform/windows-event-integration.content.md` | Listens to, queries, and writes Windows events with ETW provider support and event models. |
| `proxy_agent_setup/src/` | `copilot-docs/L3-flows/agent-installation-and-recovery.md` -> `intermediate-docs/L3-flows/agent-installation-and-recovery.content.md` | Orchestrates agent setup commands, backups, platform-specific installation, and running-state checks |
| `proxy_agent/src/redirector/**`<br>`proxy_agent/src/`<br>`proxy_agent/src/acl/`<br>`proxy_agent/src/key_keeper/`<br>`proxy_agent/src/proxy/canonical/`<br>`proxy_agent/src/service/` | `copilot-docs/L3-flows/agent-runtime-orchestration.md` -> `intermediate-docs/L3-flows/agent-runtime-orchestration.content.md` | Coordinates agent startup, provisioning, access control, key management, proxying, and traffic redirection |
| `proxy_agent/src/proxy/` | `copilot-docs/L3-flows/authorized-proxy-request-flow.md` -> `intermediate-docs/L3-flows/authorized-proxy-request-flow.content.md` | Accepts proxy connections, evaluates authorization rules, forwards requests, and summarizes activity |
| `proxy_agent_extension/src/`<br>`proxy_agent_extension/src/service_main/`<br>`proxy_agent_extension/src/windows/` | `copilot-docs/L3-flows/extension-lifecycle-orchestration.md` -> `intermediate-docs/L3-flows/extension-lifecycle-orchestration.content.md` | Coordinates extension command handling, service lifecycle, state, and status reporting across platforms |

**Coverage gap rule:** if your source path matches no row above, no DAG doc covers that area. Say so explicitly in your answer and cite the source file(s) you used. Do not silently substitute an unrelated doc.

### Defining namespace -> DAG (concept / symbol index)

Use this table when the user prompt names a **class, interface, type, or namespace** without giving you a source path. Scan the namespace and short-name columns for the term. Each entry's reading chain is the same as in the path table above (tier-1 -> tier-2).

| Defining namespace | Short | Tier-1 doc | What it covers |
|--------------------|-------|------------|----------------|
| `GuestProxyAgentTest` | `GuestProxyAgentTest` | `copilot-docs/L2-platform/agent-e2e-test-runner.md` | Runs agent end-to-end scenarios with test settings, asynchronous helpers, and JUnit reporting |
| `GuestProxyAgentTest.Models` | `GuestProxyAgentTest.Models` | `copilot-docs/L2-platform/agent-e2e-test-models.md` | Defines configuration, command outputs, results, and scenario status for agent end-to-end tests |
| `GuestProxyAgentTest.TestCases` | `GuestProxyAgentTest.TestCases` | `copilot-docs/L2-platform/agent-vm-test-cases.md` | Implements VM test cases for agent installation, validation, networking, reboot, and scalability |
| `GuestProxyAgentTest.TestScenarios` | `GuestProxyAgentTest.TestScenarios` | `copilot-docs/L2-platform/agent-deployment-test-scenarios.md` | Groups agent test cases into deployment, extension, package, security, and scalability scenarios |
| `GuestProxyAgentTest.Utilities` | `GuestProxyAgentTest.Utilities` | `copilot-docs/L2-platform/agent-cloud-test-utilities.md` | Provides VM provisioning, remote commands, storage, certificates, assertions, and logging for agent tests |
| `ProxyAgentExt` | `ProxyAgentExt` | `copilot-docs/L3-flows/extension-lifecycle-orchestration.md` | Coordinates extension command handling, service lifecycle, state, and status reporting across platforms |
| `SourceDirectory` | `SourceDirectory` | `copilot-docs/L2-platform/ebpf-socket-redirection.md` | Implements kernel socket redirection with shared socket definitions, cgroup hooks, and audit events |
| `azure_proxy_agent` | `azure_proxy_agent` | `copilot-docs/L3-flows/agent-runtime-orchestration.md` | Coordinates agent startup, provisioning, access control, key management, proxying, and traffic redirection |
| `azure_proxy_agent.common` | `azure_proxy_agent.common` | `copilot-docs/L2-platform/agent-platform-utilities.md` | Provides agent CLI parsing, configuration, logging, errors, and operating-system helpers |
| `azure_proxy_agent.proxy` | `azure_proxy_agent.proxy` | `copilot-docs/L3-flows/authorized-proxy-request-flow.md` | Accepts proxy connections, evaluates authorization rules, forwards requests, and summarizes activity |
| `azure_proxy_agent.proxy.canonical` | `proxy.canonical` | `copilot-docs/L2-platform/authorization-canonicalization.md` | Normalizes destinations, paths, queries, and rules for authorization, with property-based tests |
| `azure_proxy_agent.shared_state` | `azure_proxy_agent.shared_state` | `copilot-docs/L1-conceptual/agent-shared-state-access.md` | Defines actor-owned state boundaries, asynchronous handle contracts, and cross-component lifecycle semantics |
| `build_script_build` | `build_script_build` | `copilot-docs/L2-platform/native-build-integration.md` | Runs build-time integration for agent binaries, including eBPF compilation and object staging |
| `proxy_agent_setup` | `proxy_agent_setup` | `copilot-docs/L3-flows/agent-installation-and-recovery.md` | Orchestrates agent setup commands, backups, platform-specific installation, and running-state checks |
| `proxy_agent_shared` | `proxy_agent_shared` | `copilot-docs/L2-platform/cross-platform-service-utilities.md` | Provides shared HTTP and host clients, service helpers, logging, status reporting, and secret redaction |
| `proxy_agent_shared.telemetry` | `proxy_agent_shared.telemetry` | `copilot-docs/L2-platform/telemetry-event-delivery.md` | Logs, reads, and sends telemetry events with span tracking and configurable delivery limits. |
| `proxy_agent_shared.windows_events` | `proxy_agent_shared.windows_events` | `copilot-docs/L2-platform/windows-event-integration.md` | Listens to, queries, and writes Windows events with ETW provider support and event models. |

<!-- AUTO-GENERATED-MAPPING:END -->

## Hard Rules

- MUST read `copilot-docs/docs-index.md` before searching code for architecture,
  flow, or design questions.
- MUST read `copilot-docs/L0-foundations/codebase-primer.md` before answering
  any architecture question.
- When a compact final DAG document is insufficient, MUST read its corresponding
  detailed content file at `intermediate-docs/{layer}/{name}.content.md` BEFORE
  searching source code. Search source only if BOTH documents are insufficient.
  Example: `copilot-docs/L1-conceptual/agent-shared-state-access.md` maps to
  `intermediate-docs/L1-conceptual/agent-shared-state-access.content.md`.
- Preserve actor-owned serialization for authorization, signing, health,
  provisioning, connection summaries, identity caching, and redirection.
- Keep authorization canonicalization consistent across Windows and Linux for
  destinations, paths, queries, and privilege patterns.
- Preserve original destination and process identity through eBPF redirection
  so proxy handling can recover the caller and authorize the request.
- Preserve listener/redirector lifecycle coordination with secure-channel
  polling, policy, keys, and provisioning.

## Build & Test

Targets: Rust workspace on Windows and Linux; platform-specific eBPF integration.
The repository also includes a C# Azure VM E2E harness.

Follow the platform prerequisites and commands in
[Getting started on Windows](../doc/GettingStartedWindows.md) (`build.cmd`
from a Developer Command Prompt) or
[Getting started on Linux](../doc/GettingStartedLinux.md) (`./build-linux.sh`
in the documented development environment). These scripts can install tools or
modify the host; do not run them automatically for documentation-only changes.
Consult the curated [testing requirements](../.ai/testing-requirements.md)
before running product tests or Azure VM scenarios.

## Code Conventions

- Use Tokio actors as the serialized ownership boundary for shared runtime state.
  Keep the seven state domains distinct.
- Keep OS-specific networking and identity implementations behind the shared
  cross-platform request-processing behavior.
- Centralize CLI parsing, immutable configuration, diagnostics, and typed errors
  in agent platform utilities.
- Reuse `proxy_agent_shared` for common service lifecycle, host metadata/HTTP,
  logging, telemetry models, and OS utilities.
- Keep authorization-input normalization in the canonicalization component,
  rather than introducing divergent platform-specific normalization.
- Follow the telemetry flow: buffer in memory or JSON files, then enrich,
  redact, and batch delivery to WireServer.
- Keep Windows ETW/Event Log integration and static VCRuntime/resource build
  configuration platform-specific.
- Compose E2E scenarios from reusable VM test cases and shared Azure utilities;
  preserve the runner's per-scenario JUnit XML reporting.
