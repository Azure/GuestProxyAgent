# Documentation Index — GuestProxyAgent

> Master index for all agent-optimized documentation. Read this FIRST for any non-trivial question.


## Always-Loaded Foundation

- [L0 Primer](L0-foundations/codebase-primer.md) — Architecture, terminology, ownership. Always read before any task.


## Layer Indexes

- [L1 — Conceptual](L1-conceptual/docs-index.md) — "What is X?" — Foundational concepts, architecture, design rationale.
- [L2 — Platform](L2-platform/docs-index.md) — "How does X work?" — Infrastructure services, build, deployment, telemetry, flighting.
- [L3 — Flows](L3-flows/docs-index.md) — "How to implement X?" — End-to-end flows composing L1 concepts and L2 platform services.

## Detailed Content Fallback

Every DAG doc has a corresponding **detailed content file** at `intermediate-docs/` with per-file NL summaries. When a compact DAG doc (~200 lines) lacks sufficient detail:

1. Read the compact DAG doc in `{layer}/{name}.md`
2. If insufficient, read `intermediate-docs/{layer}/{name}.content.md` (detailed, no line limit)
3. Only then search source code directly

## Reading Chains

Ordered document sequences for common query types. Follow in order.

### "Trace a redirected request through identity recovery and authorization"
1. [L0-foundations/codebase-primer.md](L0-foundations/codebase-primer.md)
2. [L2-platform/ebpf-socket-redirection.md](L2-platform/ebpf-socket-redirection.md)
3. [L2-platform/agent-platform-utilities.md](L2-platform/agent-platform-utilities.md)
4. [L2-platform/authorization-canonicalization.md](L2-platform/authorization-canonicalization.md)
5. [L3-flows/authorized-proxy-request-flow.md](L3-flows/authorized-proxy-request-flow.md)

### "Change runtime coordination or shared authorization and signing state"
1. [L0-foundations/codebase-primer.md](L0-foundations/codebase-primer.md)
2. [L1-conceptual/agent-shared-state-access.md](L1-conceptual/agent-shared-state-access.md)
3. [L2-platform/agent-platform-utilities.md](L2-platform/agent-platform-utilities.md)
4. [L3-flows/agent-runtime-orchestration.md](L3-flows/agent-runtime-orchestration.md)
5. [L3-flows/authorized-proxy-request-flow.md](L3-flows/authorized-proxy-request-flow.md)

### "Understand agent installation, recovery, and extension lifecycle management"
1. [L0-foundations/codebase-primer.md](L0-foundations/codebase-primer.md)
2. [L2-platform/cross-platform-service-utilities.md](L2-platform/cross-platform-service-utilities.md)
3. [L2-platform/native-build-integration.md](L2-platform/native-build-integration.md)
4. [L3-flows/agent-installation-and-recovery.md](L3-flows/agent-installation-and-recovery.md)
5. [L3-flows/extension-lifecycle-orchestration.md](L3-flows/extension-lifecycle-orchestration.md)

### "Investigate health, logs, Windows events, and telemetry delivery"
1. [L0-foundations/codebase-primer.md](L0-foundations/codebase-primer.md)
2. [L1-conceptual/agent-shared-state-access.md](L1-conceptual/agent-shared-state-access.md)
3. [L2-platform/cross-platform-service-utilities.md](L2-platform/cross-platform-service-utilities.md)
4. [L2-platform/windows-event-integration.md](L2-platform/windows-event-integration.md)
5. [L2-platform/telemetry-event-delivery.md](L2-platform/telemetry-event-delivery.md)
6. [L3-flows/agent-runtime-orchestration.md](L3-flows/agent-runtime-orchestration.md)

### "Add or debug an Azure VM deployment and connectivity E2E scenario"
1. [L0-foundations/codebase-primer.md](L0-foundations/codebase-primer.md)
2. [L2-platform/agent-e2e-test-models.md](L2-platform/agent-e2e-test-models.md)
3. [L2-platform/agent-cloud-test-utilities.md](L2-platform/agent-cloud-test-utilities.md)
4. [L2-platform/agent-vm-test-cases.md](L2-platform/agent-vm-test-cases.md)
5. [L2-platform/agent-deployment-test-scenarios.md](L2-platform/agent-deployment-test-scenarios.md)
6. [L2-platform/agent-e2e-test-runner.md](L2-platform/agent-e2e-test-runner.md)
