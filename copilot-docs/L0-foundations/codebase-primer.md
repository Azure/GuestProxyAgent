# GuestProxyAgent — Primer

> Always-loaded foundation. Max 200 lines. No index.

## Architecture — High-level system architecture

GuestProxyAgent is a cross-platform guest-side system that redirects selected network connections through a loopback HTTP/1.1 proxy. Windows and Linux eBPF hooks retain the original destination and process identity so user-mode request handling can recover the caller and apply endpoint-specific authorization.

The agent coordinates secure-channel polling with an owned listener/redirector pair. Runtime orchestration brings together keys, authorization policy, provisioning, health, and request processing. Authorization canonicalization normalizes destinations, paths, queries, and privilege patterns consistently across both operating systems.

Shared state is serialized through seven Tokio actors covering authorization, signing, health, provisioning, connection summaries, identity caching, and redirection. This actor-oriented state boundary complements platform-specific networking and identity implementations.

Deployment is split between setup and extension components. The setup executable installs, backs up, restores, and removes the agent; the extension translates lifecycle commands into platform-specific service operations and continuously reconciles lifecycle state. Shared Rust utilities provide service lifecycle operations, host metadata and HTTP helpers, logging, telemetry models, and OS utilities.

Operational support includes buffered telemetry delivery to WireServer, Windows event integration, native executable build configuration, and a C# end-to-end harness that provisions Azure VMs and runs deployment and connectivity scenarios.

## Request Flow — Typical request/operation flow through the system

1. Windows or Linux eBPF hooks match a connection against redirection policy and retain its original destination and process identity.
2. The redirected connection reaches the agent's loopback HTTP/1.1 listener.
3. Proxy handling recovers caller identity and destination, then validates the request.
4. Canonicalization normalizes authorization inputs before endpoint-specific authorization is applied.
5. Request handling uses coordinated policy and signing state where required, then proxies authorized traffic to its destination.
6. Health, connection summaries, logs, and telemetry support observation of agent operation.

Alongside request handling, secure-channel polling coordinates keys, policy, and provisioning with the listener/redirector lifecycle. Installation and extension lifecycle operations use shared service APIs to manage the deployed agent independently of individual requests.

## Core Terminology — Table with Term | Definition for the 10-20 most important concepts

| Term | Definition |
|------|------------|
| GuestProxyAgent | Guest-side agent coordinating redirected HTTP traffic, authorization, signing state, and runtime health. |
| Loopback proxy | Local HTTP/1.1 endpoint that receives redirected connections and processes requests. |
| eBPF redirection | Windows and Linux socket hooks that redirect policy-matched connections while retaining destination and process metadata. |
| Original destination | Connection target retained before redirection and recovered by proxy handling. |
| Caller identity | Process and OS identity information recovered for request validation and authorization. |
| Authorization policy | Rules used for endpoint-specific decisions about whether requests are permitted. |
| Canonicalization | Consistent normalization of destinations, paths, queries, and privilege patterns for authorization. |
| Secure-channel polling | Runtime activity that coordinates keys, authorization policy, and provisioning with agent operation. |
| Signing state | Shared signing-related state coordinated by a dedicated Tokio actor. |
| Tokio actor | Serialized owner of a shared-state domain used by asynchronous Rust components. |
| Provisioning | Runtime readiness-related state coordinated with policy, keys, and agent lifecycle. |
| Listener/redirector pair | Coupled runtime components responsible for accepting proxy traffic and enabling connection redirection. |
| Connection summary | Shared accounting of connections maintained as a dedicated state domain. |
| Setup | Executable responsible for installation, backup, restoration, and removal. |
| Extension | Component that handles lifecycle commands and continuously reconciles service-related state. |
| WireServer | Destination for enriched, redacted, batched telemetry delivery. |
| Managed Run Command | Azure VM execution mechanism used by the E2E utilities to run guest-side test operations. |
| E2E scenario | Ordered VM test cases covering deployment, configuration, health, and connectivity. |

## Key Components — Table with Component | Description summarizing the major subsystems

| Component | Description |
|-----------|-------------|
| Agent runtime orchestration | Coordinates secure-channel polling, keys, policy, provisioning, and the listener/redirector lifecycle. |
| Authorized proxy request handling | Recovers identity and destination, validates requests, and applies endpoint-specific authorization. |
| Authorization canonicalization | Supplies consistent authorization input normalization across Windows and Linux. |
| eBPF socket redirection | Implements platform-specific connection interception and retention of original connection metadata. |
| Shared-state actors | Serialize authorization, signing, health, provisioning, connection-summary, identity-cache, and redirector state. |
| Agent platform utilities | Centralize CLI parsing, immutable configuration, diagnostics, typed errors, and OS-specific identity/key utilities. |
| proxy_agent_shared | Provides common service lifecycle, host metadata/HTTP, state, logging, telemetry models, and OS utilities. |
| proxy_agent_setup | Installs, backs up, restores, and removes the agent using shared service APIs and platform-specific file placement. |
| proxy_agent_extension | Maps lifecycle commands to platform service operations and continuously reconciles deployed lifecycle state. |
| Telemetry event delivery | Buffers logs and extension status in memory or JSON files, then enriches, redacts, and batches delivery to WireServer. |
| Windows event integration | Consumes ETW and Event Log subscriptions and queries historical Windows event records. |
| Native build integration | Configures static VCRuntime and Windows resources through Cargo build scripts for agent, extension, and setup executables. |
| C# E2E harness | Combines models, scenario orchestration, reusable VM cases, Azure utilities, and JUnit XML reporting. |
