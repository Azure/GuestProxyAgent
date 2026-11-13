# Architecture

Status, requested owner role, and evidence revision: [context registry](context.json).

## Component map

The [workspace](../Cargo.toml) contains four Rust members:

| Component | Responsibility and entry points |
|---|---|
| [proxy_agent](../proxy_agent/src/main.rs) | In-guest request proxy, identity/authorization, key maintenance, provisioning coordination, and redirection |
| [proxy_agent_shared](../proxy_agent_shared/src/lib.rs) | Host clients, HTTP/signing helpers, service abstractions, telemetry, and shared status models |
| [proxy_agent_extension](../proxy_agent_extension/src/service_main.rs) | Extension lifecycle, health/status reporting, and installation/update orchestration |
| [proxy_agent_setup](../proxy_agent_setup/src/main.rs) | Install, backup, restore, uninstall, and purge operations |

The [project overview](../README.md) explains the Azure IMDS/WireServer trust
model and intended transparent interception. [Linux eBPF](../linux-ebpf/ebpf_cgroup.c)
and [Windows eBPF](../ebpf/redirect.bpf.c) provide platform-specific redirection.
Shared [C audit layouts](../shared-ebpf/include/gpa_audit_event.h) bridge kernel
and user mode; their binary layout is part of the interface, not incidental detail.

## Request and control paths

- [ProxyConnection](../proxy_agent/src/proxy/proxy_connection.rs) obtains originating
  identity/destination evidence and creates claims for the connection.
- [Destination-specific authorization](../proxy_agent/src/proxy/proxy_authorizer.rs)
  evaluates the claims and applicable policy. Audit and enforce outcomes differ.
- [ProxyServer](../proxy_agent/src/proxy/proxy_server.rs) forwards requests and
  handles request signing. Do not infer the signing rules from this summary;
  inspect its conditions and the [shared HTTP helpers](../proxy_agent_shared/src/hyper_client.rs).
- [KeyKeeper](../proxy_agent/src/key_keeper.rs) maintains secure-channel/key/policy
  state. The [RuntimeCoordinator](../proxy_agent/src/runtime_coordinator.rs) manages
  the paired lifecycle of the proxy listener and redirector.
- The [extension monitor](../proxy_agent_extension/src/service_main.rs) compares
  bundled, installed, and reported running versions; equal file versions alone
  do not prove an interrupted update completed.

## Contracts to inspect before refactoring

- Runtime selection, listener health, desired local port, and provisioning
  notification are distinct states. Preserve startup, cancellation, same-port
  handoff, and failure sequencing rather than collapsing them into one flag.
- Audit/enforcement and soft-audit fallback are different mechanisms. Read the
  [security guidance](security-invariants.md) and relevant tests before changing either.
- Shared types/helpers affect more than the main agent. Trace consumers in the
  extension and setup tool, including platform-specific implementations.
- Canonicalization has implemented shadow/enforce modes selected through
  configuration. A [design proposal](../doc/plans/Innovation-2.1-canonical-request.md)
  explains intent but is not a substitute for the current
  [canonical module](../proxy_agent/src/proxy/canonical/mod.rs) and authorizer.
