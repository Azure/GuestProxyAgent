# Compatibility

Status, requested owner role, and evidence revision: [context registry](context.json).

## Documented platform baseline

The [README](../README.md) documents Linux kernel 5.15+ and Windows with
eBPF-for-Windows, with Windows 10/Server 2019+, Ubuntu 20.04+, RHEL 9+, Flatcar,
Rocky Linux 9+, and SUSE 15 SP4+. These are documented support statements, not
evidence that every combination was tested for the current change.

The [build workflow](../.github/workflows/reusable-build.yml) targets x64 and ARM64
Windows MSVC and Linux musl. Windows ARM64 cross-compilation skips unit execution
on the x64 build host. Use the actual [VM maps](../e2etest/GuestProxyAgentTest/TestMap)
and run results to establish exercised OS/architecture combinations.

## Implementation constraints

- [Linux build logic](../proxy_agent/build.rs) compiles architecture-specific
  CO-RE eBPF; kernel BTF and user-mode loading must be considered separately from
  a successful Rust build.
- [Windows prerequisites](../doc/GettingStartedWindows.md) pin compatible
  Clang/verifier expectations and SDK/WDK tools. Do not upgrade these independently
  without eBPF build/load and runtime evidence.
- The [shared manifest](../proxy_agent_shared/Cargo.toml) distinguishes signing
  dependencies and platform features, including Linux musl/GNU differences.
  Crypto backend and binary-size effects are compatibility concerns.
- The [extension handler](../proxy_agent_extension/src/handler_main.rs) has an OS
  version gate and `test_check_os_supported`; changing it alters the accepted
  platform contract.
- [C audit layouts](../shared-ebpf/include/gpa_audit_event.h) and Rust consumers
  must remain binary-compatible across both architectures.
- The [E2E harness](../e2etest/GuestProxyAgentTest/GuestProxyAgentTest.csproj)
  targets .NET 10. Its SDK requirement is build/test tooling, not a new GPA runtime
  dependency on every guest.

## Compatibility review

For changed configuration, policy, serialized status, or command-line behavior,
compare old and new consumers: agent, extension, setup, and host-facing clients.
Test relevant absent/unknown fields and older artifacts instead of assuming
mixed-version compatibility. Review install/update/downgrade and persisted-state
behavior with [deployment safety](deployment-safety.md).

Do not silently remove supported defaults, audit modes, signing exceptions, or
platform fallbacks during cleanup. Record intentional behavior changes and the
human decision authorizing them. Mark untested OS/kernel/architecture combinations
as evidence gaps rather than extending support claims.
