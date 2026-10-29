# Coding guidelines

Status, requested owner role, and evidence revision: [context registry](context.json).

## Existing conventions

- Follow the crate's Rust edition, dependency features, module structure, error
  types, and logger helpers. See the [extension manifest](../proxy_agent_extension/Cargo.toml)
  and [setup manifest](../proxy_agent_setup/Cargo.toml); do not introduce a new
  error/logging framework for a local change.
- [CI](../.github/workflows/ci.yml) runs rustfmt and Clippy with warnings denied.
  Keep new code compatible with both platform-specific lint jobs.
- Keep Windows/Linux behavior in the existing `cfg` boundaries. Preserve shared
  interfaces and platform-specific identity/service semantics.
- Maintain the existing copyright/SPDX headers in source files.
- Preserve [C/Rust audit ABI](../shared-ebpf/include/gpa_audit_event.h) field sizes,
  ordering, and alignment together; do not change one side in isolation.

## Review expectations

These are recommended engineering practices, not a claim that all existing code
already satisfies them:

- Keep changes single-purpose. Separate mechanical refactoring from behavior
  changes, but retain the regression tests that prove each behavior change.
- Reuse existing helpers and typed errors. Do not introduce silent success paths,
  swallowed errors, or permissive fallback in security/lifecycle changes.
- Preserve cancellation, ownership, and joining behavior in asynchronous code.
  Use the [runtime coordinator](../proxy_agent/src/runtime_coordinator.rs) as a
  source of lifecycle contracts, not merely a style example.
- Keep dependency features narrow. Shared signing features and
  [binary-size budgets](../.github/workflows/bloat.yml) affect multiple binaries.
- Explain only non-obvious constraints: compatibility exceptions, protocol
  requirements, and ordering that prevents races. Link the supporting test or
  approved design rationale instead of adding speculative incident history.
- Update affected [topic guidance](README.md) when a contract or validation
  command changes. A proposal does not silently become an implementation rule.

Consult [testing requirements](testing-requirements.md) before choosing commands:
full build scripts install tools, stage artifacts, and may modify the host.
