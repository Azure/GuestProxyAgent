# Testing requirements

Status, requested owner role, and evidence revision: [context registry](context.json).

## Choose the smallest faithful validation

1. Identify affected components, operating systems, architectures, and contracts.
2. Add or select behavior-focused tests, including relevant failure scenarios from
   [common regressions](common-regressions.md).
3. Run focused tests in the supported build environment. Broaden validation for
   shared code, lifecycle, authorization, packaging, and platform changes.
4. Record the exact command, assessed commit, environment/target, result, and
   evidence link. Missing execution is not a pass.

For example, the shared crate can be selected from a prepared checkout with:

```powershell
cargo test --manifest-path proxy_agent_shared\Cargo.toml --all-features -- --test-threads=1
cargo fmt --all -- --check -l
cargo clippy -- -D warnings
```

These commands use the configured/default host target unless specified otherwise.
They are not replacements for the platform build, staged agent fixtures, or VM
validation. Prerequisites and target behavior must be checked before execution.

## Build and fixture preparation

- [Windows setup](../doc/GettingStartedWindows.md) describes the VS/SDK/WDK/Clang
  environment. [build.cmd](../build.cmd) stages agent configuration, binaries,
  and eBPF artifacts before tests. It skips ARM64 unit execution on an amd64 host.
- [Linux setup](../doc/GettingStartedLinux.md) recommends the development container.
  [build-linux.sh](../build-linux.sh) prepares eBPF/configuration and test artifacts,
  runs crate tests, and packages output.
- Both build scripts select toolchains, install/restore dependencies, and run
  formatting. Do not invoke full builds as read-only inspection or casually run
  their clean options on a shared machine.
- Tests run serially in the build scripts. Preserve this when fixtures or shared
  resources require it; do not assume parallel execution is equivalent.

## Interpret configured checks accurately

| Source | Evidence and limits |
|---|---|
| [CI](../.github/workflows/ci.yml) | Windows/Linux formatting, Clippy, and dependency audit; inspect actual job results |
| [Reusable builds](../.github/workflows/reusable-build.yml) | Windows/Linux x64/ARM64 builds; configured 70% coverage checks for selected crates on x64, with exclusions |
| [CodeQL](../.github/workflows/codeql.yml) | Configured C/C++ and C# analysis, not a Rust-workspace assurance claim |
| [Bloat workflow](../.github/workflows/bloat.yml) | Per-target/binary ceilings and crate-share overrides; use current workflow values, not copied budgets |

Coverage thresholds are not coverage deltas or proof of acceptance criteria.
Dependency audit is not license validation. A configured job is not evidence that
it ran successfully for this commit or is required by branch protection.

## VM, integration, and security-sensitive validation

The [E2E project](../e2etest/GuestProxyAgentTest/GuestProxyAgentTest.csproj) is a
.NET executable, not a conventional unit-test project. Its
[entry point](../e2etest/GuestProxyAgentTest/Program.cs) runs VM scenarios using
[test maps](../e2etest/GuestProxyAgentTest/TestMap). Building it or running a generic
`dotnet test` command does not prove those scenarios executed. Runs can create
and clean Azure resources; require an approved test environment and identity.

For eBPF, authorization, networking, update, or service changes, select relevant
VM scenarios and platform evidence with the domain owner. Do not claim x64 unit
success validates ARM64, kernel loading, reboot, rollback, or production signing.

Use explicit evidence states: **Passed / Failed / Pending / Not run /
Unavailable / Not applicable**. Explain "Not applicable"; keep author-reported
results distinct from independently collected CI evidence.
