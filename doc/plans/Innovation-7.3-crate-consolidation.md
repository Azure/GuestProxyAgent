## Sections

1.  [1. Overview](#overview)
2.  [2. Today](#today)
3.  [3. Code moves](#moves)
4.  [4. musl static](#musl)
5.  [5. Bloat budget](#bloat)
6.  [6. `signing` feature gate](#signing)
7.  [7. Integration](#integration)
8.  [8. Tests](#tests)
9.  [9. Risks](#risks)
10. [10. Milestones & status](#milestones)

**GPA** · **Direction 7.3** · **Footprint** · **Status: ✅ done**

# Detailed Design — Crate Consolidation, musl Static, Bloat Budget

Move duplicated helpers (logging init, config loader, version probe) into `proxy_agent_shared`. Ship a single static `musl` binary per role with a hard cargo-bloat budget enforced in CI.

**Files affected:** `proxy_agent_shared/`, `proxy_agent/`, `proxy_agent_extension/`, `proxy_agent_setup/`, CI pipeline.

> **Prerequisites:** None — internal refactor, independent of feature work.

## 1. Overview & Goals

| Impact                       | Effort    | Risk    | Scope         |
|------------------------------|-----------|---------|---------------|
| **Internal** maintainability | **Small** | **Low** | **workspace** |

### Status snapshot — ✅ done

- **Done** — musl static binaries (`x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`) are already produced by [`build-linux.sh`](../../build-linux.sh) driven from [`reusable-build.yml`](../../.github/workflows/reusable-build.yml); Windows MSVC builds go through [`build.cmd`](../../build.cmd) in the same pipeline.
- **Done** — PR 353: logger init + GPA service name moved to `proxy_agent_shared`.
- **Done** — PR 352: `cargo-bloat` budget enforced per-(target, role) on top of those builds; `signing` Cargo feature lets non-signing binaries drop OpenSSL.
- **Out of scope** — *config loader* and *OS/version probe* consolidation. See [§3](#moves) for why: only `proxy_agent` has a JSON config loader (the other two binaries don't load JSON config at all), and the OS/version probe already lives in `proxy_agent_shared`.

### Goals

- Single source of truth for cross-cutting helpers.
- One static binary per role: `azure-proxy-agent`, `azure-proxy-agent-ext`, `azure-proxy-agent-setup`.
- Binary size capped in CI — surprise growth blocks merge.

## 2. Today

Logger init used to be duplicated across `proxy_agent`, `proxy_agent_extension`, and `proxy_agent_setup` (PR 353 removed that), and the OS service-name constant had silently drifted across `proxy_agent` / `proxy_agent_extension` / `proxy_agent_setup` (PR 353 unified that too). The OS / version probe already lives in `proxy_agent_shared::{current_info, linux, windows}`, and a workspace-wide JSON config loader exists only in `proxy_agent` — the other two binaries don't read a JSON config, so there is no "third copy" to fold in.

## 3. Code Moves

| From                       | To                                          | Status                | Notes                                                                                                                                                                                                                                                          |
|----------------------------|---------------------------------------------|-----------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| per-crate logger setup     | `proxy_agent_shared::logger::init_loggers`  | **done** (PR 353)     | One helper takes `(log_folder, &[(key, file)], primary_key, max_size, max_count, level)` and constructs the `RollingLogger` map in one place.                                                                                                                  |
| GPA service / display name | `proxy_agent_shared::constants`             | **done** (PR 353)     | `PROXY_AGENT_SERVICE_NAME` (`GuestProxyAgent` on Windows, `azure-proxy-agent` on Linux) + `PROXY_AGENT_SERVICE_DISPLAY_NAME` live in one module.                                                                                                               |
| OS / version probe         | `proxy_agent_shared::{current_info, linux, windows}` | **already done**      | Pre-existing. `proxy_agent_extension/src/handler_main.rs` already calls into `proxy_agent_shared::{linux, windows}::get_os_version`; no second copy to fold in.                                                                                                |
| HTTP client helpers        | `proxy_agent_shared::hyper_client`          | **already done**      | `hyper_client` is the only HTTP client; the three binaries all call into it directly. The per-binary "wrapper" assumption from the original plan turned out not to exist.                                                                                      |
| ~~per-crate config loaders~~ | ~~`proxy_agent_shared::config`~~          | **dropped** (not needed) | Only `proxy_agent/src/common/config.rs` reads a JSON config file. `proxy_agent_extension` is driven by the VM-extension HandlerEnvironment + `*.settings` sequence files (a different shape, owned by the extension framework), and `proxy_agent_setup` has no runtime config at all. Nothing to consolidate. |

### What the logger consolidation looks like

Before (duplicated across `proxy_agent`, `proxy_agent_extension`, `proxy_agent_setup`):

    let agent_logger = RollingLogger::create_new(log_folder.clone(), "ProxyAgent.log".to_string(), MAX_SIZE, MAX_COUNT);
    let connection_logger = RollingLogger::create_new(log_folder.clone(), "ProxyAgent.Connection.log".to_string(), MAX_SIZE, MAX_COUNT);
    let mut loggers = HashMap::new();
    loggers.insert(AGENT_LOGGER_KEY.to_string(), agent_logger);
    loggers.insert(CONNECTION_LOGGER_KEY.to_string(), connection_logger);
    logger_manager::set_loggers(loggers, AGENT_LOGGER_KEY.to_string(), level);

After (one call from each binary, including the in-tree `logger_manager` tests):

    proxy_agent_shared::logger::init_loggers(
        log_folder,
        &[
            (logger::AGENT_LOGGER_KEY, "ProxyAgent.log"),
            (ConnectionLogger::CONNECTION_LOGGER_KEY, "ProxyAgent.Connection.log"),
        ],
        logger::AGENT_LOGGER_KEY,
        constants::MAX_LOG_FILE_SIZE,
        constants::MAX_LOG_FILE_COUNT as u16,
        config::get_file_log_level(),
    );

Net: ~60 lines of boilerplate removed across the three binaries, and the rolling-logger contract (panic if `primary_key` isn't registered) is enforced in one place.

## 4. musl Static Build

**Status: done** (pre-existing; not part of PR 352 / 353). Both Linux targets are built by [`build-linux.sh`](../../build-linux.sh) and invoked from the shared [`reusable-build.yml`](../../.github/workflows/reusable-build.yml) workflow (`build-linux-amd64` / `build-linux-arm64`); Windows MSVC builds go through [`build.cmd`](../../build.cmd) in the same file (`build-windows-amd64` / `build-windows-arm64`). The bloat workflow piggy-backs on these and only adds the regression gate on top of them.

- CI targets: `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl` (selected by the `-Target amd64|arm64` argument in `build-linux.sh`).
- No dynamic libc dependency for the agent role; the setup tool ships from the same musl target.
- Cross-distro install: same binary on RHEL 8/9, Ubuntu 22.04/24.04, Azure Linux.
- eBPF object files shipped separately (loaded by libbpf at runtime), independent of libc.

## 5. Bloat Budget

**Status: done (PR 352).** Enforced on every PR via [`.github/workflows/bloat.yml`](../../.github/workflows/bloat.yml) and [`ci/check_bloat.py`](../../ci/check_bloat.py). See [`ci/README.md`](../../ci/README.md) for the full design and override path.

The gate has two ceilings on purpose:

- **Absolute ceiling** (`--max-binary-bytes`) catches "total growth" no matter where it came from.
- **Per-crate share ceiling** (`--max-crate-share`, default `0.10` = 10% of `.text`) catches "one bad dependency dominates the binary" even when the total is under the absolute ceiling — the failure message names the offending crate, turning a vague size regression into a specific code-review conversation.

First-party workspace crates (`azure-proxy-agent`, `ProxyAgentExt`, `proxy_agent_setup`, `proxy_agent_shared`) are exempt from the share gate; the absolute ceiling still bounds them. Per-(target, crate, dependency) ceiling overrides go through `--crate-share-override clap_builder=0.35` so the policy stays narrow: raising the ceiling for `clap` in `proxy_agent_setup` does not also raise it for every other binary.

### Per-(target, role) ceilings

A Linux musl binary and a Windows MSVC binary (with `static_vcruntime` + `windows-sys`) have very different baselines. One shared ceiling would either let Windows regress silently or false-flag every Linux PR, so the workflow runs as a matrix:

| Target                       | Role binary           | Max stripped size |
|------------------------------|-----------------------|-------------------|
| `x86_64-unknown-linux-musl`  | `azure-proxy-agent`   | 20 MB             |
| `x86_64-unknown-linux-musl`  | `ProxyAgentExt`       | 9 MB              |
| `x86_64-unknown-linux-musl`  | `proxy_agent_setup`   | 6 MB              |
| `aarch64-unknown-linux-musl` | `azure-proxy-agent`   | 20 MB             |
| `aarch64-unknown-linux-musl` | `ProxyAgentExt`       | 16 MB             |
| `aarch64-unknown-linux-musl` | `proxy_agent_setup`   | 11 MB             |
| `x86_64-pc-windows-msvc`     | `azure-proxy-agent`   | 10 MB             |
| `x86_64-pc-windows-msvc`     | `ProxyAgentExt`       | 5 MB              |
| `x86_64-pc-windows-msvc`     | `proxy_agent_setup`   | 4 MB              |
| `aarch64-pc-windows-msvc`    | `azure-proxy-agent`   | 8 MB              |
| `aarch64-pc-windows-msvc`    | `ProxyAgentExt`       | 5 MB              |
| `aarch64-pc-windows-msvc`    | `proxy_agent_setup`   | 4 MB              |

### Running locally

    rustup target add x86_64-unknown-linux-musl
    sudo apt-get install -y musl-tools
    cargo install cargo-bloat --locked

    cargo bloat --release --crates \
        --target x86_64-unknown-linux-musl \
        -p azure-proxy-agent \
        --message-format json > bloat.json

    python3 ci/check_bloat.py \
        --bloat-json bloat.json \
        --max-binary-bytes 20000000 \
        --max-crate-share 0.10

Exit `0` = within budget, `1` = ceiling tripped (prints top contributors and which ceiling), `2` = bad input.

### Override path

Bloat regressions are intentional sometimes (new feature, security-driven dep upgrade). Procedure:

1. Run the commands above locally and copy the report into the PR.
2. Bump the relevant `max_binary_bytes` entry (or add a `crate_share_overrides` line) in `.github/workflows/bloat.yml` **and** update the table in `ci/README.md` in the same PR. Only the regressing row(s).
3. Get two reviewer approvals specifically acknowledging the budget change (`LGTM-bloat` review tag convention).
4. After merge, the new ceiling becomes the baseline.

Unauthorized bypasses (`--no-verify`, removing the workflow) are not permitted.

## 6. `signing` feature gate

**Status: done (PR 352).** `proxy_agent_shared` now exposes an opt-in `signing` Cargo feature:

    # proxy_agent_shared/Cargo.toml
    [features]
    default = []
    # Enables compute_signature (HMAC-SHA256 via OpenSSL on Linux).
    # Binaries that don't sign anything (e.g. proxy_agent_setup) should leave this off.
    signing = ["dep:openssl"]

`openssl` is now an *optional* dep on both musl and gnu Linux targets and is `#[cfg(feature = "signing")]`-gated everywhere it is touched (`linux.rs`, `hyper_client.rs`, `misc_helpers.rs`, `error.rs`). Only `proxy_agent` opts in (`proxy_agent_shared = { path = "...", features = ["signing"] }`); `proxy_agent_setup` and `ProxyAgentExt` drop vendored OpenSSL entirely, which is a multi-MB win on musl (and lets the bloat ceilings for those two binaries land where they did).

## 7. Integration

- SBOM (3.4) generated from the static binary's compiled crate graph.
- Attestation endpoint (3.3) reports binary hash and bloat report URL.
- Pkg builds (deb/rpm) pick up the static binary unchanged.

## 8. Tests

- Smoke test on each supported distro using the static binary.
- Bloat budget test runs on every PR; documented override path with mandatory two-reviewer approval.
- The in-tree `logger_manager` unit tests now exercise `init_loggers` directly, so the consolidated helper is covered by the existing test suite.

## 9. Risks

- **musl perf** for DNS / network can differ. Mitigation: micro-benchmark before/after.
- **Bloat budget** false alarms on benign upgrades. Mitigation: per-(target, crate) overrides in `bloat.yml` + weekly main-branch baseline refresh.
- **`signing` feature drift**: adding a new caller of `compute_signature` from a binary that doesn't opt into `signing` is a compile-time error rather than a runtime surprise — the `#[cfg(feature = "signing")]` gates make the contract explicit.

## 10. Milestones & status

| M   | Deliverable                          | Status                                          | Exit                                                              |
|-----|--------------------------------------|-------------------------------------------------|-------------------------------------------------------------------|
| M1  | Helper moves to `proxy_agent_shared` | **done** (PR 353 + pre-existing)                | Logger setup + GPA service name unified in PR 353; OS/version probe and HTTP client already lived in `proxy_agent_shared`. Config loader intentionally not moved — only one binary has one. |
| M2  | musl static binary in CI             | **done** (pre-existing)                         | Built by `build-linux.sh` via `reusable-build.yml` (amd64 + arm64) |
| M3  | Bloat budget enforced                | **done** (PR 352)                               | Per-(target, role) ceilings active; PRs blocked over ceiling      |
| M4  | OpenSSL gated off non-signing roles  | **done** (PR 352)                               | `proxy_agent_shared` `signing` feature; setup + ext build without |

Detail design for direction 7.3. Parent: [Innovation-Directions.md](Innovation-Directions.md).
