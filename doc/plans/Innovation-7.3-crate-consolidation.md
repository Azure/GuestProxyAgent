## Sections

1.  [1. Overview](#overview)
2.  [2. Today](#today)
3.  [3. Code moves](#moves)
4.  [4. musl static](#musl)
5.  [5. Bloat budget](#bloat)
6.  [6. Integration](#integration)
7.  [7. Tests](#tests)
8.  [8. Risks](#risks)
9.  [9. Milestones](#milestones)

**GPA** · **Direction 7.3** · **Footprint**

# Detailed Design — Crate Consolidation, musl Static, Bloat Budget

Move duplicated helpers (logging init, config loader, version probe) into `proxy_agent_shared`. Ship a single static `musl` binary per role with a hard cargo-bloat budget enforced in CI.

**Files affected:** `proxy_agent_shared/`, `proxy_agent/`, `proxy_agent_extension/`, `proxy_agent_setup/`, CI pipeline.

> **Prerequisites:** None — internal refactor, independent of feature work.

## 1. Overview & Goals

| Impact                       | Effort    | Risk    | Scope         |
|------------------------------|-----------|---------|---------------|
| **Internal** maintainability | **Small** | **Low** | **workspace** |

### Goals

- Single source of truth for cross-cutting helpers.
- One static binary per role: `azure-proxy-agent`, `azure-proxy-agent-ext`, `azure-proxy-agent-setup`.
- Binary size capped in CI — surprise growth blocks merge.

## 2. Today

Logger init, config loader, and version probe exist in slightly different shapes across `proxy_agent`, `proxy_agent_extension`, and `proxy_agent_setup`. `proxy_agent_shared` already exists but is under-used.

## 3. Code Moves

| From                       | To                              | Notes                                 |
|----------------------------|---------------------------------|---------------------------------------|
| per-crate `logger` setup   | `proxy_agent_shared::logging`   | One `init(role, level)` entry point   |
| per-crate `config` loaders | `proxy_agent_shared::config`    | Layered: file → env → defaults; serde |
| OS / version probe         | `proxy_agent_shared::host_info` | One function returns full struct      |
| HTTP client helpers        | `proxy_agent_shared::http`      | One client, with the right TLS roots  |

## 4. musl Static Build

- Add CI target `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl`.
- Drop dynamic libc dependency for the agent role; setup tool optionally remains glibc.
- Cross-distro install: same binary on RHEL 8/9, Ubuntu 22.04/24.04, Azure Linux.
- eBPF object files shipped separately (loaded by libbpf at runtime), independent of libc.

## 5. Bloat Budget

    # CI step
    cargo install cargo-bloat --locked
    cargo bloat --release --crates --message-format json > bloat.json
    python3 ci/check_bloat.py --max-binary-bytes 20000000 --max-crate-share 0.10

- Hard ceiling on total binary size (e.g. 20 MB stripped).
- No single non-first-party crate may exceed 10% of total text.
- Drift detector: PR comment shows top contributors and delta from main.

## 6. Integration

- SBOM (3.4) generated from the static binary's compiled crate graph.
- Attestation endpoint (3.3) reports binary hash and bloat report URL.
- Pkg builds (deb/rpm) pick up the static binary unchanged.

## 7. Tests

- Smoke test on each supported distro using the static binary.
- Bloat budget test runs on every PR; documented override path with mandatory two-reviewer approval.

## 8. Risks

- **musl perf** for DNS / network can differ. Mitigation: micro-benchmark before/after.
- **Bloat budget** false alarms on benign upgrades. Mitigation: weekly main-branch baseline refresh.

## 9. Milestones

| M   | Deliverable                          | Exit                           |
|-----|--------------------------------------|--------------------------------|
| M1  | Helper moves to `proxy_agent_shared` | No duplicate code; tests green |
| M2  | musl static binary in CI             | Cross-distro smoke green       |
| M3  | Bloat budget enforced                | PRs blocked over ceiling       |

Detail design for direction 7.3. Parent: [Innovation-Directions.md](Innovation-Directions.md).
