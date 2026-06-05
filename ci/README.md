# CI Helpers — Bloat Budget

This directory implements a hard
`cargo-bloat` budget enforced on every PR.

The musl static binaries themselves (both `x86_64-unknown-linux-musl` and
`aarch64-unknown-linux-musl`) are already produced by
[`.github/workflows/reusable-build.yml`](../.github/workflows/reusable-build.yml)
via `build-linux.sh`. This directory only adds the regression gate.

## Why this matters

The guest proxy agent ships on **every** Azure Linux VM. Every byte the
binary grows is paid millions of times over: bigger images, slower VM
provisioning, larger memory-resident `.text`, slower cold start, more
surface area to attest in the SBOM (3.4) and supply-chain pipeline.

Binary size is the kind of thing that rots silently. A typical PR will
**not** mention size in its title, and reviewers can't eyeball it from a
diff. The usual culprits are invisible at the source-code level:

- enabling an extra Cargo **feature** on a transitive dep (e.g. flipping
  `tokio = { features = ["full"] }`) pulls in megabytes;
- a small generic helper used from many call sites causes **monomorphization
  blowup**;
- a "harmless" new dependency drags in `openssl-sys`, `chrono` with all
  locales, a full `regex` engine, or a duplicated async runtime;
- a `cargo update` bumps a transitive crate to a version that vendors more
  data tables.

Any of those can add **multiple megabytes** to a release binary without a
single line of our code changing. Without a gate, the only way we find out
is when a customer complains months later.

## What "regression gate" means here

A *regression gate* is a CI check that fails the PR when a numeric metric
crosses a threshold, independent of whether the code compiles or tests
pass. We already have several of those (clippy `-D warnings`, code-coverage
≥ 70 %, `cargo-audit`). The bloat budget is the same idea applied to the
release binary:

> If this PR would make the agent larger than 20 MB stripped, or would let
> any single third-party crate own more than 10 % of `.text`, **block the
> merge** until either the cause is fixed or the budget change is
> explicitly reviewed (see "Override path" below).

The gate has two ceilings on purpose:

- **Absolute ceiling** catches "total growth" no matter where it came from.
- **Per-crate share ceiling** catches "one bad dependency dominates the
  binary" even when total size is still under the absolute ceiling. This
  is what makes the gate point a finger — the failure message names the
  offending crate.

## What `cargo-bloat` actually does

[`cargo-bloat`](https://github.com/RazrFalcon/cargo-bloat) is a small tool
that compiles the workspace, then inspects the resulting binary's symbol
table and groups every function in `.text` by the crate that produced it.
Run with `--crates --message-format json` it emits a structured report
like:

```json
{
  "file-size": 17234048,
  "text-section-size": 9123456,
  "crates": [
    { "name": "azure-proxy-agent", "size": 2_100_000 },
    { "name": "tokio",             "size":   870_000 },
    { "name": "regex",             "size":   640_000 },
    ...
  ]
}
```

We feed that JSON into `check_bloat.py`, which:

1. checks total binary size against `--max-binary-bytes`;
2. checks every non-first-party crate's share of `.text` against
   `--max-crate-share`;
3. prints the top contributors so a failing PR comes with an actionable
   report ("crate `foo` is 17.3 % of text — did this PR add a feature?").

Concretely, `cargo-bloat` gives us **attribution**: instead of "the binary
grew 4 MB", we get "the binary grew 4 MB and 3.6 MB of it landed in
`some-crate`". That attribution is the whole point — it turns a vague size
problem into a specific code-review conversation.

## Files

| File              | Purpose                                                                 |
| ----------------- | ----------------------------------------------------------------------- |
| `check_bloat.py`  | Reads `cargo bloat --message-format json` and fails if a budget is hit. |

The workflow that runs it lives at
[`.github/workflows/bloat.yml`](../.github/workflows/bloat.yml).

## Budgets (default)

The gate runs as a matrix over `(target, role binary)`. The absolute
ceiling is per matrix entry — a Windows MSVC binary with `static_vcruntime`
and `windows-sys` has a different baseline than a Linux musl binary, and
the setup tool has a different baseline than the main agent. The
per-crate share is a ratio and is kept global.

| Target                          | Role binary           | Max stripped size |
| ------------------------------- | --------------------- | ----------------- |
| `x86_64-unknown-linux-musl`     | `azure-proxy-agent`   | 20 MB             |
| `x86_64-unknown-linux-musl`     | `ProxyAgentExt`       | 15 MB             |
| `x86_64-unknown-linux-musl`     | `proxy_agent_setup`   | 10 MB             |
| `aarch64-unknown-linux-musl`    | `azure-proxy-agent`   | 22 MB             |
| `aarch64-unknown-linux-musl`    | `ProxyAgentExt`       | 16 MB             |
| `aarch64-unknown-linux-musl`    | `proxy_agent_setup`   | 11 MB             |
| `x86_64-pc-windows-msvc`        | `azure-proxy-agent`   | 28 MB             |
| `x86_64-pc-windows-msvc`        | `ProxyAgentExt`       | 22 MB             |
| `x86_64-pc-windows-msvc`        | `proxy_agent_setup`   | 15 MB             |
| `aarch64-pc-windows-msvc`       | `azure-proxy-agent`   | 30 MB             |
| `aarch64-pc-windows-msvc`       | `ProxyAgentExt`       | 23 MB             |
| `aarch64-pc-windows-msvc`       | `proxy_agent_setup`   | 16 MB             |

Per-crate share ceiling (`--max-crate-share`): **0.10** (10 % of `.text`),
applied to every matrix entry.

First-party workspace crates (`azure-proxy-agent`, `ProxyAgentExt`,
`proxy_agent_setup`, `proxy_agent_shared`) are exempt from the per-crate
share gate; the absolute size ceiling still applies to them.

## Running locally

```bash
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
```

The script exits `0` when within budget, `1` when the budget is exceeded
(prints a report of top contributors and which ceiling was tripped), and
`2` on invalid input.

## Override path

Bloat regressions are intentional sometimes (new feature, security-driven
dependency upgrade). When that happens:

1. Run the commands above locally and copy the report into the PR.
2. Bump the relevant `max_binary_bytes` entry (or `MAX_CRATE_SHARE`) in
   the matrix in `.github/workflows/bloat.yml` **and** update the table
   above in the same PR. Only change the row(s) that actually regressed
   — do not raise unrelated platforms.
3. Get **two reviewer approvals** specifically acknowledging the budget
   change (a `LGTM-bloat` review tag in the PR body is the convention).
4. After merge, the new ceiling becomes the baseline for subsequent PRs.

Unauthorized bypasses (e.g. `--no-verify`, removing the workflow) are not
permitted.
