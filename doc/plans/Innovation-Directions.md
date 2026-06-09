## Innovation Directions

1.  [1. AuthN/AuthZ Model](#d1)
    - [Short-lived PoP tokens](#d1-tokens)
    - [vTPM / CVM sealing](#d1-vtpm)
    - [Measured identity](#d1-identity)
    - [Capability grants](#d1-cap)
2.  [2. Rule Engine Modernization](#d2)
3.  [3. Observability & Supply Chain](#d3)
4.  [4. eBPF / Kernel Hardening](#d4)
5.  [5. Threat Coverage Expansion](#d5)
6.  [6. Developer & Operator UX](#d6)
7.  [7. Performance & Footprint](#d7)
8.  [Cross-cutting Roadmap](#roadmap)
9.  [**★ Plans & Milestones**](Innovation-Plans-Milestones.md)

**Azure Guest Proxy Agent** · **Rust + eBPF** · **Security**

# Innovation Directions — Detailed Designs & Implementation Plans

Companion document to the repo analysis. Each direction includes goals, design, code-level touch points in the GPA codebase, an incremental implementation plan, test strategy, risks, and success metrics.

→ See also: [**Consolidated Plans & Milestones**](Innovation-Plans-Milestones.md) — cross-track schedule, dependency map, per-innovation M0–M4 milestones, RACI, risks, and program exit criteria.

**Reference areas:** `proxy_agent/src/proxy/authorization_rules.rs`, `proxy_agent/src/key_keeper/`, `proxy_agent/src/redirector/`, `proxy_agent_extension/`, `pentest/linux/`.

## 1. Strengthen the AuthN/AuthZ Model

| Impact                             | Effort           | Risk                        | Scope                    |
|------------------------------------|------------------|-----------------------------|--------------------------|
| **High** closes whole vuln classes | **Medium–Large** | **Wire-compat with fabric** | **agent + fabric coord** |

Today GPA authenticates with a long-lived HMAC key latched at provisioning time (`proxy_agent/src/key_keeper/key.rs`) and adds `x-ms-azure-signature` to every authorized request. Identity is taken from cgroup + `processFullPath` reported by eBPF audit. Four sub-initiatives raise the floor.

### 1.1 Short-lived Proof-of-Possession (PoP) tokens

[Detailed design](Innovation-1.1-pop-tokens.md)

#### Goal

- Eliminate the "steal key file → sign forever" path (pentest `B3`, `E5`).
- Bind each token to caller, destination, and time, so replay (`B2`) becomes structurally impossible.

#### Design

- Replace the single HMAC over `METHOD || URL || time-tick` with a JWS-like compact token: `header.payload.sig` where payload includes `{aud, sub (caller fingerprint), iat, exp ≤ 30s, nonce, dest_ip, url_hash}`.
- Signature stays HMAC-SHA256 initially (no fabric crypto change), but the *signed claims* shape changes, so the fabric can reject any token without an `exp`.
- Token is minted per request in `proxy_server.rs` right before forwarding; replaces direct header injection.
- Add a *session key* derived from latched key + nonce so the latched key never appears on the wire and never signs raw HTTP.

#### Code touch points

- `proxy_agent/src/key_keeper/key.rs` — add `derive_session_key(nonce) -> SessionKey`.
- `proxy_agent/src/proxy/proxy_server.rs` — replace `x-ms-azure-signature` mint path with `mint_pop_token(req, caller, dest)`.
- `proxy_agent_shared` — new module `pop_token` with serde structs + constant-time compare.
- Wire-compat shim: emit both legacy and new headers behind a feature flag `pop_v2` until fabric is ready.

#### Plan

1.  RFC + threat model doc; align with WireServer/IMDS team on header name and accepted claim set.
2.  Implement `pop_token` crate with golden-vector tests.
3.  Ship dual-emit behind config flag; telemetry-only (fabric ignores new header).
4.  Fabric flips acceptance; deprecate legacy header after one release cycle.

#### Tests

- Unit: claim canonicalization, clock-skew tolerance, constant-time verify.
- Pentest re-runs: `B2` replay must fail; `B3` stolen-key + cross-VM must still fail because `sub` binds caller identity verified by fabric+vTPM (see 1.2).
- Fuzz the token parser (`cargo-fuzz`).

#### Risks

- Clock drift; mitigate by accepting ±60s and refreshing via fabric time.
- Fabric rollout coupling; mitigate with dual-emit flag.

### 1.2 vTPM / Confidential-VM attestation binding

[Detailed design](Innovation-1.2-vtpm-sealing.md)

#### Goal

Make a stolen key file useless on another VM, and make key rollback (`E5`) cryptographically infeasible.

#### Design

- At provisioning, seal the latched key to vTPM PCRs covering: firmware, bootloader, kernel cmdline, and `azure-proxy-agent` binary measurement (IMA).
- Under CVM (SEV-SNP / TDX), include the attestation report hash. The fabric stores the bound report and only honors signatures whose KID matches.
- On unseal failure (rebooted into a tampered image), GPA enters fail-closed and requests a re-provisioning.

#### Code touch points

- New crate `proxy_agent/src/key_keeper/sealing/` with backends: `tpm2.rs` (uses `tss-esapi`), `snp.rs`, `tdx.rs`, `noop.rs`.
- `key.rs` — add `load_sealed()` / `store_sealed()` wrapping current on-disk reads.
- Provisioning flow in `provision.rs` — request fresh attestation, hand to fabric, persist sealed blob.

#### Plan

1.  Backend detection helper (probe `/dev/tpmrm0`, SEV-SNP MSRs, TDX guest module).
2.  Implement `noop` + `tpm2` backends behind feature flag; keep current plain-file path as default.
3.  Pilot in selected SKUs; collect attestation latency telemetry.
4.  Promote to default for CVM SKUs; keep plain-file as fallback for legacy SKUs.

#### Tests

- Reboot with modified kernel cmdline must produce unseal failure → fail-closed.
- Snapshot+restore of `/var/lib/azure-proxy-agent` to a different VM must fail unseal.
- Pentest `E5` rollback: re-introducing an older sealed blob fails monotonic counter check.

### 1.3 Measured caller identity (replace path-string matching)

[Detailed design](Innovation-1.3-measured-identity.md)

#### Goal

Defeat pentest scenarios `C3` (bind-mount over `/proc/self/exe`) and `D2` (symlink to allowed binary) by matching on *what the code is*, not *where it lives*.

#### Design

- Capture binary measurement in-kernel via **IMA** (`ima_file_hash()`) or **fs-verity** root hash; on Windows, use code-integrity / WDAC hash.
- Emit measurement in the eBPF audit event consumed by `redirector::lookup_audit`.
- Extend `Privilege` in `key.rs` with optional `exeHash: Option<Sha256>`; matcher prefers hash over path when present, and rejects when both diverge.

#### Code touch points

- `linux-ebpf/ebpf_cgroup.c` — augment audit map value with hash bytes.
- `proxy_agent/src/redirector/linux/` — surface hash field.
- `proxy_agent/src/proxy/authorization_rules.rs` — new matcher predicate; back-compat: if rule lacks hash, fall back to path matching.

#### Plan

1.  Add hash plumbing end-to-end, audit-only (log mismatches).
2.  Author tooling to generate hashes for allow-listed binaries (extension handlers, customer agents).
3.  Enable enforcement per rule via `enforceMeasurement: true`.

### 1.4 Capability-style scoped grants

[Detailed design](Innovation-1.4-capability-scopes.md)

#### Goal

Move from "this path is allowed for this identity" to verifiable scopes (`imds:instance:read`, `wireserver:goalstate:read`, `hostga:extensions:status:write`).

#### Design

- Introduce a Cedar/CEL-style policy compiled to an evaluation IR at rule-load time.
- Each request is mapped to a typed `Action` + `Resource` by a URL classifier (one canonical mapping table per endpoint).
- Identity carries a set of granted scopes; decision is `scopes ⊇ required(action)`.

#### Why it matters

- Enables static analysis ("does any rule grant unauthenticated WireServer write?") — see direction 2.
- Eliminates SSRF-style URL-encoding bypasses because the classifier normalizes once and operates on the typed action.

## 2. Modernize the Rule Engine

| Impact                            | Effort     | Risk               | Scope          |
|-----------------------------------|------------|--------------------|----------------|
| **High** kills SSRF-bypass family | **Medium** | **Self-contained** | **agent only** |

Current matcher: lowercased `request.path().starts_with(rule.path)` plus a query-param map (authorization_rules.rs:194, key.rs:223). This is the largest single source of latent AuthZ bypass surface.

### 2.1 Canonical request model

[Detailed design](Innovation-2.1-canonical-request.md)

- Build a single `CanonicalRequest` type produced by *one* normalizer: percent-decode → collapse `.`/`..` → strip `;params` → lowercase host → resolve numeric IP forms (decimal, hex, IPv4-mapped IPv6 — pentest `C7`).
- Use the same normalizer for rule loading and request matching — eliminates rule/request asymmetry.
- Reject requests whose normalization is ambiguous (e.g. invalid UTF-8 in path) — fail-closed.

### 2.2 Typed policy language

[Detailed design](Innovation-2.2-typed-policy-cedar.md)

- Pick one: **Cedar** (Rust-native, fast, analyzable) or **OPA/Rego** (familiar). Recommendation: **Cedar** — has a verified evaluator and supports static analysis.
- Compile JSON rules at load time into a Cedar policy set; keep a legacy adapter so existing rules continue to work.

&nbsp;

    // proxy_agent/src/proxy/policy/mod.rs
    pub struct CompiledPolicy { /* Cedar policy set + entity store */ }

    impl CompiledPolicy {
        pub fn from_legacy(rules: &AuthorizationItem) -> Result<Self> { /* ... */ }
        pub fn evaluate(&self, req: &CanonicalRequest, caller: &CallerIdentity) -> Decision { /* ... */ }
    }

### 2.3 Versioned snapshots (TOCTOU fix — pentest D5)

[Detailed design](Innovation-2.3-versioned-snapshots.md)

- Wrap the active policy in `arc_swap::ArcSwap<CompiledPolicy>`.
- Each request captures `(arc, epoch)` at accept time and uses it for the whole forwarding decision.
- Surface `policy_epoch` in the connection log.

### 2.4 Differential / property testing

[Detailed design](Innovation-2.4-differential-testing.md)

- For each rule loaded, auto-generate "evil twins": case toggles, percent-encoded slashes, trailing-slash variants, IPv6 forms, Unicode confusables.
- Run the matcher on each variant; mismatch with the original ⇒ block the rule and alert.
- Integrate into `local_rules.rs` reload path and into CI.

### Plan

1.  Introduce `CanonicalRequest` + normalizer; add property-tests (`proptest`) and run against the current matcher in shadow mode.
2.  Land Cedar compilation behind a feature flag; dual-evaluate (legacy + Cedar), log divergences.
3.  Flip enforcement to Cedar once divergence rate is zero for N days in production telemetry.
4.  Remove legacy matcher.

### Metrics

- Divergence rate (legacy vs Cedar) → must reach 0 before cutover.
- Pentest `D1`/`C7` scenarios reach 100% pass.
- Rule load time \< 50 ms for 1k rules.

## 3. Observability & Supply-Chain Trust

| Impact                        | Effort     | Risk    | Scope                      |
|-------------------------------|------------|---------|----------------------------|
| **Medium** + audit/compliance | **Medium** | **Low** | **agent + build pipeline** |

### 3.1 Hash-chained, append-only audit log

[Detailed design](Innovation-3.1-hash-chained-log.md)

- Wrap the existing connection log with a Merkle chain: `entry_n.hash = SHA256(entry_n.payload || entry_{n-1}.hash)`.
- Periodically anchor the tip to a transparency log (rekor-compatible) or to Azure Monitor as a signed sentinel.
- Closes pentest `F2` (log injection) and `F3` (rotation race) — tampering breaks the chain and is detectable.

### 3.2 OpenTelemetry export

[Detailed design](Innovation-3.2-otel-export.md)

- Emit metrics: allow/deny counts by rule id, signer latency, eBPF map occupancy, restart count.
- Emit traces for the proxy hop (accept → authz → upstream → response) with W3C trace context.
- Optional OTLP endpoint; defaults to local Prometheus exposition on a UDS only.

### 3.3 Self-attestation endpoint

[Detailed design](Innovation-3.3-self-attestation.md)

- New read-only endpoint on the local listener: `GET /.well-known/gpa/attestation`.
- Returns: agent version, binary measurement, loaded eBPF prog ids and bytecode hash, attached cgroup, active `policy_epoch`, sealed-key KID, attestation backend in use.
- Consumable by Defender for Cloud, Azure Policy, or operator scripts.

### 3.4 Supply chain

[Detailed design](Innovation-3.4-supply-chain.md)

- **SBOM**: generate CycloneDX during the cargo build (`cargo-cyclonedx`).
- **Reproducible builds**: pin `rust-toolchain.toml`, vendor deps, use `-Clink-arg=-Wl,--build-id=none`; verify via two-builder diff in CI.
- **in-toto / Sigstore**: sign release artifacts; `proxy_agent_setup` verifies signature before installing — closes pentest `H1`.

### Plan

1.  Refactor logger into a `trait Sink` with a chained-Merkle implementation.
2.  Wire OTel behind `--features otel`; default off to keep footprint.
3.  Add attestation endpoint (no secrets in payload; just measurements).
4.  Pipeline work: SBOM, reproducible build, Sigstore signing, verification in setup binary.

## 4. eBPF / Kernel Hardening

| Impact                           | Effort     | Risk                      | Scope                       |
|----------------------------------|------------|---------------------------|-----------------------------|
| **High** kernel-layer chokepoint | **Medium** | **Kernel-version matrix** | **linux-ebpf + redirector** |

### 4.1 Move from cgroup/`connect4` to `bpf_lsm` + `sk_lookup`

[Detailed design](Innovation-4.1-sk-lookup-bpf-lsm.md)

- `sk_lookup` redirects on the listening side; the original destination IP is preserved (no SNAT-to-localhost), so we can match on real destination after netns shenanigans (pentest `C5`, `C6`).
- `bpf_lsm` hooks (`socket_connect`) provide a deny path even when a hostile program tries to construct sockets in alternate namespaces.
- Fallback to existing cgroup hook for kernels \< 5.13 (no `sk_lookup`).

### 4.2 Unify Linux + Windows eBPF on CO-RE

[Detailed design](Innovation-4.2-core-unify-ebpf.md)

- Today: separate sources in `ebpf/` (Windows) and `linux-ebpf/` (Linux).
- Adopt libbpf-rs with CO-RE relocations; share the audit-event struct via a common header.
- Ship a single BTF-portable object per platform; drop kernel-version-specific builds.

### 4.3 IPv6 / dual-stack

[Detailed design](Innovation-4.3-ipv6-dual-stack.md)

- Add v6 redirect for IMDS/WireServer link-local equivalents.
- Normalize address family at the audit-event boundary so the rule engine sees a unified `Destination` enum, not raw bytes.

### 4.4 Kernel-side throttling and audit-map LRU

[Detailed design](Innovation-4.4-ebpf-throttling-lru.md)

- Replace the audit hash map with `BPF_MAP_TYPE_LRU_HASH` sized by cgroup count (pentest `G3`).
- Add a token bucket per cgroup in BPF; over-rate connections get an early reject before reaching user space (mitigates `G1`).

### Code touch points

- `linux-ebpf/ebpf_cgroup.c` → split into `cgroup_connect.bpf.c`, `sk_lookup.bpf.c`, `lsm.bpf.c`.
- `proxy_agent/src/redirector/linux/` → loader picks the best available program set.
- Build system: introduce `build.rs` step invoking `clang -target bpf` with BTF.

### Plan

1.  Add CO-RE build, keep behavior identical (no semantic change).
2.  Land `sk_lookup` as optional, gated by kernel probe; A/B in pentest harness.
3.  Add `bpf_lsm` deny hook; verify with `C5`/`C6` scenarios.
4.  Switch audit map to LRU and add token bucket; verify with `G1`/`G3`.
5.  IPv6 path last (depends on fabric v6 readiness).

## 5. Expand the Threat Coverage

| Impact                       | Effort    | Risk                        | Scope                 |
|------------------------------|-----------|-----------------------------|-----------------------|
| **High** new product surface | **Large** | **Cross-team coordination** | **agent + ecosystem** |

### 5.1 Container-native / AKS mode

[Detailed design](Innovation-5.1-aks-container-native.md)

#### Problem

On AKS nodes, any pod with hostNetwork or a permissive NetworkPolicy can reach node IMDS and steal the node managed identity. This is the well-known "pod-steals-node-credentials" class. GPA already runs as the IMDS chokepoint — the missing piece is *per-pod identity*.

#### Design

- Map cgroup id (already captured by eBPF audit) → Kubernetes pod via the kubelet pod-resources API or by reading `/proc/<pid>/cgroup` + the CRI socket.
- Project pod ServiceAccount → SPIFFE ID; use Azure Workload Identity federation to mint a pod-scoped token instead of handing back the node MI token.
- Rule shape: `{ namespace: "app-*", serviceAccount: "billing", allow: ["imds:identity:read"] }`.

#### Plan

1.  Ship a `--mode kubernetes` flag and a sidecar/DaemonSet manifest.
2.  Integrate with Azure Workload Identity issuer; reuse OIDC trust to AKS cluster.
3.  Pilot on internal clusters; publish reference NetworkPolicy that forces all IMDS traffic through GPA.

### 5.2 Gate other cloud endpoints

[Detailed design](Innovation-5.2-gate-more-endpoints.md)

- Generalize destination handling so KeyVault MSI, ARM token endpoint, and Storage MI flows can be authorized through the same rule engine.
- Add pluggable *destination drivers* with: address set, request classifier (URL → typed action), signer.
- Customer-visible: one rule language to govern all cloud-credential egress.

### 5.3 Cross-cloud port

[Detailed design](Innovation-5.3-cross-cloud-port.md)

- Architecture (cgroup eBPF + identity-aware proxy) is cloud-neutral. The signer and destination set are Azure-specific.
- Factor `signer` and `destinations` into traits; ship community drivers for AWS IMDSv2 and GCP metadata.
- Positioning: *a metadata firewall for any cloud*.

## 6. Developer & Operator Experience

| Impact                                  | Effort           | Risk    | Scope       |
|-----------------------------------------|------------------|---------|-------------|
| **Medium** adoption + incident response | **Small–Medium** | **Low** | **tooling** |

### 6.1 Policy simulator / dry-run

[Detailed design](Innovation-6.1-policy-simulator.md)

- CLI: `gpa policy simulate --rules rules.json --request 'GET http://169.254.169.254/metadata/identity?api-version=2021-08-01' --caller pid=1234`
- Output: decision, which rule matched, canonicalization steps applied, divergence vs current production rules.
- Library-mode for unit tests so customers can lock down expected behavior.

### 6.2 `gpa-doctor`

[Detailed design](Innovation-6.2-gpa-doctor.md)

- One command runs hardening checks derived from `pentest/linux/`: port exposure (A1), file modes (E1), restart safety (E4), orphan eBPF programs (G4), rule loader sanity (D4).
- Green/yellow/red report + remediation links; safe to run on production VMs.

### 6.3 Rule authoring UX

[Detailed design](Innovation-6.3-rule-authoring-ux.md)

- JSON Schema for the rules file; ship in repo.
- VS Code extension providing schema-driven autocomplete, live validation, and a "rule diff" view for remote vs `local_rules.rs` overrides.
- Portal-side experience reuses the same schema.

### 6.4 WASM rule sandbox (optional)

[Detailed design](Innovation-6.4-wasm-rule-sandbox.md)

- Allow customer-supplied AuthZ in WebAssembly with a tightly scoped host ABI (read normalized request, read claims, return decision; no syscalls, no clocks).
- Useful for advanced customers needing logic that doesn't fit a declarative rule.
- Guardrails: hard CPU/memory limits per invocation; disabled by default.

## 7. Performance & Footprint

| Impact                    | Effort     | Risk    | Scope          |
|---------------------------|------------|---------|----------------|
| **Medium** latency + cost | **Medium** | **Low** | **agent only** |

### 7.1 io_uring hot path

[Detailed design](Innovation-7.1-io-uring-hot-path.md)

- Behind feature flag, replace tokio-default reactor for the listener with `tokio-uring` or `monoio`.
- Targets the IMDS read path (the most frequent request shape).

### 7.2 Zero-copy forwarding

[Detailed design](Innovation-7.2-zero-copy-splice.md)

- After AuthN/AuthZ pass, splice the body between accept socket and upstream socket using `splice(2)` when the request has no body transformation.
- Avoids two user-space copies on the common GET path.

### 7.3 Crate consolidation — ✅ done

[Detailed design](Innovation-7.3-crate-consolidation.md)

- Today: `proxy_agent`, `proxy_agent_extension`, `proxy_agent_setup`, `proxy_agent_shared`.
- Move duplicated helpers (logging, config loading, version probing) into `proxy_agent_shared`.
- Build with musl for a single static binary per role; run `cargo-bloat` in CI with a budget.

**Status: done.** Logger setup and the GPA service-name constants have moved into `proxy_agent_shared` (PR 353), removing ~60 lines of boilerplate from the three binaries. The OS/version probe and the HTTP client already live in `proxy_agent_shared`; the JSON config loader is intentionally not moved — only `proxy_agent` reads a JSON config (the extension is driven by HandlerEnvironment / sequence files, and the setup tool has no runtime config), so there is no second copy to consolidate. The musl static-binary builds for both `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl` are already produced by `build-linux.sh` from the shared `reusable-build.yml` workflow (Windows MSVC builds go through `build.cmd` in the same file). On top of those, the `cargo-bloat` regression gate is now live in CI as a per-(target, role) matrix with absolute + per-crate-share ceilings (PR 352, see [`ci/README.md`](../../ci/README.md)). A new opt-in `signing` Cargo feature on `proxy_agent_shared` lets `proxy_agent_setup` and `ProxyAgentExt` drop the vendored OpenSSL dep entirely.

### Metrics

- p99 added latency per IMDS request ≤ 1 ms (target).
- RSS at idle ≤ 20 MB (target).
- Binary size ≤ 8 MB stripped (target).

## ★. Cross-Cutting Roadmap

| Phase                     | Focus                                  | Items                                                                                                                   | Exit criteria                                                    |
|---------------------------|----------------------------------------|-------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------|
| P1 — Foundations          | Safe refactors, no behavior change     | 2.1 canonicalizer (shadow), 2.3 ArcSwap epochs, 3.2 OTel skeleton, 7.3 crate consolidation, 4.2 CO-RE build             | Zero shadow-mode divergence; CI green on all targets             |
| P2 — Hardening            | Close pentest-known gaps               | 2.2 Cedar dual-eval, 4.1 sk_lookup + bpf_lsm, 4.4 LRU + token bucket, 3.1 hash-chained log, 3.4 Sigstore-verified setup | Pentest categories C5–C7, D1, D4–D5, F2–F3, G1, G3, H1 all PASS  |
| P3 — Identity step-change | Defeat key-theft and identity spoofing | 1.1 PoP tokens (dual-emit), 1.2 vTPM/CVM sealing, 1.3 measured identity                                                 | Fabric accepts PoP; CVM SKUs default to sealed keys              |
| P4 — Surface expansion    | New customers, new endpoints           | 1.4 capability scopes, 5.1 AKS mode, 5.2 more endpoints, 6.1 simulator, 6.2 `gpa-doctor`, 6.3 schema/VS Code            | Pilot AKS customer; first non-IMDS endpoint governed by GPA      |
| P5 — Reach                | Ecosystem & perf polish                | 5.3 cross-cloud drivers, 6.4 WASM sandbox, 7.1 io_uring, 7.2 splice                                                     | Latency & size budgets met; community-maintained AWS/GCP drivers |

**Suggested first PR sequence**

1.  Introduce `CanonicalRequest` + property tests in shadow mode (direction 2.1).
2.  Wrap policy in `ArcSwap` with per-request epoch logging (direction 2.3).
3.  Add CO-RE build for the eBPF objects without behavior change (direction 4.2).
4.  Add hash-chained log sink behind a feature flag (direction 3.1).
5.  Begin Cedar policy compilation in dual-evaluation mode (direction 2.2).

These five are low-risk, independently shippable, and unlock most of the later work.

**Coordination required**

- Direction 1.1 (PoP tokens) and 1.2 (vTPM sealing) require WireServer/IMDS fabric-side acceptance changes.
- Direction 5.1 (AKS mode) requires alignment with Azure Workload Identity team.
- Direction 4.1 needs a kernel-version matrix decision (CO-RE fallback path).

Generated companion to the GPA repo analysis. Cross-references: `proxy_agent/src/proxy/authorization_rules.rs`, `proxy_agent/src/key_keeper/key.rs`, `proxy_agent/src/redirector/`, `pentest/linux/DESIGN.md`.
