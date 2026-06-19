## Sections

1.  [1. Overview](#overview)
2.  [2. Phases & KPIs](#phases)
3.  [3. 12-Quarter Roadmap](#roadmap)
4.  [4. Dependency Map](#deps)
5.  [5. Per-Innovation Milestones](#milestones)
    - [D1 — AuthN/AuthZ](#d1-plans)
    - [D2 — Rule Engine](#d2-plans)
    - [D3 — Observability & Supply Chain](#d3-plans)
    - [D4 — eBPF / Kernel](#d4-plans)
    - [D5 — Threat Coverage](#d5-plans)
    - [D6 — Dev/Operator UX](#d6-plans)
    - [D7 — Performance](#d7-plans)
6.  [6. RACI / Coordination](#raci)
7.  [7. Risk Register](#risks)
8.  [8. Program Exit Criteria](#exit)

**GPA** · **Program Plan** · **P1 → P5** · **~12 quarters**

# Innovation Program — Consolidated Plans & Milestones

One operational view across all 25 innovations: phase placement, dependencies, per-track milestones (M0–M4), exit gates, owners, and risks. Each detailed design page remains the source of truth for its own scope; this page is the scheduling and coordination contract.

**Conventions:** milestone numbering is uniform — `M0` design lock, `M1` prototype/shadow, `M2` dual-mode behind flag, `M3` default-on for target SKU, `M4` legacy removed. Week numbers (`W1..W48`) are relative to program start; quarters Q1–Q12 mirror the swimlane.

## 1. Program Overview

The roadmap groups the 25 innovations into five sequenced phases that respect prerequisite chains and the cross-team coupling already called out in [Innovation Directions § Roadmap](Innovation-Directions.md#roadmap). Each phase ends with a quantitative gate; later phases cannot start their *default-on* step until earlier phases reach `M3` on the same SKU class.

| Innovations | Directions | Phases (P1–P5) | Quarters end-to-end |
|-------------|------------|----------------|---------------------|
| **25**      | **7**      | **5**          | **≈12**             |

## 2. Phases & KPIs

| Phase                         | Window  | Theme                               | Items                             | Phase exit KPI                                                                                         |
|-------------------------------|---------|-------------------------------------|-----------------------------------|--------------------------------------------------------------------------------------------------------|
| **P1 — Foundations**          | Q1–Q3   | Safe refactors, no behavior change  | 2.1, 2.3, 2.4, 3.2, 4.2, 7.3      | Zero shadow-mode divergence across 7 days of prod traffic; CI green on win+linux; binary ≤ 8 MB        |
| **P2 — Hardening**            | Q3–Q6   | Close pentest-known gaps            | 2.2, 3.1, 3.3, 3.4, 4.1, 4.3, 4.4 | Pentest categories C5–C7, D1, D4–D5, F2–F3, G1, G3, H1 → 100% PASS in CI harness                       |
| **P3 — Identity step-change** | Q5–Q9   | Defeat key-theft and identity spoof | 1.1, 1.2, 1.3                     | Fabric accepts PoP-v2 in 100% of regions; CVM SKUs default to sealed keys; pentest B2/B3/C3/D2/E5 PASS |
| **P4 — Surface expansion**    | Q7–Q11  | New customers, new endpoints        | 1.4, 5.1, 5.2, 6.1, 6.2, 6.3      | ≥ 1 AKS pilot in prod; ≥ 1 non-IMDS endpoint governed; `gpa-doctor` shipped in agent package           |
| **P5 — Reach**                | Q10–Q12 | Ecosystem & perf polish             | 5.3, 6.4, 7.1, 7.2                | p99 added latency ≤ 1 ms; RSS ≤ 20 MB idle; community drivers building in CI                           |

## 3. 12-Quarter Swimlane

| Track | Q1 | Q2 | Q3 | Q4 | Q5 | Q6 | Q7 | Q8 | Q9 | Q10 | Q11 | Q12 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **D1 AuthN/Z** | — | — | — | — | 1.2 M0–M1 | 1.1 M0–M1 | 1.1 M2 | 1.2 M2 | 1.3 M2 | 1.4 M1 | 1.4 M2 | _M3/4_ |
| **D2 Rules** | 2.1 M1 | 2.3 M2 | 2.4 M2 | 2.2 M1 | 2.2 M2 | 2.2 M3 | _M4 remove_ | — | — | — | — | — |
| **D3 Obs/SC** | — | 3.2 M1 | 3.2 M2 | 3.1 M1 | 3.4 M2 | 3.3 M2 | 3.1 M3 | _M4_ | — | — | — | — |
| **D4 eBPF** | — | 4.2 M1 | 4.2 M2 | 4.1 M1 | 4.4 M2 | 4.1 M2 | 4.3 M2 | 4.1 M3 | — | — | — | — |
| **D5 Threats** | — | — | — | — | — | — | 5.1 M1 | 5.2 M1 | 5.1 M2 | 5.2 M2 | 5.3 M1 | 5.3 M2 |
| **D6 UX** | — | — | 6.3 M1 | — | — | — | 6.1 M2 | 6.2 M2 | 6.3 M2 | 6.4 M1 | 6.4 M2 | — |
| **D7 Perf** | 7.3 M1 | 7.3 M2 | — | — | — | — | — | — | — | 7.1 M2 | 7.2 M2 | _tune_ |

Legend: **P1** Foundations · **P2** Hardening · **P3** Identity · **P4** Surface · **P5** Reach.
Milestones — `M0` design lock · `M1` prototype/shadow · `M2` dual-mode behind flag · `M3` default-on · `M4` legacy removed.

Bars use uniform milestone names: `M0` design lock · `M1` prototype/shadow · `M2` dual-mode behind flag · `M3` default-on · `M4` legacy removed. Cells without a bar are intentionally idle for that track that quarter; idle quarters are buffer for risk.

## 4. Dependency Map

Hard prerequisites (must reach `M2` on the upstream item before the downstream item can begin `M1`):

- **1.1 PoP tokens** ← 2.1 CanonicalRequest (`url_hash` uses canonical form)
- **1.2 vTPM sealing** ← 3.3 Self-attestation (KID surfaced for fabric pinning)
- **1.3 Measured identity** ← 4.2 CO-RE eBPF (audit event carries hash bytes)
- **1.4 Capability scopes** ← 2.2 Cedar (scopes encoded as Cedar actions)
- **2.2 Cedar** ← 2.1 CanonicalRequest + 2.3 ArcSwap
- **2.4 Diff testing** ← 2.1 CanonicalRequest
- **3.1 Hash-chained log** ← 3.2 OTel skeleton (shared sink trait)
- **3.3 Self-attestation** ← 4.2 CO-RE (prog id + bytecode hash exposure)
- **3.4 Supply chain** ← 7.3 Crate consolidation (single artifact to sign)
- **4.1 sk_lookup + bpf_lsm** ← 4.2 CO-RE
- **4.3 IPv6 dual-stack** ← 4.1 (unified destination enum)
- **4.4 LRU + throttling** ← 4.2 CO-RE
- **5.1 AKS mode** ← 1.4 Capability scopes + 4.2 CO-RE
- **5.2 More endpoints** ← 2.2 Cedar + 1.4 scopes
- **5.3 Cross-cloud** ← 5.2 (destination driver trait)
- **6.1 Simulator** ← 2.1 + 2.2 (uses compiled policy in library mode)
- **6.2 gpa-doctor** ← 3.3 Self-attestation
- **6.3 Authoring UX** ← 2.2 (schema generated from Cedar)
- **6.4 WASM sandbox** ← 2.2 + 6.1
- **7.1 io_uring** ← 7.3 Crate consolidation
- **7.2 splice forwarding** ← 1.1 (decision before splice means token mint stays in user-space)

## 5. Per-Innovation Milestones

Each entry below uses the same template: `M0 design lock` · `M1 prototype/shadow` · `M2 dual-mode behind flag` · `M3 default-on` · `M4 legacy removed`. Week numbers are relative to program start.

### Direction 1 — AuthN/AuthZ Model

#### 1.1 Short-lived PoP tokens — [design](Innovation-1.1-pop-tokens.md)

##### Deliverables

- `proxy_agent_shared/src/pop_token/` module with serde + constant-time verify
- `derive_session_key()` in `key_keeper/key.rs`
- Dual-emit behind `--feature pop_v2` in `proxy_server.rs`
- Fabric-side acceptance change (WireServer/IMDS)

##### Milestones

| Milestone | Week | Description                                                       | Exit criteria                             |
|-----------|------|-------------------------------------------------------------------|-------------------------------------------|
| M0        | W17  | RFC + threat-model signed off with fabric team                    | Header name + claim set frozen            |
| M1        | W20  | pop_token crate + golden vectors; agent mints into local log only | Fuzz 60 min clean                         |
| M2        | W26  | Dual-emit in production; fabric ignores, telemetry tracks parity  | ≥ 99.99% mint success; clock-skew \< 0.1% |
| M3        | W34  | Fabric flips acceptance; legacy header kept for 1 release         | B2 replay pentest FAIL ⇒ blocked          |
| M4        | W42  | Legacy `x-ms-azure-signature` removed                             | 0 legacy headers in 14-day telemetry      |

#### 1.2 vTPM / CVM sealing — [design](Innovation-1.2-vtpm-sealing.md)

##### Deliverables

- `key_keeper/sealing/` with backends `noop`, `tpm2`, `snp`, `tdx`
- `load_sealed()` / `store_sealed()` in `key.rs`
- Backend probe in `provision.rs`; fail-closed on unseal failure

##### Milestones

| Milestone | Week | Description                                            | Exit criteria                         |
|-----------|------|--------------------------------------------------------|---------------------------------------|
| M0        | W14  | PCR set + monotonic-counter design                     | Sec review pass                       |
| M1        | W22  | tpm2 backend on a single SKU; noop fallback            | Reboot survives; unseal \< 200 ms p99 |
| M2        | W30  | Pilot CVM SKUs (SEV-SNP first), feature-flagged        | E5 rollback pentest blocked           |
| M3        | W36  | Default-on for CVM SKUs; legacy plain-file for non-CVM | Snapshot-restore-other-VM FAIL        |
| M4        | W48  | Plain-file path deleted on CVM build                   | 0 plain-file reads in CVM telemetry   |

#### 1.3 Measured caller identity — [design](Innovation-1.3-measured-identity.md)

##### Deliverables

- Augment audit map value in `linux-ebpf/ebpf_cgroup.c` with IMA / fs-verity hash
- Surface `exeHash` in `redirector::lookup_audit`
- `enforceMeasurement` matcher in `authorization_rules.rs`
- Hash-generation CLI for allow-listed binaries

##### Milestones

| Milestone | Week | Description                                                     | Exit criteria                  |
|-----------|------|-----------------------------------------------------------------|--------------------------------|
| M0        | W26  | Choose IMA vs fs-verity per distro; pick Windows CI hash source | Spec lock                      |
| M1        | W30  | End-to-end hash plumbing, audit-only logging                    | Mismatch rate observable       |
| M2        | W36  | Per-rule `enforceMeasurement` opt-in                            | C3 + D2 pentest FAIL ⇒ blocked |
| M3        | W44  | Default-on for fabric-shipped extension handlers                | No false-positives in 14 days  |

#### 1.4 Capability-style scoped grants — [design](Innovation-1.4-capability-scopes.md)

##### Deliverables

- URL classifier (one canonical action/resource table per endpoint)
- Scope type carried in `CallerIdentity`
- Cedar action set generated from classifier

##### Milestones

| Milestone | Week | Description                                                       | Exit criteria                 |
|-----------|------|-------------------------------------------------------------------|-------------------------------|
| M0        | W30  | Classifier table reviewed with IMDS + WireServer owners           | Action set frozen v1          |
| M1        | W34  | Library mode + simulator integration (6.1)                        | All current rules round-trip  |
| M2        | W40  | Scoped grants accepted in rules, dual-evaluated with path matcher | 0 divergences for 7 days      |
| M3        | W46  | Path matcher disabled for scoped rules                            | Encoding-bypass class blocked |

### Direction 2 — Rule Engine Modernization

#### 2.1 CanonicalRequest — [design](Innovation-2.1-canonical-request.md)

##### Deliverables

- Single normalizer module used by rule loader and request path
- `proptest` suite (case, %-encoding, dots, IPv4/IPv6, Unicode confusables)
- Shadow comparison harness in `proxy_server.rs`

##### Milestones

| Milestone | Week | Description                                              | Exit criteria                    |
|-----------|------|----------------------------------------------------------|----------------------------------|
| M0        | W1   | Normalizer spec frozen with fail-closed cases enumerated | Sec review pass                  |
| M1        | W3   | Normalizer + property tests; shadow log in prod          | ≥ 99.9% match with legacy        |
| M2        | W8   | Used by Cedar evaluator (2.2)                            | 0 ambiguous requests in 7 days   |
| M3        | W14  | Legacy normalizer paths removed                          | CI green; one normalizer in tree |

#### 2.2 Typed policy (Cedar) — [design](Innovation-2.2-typed-policy-cedar.md)

##### Milestones

| Milestone | Week | Description                                           | Exit criteria                       |
|-----------|------|-------------------------------------------------------|-------------------------------------|
| M0        | W8   | Cedar adopted; legacy adapter spec                    | Policy-set schema v1                |
| M1        | W12  | Compile-on-load + dual-eval shadow                    | Rule load ≤ 50 ms / 1k rules        |
| M2        | W18  | Enforcement gated by config flag                      | Divergence = 0 for 7 prod days      |
| M3        | W22  | Cedar is default; legacy adapter still loads old JSON | D1 / C7 pentest 100% PASS           |
| M4        | W28  | Legacy matcher code removed                           | No `starts_with` on path in matcher |

#### 2.3 Versioned snapshots (ArcSwap) — [design](Innovation-2.3-versioned-snapshots.md)

##### Milestones

| Milestone | Week | Description                                           | Exit criteria                    |
|-----------|------|-------------------------------------------------------|----------------------------------|
| M1        | W4   | `ArcSwap<CompiledPolicy>`, epoch captured per request | D5 TOCTOU pentest FAIL ⇒ blocked |
| M2        | W6   | `policy_epoch` in connection log + OTel metric        | Reload latency \< 5 ms p99       |

#### 2.4 Differential / property testing — [design](Innovation-2.4-differential-testing.md)

##### Milestones

| Milestone | Week | Description                            | Exit criteria                       |
|-----------|------|----------------------------------------|-------------------------------------|
| M1        | W6   | Evil-twin generator + CI gate          | 100 variants/rule, 0 false-mismatch |
| M2        | W9   | Plug into `local_rules.rs` reload path | Bad rule = reject + telemetry alert |

### Direction 3 — Observability & Supply Chain

#### 3.1 Hash-chained audit log — [design](Innovation-3.1-hash-chained-log.md)

##### Milestones

| Milestone | Week | Description                                | Exit criteria                    |
|-----------|------|--------------------------------------------|----------------------------------|
| M0        | W10  | Sink trait + Merkle chain spec             | Recovery from torn write defined |
| M1        | W14  | Chain implementation; tip anchored locally | Tamper detect 100%               |
| M2        | W18  | Rekor / Monitor sentinel publisher         | F2 + F3 pentest blocked          |
| M3        | W26  | Default sink on all SKUs                   | \< 2% log throughput overhead    |

#### 3.2 OpenTelemetry export — [design](Innovation-3.2-otel-export.md)

##### Milestones

| Milestone | Week | Description                               | Exit criteria                     |
|-----------|------|-------------------------------------------|-----------------------------------|
| M1        | W5   | Metrics skeleton on UDS (Prom exposition) | No new heap on hot path           |
| M2        | W9   | OTLP exporter behind `--features otel`    | Trace W3C ctx propagates upstream |

#### 3.3 Self-attestation endpoint — [design](Innovation-3.3-self-attestation.md)

##### Milestones

| Milestone | Week | Description                             | Exit criteria           |
|-----------|------|-----------------------------------------|-------------------------|
| M0        | W14  | Payload schema, no-secret contract      | Sec review pass         |
| M2        | W22  | Endpoint live, consumed by `gpa-doctor` | Defender pulls in pilot |

#### 3.4 Supply chain (SBOM + repro + Sigstore) — [design](Innovation-3.4-supply-chain.md)

##### Milestones

| Milestone | Week | Description                                                   | Exit criteria                   |
|-----------|------|---------------------------------------------------------------|---------------------------------|
| M1        | W14  | CycloneDX SBOM emitted; reproducible flags set                | Two-builder diff bit-identical  |
| M2        | W20  | Sigstore signing; `proxy_agent_setup` verifies before install | H1 supply-chain pentest blocked |

### Direction 4 — eBPF / Kernel Hardening

#### 4.1 sk_lookup + bpf_lsm — [design](Innovation-4.1-sk-lookup-bpf-lsm.md)

##### Milestones

| Milestone | Week | Description                           | Exit criteria                  |
|-----------|------|---------------------------------------|--------------------------------|
| M0        | W14  | Kernel-version matrix + fallback plan | Min kernel set frozen          |
| M1        | W18  | sk_lookup probe + gated load          | A/B match cgroup-connect path  |
| M2        | W24  | bpf_lsm deny hook                     | C5 + C6 pentest FAIL ⇒ blocked |
| M3        | W30  | Default-on for supported kernels      | No regression vs cgroup-only   |

#### 4.2 CO-RE unification — [design](Innovation-4.2-core-unify-ebpf.md)

##### Milestones

| Milestone | Week | Description                                        | Exit criteria               |
|-----------|------|----------------------------------------------------|-----------------------------|
| M1        | W5   | libbpf-rs build, shared header, no behavior change | All current tests pass      |
| M2        | W9   | Single BTF-portable object per platform            | Loads on 3+ kernel versions |

#### 4.3 IPv6 / dual-stack — [design](Innovation-4.3-ipv6-dual-stack.md)

##### Milestones

| Milestone | Week | Description                                            | Exit criteria        |
|-----------|------|--------------------------------------------------------|----------------------|
| M1        | W22  | Unified `Destination` enum in user-space               | v4 path unaffected   |
| M2        | W26  | v6 redirect for IMDS/WireServer link-local equivalents | Fabric v6 acceptance |

#### 4.4 LRU + throttling — [design](Innovation-4.4-ebpf-throttling-lru.md)

##### Milestones

| Milestone | Week | Description                  | Exit criteria      |
|-----------|------|------------------------------|--------------------|
| M1        | W18  | `BPF_MAP_TYPE_LRU_HASH` swap | G3 pentest blocked |
| M2        | W22  | Per-cgroup token bucket      | G1 pentest blocked |

### Direction 5 — Threat Coverage Expansion

#### 5.1 AKS / container-native — [design](Innovation-5.1-aks-container-native.md)

##### Milestones

| Milestone | Week | Description                                                   | Exit criteria                      |
|-----------|------|---------------------------------------------------------------|------------------------------------|
| M0        | W26  | Alignment with Azure Workload Identity team                   | OIDC trust path agreed             |
| M1        | W34  | `--mode kubernetes` DaemonSet manifest, cgroup→pod resolution | SPIFFE ID minted per pod           |
| M2        | W40  | Pilot on internal AKS cluster                                 | Pod-steals-node-cred class blocked |

#### 5.2 Gate more endpoints — [design](Innovation-5.2-gate-more-endpoints.md)

##### Milestones

| Milestone | Week | Description                                    | Exit criteria                     |
|-----------|------|------------------------------------------------|-----------------------------------|
| M1        | W34  | Destination-driver trait + KeyVault MSI driver | Same rule lang governs both       |
| M2        | W42  | ARM token + Storage MI drivers                 | ≥ 1 customer enabling beyond IMDS |

#### 5.3 Cross-cloud port — [design](Innovation-5.3-cross-cloud-port.md)

##### Milestones

| Milestone | Week | Description                                      | Exit criteria                    |
|-----------|------|--------------------------------------------------|----------------------------------|
| M1        | W42  | Signer + destination traits factored             | AWS IMDSv2 driver compiles in CI |
| M2        | W46  | GCP metadata driver; positioned as cloud-neutral | External contributor PR landed   |

### Direction 6 — Developer & Operator UX

#### 6.1 Policy simulator — [design](Innovation-6.1-policy-simulator.md)

##### Milestones

| Milestone | Week | Description                              | Exit criteria             |
|-----------|------|------------------------------------------|---------------------------|
| M1        | W30  | `gpa policy simulate` CLI + library mode | Reproduces prod decisions |
| M2        | W34  | Diff vs production rules; CI helper      | Used by ≥ 1 customer test |

#### 6.2 gpa-doctor — [design](Innovation-6.2-gpa-doctor.md)

##### Milestones

| Milestone | Week | Description                       | Exit criteria                            |
|-----------|------|-----------------------------------|------------------------------------------|
| M1        | W32  | Checks A1/E1/E4/G4/D4 implemented | Green-yellow-red report                  |
| M2        | W38  | Shipped in agent package          | Safe on prod; no privileged side-effects |

#### 6.3 Rule authoring UX — [design](Innovation-6.3-rule-authoring-ux.md)

##### Milestones

| Milestone | Week | Description                        | Exit criteria            |
|-----------|------|------------------------------------|--------------------------|
| M1        | W9   | JSON Schema in repo                | Portal reuses schema     |
| M2        | W40  | VS Code extension + rule-diff view | Marketplace listing live |

#### 6.4 WASM rule sandbox — [design](Innovation-6.4-wasm-rule-sandbox.md)

##### Milestones

| Milestone | Week | Description                             | Exit criteria             |
|-----------|------|-----------------------------------------|---------------------------|
| M1        | W42  | Tightly scoped host ABI, wasmtime embed | CPU/mem caps enforced     |
| M2        | W46  | Opt-in for one preview customer         | No syscall escape in fuzz |

### Direction 7 — Performance & Footprint

#### 7.1 io_uring hot path — [design](Innovation-7.1-io-uring-hot-path.md)

##### Milestones

| Milestone | Week | Description                                    | Exit criteria              |
|-----------|------|------------------------------------------------|----------------------------|
| M1        | W40  | `tokio-uring` behind feature flag for listener | Bench shows ≥ 20% p99 win  |
| M2        | W44  | Default-on for Linux ≥ 5.15                    | No regression on small VMs |

#### 7.2 Zero-copy splice — [design](Innovation-7.2-zero-copy-splice.md)

##### Milestones

| Milestone | Week | Description                                      | Exit criteria                |
|-----------|------|--------------------------------------------------|------------------------------|
| M1        | W42  | Splice path for body-unchanged GET               | 2 fewer copies on perf trace |
| M2        | W46  | Default-on; fallback for HTTPS-terminating paths | p99 added latency ≤ 1 ms     |

#### 7.3 Crate consolidation — [design](Innovation-7.3-crate-consolidation.md)

##### Milestones

| Milestone | Week | Description                                            | Exit criteria                      |
|-----------|------|--------------------------------------------------------|------------------------------------|
| M1        | W2   | Shared helpers moved to `proxy_agent_shared`           | No duplicated logger / config code |
| M2        | W6   | musl static build per role; `cargo-bloat` budget in CI | Binary ≤ 8 MB stripped             |

## 6. RACI & Coordination

| Item                    | Owner (R)   | Approver (A) | Consulted (C)         | Informed (I)       |
|-------------------------|-------------|--------------|-----------------------|--------------------|
| 1.1 PoP tokens          | GPA core    | GPA TL       | WireServer, IMDS      | Defender, AzPolicy |
| 1.2 vTPM sealing        | GPA core    | GPA TL       | CVM team, Host OS     | Compliance         |
| 1.3 Measured identity   | GPA core    | GPA TL       | Linux IMA, Windows CI | Extension teams    |
| 1.4 Capability scopes   | GPA core    | Security PM  | IMDS, WireServer      | Customers          |
| 2.x Rule engine         | GPA core    | GPA TL       | Cedar SIG             | Portal             |
| 3.1 Hash-chained log    | GPA core    | Sec review   | Rekor / Sigstore      | Compliance         |
| 3.4 Supply chain        | Build owner | Sec review   | 1ES pipelines         | Release mgmt       |
| 4.1 sk_lookup / bpf_lsm | Kernel SIG  | GPA TL       | Distro vendors        | Customers          |
| 5.1 AKS mode            | GPA core    | AKS PM       | Workload Identity     | Customers          |
| 5.3 Cross-cloud         | Community   | GPA TL       | —                     | External           |
| 7.x Performance         | GPA core    | GPA TL       | —                     | Customers          |

## 7. Risk Register

| \#  | Risk                                                 | Phase | Severity | Mitigation                                                                 |
|-----|------------------------------------------------------|-------|----------|----------------------------------------------------------------------------|
| R1  | Fabric acceptance of PoP-v2 slips a quarter          | P3    | High     | Dual-emit indefinitely; legacy header gated by remote feature switch       |
| R2  | CO-RE breaks on a niche kernel                       | P1/P2 | Med      | Keep classic-BPF path; runtime probe + automatic fallback                  |
| R3  | Cedar evaluator divergence non-zero at cutover       | P2    | Med      | Hold M3; auto-revert to legacy via ArcSwap epoch                           |
| R4  | vTPM unavailable on legacy SKUs                      | P3    | Med      | noop backend remains supported; sealing is opt-in by SKU class             |
| R5  | AKS pod-resources API instability                    | P4    | Low      | Fall back to CRI socket; pin tested k8s versions                           |
| R6  | splice(2) path mis-applied to body-rewriting request | P5    | Med      | Strict precondition matrix + property test; default off until matrix green |
| R7  | Sigstore outage blocks installs                      | P2    | Low      | Cache signed bundle locally; verify-or-warn during outage window           |
| R8  | WASM rule escape                                     | P5    | High     | Default-off; hard limits; opt-in single customer; differential fuzz        |

## 8. Program Exit Criteria

**The program is "done" when all of the following hold simultaneously:**

1.  Every pentest scenario currently tracked in `pentest/linux/DESIGN.md` reports PASS in CI for two consecutive releases.
2.  Fabric (WireServer + IMDS) accepts only PoP-v2 tokens; legacy signature path removed from agent.
3.  Cedar is the sole authorization evaluator; legacy `starts_with` matcher deleted.
4.  CO-RE eBPF objects load on all supported kernels; `sk_lookup` + `bpf_lsm` default-on for kernel ≥ 5.13.
5.  Default-on hash-chained audit log + Sigstore-verified installer on all SKUs.
6.  ≥ 1 AKS production customer; ≥ 1 non-IMDS endpoint governed; `gpa-doctor` shipped.
7.  Performance budgets met: p99 added latency ≤ 1 ms, RSS ≤ 20 MB idle, stripped binary ≤ 8 MB.
8.  Community drivers for AWS / GCP build green in CI.

**Hard gates between phases.** P2 cannot start `M3` on any item until P1 `M3` is universal. P3 cannot start `M3` until P2 pentest exit KPI is green. P4 surface expansion is blocked from `M3` until P3 identity step-change reaches `M2` in dual-emit.

Companion to [Innovation-Directions.md](Innovation-Directions.md) and the 25 per-innovation detailed designs. Source-of-truth for scheduling, dependencies, and exit gates across the GPA innovation program.
