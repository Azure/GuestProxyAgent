## Sections

1.  [1. Overview](#overview)
2.  [2. Today](#today)
3.  [3. Design](#design)
4.  [4. API](#api)
5.  [5. Reload protocol](#reload)
6.  [6. Audit emission](#audit)
7.  [7. Integration](#integration)
8.  [8. Tests](#tests)
9.  [9. Risks](#risks)
10. [10. Milestones](#milestones)

**GPA** · **Direction 2.3** · **Concurrency**

# Detailed Design — Versioned, Per-Request Policy Snapshots

Wrap the active policy in `ArcSwap` with a monotonic `epoch`. Each incoming request captures the policy snapshot at accept time and uses it for the whole forwarding decision. Closes pentest `D5` (TOCTOU between rule reload and in-flight request) and gives operators a precise audit trail.

**Files affected:** `proxy_agent/src/key_keeper/key.rs`, `proxy_agent/src/proxy/proxy_authorizer.rs`, `proxy_agent/src/proxy/proxy_server.rs`, `proxy_agent/src/key_keeper/local_rules.rs`.

> **Prerequisites:** [2.2 Typed policy (Cedar)](Innovation-2.2-typed-policy-cedar.md)

## 1. Overview & Goals

| Impact               | Effort    | Risk    | Scope          |
|----------------------|-----------|---------|----------------|
| **Medium** closes D5 | **Small** | **Low** | **agent only** |

### Goals

- A request that started under policy *P_n* finishes under *P_n*, even if reload occurs mid-request.
- Audit log records the exact policy `epoch` that authorized each request.
- Reloads are wait-free for readers; no mutex on the hot path.

## 2. Today's Behavior

Rules are stored in shared mutable state. A reload can race with an in-flight authorize call — different parts of the decision can read different versions, and there is no *per-request* identifier of which policy version applied.

## 3. Design

### 3.1 Types

    pub struct PolicyEpoch(pub u64);

    pub struct PolicySnapshot {
        pub epoch: PolicyEpoch,
        pub computed: ComputedAuthorizationRules,
        pub source_hash: [u8;32],
        pub loaded_at: SystemTime,
    }

    pub struct PolicyStore {
        inner: arc_swap::ArcSwap<PolicySnapshot>,
        next_epoch: AtomicU64,
    }

    impl PolicyStore {
        pub fn current(&self) -> Arc<PolicySnapshot>;
        pub fn install(&self, computed: ComputedAuthorizationRules, source_hash: [u8;32])
            -> PolicyEpoch;
    }

### 3.2 Invariants

- `epoch` is monotonically increasing across the agent process lifetime; persists across restart by reading the last `epoch` stamped in the `AuthorizationRules_*.json` file and incrementing.
- Installation is fail-closed: if validation fails, no install occurs and previous snapshot stays active. A counter `gpa_policy_install_failed_total` increments.
- Readers never block writers; writers never block readers.

## 4. Usage

    // Accept site (proxy_server.rs)
    let snap = policy_store.current();          // cheap Arc clone
    ctx.policy_snapshot = snap;
    ctx.policy_epoch = snap.epoch;

    // Authorizer (proxy_authorizer.rs)
    let decision = ctx.policy_snapshot.is_allowed(&canon_req, &claims);
    logger.attach_field("policy_epoch", ctx.policy_epoch.0);

## 5. Reload Protocol

1.  Reload thread fetches new rules (remote + local merge per `local_rules.rs`).
2.  Compile to `ComputedAuthorizationRules` (and Cedar policy set when 2.2 lands).
3.  Validate (schema + structural). On failure: log + telemetry + leave previous in place.
4.  `PolicyStore::install` assigns the next epoch and swaps the Arc.
5.  Emit a structured event `PolicyInstalled{epoch, source_hash, loaded_at}`.

## 6. Audit Emission

- Every connection log entry gains `policy_epoch`.
- `status.json` reports `active_policy_epoch`, `last_failed_install_at`, `last_failed_install_reason`.
- Telemetry: histogram of `request_age_vs_policy_age_seconds` to detect long-lived connections still bound to ancient snapshots (potentially a sign of upstream hang).

## 7. Integration Points

- `proxy_agent/src/key_keeper/key.rs` — replace direct sharing with `Arc<PolicyStore>`.
- `proxy_agent/src/proxy/proxy_server.rs` — capture snapshot on accept and stash on connection context.
- `proxy_agent/src/proxy/proxy_authorizer.rs` — read from context, not global.
- `proxy_agent/src/proxy/proxy_summary.rs` — propagate `policy_epoch` into log entries.
- `proxy_agent/src/key_keeper/local_rules.rs` — fail-closed merge already exists; just route the install through the store.

## 8. Tests

- Concurrent test: 64 worker threads issue authorize calls; reload thread installs new policies at random intervals. Assert every decision is consistent (Allow/Deny matches the snapshot's rules) and no thread observes a half-installed state.
- Pentest `D5`: with an in-flight request held by a slow upstream, install a deny policy; the in-flight request still completes with the prior epoch (documented behavior) but no new connections see the old policy.
- Fail-closed: corrupt the rules file → install fails → previous epoch remains active and is reflected in `status.json`.

## 9. Risks

- **Long-lived requests retain old policies.** Mitigation: documented behavior; emit warning when request_age \> threshold.
- **Epoch wraparound:** `u64`, no practical issue.
- **Stale snapshot retained by Arc.** Memory only; small (one struct per request in flight).

## 10. Milestones

| M   | Deliverable                             | Exit                                                |
|-----|-----------------------------------------|-----------------------------------------------------|
| M1  | Introduce `PolicyStore` + plumb context | All unit tests pass; `policy_epoch` visible in logs |
| M2  | Status + telemetry fields               | Operator dashboards updated                         |
| M3  | Pentest D5 regression test added        | Test green; runs in CI                              |

Detail design for direction 2.3. Parent: [Innovation-Directions.md](Innovation-Directions.md).
