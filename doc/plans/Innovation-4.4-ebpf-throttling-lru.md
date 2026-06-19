## Sections

1.  [1. Overview](#overview)
2.  [2. Today](#today)
3.  [3. LRU map](#lru)
4.  [4. Token bucket](#bucket)
5.  [5. Sizing](#sizing)
6.  [6. Integration](#integration)
7.  [7. Tests](#tests)
8.  [8. Risks](#risks)
9.  [9. Milestones](#milestones)

**GPA** · **Direction 4.4** · **DoS hardening**

# Detailed Design — Kernel-side Throttling & Audit-map LRU

Replace the audit hash map with an LRU-evicting map, and add a per-cgroup token bucket in BPF so connection floods are dropped early. Mitigates pentest `G1` (connection flood) and `G3` (audit-map exhaustion).

**Files affected:** `linux-ebpf/cgroup_connect.bpf.c`, `linux-ebpf/audit_event.bpf.c`, `proxy_agent/src/redirector/`.

> **Prerequisites:** [4.2 Core eBPF unification](Innovation-4.2-core-unify-ebpf.md)

## 1. Overview & Goals

| Impact                  | Effort    | Risk    | Scope    |
|-------------------------|-----------|---------|----------|
| **Medium** availability | **Small** | **Low** | **eBPF** |

### Goals

- Audit map cannot be exhausted to evict legitimate entries.
- A noisy cgroup cannot DoS the agent into a fail-open window.
- Throttling visible via the metrics in 3.2.

## 2. Today

The audit map is a fixed-size hash map. Once full, new identities cannot be recorded and a legitimate caller may be missing an audit entry at decision time. There is no kernel-side rate limit.

## 3. LRU Map

    struct { __uint(type, BPF_MAP_TYPE_LRU_HASH);
             __type(key, __u64);  // cgroup_id
             __type(value, struct gpa_audit_event);
             __uint(max_entries, AUDIT_MAP_MAX);
    } gpa_audit_map SEC(".maps");

- Eviction is least-recently-used; a stale cgroup ages out, an active one stays.
- `AUDIT_MAP_MAX` sized from `(expected unique cgroups) * 2`; default 16,384.
- Map size sampled by the agent every 30 s and exported (`gpa_ebpf_audit_map_entries`).

## 4. Token Bucket

    struct token_bucket { __u64 tokens; __u64 last_refill_ns; };
    struct { __uint(type, BPF_MAP_TYPE_LRU_HASH);
             __type(key, __u64);  // cgroup_id
             __type(value, struct token_bucket);
             __uint(max_entries, AUDIT_MAP_MAX);
    } gpa_rl SEC(".maps");

    SEC("cgroup/connect4")
    int gpa_rate_limit(struct bpf_sock_addr *ctx) {
        __u64 cg = bpf_get_current_cgroup_id();
        struct token_bucket *b = bpf_map_lookup_elem(&gpa_rl, &cg);
        if (!b) { /* lazy init */ }
        refill(b, bpf_ktime_get_ns());
        if (b->tokens == 0) {
            increment_counter(METRIC_RL_DROPPED, cg);
            return 0; // deny connect
        }
        b->tokens--;
        return 1;
    }

- Bucket capacity: 100 connects, refill 50/s per cgroup (tunable).
- Dropped connect returns `EACCES` to the caller; not a silent black-hole.
- Per-cgroup, so a single noisy container cannot starve neighbors.

## 5. Sizing & Tuning

| Param                    | Default | Source                                     |
|--------------------------|---------|--------------------------------------------|
| `AUDIT_MAP_MAX`          | 16384   | Config; overridable via `--ebpf-audit-max` |
| Token bucket capacity    | 100     | Config                                     |
| Token bucket refill rate | 50/s    | Config                                     |
| Map sampler interval     | 30 s    | Config                                     |

## 6. Integration

- Redirector loads the new map types and exposes counters to OTel (3.2).
- Telemetry: `gpa_ebpf_audit_map_evictions_total`, `gpa_ebpf_rate_limited_total{cgroup}`.
- `gpa-doctor` warns when eviction rate or RL drop rate is non-zero over 5 minutes.

## 7. Tests

- Spawn many short-lived cgroups → map grows but never exceeds `AUDIT_MAP_MAX`; eviction counter increases; legitimate cgroup retains entry due to recency.
- Connect-flood single cgroup → RL drops counter increments; agent CPU stays bounded; service does not crash (pentest `G1`).
- G3 audit-map exhaustion attempt → legitimate caller retains decision attribution.

## 8. Risks

- **Bursty workloads** hit RL ceiling. Mitigation: per-config bucket; observable in metrics; doc tuning guidance.
- **LRU not strict FIFO** — acceptable for this use case.

## 9. Milestones

| M   | Deliverable       | Exit                                   |
|-----|-------------------|----------------------------------------|
| M1  | LRU map + sampler | G3 pentest PASS                        |
| M2  | Token bucket      | G1 pentest PASS; agent steady at flood |

Detail design for direction 4.4. Parent: [Innovation-Directions.md](Innovation-Directions.md).
