## Sections

1.  [1. Overview](#overview)
2.  [2. Today](#today)
3.  [3. Design](#design)
4.  [4. Feature flag](#features)
5.  [5. Benchmark plan](#bench)
6.  [6. Integration](#integration)
7.  [7. Tests](#tests)
8.  [8. Risks](#risks)
9.  [9. Milestones](#milestones)

**GPA** · **Direction 7.1** · **Perf**

# Detailed Design — io_uring Hot Path

Switch the IMDS GET hot path to `tokio-uring` (or `monoio`) behind a feature flag. Cuts syscall overhead for the highest-volume request shape.

**Files affected:** `proxy_agent/src/proxy/proxy_server.rs`; new runtime selection module.

> **Prerequisites:** None — performance-only change, independent of identity / policy / audit work.

## 1. Overview & Goals

| Impact                   | Effort     | Risk             | Scope           |
|--------------------------|------------|------------------|-----------------|
| **Medium** latency + CPU | **Medium** | **Runtime swap** | **proxy_agent** |

### Goals

- p50 latency reduction ≥ 30% on IMDS GET path on modern kernels.
- CPU per million requests reduced ≥ 20%.
- No regression on legacy kernels (feature flag off).

## 2. Today

Tokio + epoll on Linux. Every request: `accept`, `read`, `write`, `read`, `write`. For a fast localhost GET this is dominated by syscall overhead and scheduler wake-ups.

## 3. Design

- Use `tokio-uring` for accept + read + write on the proxy hot loop; the rest of the agent stays on stock Tokio.
- Single-threaded reactor per CPU; SO_REUSEPORT to spread accept.
- Buffer pool: reusable 4 KB buffers registered with io_uring (zero allocations on hot path).
- For unauthorized requests the agent still falls back to the standard path (cold).

## 4. Feature Flag

- Cargo feature `io_uring`; off by default.
- Runtime probe: kernel ≥ 5.15 and unrestricted `io_uring_setup`; otherwise the proxy falls back to the Tokio path with one INFO log line.
- Attestation endpoint (3.3) advertises which path is in use.

## 5. Benchmark Plan

| Workload            | Metric            | Target                       |
|---------------------|-------------------|------------------------------|
| 1 client × 10k req  | p50 / p99 latency | ≥ 30% / ≥ 20% lower          |
| 50 clients × 10 min | RPS / CPU         | ≥ 30% higher RPS at same CPU |
| 500 clients         | Tail latency      | p99.9 stable                 |

## 6. Integration

- Authorizer stays unchanged; lives behind an async boundary.
- Telemetry (3.2) emits `gpa_runtime_kind` label.

## 7. Tests

- Functional parity test: same input → same response on both runtimes.
- Kernel matrix CI (5.4, 5.15, 6.1, 6.8): flag-on tests skipped on unsupported kernels.
- Fuzz: malformed HTTP requests handled identically.

## 8. Risks

- **io_uring CVEs** on older kernels. Mitigation: explicit kernel-version gate; documented minimum.
- **Code split** between two runtimes. Mitigation: keep the hot path tiny; AuthZ remains shared.

## 9. Milestones

| M   | Deliverable                      | Exit                  |
|-----|----------------------------------|-----------------------|
| M1  | Hot path prototype (flag off)    | Benchmark numbers     |
| M2  | Feature flag + probe + telemetry | Internal opt-in       |
| M3  | Default-on for supported kernels | SLOs hold for 1 month |

Detail design for direction 7.1. Parent: [Innovation-Directions.md](Innovation-Directions.md).
