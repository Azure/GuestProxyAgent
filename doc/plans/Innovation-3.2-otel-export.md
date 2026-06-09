## Sections

1.  [1. Overview](#overview)
2.  [2. Schema](#schema)
3.  [3. Metrics](#metrics)
4.  [4. Traces](#traces)
5.  [5. Exporter](#exporter)
6.  [6. Perf](#perf)
7.  [7. Integration](#integration)
8.  [8. Tests](#tests)
9.  [9. Risks](#risks)
10. [10. Milestones](#milestones)

**GPA** · **Direction 3.2** · **Observability**

# Detailed Design — OpenTelemetry Export

Emit standards-based metrics and traces so GPA can be observed by any modern monitoring stack (Azure Monitor, Prometheus, OTel collectors). Closes the gap where today's only signal is a text log.

**Files affected:** new `proxy_agent/src/telemetry/` module, light hooks in proxy/redirector.

> **Prerequisites:** [3.1 Hash-chained log](Innovation-3.1-hash-chained-log.md)

## 1. Overview & Goals

| Impact                             | Effort    | Risk    | Scope     |
|------------------------------------|-----------|---------|-----------|
| **Medium** SLO + incident response | **Small** | **Low** | **agent** |

### Goals

- Production teams can graph allow/deny by rule id and chase regressions without parsing logs.
- Optional OTLP exporter; default off keeps footprint minimal.
- No PII / secrets in metric labels.

## 2. Resource Attributes

    service.name        = "gpa"
    service.version     = <crate version>
    host.id             = <VM id from IMDS, cached at start>
    gpa.binary.hash     = <sha256 of /usr/sbin/azure-proxy-agent>
    gpa.policy.epoch    = <active epoch>     // updated on reload
    gpa.seal.backend    = "tpm2|snp|tdx|noop"

## 3. Metrics

| Name                         | Type      | Labels             | Notes                         |
|------------------------------|-----------|--------------------|-------------------------------|
| `gpa_requests_total`         | counter   | `dest`, `decision` | Decision = allow\|deny\|error |
| `gpa_request_latency_us`     | histogram | `dest`, `decision` | End-to-end through the agent  |
| `gpa_canon_errors_total`     | counter   | `code`             | From direction 2.1            |
| `gpa_policy_install_total`   | counter   | `result`           | success\|failed               |
| `gpa_policy_epoch`           | gauge     | —                  | Currently active epoch        |
| `gpa_ebpf_audit_map_entries` | gauge     | —                  | From direction 4.4            |
| `gpa_pop_verify_total`       | counter   | `result`           | From direction 1.1            |
| `gpa_restart_total`          | counter   | `reason`           | graceful\|crash\|sigterm      |

## 4. Traces

- One span per inbound request: `gpa.serve_request` with attributes `http.method`, `gpa.dest`, `gpa.decision`, `gpa.policy_epoch`, `gpa.matched_scope`.
- Child span: `gpa.upstream_request` with `net.peer.ip`, `http.status_code`.
- W3C trace context propagation: *do not* propagate inbound trace context to upstream metadata services (avoid leaking client trace ids into fabric). GPA spans share its own trace id rooted at the connection.

## 5. Exporter

- Default: **Prometheus exposition over Unix socket** at `/run/azure-proxy-agent/metrics.sock` (so it never goes over TCP).
- Optional: OTLP/gRPC to a configurable endpoint (used by AKS observability pipelines).
- Sampling: traces sampled at 1/100 by default; head-based; configurable.

## 6. Performance Budget

- Recording overhead per request ≤ 1 µs in default mode; ≤ 5 µs with trace sampled.
- Exporter flush is asynchronous, bounded queue; backpressure drops oldest with a counter.

## 7. Integration

- Use `opentelemetry` + `opentelemetry_sdk` crates; `prometheus` crate for exposition.
- Init in `main.rs` behind `--features otel`; no-op otherwise.
- Hook points: accept, authorize result, upstream call boundary, reload, eBPF map size sampler (every 30 s).

## 8. Tests

- Unit: counters/histograms record expected values.
- Integration: spawn agent with metrics socket, hit it with sample requests, assert metrics endpoint output matches.
- Soak: 24 h with metrics on; memory and CPU within budget.

## 9. Risks

- **Cardinality explosion** if URL or identity goes into labels. Mitigation: only typed enums in labels; never raw strings from requests.
- **Dependency weight.** Mitigation: feature flag default off.

## 10. Milestones

| M   | Deliverable                   | Exit                            |
|-----|-------------------------------|---------------------------------|
| M1  | Metric registry + Prom socket | Local dashboards working        |
| M2  | Traces + OTLP                 | Pilot in one production cluster |

Detail design for direction 3.2. Parent: [Innovation-Directions.md](Innovation-Directions.md).
