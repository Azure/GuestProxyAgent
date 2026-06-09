## Sections

1.  [1. Overview](#overview)
2.  [2. Today](#today)
3.  [3. Design](#design)
4.  [4. Header handling](#headers)
5.  [5. Integration](#integration)
6.  [6. Tests](#tests)
7.  [7. Risks](#risks)
8.  [8. Milestones](#milestones)

**GPA** · **Direction 7.2** · **Perf**

# Detailed Design — Zero-Copy splice(2) after AuthZ Pass

Once authorization succeeds, splice the client socket directly to the upstream socket via `splice(2)`. The agent stops touching the payload; bytes flow through a kernel pipe without user-space copy.

**Files affected:** `proxy_agent/src/proxy/proxy_server.rs`, `proxy_agent/src/proxy/upstream.rs`.

> **Prerequisites:** None — performance-only change, independent of identity / policy / audit work.

## 1. Overview & Goals

| Impact                     | Effort    | Risk    | Scope           |
|----------------------------|-----------|---------|-----------------|
| **Medium** bandwidth + CPU | **Small** | **Low** | **proxy_agent** |

### Goals

- Zero user-space copies for the response body.
- Reduce CPU by ≥ 15% on bodies \> 16 KB.
- Preserve TLS-terminated paths (5.2) by skipping splice when content must be inspected/transformed.

## 2. Today

Each response goes `recv → userland buffer → send`. For large IMDS goal-state pulls or WireServer extensions data this dominates CPU.

## 3. Design

client ──accept──\> agent │ ▼ AuthZ pass (headers parsed) │ ▼ open upstream socket │ ▼ splice(client_fd, upstream_fd) for request body │ ▼ splice(upstream_fd, client_fd) for response body │ └── still record byte counts via tee(2) for audit

- Two kernel pipes per direction; `splice(2)` with `SPLICE_F_MOVE | SPLICE_F_MORE`.
- `tee(2)` teaches an audit ring of message lengths without copying payload.
- Skip splice when: TLS-terminated, payload transformation required, or body \< 4 KB.

## 4. Header Handling

- Agent still parses request line + headers in user space (needed for AuthZ + canonical model).
- Once the boundary is found and the verdict is allow, the remaining body and response are spliced.
- Response headers from upstream are parsed and re-emitted under agent control; only the body is spliced.

## 5. Integration

- Falls back to copy-loop on non-Linux and when splice is unsupported.
- Telemetry: `gpa_splice_bytes_total` vs `gpa_copy_bytes_total`.

## 6. Tests

- Functional parity: identical byte-for-byte response under both paths.
- Large body benchmark: ≥ 15% CPU reduction at 1 MB bodies.
- Short body verification: short paths unaffected (still copy).

## 7. Risks

- **Connection lifecycle** bugs are subtle (half-close, RST during splice). Mitigation: explicit unit + integration tests for terminations.
- **Bypassing future hooks** that would want to inspect payload — keep splice optional per destination driver.

## 8. Milestones

| M   | Deliverable               | Exit                             |
|-----|---------------------------|----------------------------------|
| M1  | Splice for IMDS large GET | CPU target met                   |
| M2  | Per-driver opt-in         | TLS-terminated paths skip splice |

Detail design for direction 7.2. Parent: [Innovation-Directions.md](Innovation-Directions.md).
