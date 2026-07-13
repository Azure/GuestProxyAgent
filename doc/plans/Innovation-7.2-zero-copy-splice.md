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

This document now tracks both the target direction and the current implementation status.

Current status (July 2026): a Linux-only Phase 1 splice path exists for **signed GET/HEAD downloads** (the WireServer/IMDS goal-state and config blobs — where the large payload is in the *response*). It splices upstream response bytes into a kernel pipe and streams them back through hyper. The splice attempt is confined to idempotent GET/HEAD so a fallback re-send is always safe.

**Files affected:** `proxy_agent/src/proxy/proxy_server.rs`, `proxy_agent/src/proxy/splice_io.rs`, `proxy_agent/src/proxy.rs`.

> **Prerequisites:** None — performance-only change, independent of identity / policy / audit work.

## 1. Overview & Goals

| Impact                     | Effort    | Risk    | Scope           |
|----------------------------|-----------|---------|-----------------|
| **Medium** bandwidth + CPU | **Small** | **Low** | **proxy_agent** |

### Goals

- Reduce copy overhead on large Linux response bodies.
- Reduce CPU by ≥ 15% on bodies \> 16 KB.
- Preserve existing behavior by falling back to the standard hyper streaming path when splice is not applicable.

## 2. Today

Before this change, all paths used hyper streaming (`Incoming` -> boxed body). This avoids full buffering but still incurs kernel/user copy overhead on each chunk.

## 3. Design

Implemented path (Phase 1):

1. AuthZ passes and the request is a **signed GET/HEAD** handled by `handle_request_with_signature`. The signature is computed as usual over the (empty) request body and canonical headers.
2. On Linux, GPA calls `splice_io::forward_via_raw_socket`, which uses a raw upstream path (`raw_upstream_request`) that:
	- opens a fresh TCP connection to upstream,
	- writes the HTTP/1.1 request line + signed headers (empty body for GET/HEAD),
	- reads response headers byte-by-byte until `\r\n\r\n` so no body bytes are over-read into user space.
3. Based on the upstream response:
	- **Large body** (`Content-Length >= SPLICE_THRESHOLD`): GPA starts `splice_to_pipe` — the `TcpStream` is moved to a `spawn_blocking` task, `libc::splice(..., SPLICE_F_MOVE)` copies upstream socket -> pipe write end, and `SpliceBody` exposes the pipe as a hyper `Body`.
	- **Small body**: GPA reads exactly `Content-Length` bytes directly into a buffered `Full` body (a single read, no second request to the host).
4. If not eligible (chunked / no `Content-Length`) or if any hard I/O error occurs, GPA falls back to the existing pooled hyper forwarding path. Because the target is idempotent GET/HEAD, this re-send is safe.

Current eligibility rules:

- Linux only (`target_os = "linux"`).
- Signed **GET/HEAD** requests only (body-less, idempotent downloads).
- Response must have `Content-Length`.
- Splice is used when `Content-Length >= 16 KB` (`SPLICE_THRESHOLD`); smaller bodies use a direct buffered read.
- `Transfer-Encoding: chunked` is not currently supported (falls back to hyper).

Important limitation in Phase 1:

- This is not yet full socket-to-socket zero-copy. The upstream->pipe leg uses splice, but hyper still owns the client-side send path.

## 4. Header Handling

- AuthZ and canonical checks remain unchanged.
- Request line and headers are still parsed in user space.
- Response status and headers are parsed and re-emitted by GPA.
- Only the response body is splice-accelerated in Phase 1.

## 5. Integration

- Integration point is `handle_request_with_signature` in `proxy_server.rs` (the signed GET/HEAD download path). The skip-signature branch is left on the unmodified streaming path (its large traffic is *uploads*, where splice would not help the response side).
- Linux path calls `splice_io::forward_via_raw_socket`; non-Linux remains on the existing hyper path.
- Fallback is automatic for unsupported shapes (chunked, no content-length) and on any raw/splice I/O error.
- Internal counters exist in `splice_io.rs`:
	- `SPLICE_BYTES_TOTAL`
	- `COPY_BYTES_TOTAL`
	Metric export wiring is still pending.

## 6. Tests

- Implemented so far:
	- Windows build remains green (`cargo check -p azure-proxy-agent`).
- Still needed:
	- Linux functional parity tests for splice vs fallback.
	- Chunked-response fallback regression test.
	- Large-body benchmark proving CPU reduction target.
	- Connection lifecycle tests (EOF/RST/cancel while splice task is active).

## 7. Risks

- **Raw + hyper split path complexity:** the GET/HEAD download path uses a separate raw upstream connection for splice attempts, discarding the pooled `SendRequest` and its keep-alive (splice requires a raw fd). This adds a handshake per spliced download. Mitigation: confine to GET/HEAD and preserve robust fallback to pooled hyper forwarding.
- **Signature over raw framing:** the signature is computed over canonical headers/params, not wire framing, so GPA's own `Host`/`Connection: close` framing should not invalidate it — but this needs integration testing against a real host.
- **Protocol coverage gap:** chunked responses currently bypass splice. Mitigation: explicit fallback (idempotent GET/HEAD re-send) and test coverage.
- **Lifecycle edge cases:** EOF/RST/cancellation around `spawn_blocking` splice loop can be subtle. Mitigation: targeted Linux integration tests.

## 8. Milestones

| M   | Deliverable               | Exit                             |
|-----|---------------------------|----------------------------------|
| M0  | Phase 1 landed            | Linux signed GET/HEAD download path attempts splice with safe fallback |
| M1  | Linux parity + perf proof | CPU target met on large bodies; parity tests green      |
| M2  | Broader protocol support  | Chunked handling and lifecycle hardening complete        |
| M3  | Optional full zero-copy   | Evaluate direct socket->socket architecture beyond hyper |

Detail design for direction 7.2. Parent: [Innovation-Directions.md](Innovation-Directions.md).
