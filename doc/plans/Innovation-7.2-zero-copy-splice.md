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

This document tracks the target direction. It also records a Phase 1 prototype that was implemented and then **reverted** in July 2026, along with the reasoning behind that decision.

**Current status (July 2026): NOT implemented — prototype reverted.** A Linux-only Phase 1 splice path was prototyped for **signed GET/HEAD downloads** (WireServer/IMDS goal-state and config blobs, where the large payload is in the *response*). It splice(2)'d upstream response bytes into a kernel pipe and streamed them back through hyper. After review it was reverted because the cost/complexity did not justify the benefit for GPA's workload (see [§2.1 Decision](#decision)). The code (`proxy_agent/src/proxy/splice_io.rs` and its integration in `proxy_server.rs` / `proxy.rs`) has been removed; GPA is back on the pure hyper streaming path.

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

All paths use hyper streaming (`Incoming` -> boxed body). On both the request and response sides GPA maps the body straight through with `body.boxed()` (e.g. `Response::map(|b| b.boxed())` / `Request::from_parts(head, body.boxed())`) instead of collecting it. This means:

- **Memory pressure is already solved.** The body is never fully buffered; GPA holds roughly one frame at a time, so peak memory is `O(frame)` per connection instead of `O(Content-Length)`. This is the important win, and it is already in place — see [§2.1](#decision).
- **Copies remain.** Each byte is still copied twice — kernel→user on `recv`, user→kernel on `send`. That per-byte memcpy is the only thing splice would remove.

> Exception: the **signed** request path (`handle_request_with_signature`) deliberately buffers the whole request body via `read_body_bytes`, because it must have the complete bytes in hand to compute the HMAC signature. splice cannot help once the bytes are already in user space.

<a id="decision"></a>
## 2.1 Decision (July 2026): reverted, streaming is sufficient

The Phase 1 prototype was removed. Rationale:

1. **Streaming already fixes the real problem (memory).** `body.boxed()` streaming bounds peak memory to one frame regardless of payload size and applies backpressure to slow clients. splice does **not** improve memory — it only removes a CPU memcpy.
2. **The copy CPU is not a measured bottleneck.** On the host link, per-byte memcpy is tiny next to network transfer time. No profile showed GPA CPU-bound on large transfers, so the ≥15% CPU goal was unproven.
3. **splice can't help the signed path anyway.** Signed GET/HEAD downloads were the only candidate, yet the signature path must buffer the body for HMAC — and for the *request* body specifically. For the *response* body splice was possible, but the payoff was marginal (infrequent large blobs) versus the cost below.
4. **The prototype lost keep-alive and added significant code.** To get a raw fd for `splice(2)`, the prototype opened a **fresh** TCP connection per download and sent `Connection: close`, discarding hyper's pooled keep-alive to the host (168.63.129.16) and paying a handshake each time. It also re-implemented ~200 lines of HTTP/1.1 request writing and byte-by-byte response-header parsing that hyper already does correctly.
5. **Wrong direction for the other large traffic.** The large *skip-signature* traffic is **uploads** (client→host); the reverted splice only accelerated the response (download) leg, so it would not have helped that traffic regardless.

**When to revisit:** only if profiling shows GPA is CPU-bound on large transfers *and* the design keeps connection keep-alive (i.e. splice within a pooled connection, or a dedicated raw connection pool) rather than a new connection per request.

## 3. Design (candidate, if revisited)

The reverted prototype worked as follows and is kept here as a reference design should the [revisit criteria](#decision) ever be met:

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

Important limitation of the candidate design:

- This was not full socket-to-socket zero-copy. The upstream->pipe leg used splice, but hyper still owned the client-side send path, so one user-space copy remained.

## 4. Header Handling

- AuthZ and canonical checks remain unchanged.
- Request line and headers are still parsed in user space.
- Response status and headers are parsed and re-emitted by GPA.
- Only the response body would be splice-accelerated.

## 5. Integration (as prototyped, now removed)

- Integration point *was* `handle_request_with_signature` in `proxy_server.rs` (the signed GET/HEAD download path). The skip-signature branch was left on the unmodified streaming path (its large traffic is *uploads*, where splice would not help the response side).
- Linux path called `splice_io::forward_via_raw_socket`; non-Linux stayed on the existing hyper path.
- Fallback was automatic for unsupported shapes (chunked, no content-length) and on any raw/splice I/O error.
- Internal counters (`SPLICE_BYTES_TOTAL`, `COPY_BYTES_TOTAL`) lived in `splice_io.rs`; metric export was never wired up.

All of the above has been reverted. GPA now uses only the pooled hyper streaming path for these requests.

## 6. Tests

N/A while reverted. If the feature is revisited, the following would be prerequisites before landing:

- A large-body benchmark **first**, proving GPA is CPU-bound on the copy and that splice yields the ≥15% CPU target. This is the gating evidence that was missing.
- Linux functional parity tests for splice vs fallback.
- Chunked-response fallback regression test.
- Connection lifecycle tests (EOF/RST/cancel while a splice task is active).

## 7. Risks

- **Raw + hyper split path complexity:** the GET/HEAD download path uses a separate raw upstream connection for splice attempts, discarding the pooled `SendRequest` and its keep-alive (splice requires a raw fd). This adds a handshake per spliced download. Mitigation: confine to GET/HEAD and preserve robust fallback to pooled hyper forwarding.
- **Signature over raw framing:** the signature is computed over canonical headers/params, not wire framing, so GPA's own `Host`/`Connection: close` framing should not invalidate it — but this needs integration testing against a real host.
- **Protocol coverage gap:** chunked responses currently bypass splice. Mitigation: explicit fallback (idempotent GET/HEAD re-send) and test coverage.
- **Lifecycle edge cases:** EOF/RST/cancellation around `spawn_blocking` splice loop can be subtle. Mitigation: targeted Linux integration tests.

## 8. Milestones

| M   | Deliverable               | Exit                             |
|-----|---------------------------|----------------------------------|
| M0  | ~~Phase 1 landed~~ **Reverted** | Prototype removed; GPA on pure hyper streaming. Memory pressure already handled by `body.boxed()` streaming. |
| M1  | Perf evidence (gate)      | Benchmark proves GPA is CPU-bound on large transfers and splice meets the CPU target — **required before any re-attempt** |
| M2  | Keep-alive-safe design    | A splice approach that preserves host connection keep-alive (pooled/raw pool), not a new connection per request |
| M3  | Linux parity + protocol   | Parity tests, chunked handling, lifecycle hardening      |

Detail design for direction 7.2. Parent: [Innovation-Directions.md](Innovation-Directions.md).
