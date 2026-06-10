## Sections

1.  [1. Overview](#overview)
2.  [2. Host ABI](#abi)
3.  [3. Limits](#limits)
4.  [4. Example](#example)
5.  [5. Opt-in](#optin)
6.  [6. Integration](#integration)
7.  [7. Tests](#tests)
8.  [8. Risks](#risks)
9.  [9. Milestones](#milestones)

**GPA** · **Direction 6.4** · **Extensibility**

# Detailed Design — WASM Rule Sandbox

An opt-in WebAssembly extension point for organizations that need conditions richer than the declarative rule language. WASM modules are deny-by-default sandboxed: no syscalls, no clocks, no network, no I/O — just compute over the canonical request and claims.

**Files affected:** new `proxy_agent/src/authorization/wasm/` module; integrates with rule engine (after Cedar from 2.2).

> **Prerequisites:** [2.2 Typed policy (Cedar)](Innovation-2.2-typed-policy-cedar.md)

## 1. Overview & Goals

| Impact                        | Effort     | Risk                    | Scope     |
|-------------------------------|------------|-------------------------|-----------|
| **Medium** niche but powerful | **Medium** | **Sandbox correctness** | **agent** |

### Goals

- Custom conditions without exposing the agent to arbitrary code.
- Hard, enforced CPU + memory limits.
- Modules are content-addressed; auditable via 3.4 supply-chain pipeline.

## 2. Host ABI

    // Exported by the WASM module:
    //   fn decide(req_ptr: i32, req_len: i32,
    //             claims_ptr: i32, claims_len: i32) -> i32   // 0 = allow, 1 = deny

    // Imported from host (the only imports allowed):
    //   fn log(ptr: i32, len: i32);            // append to a per-decision diag string
    //   fn abort();                            // immediate deny

    // No clocks. No filesystem. No network. No randomness.

- Inputs and outputs are JSON-encoded canonical request + resolved claims.
- Runtime: [wasmtime](https://github.com/bytecodealliance/wasmtime) with all WASI features disabled.
- Memory cap: 16 MB; fuel cap: 100,000 instructions per call.

## 3. Limits

| Limit                | Default             | Reason                  |
|----------------------|---------------------|-------------------------|
| Memory               | 16 MB               | Bounded request size    |
| Fuel                 | 100k instructions   | ~1 ms on typical hosts  |
| Imports              | `log`, `abort` only | Deny-by-default surface |
| Modules per rule set | 16                  | Bounded compile time    |
| Wall-clock per call  | 5 ms hard kill      | Tail-latency guard      |

## 4. Example

    // rust crate compiled to wasm32-unknown-unknown
    #[no_mangle]
    pub extern "C" fn decide(req_ptr: i32, req_len: i32,
                             claims_ptr: i32, claims_len: i32) -> i32 {
        let req: CanonicalRequest    = json_read(req_ptr, req_len);
        let claims: ResolvedIdentity = json_read(claims_ptr, claims_len);
        // Custom rule: only allow IMDS identity reads from pods that exist for > 5 min
        if req.destination == "imds" && claims.pod_age_secs.unwrap_or(0) >= 300 { 0 } else { 1 }
    }

The module is referenced from a normal grant: `"condition": { "wasm": "sha256:..."}`.

## 5. Opt-in

- Disabled by default. Enabled per-deployment via `--enable-wasm-rules`.
- Module hash must be present in the trust list (Sigstore-signed; see 3.4).
- Per-call telemetry tagged with module hash so noisy modules are findable.

## 6. Integration

- After Cedar (2.2) returns "allow with condition C", the engine invokes the WASM condition module.
- Result combined with Cedar's verdict; deny always wins.
- Module compiled once at load, cached in memory.

## 7. Tests

- Resource-exhaustion modules (infinite loop, oversize allocation) are bounded as expected.
- Malformed input handling: module returns deny; agent treats abort as deny.
- Sandbox escape attempts (using removed WASI imports) fail to link.

## 8. Risks

- **wasmtime CVEs** — pin to LTS; track advisories.
- **Performance regression** if customers push hot paths into WASM. Mitigation: opt-in + telemetry visible.

## 9. Milestones

| M   | Deliverable                          | Exit                       |
|-----|--------------------------------------|----------------------------|
| M1  | Host ABI + limits + reference module | Internal demo              |
| M2  | Sigstore-signed module store         | Trust list enforced        |
| M3  | Pilot                                | One real customer use-case |

Detail design for direction 6.4. Parent: [Innovation-Directions.md](Innovation-Directions.md).
