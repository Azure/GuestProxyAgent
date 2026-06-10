## Sections

1.  [1. Overview](#overview)
2.  [2. Today](#today)
3.  [3. Token format](#token)
4.  [4. Mint & verify](#mint)
5.  [5. Wire protocol](#wire)
6.  [6. Integration](#integration)
7.  [7. Rollout](#rollout)
8.  [8. Tests](#tests)
9.  [9. Risks](#risks)
10. [10. Milestones](#milestones)

**GPA** · **Direction 1.1** · **AuthN**

# Detailed Design — Short-lived Proof-of-Possession Tokens

Replace the long-lived HMAC signature header with a compact, audience-scoped, time-bound token derived from the latched key, so a leaked key file cannot be used to sign arbitrary requests offline or to replay captured ones.

**Files affected:** `proxy_agent_shared/src/` (new `pop_token` module), `proxy_agent/src/key_keeper/key.rs`, `proxy_agent/src/proxy/proxy_server.rs`.

> **Prerequisites:** None — foundational identity-layer change. Strengthened by [1.2 vTPM sealing](Innovation-1.2-vtpm-sealing.md) (key-source hardening) and [1.3 Measured identity](Innovation-1.3-measured-identity.md) (binding the signer).

## 1. Overview & Goals

| Impact                           | Effort     | Risk                | Scope                       |
|----------------------------------|------------|---------------------|-----------------------------|
| **High** kills replay + key-leak | **Medium** | **Fabric coupling** | **agent + WireServer/IMDS** |

### 1.1 Goals

- Each request bears a token valid for ≤ 30 s, bound to *caller*, *destination*, and *URL*.
- The latched key never appears on the wire and never signs raw HTTP — it signs a derived session key.
- Replay (pentest `B2`) becomes structurally impossible.
- A leaked key file (pentest `B3`) is still useless without live caller-fingerprint material (cgroup, pid-starttime, vTPM PCRs from direction 1.2).

### 1.2 Non-goals

- Replacing the underlying primitive (still HMAC-SHA256 in v1; PQ migration is out of scope).
- Asymmetric tokens — would force a fabric crypto change we want to defer.

## 2. Today's Behavior

GPA signs each authorized request with an HMAC over a static string derived from method, URL, and a coarse "time tick"; the signature is placed in `x-ms-azure-signature` with a sibling `x-ms-azure-time-tick` header. The HMAC key is the latched key written at provisioning. Once disclosed, it can sign anything indefinitely.

The fabric checks the signature against the latched key it holds for this VM. There is no per-request nonce, no audience binding, and no caller binding.

## 3. Token Format

Compact, JWS-like, three base64url segments joined by `.`:

    HEADER  = { "alg":"HS256", "kid":<latched-key-id>, "v":2 }
    PAYLOAD = {
      "iss":  "gpa",                       // issuer
      "aud":  "wireserver" | "imds" | "hostga",
      "sub":  <caller-fingerprint hash>,    // see §3.1
      "iat":  <unix-seconds>,
      "exp":  <unix-seconds, exp - iat <= 30>,
      "nbf":  <unix-seconds, == iat>,
      "jti":  <128-bit random>,            // nonce (anti-replay)
      "url":  <sha256(canonical url + method)>,
      "dip":  <destination ip:port>,
      "src":  <caller pid-starttime & cgroup id, hashed>
    }
    SIG     = HMAC-SHA256( derive_session_key(latched, jti), HEADER || "." || PAYLOAD )

### 3.1 Caller fingerprint (`sub`)

- `sub = sha256( cgroup_id || pid_starttime_ns || exe_hash )`.
- `exe_hash` is the IMA / fs-verity hash from direction 1.3 when available; falls back to `processFullPath` bytes.
- The fabric does not interpret `sub`; it only ensures the same `sub` isn't reused after expiry.

### 3.2 Session key derivation

    session_key = HKDF-SHA256(
        ikm   = latched_key,
        salt  = jti,
        info  = "gpa-pop-v2" || aud || dip
    )

This means the latched key never directly produces a tag visible on the wire; recovering the latched key requires inverting HKDF, not HMAC.

## 4. Mint & Verify

### 4.1 Rust API

    pub struct PopToken(String);

    pub struct MintParams<'a> {
        pub aud: Audience,
        pub canonical_url_method_hash: [u8; 32],
        pub destination: SocketAddr,
        pub caller: &'a CallerFingerprint,
        pub ttl: Duration, // clamp to <=30s
    }

    impl PopToken {
        pub fn mint(key: &LatchedKey, p: &MintParams) -> Result<PopToken, MintError>;
        pub fn verify(token: &str, key: &LatchedKey, now: SystemTime,
                      expected_aud: Audience) -> Result<Claims, VerifyError>;
    }

### 4.2 Constant-time comparison

- Use `subtle::ConstantTimeEq` for the signature compare in `verify`.
- HMAC computation uses `hmac` crate with `sha2::Sha256`; both are constant-time and already in the dependency tree.

### 4.3 Anti-replay storage

- Agent side: nothing (tokens are stateless on the way out).
- Fabric side: bloom filter or LRU of recently-seen `jti` values keyed by `(aud, sub)` with TTL ≥ 2× max `exp - iat`. Detail belongs to the fabric design but the agent must pick `jti` from a CSPRNG with at least 128 bits.

## 5. Wire Protocol

### 5.1 Headers (v2)

| Header                    | Direction      | Notes                                                           |
|---------------------------|----------------|-----------------------------------------------------------------|
| `x-ms-azure-pop`          | agent → fabric | The compact token from §3.                                      |
| `x-ms-azure-pop-aud`      | agent → fabric | Redundant audience hint to allow fast rejection before parsing. |
| `x-ms-azure-signature`    | agent → fabric | Legacy header, still emitted during dual-emit phase.            |
| `x-ms-azure-pop-rejected` | fabric → agent | Reason code on 401; consumed by GPA telemetry only.             |

### 5.2 Header stripping

GPA **always** strips any inbound `x-ms-azure-pop*` and `x-ms-azure-signature*` headers from the client request before forwarding (pentest `B4`); never propagates client-supplied values.

## 6. Integration Points

| File                                        | Change                                                                                       |
|---------------------------------------------|----------------------------------------------------------------------------------------------|
| `proxy_agent_shared/src/pop_token/`         | New module: types, mint, verify, fuzz target.                                                |
| `proxy_agent/src/key_keeper/key.rs`         | Add `derive_session_key`; expose `kid()`.                                                    |
| `proxy_agent/src/proxy/proxy_server.rs`     | Replace HMAC mint with `PopToken::mint`; keep legacy header behind `pop_v2.mode != enforce`. |
| `proxy_agent/src/proxy/proxy_authorizer.rs` | Compute canonical URL hash (reuse `CanonicalRequest` from 2.1) and caller fingerprint.       |
| `config/GuestProxyAgent.*.json`             | New `popToken.mode` = `off|dual|enforce`.                                                    |

## 7. Rollout

1.  **Phase A — Off:** ship code, dormant. Unit / fuzz tests run in CI only.
2.  **Phase B — Dual-emit:** emit both headers; fabric ignores PoP. Telemetry only.
3.  **Phase C — Dual-verify:** fabric verifies PoP if present, accepts either. Agent telemetry tracks fabric verdicts via the `x-ms-azure-pop-rejected` header.
4.  **Phase D — PoP-only:** fabric rejects requests without PoP. Legacy header removed in the next release.

A region only advances to the next phase when error rate \< 0.001 % for 14 days.

## 8. Test Strategy

- Golden vectors signed by a reference implementation; agent must verify identical bytes.
- Property test: round-trip `mint → verify` always succeeds for fresh tokens; modifying any byte fails.
- Property test: skewing the clock by \> 60 s rejects; within ±60 s accepts (configurable skew).
- `cargo fuzz` on `verify`: must never panic.
- Pentest reruns: `B2` replay → REJECT; `B3` stolen-key replay on a different VM → REJECT once fabric checks `sub` stickiness.
- Soak: 1 million mint/verify pairs/sec on a single core baseline; track regressions.

## 9. Risks & Mitigations

- **Clock drift:** ±60 s tolerance; if NTP is broken GPA can request fabric time via WireServer health endpoint.
- **Header bloat:** typical token ≈ 380 bytes b64u; bounded.
- **Fabric rollout coupling:** dual-emit/dual-verify phases decouple agent and fabric releases.
- **HSM-bound key future:** session-key derivation already isolates the latched key, easing later migration to a vTPM-resident key (direction 1.2).

## 10. Milestones

| M   | Deliverable                            | Exit                                   |
|-----|----------------------------------------|----------------------------------------|
| M1  | `pop_token` crate + 200 golden vectors | Fuzz clean for 1 CPU-day               |
| M2  | Dual-emit behind flag in canary region | Zero correctness regressions vs legacy |
| M3  | Fabric dual-verify enabled             | Pentest B2/B3 PASS                     |
| M4  | PoP-only enforcement                   | Legacy header deletion PR merged       |

Detail design for direction 1.1. Parent: [Innovation-Directions.md](Innovation-Directions.md).
