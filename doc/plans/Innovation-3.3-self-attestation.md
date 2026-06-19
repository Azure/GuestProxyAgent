## Sections

1.  [1. Overview](#overview)
2.  [2. Endpoint](#endpoint)
3.  [3. Payload](#payload)
4.  [4. Access control](#access)
5.  [5. Signing](#sign)
6.  [6. Integration](#integration)
7.  [7. Tests](#tests)
8.  [8. Risks](#risks)
9.  [9. Milestones](#milestones)

**GPA** · **Direction 3.3** · **Attestation**

# Detailed Design — Self-Attestation Endpoint

Expose a read-only endpoint that returns GPA's own measurements: binary hash, loaded eBPF program ids and bytecode hashes, attached cgroup, active policy epoch, sealed-key id, attestation backend. Consumable by Defender for Cloud, Azure Policy, and operator tooling.

**Files affected:** `proxy_agent/src/proxy/proxy_server.rs` (new route), new `proxy_agent/src/attestation/`.

> **Prerequisites:** [1.2 vTPM sealing](Innovation-1.2-vtpm-sealing.md)[3.1 Hash-chained log](Innovation-3.1-hash-chained-log.md)

## 1. Overview & Goals

| Impact                                  | Effort    | Risk    | Scope     |
|-----------------------------------------|-----------|---------|-----------|
| **Medium** compliance + drift detection | **Small** | **Low** | **agent** |

### Goals

- Externally verifiable proof of which GPA is running, with which policy, and which kernel-side components are attached.
- Cheap probe with no secrets in the payload.

## 2. Endpoint

- HTTP GET `/.well-known/gpa/attestation` on the local listener (`127.0.0.1:3080`).
- Optional `?nonce=BASE64URL(32 bytes)` for freshness.
- Response: `application/json` with a signed `jws` field when an attestation backend is present.

## 3. Payload Shape

    {
      "version": 1,
      "service": {
        "name": "gpa",
        "version": "1.X.Y",
        "binary_hash": "sha256:...",
        "uptime_s": 12345
      },
      "policy": {
        "epoch": 175201,
        "source_hash": "sha256:...",
        "loaded_at": "2026-06-01T12:30:00Z",
        "selftest_passed": true
      },
      "ebpf": [
        { "name": "cgroup_connect", "id": 42, "bytecode_hash": "sha256:...", "attach_cgroup": "/sys/fs/cgroup" },
        { "name": "audit_event",    "id": 43, "bytecode_hash": "sha256:..." }
      ],
      "seal": {
        "backend": "tpm2|snp|tdx|noop",
        "kid": "...",
        "counter": 7
      },
      "nonce": "...",
      "ts": "2026-06-01T12:34:56Z",
      "jws": "eyJhbGc..."  // optional, present when sealed
    }

## 4. Access Control

- Reachable only via the localhost listener; no external exposure.
- Subject to standard GPA AuthZ: by default, any in-VM caller may read; rules can restrict if desired.
- Rate-limited (1 req/s per caller cgroup) to prevent measurement-driven side channels.

## 5. Signing

- When a hardware backend (1.2) is present, sign the canonical JSON payload + nonce with the attestation key (TPM AIK, SNP report, TDX QUOTE) and place the proof in `jws`.
- When `noop` backend, omit `jws`; tooling treats the response as unauthenticated diagnostic.
- Nonce is reflected verbatim; binding nonce + measurements prevents replay across calls.

## 6. Integration

- `proxy_agent/src/proxy/proxy_server.rs` — new handler before the generic forwarding path.
- Pulls fields from: build-time const (version), `policy_store.current()`, `redirector::loaded_programs()`, `key_keeper::sealing`.
- `gpa-doctor` (direction 6.2) and Azure Policy hook can both consume this.

## 7. Tests

- Probe returns expected fields; binary_hash matches actual file hash.
- With `tpm2` backend simulator, JWS validates with the AIK.
- Rate-limit test: 100 rapid requests → some 429s; payload counter stable.
- Mutate binary (in test harness) → next call returns the new hash; external monitor detects drift.

## 8. Risks

- **Information disclosure** of internal program ids. Mitigation: ids are not secrets; documented as public attestation surface.
- **Hot-loop callers** can heat up the agent. Mitigation: rate limit + cheap payload caching with nonce-only signing per request.

## 9. Milestones

| M   | Deliverable              | Exit                        |
|-----|--------------------------|-----------------------------|
| M1  | Unsigned endpoint        | Surfaces in `gpa-doctor`    |
| M2  | Signed via vTPM backend  | JWS verification documented |
| M3  | Defender for Cloud probe | Drift alerts configured     |

Detail design for direction 3.3. Parent: [Innovation-Directions.md](Innovation-Directions.md).
