## Sections

1.  [1. Overview](#overview)
2.  [2. Today](#today)
3.  [3. Record format](#format)
4.  [4. Chain semantics](#chain)
5.  [5. Anchoring](#anchor)
6.  [6. Rotation](#rotation)
7.  [7. Verifier tool](#verify)
8.  [8. Integration](#integration)
9.  [9. Tests](#tests)
10. [10. Risks](#risks)
11. [11. Milestones](#milestones)

**GPA** · **Direction 3.1** · **Audit integrity**

# Detailed Design — Hash-chained, Append-only Audit Log

Wrap the connection log with a Merkle/hash chain so any post-hoc tampering (deletion, edit, injection) breaks the chain and is detectable. Optional anchoring to an external transparency log makes the chain non-repudiable.

**Files affected:** `proxy_agent/src/common/logger` (Sink abstraction), `proxy_agent/src/proxy/proxy_summary.rs`, new `proxy_agent/src/audit/chain.rs`.

> **Prerequisites:** None — foundational audit layer. Required by [3.2 OTel export](Innovation-3.2-otel-export.md), [3.3 Self-attestation](Innovation-3.3-self-attestation.md), [6.2 GPA doctor](Innovation-6.2-gpa-doctor.md).

## 1. Overview & Goals

| Impact                     | Effort    | Risk    | Scope     |
|----------------------------|-----------|---------|-----------|
| **Medium** compliance + IR | **Small** | **Low** | **agent** |

### Goals

- Tampering with the audit log is detectable; addresses pentest `F2` (log injection) and `F3` (rotation race).
- No central service required for tamper-evidence; anchoring optional.
- Negligible runtime overhead (≤ 1 µs / record).

## 2. Today

Connection log is a plain newline-delimited JSON file. A root attacker can edit or delete entries; an attacker who can inject newlines into a process name or URL can forge entries that pass downstream parsers.

## 3. Record Format

    // One line per record (NDJSON)
    {
      "seq": 175201,
      "ts": "2026-06-01T12:34:56.789Z",
      "kind": "decision|policy_install|service|...",
      "payload": { ... arbitrary ... },
      "prev_hash": "b3:9f8a...",      // hash of record seq-1 (full line bytes)
      "hash": "b3:2c1d..."            // sha256 of (prev_hash || canonical_json(payload) || ts || seq)
    }

- **Canonical JSON** for the payload to ensure deterministic hashing across runtimes.
- **Length-prefix** embedded in the line (start of line: `16-hex-len `) to defeat newline-injection — parsers ignore content past `len`.
- Every record carries its sequence number; gaps are immediately detected.

## 4. Chain Semantics

- The chain is a forward hash list — minimal compute, sufficient for tamper-evidence.
- Periodic "checkpoint" records (every N records or T seconds) include a Merkle root over the latest segment to allow O(log N) inclusion proofs later.
- `prev_hash` at sequence 0 is a fixed sentinel containing service start time, binary hash, and policy epoch at startup.

## 5. Anchoring (optional)

- Periodic checkpoint hashes can be:
  - Submitted to a Rekor-compatible transparency log.
  - Sent to Azure Monitor as a signed custom-log entry, signed by the VM's vTPM AIK if available.
  - Mirrored locally to a read-only directory under `/var/log/azure-proxy-agent/checkpoints/` for offline forensic use.
- Anchoring failures do not block log writes — fail-open for availability, log telemetry instead.

## 6. Rotation (closes F3)

- Rotation creates a new file `ProxyAgent.Connection.NNN.log`; the first record in NNN+1 is a "rotation" record that includes the final `hash` of NNN.
- Open file via `O_NOFOLLOW | O_CREAT | O_EXCL` to defeat symlink swap.
- Permissions enforced as 0600 root:root via `fchmod` after creation and verified before each append.
- Rotation never overwrites; old files are renamed atomically.

## 7. Verifier Tool

`gpa audit verify [--from N] [--to M] [--anchor file]`

- Walks the chain, validates each record's hash; reports first divergence with sequence numbers and byte offsets.
- `--anchor` validates against a fetched checkpoint file (or rekor inclusion proof).
- Exits non-zero on tamper-detection; suitable for SIEM integration.

## 8. Integration

- Logger refactored to a `trait Sink` with implementations: `PlainFileSink` (legacy), `ChainedFileSink`, `SyslogSink`, `TestSink`.
- Choice via config `audit.sink = "chained"`; default off in v1.
- Connection log writer + service log writer share the sink trait so both gain integrity.

## 9. Tests

- Append, verify → pass. Edit one byte of payload → verifier reports failure at that sequence.
- Delete a record line → next record's `prev_hash` mismatch detected.
- Newline injection in process name → verifier still parses correctly because length-prefix bounds the record.
- Symlink swap pre-rotation → `O_NOFOLLOW` open fails; alert event written to previous file before exit.
- Pentest `F2`/`F3` reruns: PASS.

## 10. Risks

- **Performance:** hashing every record adds ~1 µs; bounded.
- **Recovery after crash:** last partial line skipped on restart; checkpoint emitted noting the gap.
- **Disk full:** chain still self-consistent; rotation policy must avoid pruning without a verified anchor.

## 11. Milestones

| M   | Deliverable                        | Exit                                       |
|-----|------------------------------------|--------------------------------------------|
| M1  | Sink trait + plain + chained impls | Logger refactor merged behind feature flag |
| M2  | Verifier CLI                       | F2/F3 pentest PASS                         |
| M3  | Optional Rekor anchoring           | Anchor docs published                      |

Detail design for direction 3.1. Parent: [Innovation-Directions.md](Innovation-Directions.md).
