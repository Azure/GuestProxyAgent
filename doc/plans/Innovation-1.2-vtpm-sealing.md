## Sections

1.  [1. Overview](#overview)
2.  [2. Today](#today)
3.  [3. Sealing design](#design)
4.  [4. Backends](#backends)
5.  [5. PCR / report bindings](#pcrs)
6.  [6. Provisioning flow](#provision)
7.  [7. Unseal flow](#unseal)
8.  [8. Integration](#integration)
9.  [9. Tests](#tests)
10. [10. Risks](#risks)
11. [11. Milestones](#milestones)

**GPA** · **Direction 1.2** · **Hardware root of trust**

# Detailed Design — vTPM / CVM Attestation Binding for the Latched Key

Seal the latched key to a hardware root of trust so that copying `/var/lib/azure-proxy-agent/keys/*` to another VM, restoring an older snapshot, or booting a tampered image yields an unrecoverable key blob.

**Files affected:** new `proxy_agent/src/key_keeper/sealing/` module, `proxy_agent/src/key_keeper/key.rs`, `proxy_agent/src/provision.rs`.

> **Prerequisites:** None — foundational TPM/sealing layer. Enables [1.3 Measured identity](Innovation-1.3-measured-identity.md) and [3.3 Self-attestation](Innovation-3.3-self-attestation.md).

## 1. Overview & Goals

| Impact                              | Effort     | Risk                | Scope                           |
|-------------------------------------|------------|---------------------|---------------------------------|
| **High** kills key-theft & rollback | **Medium** | **Hardware matrix** | **agent + fabric KID registry** |

### Goals

- Stolen key blob on disk cannot be used on a different VM (pentest `B3`).
- Older sealed blob cannot be replayed after rotation (pentest `E5`).
- Booting a tampered kernel/agent invalidates the seal and forces re-provisioning.
- CVM (SEV-SNP / TDX) deployments get cryptographic guest-identity binding.

### Non-goals

- Generic vTPM management or attestation service implementation — we consume Azure's MAA (Microsoft Azure Attestation) where applicable.
- Migrating the HMAC algorithm itself (PoP work is direction 1.1).

## 2. Today's Behavior

The latched key is written as a plain file under `/var/lib/azure-proxy-agent/keys/` with mode 0600. Any root-level compromise reads it; a snapshot of the directory survives migration to a different VM; a previous file restored after rotation works against the fabric until rotation logic catches up.

## 3. Sealing Design

### 3.1 On-disk format

    // .sealed file format (binary, versioned)
    struct SealedBlob {
        magic: [u8;4]           = b"GSP1",
        version: u8             = 1,
        backend: u8             = TPM2 | SNP | TDX | NOOP,
        kid: [u8;16],           // key id, same as PoP header kid
        counter: u64,           // monotonic, signed by backend (anti-rollback)
        attestation_ref: [u8;32], // sha256 of attestation report or PCR digest
        ciphertext_len: u32,
        ciphertext: [u8],       // AES-256-GCM-SIV under a backend-managed KEK
        tag_len: u32,
        tag: [u8],              // backend-specific attestation/seal proof
    }

### 3.2 Layered keys

- **LatchedKey** (random, 32 bytes) — what the rest of GPA already uses.
- **KEK** (key-encryption key) — derived inside the backend (vTPM sealed object, SNP-derived key, or TDX MRTD-bound key).
- Plaintext LatchedKey is unwrapped only into protected memory (`mlock` + `zeroize::Zeroizing`) and never reaches disk.

## 4. Backends

| Backend | Crate          | Detection                              | Notes                                                                                                    |
|---------|----------------|----------------------------------------|----------------------------------------------------------------------------------------------------------|
| `tpm2`  | `tss-esapi`    | `/dev/tpmrm0` on Linux; TBS on Windows | Uses TPM 2.0 sealed object + PolicyPCR.                                                                  |
| `snp`   | `sev` + custom | `SEV_STATUS` MSR / `/dev/sev-guest`    | Derives KEK from SNP `VLEK`/`VCEK`; attestation report embeds VM measurement.                            |
| `tdx`   | `tdx-attest`   | TDX guest module device                | KEK from TDX RTMR; attestation report from TD QUOTE.                                                     |
| `noop`  | —              | fallback                               | Encrypts with a host-stored DPAPI / Linux kernel keyring entry; explicitly weaker, only for legacy SKUs. |

### 4.1 Backend trait

    pub trait SealingBackend: Send + Sync {
        fn id(&self) -> BackendId;
        fn seal(&self, plaintext: &[u8], policy: &SealPolicy)
            -> Result<SealedBlob, SealError>;
        fn unseal(&self, blob: &SealedBlob)
            -> Result<Zeroizing<Vec<u8>>, SealError>;
        fn attest(&self, nonce: &[u8]) -> Result<AttestationDoc, SealError>;
        fn monotonic_counter_get(&self) -> Result<u64, SealError>;
        fn monotonic_counter_increment(&self) -> Result<u64, SealError>;
    }

## 5. PCR / Report Bindings

### 5.1 TPM2 (PCR selection)

| PCR    | Measures                               | Why                            |
|--------|----------------------------------------|--------------------------------|
| 0      | Firmware code                          | Detect firmware swap.          |
| 4      | Bootloader                             | Detect bootloader swap.        |
| 7      | Secure Boot policy                     | Detect SB disable / new keys.  |
| 8      | Kernel + initrd (via grub measurement) | Detect kernel swap.            |
| 9 / 14 | IMA log root                           | Detect agent binary tampering. |

### 5.2 SNP / TDX

- Bind the seal to the launch measurement (`MEASUREMENT` field in SNP report, `MRTD`+`RTMR` in TDX QUOTE).
- Include the agent binary digest in `REPORT_DATA`/`RTMR3` so post-launch upgrades trigger a controlled re-seal rather than failing open.

### 5.3 Anti-rollback counter

- TPM: NV index with `NVCounter`; agent reads and compares against blob counter on every unseal.
- SNP/TDX: use the agent's own VM-persistent virtual counter file *plus* a hash of the latest signed counter embedded in the next attestation request to the fabric (anchor to fabric monotonicity).

## 6. Provisioning Flow

agent fabric │ probe backend ───────────────────► │ ◄──── selected: tpm2 │ │ attest(nonce_from_fabric) ─────► │ ◄──── ack + bound_kid │ │ generate LatchedKey (CSPRNG) │ seal(LatchedKey, policy{PCR set, counter+1}) → SealedBlob │ persist SealedBlob to disk │ register(bound_kid, attestation_doc) ─► │ ◄──── 200 OK

## 7. Unseal Flow on Service Start

1.  Read `.sealed` blob; reject if magic/version mismatch (fail-closed).
2.  Call `backend.unseal`; on policy mismatch (PCR changed), enter **reprovision** state, request a fresh latch from fabric, do not serve traffic until success.
3.  Verify `blob.counter ≥ backend.monotonic_counter_get()`; equal allowed once per boot, lesser rejected as rollback.
4.  Place plaintext in `Zeroizing<Vec<u8>>`, `mlock` the buffer.
5.  Erase plaintext on shutdown / SIGTERM (already happens with `zeroize` drop).

## 8. Integration Points

- `proxy_agent/src/key_keeper/key.rs` — add `load_sealed` / `store_sealed`, gated on a config flag. Existing plain-file path is the `noop` backend.
- `proxy_agent/src/provision.rs` — attestation handshake; expose `Reprovisioning` state to the status endpoint.
- `proxy_agent/src/service/` — surface backend id and `kid` in startup log + status JSON.
- Build: feature flags `seal-tpm2`, `seal-snp`, `seal-tdx` so distros without those crates still build.

## 9. Tests

- **Hermetic backend simulator** for CI — implements the trait with in-memory PCRs to validate flows without real hardware.
- Modify a simulated PCR after seal → unseal fails → agent enters reprovision; verify it serves nothing in the interim (closes a fail-open window).
- Rollback test: write `counter-1` blob → unseal rejected with `SealError::Rollback`.
- Cross-VM test in staging: snapshot `/var/lib/azure-proxy-agent` from VM-A, place on VM-B → unseal fails with policy mismatch.
- Tamper kernel cmdline → next boot PCR9 differs → reprovision triggered.
- Pentest `E5`: rollback rejected; `B3`: stolen blob useless on new VM.

## 10. Risks & Mitigations

- **Routine kernel updates trigger reprovision storms.** Mitigation: ride the OS update pipeline; pre-stage a new seal during update window before old kernel reboots.
- **Backend crate maturity.** Mitigation: ship behind feature flags; default to `noop` on legacy SKUs.
- **Latency at start.** TPM unseal ≈ 20–50 ms; acceptable because it's once per boot.
- **NV counter exhaustion (TPM).** Mitigation: increment only on rotation, not on each boot.

## 11. Milestones

| M   | Deliverable                        | Exit                                           |
|-----|------------------------------------|------------------------------------------------|
| M1  | Trait + `noop` + simulator backend | All current tests still pass                   |
| M2  | TPM2 backend behind `seal-tpm2`    | Tamper/rollback tests PASS on a TPM-enabled VM |
| M3  | SNP + TDX backends                 | Cross-VM pentest `B3` PASS on CVM SKUs         |
| M4  | Default-on for CVM SKUs            | Field error rate \< 0.001 % for 14 days        |

Detail design for direction 1.2. Parent: [Innovation-Directions.md](Innovation-Directions.md).
