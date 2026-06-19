## Sections

1.  [1. Overview](#overview)
2.  [2. SBOM](#sbom)
3.  [3. Reproducible build](#repro)
4.  [4. Signing (Sigstore)](#signing)
5.  [5. Setup verification](#verify)
6.  [6. CI pipeline](#pipeline)
7.  [7. Tests](#tests)
8.  [8. Risks](#risks)
9.  [9. Milestones](#milestones)

**GPA** · **Direction 3.4** · **Supply chain**

# Detailed Design — Supply-chain Hardening (SBOM, Reproducible Builds, Sigstore)

Produce an SBOM, make the build bit-reproducible, sign artifacts with Sigstore, and have `proxy_agent_setup` verify the signature before installing. Closes pentest `H1` (rollback to malicious previous-version archive).

**Files affected:** CI pipeline, `proxy_agent_setup/`, package build for Linux/Windows.

> **Prerequisites:** None — build-time / release-pipeline change, independent of agent runtime work.

## 1. Overview & Goals

| Impact                            | Effort     | Risk    | Scope             |
|-----------------------------------|------------|---------|-------------------|
| **Medium** compliance + integrity | **Medium** | **Low** | **build + setup** |

### Goals

- Auditable list of every transitive crate / system library shipped.
- Builds bit-reproducible across two builders; output hash matches what is signed.
- `proxy_agent_setup` refuses to install an unsigned, downgraded, or tampered archive.

## 2. SBOM

- Generate CycloneDX with `cargo-cyclonedx --format json` for each crate in the workspace, merged into a single document.
- Include the eBPF object files and their `clang` + `BTF` versions.
- Ship SBOM alongside the package (`gpa-<ver>.sbom.json`); attach to GitHub Release.

## 3. Reproducible Build

- Pin toolchain via `rust-toolchain.toml`.
- Vendor dependencies (`cargo vendor`); commit checksum.
- Strip build paths: `RUSTFLAGS="--remap-path-prefix $(pwd)=. -C link-arg=-Wl,--build-id=none"`.
- Pin clang version for eBPF objects.
- CI runs two independent builders; compares sha256 of all output artifacts; fail if not equal.

## 4. Signing (Sigstore / cosign)

- **Keyless signing** via `cosign sign --certificate-identity ...` backed by GitHub Actions OIDC token.
- Signed artifacts: the agent binaries, the extension `HandlerManifest`, eBPF objects, SBOM.
- Signatures + Rekor transparency entries are published in the same release.
- Optional in-toto attestation describing the build (commit, builder, dependencies).

## 5. Setup-side Verification

- `proxy_agent_setup` ships with the Sigstore root + the expected identity (the GitHub repo / workflow).
- Before any install / replace operation:
  1.  Verify cosign signature on the new archive.
  2.  Verify the Rekor inclusion proof (offline-verifiable bundle ships alongside the artifact).
  3.  Verify the new version is ≥ the previously-installed version recorded in `/var/lib/azure-proxy-agent/installed_version`; refuse downgrades unless an explicit operator override flag is provided.
- Any failure: leave the prior installation in place, write a structured audit event, exit non-zero.

## 6. CI Pipeline

PR build: cargo build / test / clippy / fmt cargo-cyclonedx (SBOM) cargo audit (advisory DB) Release build (two builders in parallel): build → diff hashes → must match cosign sign --keyless (each artifact) publish: artifacts + signatures + Rekor entries + SBOM

## 7. Tests

- Tamper a release archive → setup verification fails with explicit reason.
- Downgrade attempt → setup refuses; override flag accepted only via documented path.
- Reproducible-build diff job catches an intentionally inserted timestamp.
- Pentest `H1`: malicious rollback archive → REJECTED.

## 8. Risks

- **Reproducibility on Windows** is harder due to PDB embedding. Mitigation: strip PDBs from the verified path; archive separately for symbol servers.
- **Sigstore root rotation** requires periodic updates. Mitigation: ship root bundle; refresh on agent update.
- **Operator downgrade workflows** need a documented override; design it so the override itself is signed and audited.

## 9. Milestones

| M   | Deliverable                  | Exit                                            |
|-----|------------------------------|-------------------------------------------------|
| M1  | SBOM in CI artifacts         | Published with releases                         |
| M2  | Reproducible build job       | Two builders match for two consecutive releases |
| M3  | Cosign signing + Rekor       | Setup verifies on install in staging            |
| M4  | Downgrade refusal default-on | Pentest H1 PASS                                 |

Detail design for direction 3.4. Parent: [Innovation-Directions.md](Innovation-Directions.md).
