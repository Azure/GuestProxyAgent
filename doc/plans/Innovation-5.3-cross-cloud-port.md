## Sections

1.  [1. Overview](#overview)
2.  [2. Why cross-cloud](#why)
3.  [3. Abstraction](#abstraction)
4.  [4. AWS driver](#aws)
5.  [5. GCP driver](#gcp)
6.  [6. Packaging](#packaging)
7.  [7. Integration](#integration)
8.  [8. Tests](#tests)
9.  [9. Risks](#risks)
10. [10. Milestones](#milestones)

**GPA** · **Direction 5.3** · **Multi-cloud**

# Detailed Design — Cross-Cloud Port

Refactor signer + destinations into traits so community-supported drivers can govern AWS IMDSv2 and GCP metadata server traffic with the same eBPF chokepoint and rule engine. Positioning: a *metadata firewall for any cloud*.

**Files affected:** trait surfaces in `proxy_agent/src/destinations/` and `proxy_agent/src/key_keeper/`.

> **Prerequisites:** [4.2 Core eBPF unification](Innovation-4.2-core-unify-ebpf.md)[2.1 Canonical request](Innovation-2.1-canonical-request.md)

## 1. Overview & Goals

| Impact                     | Effort     | Risk             | Scope               |
|----------------------------|------------|------------------|---------------------|
| **Medium** ecosystem reach | **Medium** | **Low** additive | **agent + drivers** |

### Goals

- AWS / GCP metadata services can be governed by the same agent.
- Driver authors implement two traits; core remains untouched.
- Existing Azure behavior unchanged.

## 2. Why Cross-Cloud

- AWS IMDSv2 and GCP metadata both have the confused-deputy class of bugs that motivated GPA.
- Multi-cloud security teams want one mental model for "what can read instance credentials."
- Architecture (cgroup eBPF + identity-aware proxy) is cloud-neutral; only the signer and destination set are Azure-specific.

## 3. Abstraction Lines

    pub trait CloudPlatform: Send + Sync {
        fn name(&self) -> &'static str;
        fn destinations(&self) -> Vec<Box<dyn DestinationDriver>>;
        fn local_identity_source(&self) -> Box<dyn IdentitySource>; // node identity / instance role
    }

    pub trait RequestSigner: Send + Sync {
        fn sign(&self, req: &mut http::Request<Body>, dest: &Destination, caller: &ResolvedIdentity)
            -> Result<(), SignError>;
    }

- Azure platform implementation reuses today's logic.
- AWS / GCP implementations provided as separate crates so they can iterate independently.

## 4. AWS Driver

- Destinations: `169.254.169.254:80` (IMDS) and instance-profile endpoints.
- Signer: re-mints IMDSv2 session tokens with TTL bound by the caller's policy; rejects IMDSv1 PUT-less requests entirely.
- Caller-scoped tokens optionally bound to pod identity in EKS.

## 5. GCP Driver

- Destinations: `metadata.google.internal` (169.254.169.254) and `metadata.google.internal:80`.
- Mandates `Metadata-Flavor: Google` header presence (the standard GCP SSRF guard) and rejects requests without it.
- Authorization scopes derived from URL path (`/instance/service-accounts/default/token` → `gcp:identity:read`).

## 6. Packaging

- `gpa-azure`, `gpa-aws`, `gpa-gcp` binaries built from the same workspace with feature flags.
- Default release is `gpa-azure`; AWS/GCP builds maintained by community + signed via the same Sigstore process (3.4).

## 7. Integration

- Canonical model (2.1) cloud-neutral; `Destination::Unknown` becomes `Destination::CloudSpecific(&'static str)` for non-fabric endpoints.
- Capability scopes (1.4) namespaced per platform: `aws:sts:assume_role`, `gcp:storage:read`.
- Telemetry (3.2) labels include `cloud`.

## 8. Tests

- Conformance tests per driver against documented metadata API shapes.
- Regression: Azure default build behaves byte-identically to today's release.
- SSRF regression: cross-cloud known bypasses (e.g. `Metadata-Flavor` missing on GCP) blocked.

## 9. Risks

- **Community ownership** for non-Azure drivers — must clearly mark non-Azure builds as community-maintained.
- **License compatibility** for any cloud-specific SDKs — prefer plain HTTP clients.

## 10. Milestones

| M   | Deliverable                     | Exit                                      |
|-----|---------------------------------|-------------------------------------------|
| M1  | Trait refactor; Azure unchanged | All existing tests pass                   |
| M2  | AWS driver MVP                  | EC2 instance with IMDSv2 enforcement demo |
| M3  | GCP driver MVP                  | GCE instance demo                         |

Detail design for direction 5.3. Parent: [Innovation-Directions.md](Innovation-Directions.md).
