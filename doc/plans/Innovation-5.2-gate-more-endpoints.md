## Sections

1.  [1. Overview](#overview)
2.  [2. Today](#today)
3.  [3. Destination drivers](#design)
4.  [4. KeyVault example](#kv)
5.  [5. ARM token example](#arm)
6.  [6. Config](#config)
7.  [7. Integration](#integration)
8.  [8. Tests](#tests)
9.  [9. Risks](#risks)
10. [10. Milestones](#milestones)

**GPA** · **Direction 5.2** · **New endpoints**

# Detailed Design — Gate Additional Cloud-Credential Endpoints

Generalize GPA from "IMDS + WireServer + HostGAPlugin" to a pluggable framework where additional cloud-credential endpoints (KeyVault MSI, ARM token, Storage MI) are governed by the same rule engine.

**Files affected:** new `proxy_agent/src/destinations/` module, canonical model (2.1), classifier (1.4).

> **Prerequisites:** [2.1 Canonical request](Innovation-2.1-canonical-request.md)[2.2 Typed policy (Cedar)](Innovation-2.2-typed-policy-cedar.md)

## 1. Overview & Goals

| Impact                          | Effort     | Risk             | Scope     |
|---------------------------------|------------|------------------|-----------|
| **High** bigger product surface | **Medium** | **Low** additive | **agent** |

### Goals

- One rule language to govern all cloud-credential egress.
- New endpoints add a driver module; no core changes.
- Authoring stays declarative.

## 2. Today

Destination IPs are hard-coded; classifier knows only IMDS/WireServer/HostGAPlugin URL shapes. Customers wanting to gate KeyVault calls have no path through GPA.

## 3. Destination Drivers

    pub trait DestinationDriver: Send + Sync {
        fn id(&self) -> &'static str;
        fn addresses(&self) -> &[SocketAddrSpec]; // IPs/ports for eBPF redirect map
        fn classify(&self, req: &CanonicalRequest) -> Option<Scope>;
        fn signer(&self) -> &dyn RequestSigner; // adds creds before forwarding
        fn upstream(&self, req: &CanonicalRequest) -> Upstream; // resolved URL/host
    }

- Built-in drivers: `imds`, `wireserver`, `hostga`.
- New drivers: `keyvault_msi`, `arm_token`, `storage_mi`.
- Drivers register their address specs at startup; eBPF redirect map is populated dynamically.

## 4. KeyVault MSI Example

- Destination spec: `*.vault.azure.net:443` (TLS-terminated; SNI used for routing).
- Classifier maps `GET /secrets/<name>?api-version=...` to scope `keyvault:secret:read:<vault>`.
- Signer fetches an AAD token using PoP-bound identity (no static client secrets in the agent).
- Rules: `{ identity: "billing-pod", scopes: ["keyvault:secret:read:billing-vault"] }`.

## 5. ARM Token Example

- Destination: `management.azure.com:443`.
- Classifier maps verb + resource provider to typed scopes (`arm:Microsoft.Compute/virtualMachines:read`).
- Scopes intentionally align with Azure RBAC action names so policy is reviewable side-by-side with RBAC role definitions.

## 6. Config

    {
      "destinations": {
        "enabled": ["imds","wireserver","hostga","keyvault_msi"],
        "keyvault_msi": { "vaults": ["billing-vault","app-vault"] }
      }
    }

- Enabled set drives which BPF redirect entries are loaded.
- Disabling a driver removes its redirect entries safely.

## 7. Integration

- Canonical model (2.1) needs to handle TLS-fronted destinations; for those, the agent terminates TLS using a fabric-provisioned cert (acceptable for the localhost hop).
- PoP (1.1) signing applies uniformly because tokens are minted with audience = driver id.
- OTel (3.2) labels include driver id.

## 8. Tests

- Per-driver classification golden vectors.
- Disable driver → no redirect entry → connection bypasses agent → fabric-side AAD rejects (defense-in-depth).
- End-to-end: pod calls KeyVault → agent enforces scope → upstream succeeds.

## 9. Risks

- **TLS termination at localhost** requires careful cert handling. Mitigation: certs generated per-boot, pinned by SPKI; never exposed off-host.
- **Endpoint churn** — APIs evolve. Mitigation: driver tables updateable independently of agent core.

## 10. Milestones

| M   | Deliverable                                | Exit                          |
|-----|--------------------------------------------|-------------------------------|
| M1  | Driver trait + refactor existing endpoints | No behavior change            |
| M2  | KeyVault MSI driver                        | Pilot customer                |
| M3  | ARM token driver                           | Mapped scopes align with RBAC |

Detail design for direction 5.2. Parent: [Innovation-Directions.md](Innovation-Directions.md).
