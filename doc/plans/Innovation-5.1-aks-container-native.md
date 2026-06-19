## Sections

1.  [1. Overview](#overview)
2.  [2. Problem](#problem)
3.  [3. Pod identity](#identity)
4.  [4. Azure Workload Identity primer](#workload-identity)
5.  [5. Token issuance](#tokens)
6.  [6. Deployment](#deploy)
7.  [7. Rule shape](#rules)
8.  [8. Integration](#integration)
9.  [9. Tests](#tests)
10. [10. Risks](#risks)
11. [11. Milestones](#milestones)

**GPA** · **Direction 5.1** · **AKS**

# Detailed Design — Kubernetes / AKS-native Mode

Run GPA per node as a DaemonSet; map the eBPF-captured `cgroup_id` for each connect to a Kubernetes pod identity. Issue pod-scoped tokens via Azure Workload Identity instead of handing back the node-MI token — closes the "pod steals node MI" class of attack.

**Prerequisite eBPF change:** the audit map entry must include `cgroup_id` (see [4.2 Core eBPF unification](Innovation-4.2-core-unify-ebpf.md)). Today's `sock_addr_audit_entry` only carries `process_id` — see [linux-ebpf/socket.h](../linux-ebpf/socket.h).

**Files affected:** new `proxy_agent/src/k8s/` module, deployment manifests, integrates with PoP (1.1).

> **Prerequisites:** [4.2 Core eBPF unification](Innovation-4.2-core-unify-ebpf.md)[1.4 Capability scopes](Innovation-1.4-capability-scopes.md)[1.1 PoP tokens](Innovation-1.1-pop-tokens.md)

## 1. Overview & Goals

| Impact                           | Effort    | Risk                      | Scope                 |
|----------------------------------|-----------|---------------------------|-----------------------|
| **High** new surface, big market | **Large** | **Coordination with AKS** | **agent + ecosystem** |

### Goals

- A pod that calls IMDS gets a token scoped to *its* ServiceAccount, not the node identity.
- Operators write rules using familiar K8s identifiers (namespace, ServiceAccount, label selectors).
- Zero application code change for pods that already use Azure Workload Identity SDKs.

## 2. Problem

On an AKS node, any pod with hostNetwork or a permissive NetworkPolicy can `curl 169.254.169.254/metadata/identity/oauth2/token` and obtain the node managed identity. This is documented as the most common cluster-credential escalation. Existing mitigations are network-policy and Workload Identity but they are easily misconfigured.

## 3. Pod Identity Resolution

**Prerequisite (not yet implemented):** step 1 below requires extending the eBPF `sock_addr_audit_entry` to carry `cgroup_id` populated via `bpf_get_current_cgroup_id()`. Today the struct in [linux-ebpf/socket.h](../linux-ebpf/socket.h) (and the Windows counterpart in [ebpf/socket.h](../ebpf/socket.h)) only stores `process_id`. The field is proposed in the unified schema of [4.2 Core eBPF unification](Innovation-4.2-core-unify-ebpf.md). Until then, the agent must derive cgroup from `/proc/<pid>/cgroup` via the audit entry's `process_id` (slower, racy for short-lived PIDs).

1.  eBPF audit map provides `cgroup_id` for each connect *(post-4.2)*; pre-4.2 fallback uses `process_id` + `/proc/<pid>/cgroup`.
2.  Agent reads `/proc/<pid>/cgroup` + CRI socket (`containerd` / `cri-o`) to map cgroup → container ID → pod.
3.  Pod metadata (namespace, name, ServiceAccount, labels) is cached from the local kubelet pod-resources API and the `--pod-manifest-path` watch.
4.  Cache invalidated when pod sandbox is recreated; cached entries hold for ≤ 60 s after pod deletion to handle in-flight requests.

## 4. Azure Workload Identity — Primer

Azure Workload Identity (AWI) is the upstream Kubernetes-native way for pods to authenticate to Entra ID (Azure AD) **without storing secrets**. GPA's AKS mode consumes AWI as the identity source — the projected ServiceAccount token (or the resulting AAD token) becomes the caller identity bound to a pod, replacing host-level IMDS interception as the trust anchor.

### 4.1 How it works

1.  The AKS cluster publishes a public OIDC discovery document (`/.well-known/openid-configuration` + JWKS).
2.  Each pod gets a **projected ServiceAccount JWT** mounted by kubelet, signed by the cluster issuer.
3.  The pod (via Azure SDK `DefaultAzureCredential` / `WorkloadIdentityCredential`) exchanges that JWT at Entra ID's `/oauth2/v2.0/token` endpoint using the *federated credential* flow (`client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer`).
4.  Entra ID validates `iss` (cluster issuer URL) and `sub` (`system:serviceaccount:<ns>:<sa>`) against a **Federated Identity Credential** configured on the target App Registration / User-Assigned Managed Identity, and returns an AAD access token scoped to that workload.

End-to-end token exchange (baseline AWI, no GPA in the path):

sequenceDiagram autonumber participant Pod as Pod (Azure SDK) participant Kubelet participant Entra as Entra ID (AAD) participant Azure as Azure Resource  
(Key Vault / Storage / ARM) Kubelet-\>\>Pod: Mount projected SA JWT  
(iss = cluster OIDC, sub = system:serviceaccount:ns:sa) Pod-\>\>Pod: Read AZURE_FEDERATED_TOKEN_FILE +  
AZURE_CLIENT_ID / TENANT_ID (injected env) Pod-\>\>Entra: POST /oauth2/v2.0/token  
grant_type=client_credentials  
client_assertion_type=jwt-bearer  
client_assertion=\<SA JWT\> Entra-\>\>Entra: Validate iss + sub against  
Federated Identity Credential Entra--\>\>Pod: AAD access token (pod-scoped) Pod-\>\>Azure: API call with Bearer \<AAD token\> Azure--\>\>Pod: 200 OK

With GPA in AKS-mode (§5) synthesizing the IMDS response for legacy callers:

sequenceDiagram autonumber participant App as Legacy Pod  
(curl 169.254.169.254) participant eBPF as eBPF redirect  
(on node) participant GPA as GPA DaemonSet  
(node-local) participant CRI as containerd / CRI participant Entra as Entra ID (AAD) App-\>\>eBPF: GET /metadata/identity/oauth2/token eBPF-\>\>GPA: Redirect + cgroup_id, pid GPA-\>\>CRI: Resolve cgroup -\> container -\> pod CRI--\>\>GPA: namespace, ServiceAccount, labels GPA-\>\>GPA: Policy check (§7 grants)  
match k8s_pod principal alt allowed GPA-\>\>GPA: Read pod's projected SA JWT  
from kubelet token volume GPA-\>\>Entra: jwt-bearer exchange  
(SA JWT -\> AAD token) Entra--\>\>GPA: Pod-scoped AAD token GPA--\>\>App: IMDS-shaped JSON  
{access_token, expires_in, ...} else denied GPA--\>\>App: 403 + structured audit event end

### 4.2 Key pieces

| Component                         | Role                                                                                                                                                                                                            |
|-----------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **AKS OIDC issuer**               | Cluster publishes JWKS that Entra ID trusts.                                                                                                                                                                    |
| **ServiceAccount annotation**     | `azure.workload.identity/client-id: <app-id>` links SA → Entra app/UAMI.                                                                                                                                        |
| **Federated Identity Credential** | On the Entra app/UAMI: trusts tokens where `iss=<cluster issuer>` and `sub=system:serviceaccount:<ns>:<sa>`.                                                                                                    |
| **Mutating webhook**              | Injects `AZURE_*` env vars (`AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_FEDERATED_TOKEN_FILE`, `AZURE_AUTHORITY_HOST`) and the projected token volume into pods labeled `azure.workload.identity/use: "true"`. |
| **Azure SDK credential**          | Performs the JWT-bearer exchange transparently.                                                                                                                                                                 |

### 4.3 Why it matters (vs. predecessors)

- **No secrets** — replaces client-secret-based service principals.
- **Supersedes AAD Pod Identity v1** (deprecated May 2024), which used the NMI/MIC DaemonSets to intercept IMDS — brittle, racy at pod startup, and the very pattern this innovation hardens.
- **Per-pod identity** — each ServiceAccount maps to a distinct Entra identity, enabling least privilege.
- **Cloud-agnostic shape** — same OIDC federation model used by GitHub Actions, GKE, EKS.

### 4.4 Relevance to GPA

- GPA *does not replace* AWI — it complements it: pods that already use the AWI SDK keep working unchanged, and GPA additionally enforces a node-side policy so that **even compromised or misconfigured pods cannot fall back to the node MI** via raw IMDS.
- For pods that bypass the SDK and hit `169.254.169.254` directly, GPA can synthesize an IMDS-shaped response backed by the pod's AWI-derived AAD token (see §5) — making AWI the default, transparently.
- The `sub` claim from the projected SA JWT (`system:serviceaccount:<ns>:<sa>`) is the same string GPA's rule engine matches in §7 grants — one identity model end-to-end.

### 4.5 References

- [AKS Workload Identity overview](https://learn.microsoft.com/azure/aks/workload-identity-overview)
- [azure-workload-identity project site](https://azure.github.io/azure-workload-identity/)
- [Entra ID workload identity federation](https://learn.microsoft.com/entra/workload-id/workload-identity-federation)

## 5. Token Issuance

- Pod's projected ServiceAccount token (OIDC, signed by cluster) is sent to AAD's federated credential endpoint; AAD returns a pod-scoped access token.
- The IMDS-shaped response is synthesized by GPA from this token: same JSON contract as IMDS `/identity/oauth2/token`.
- For non-Workload-Identity pods, behavior is policy-driven: *deny* (default), *node identity* (explicit opt-in), or a fixed allow-list.

## 6. Deployment

- **DaemonSet**: one privileged GPA pod per node; mounts host paths for cgroup, kubelet sockets, and the BPF FS.
- **NetworkPolicy** shipped as a sample: blocks all egress to 169.254/16 and 168.63/29 except from the GPA pod's host network.
- **Helm chart** + reference Azure Policy that pins the configuration.

## 7. Rule Shape

    {
      "version": 2,
      "grants": [
        {
          "principal": { "kind": "k8s_pod",
                         "namespace": "billing",
                         "serviceAccount": "frontend" },
          "scopes": ["imds:identity:read"]
        },
        {
          "principal": { "kind": "k8s_pod",
                         "namespace": "*",
                         "labelSelector": "tier=batch" },
          "scopes": ["imds:instance:read"]
        }
      ]
    }

- Builds on direction 1.4 capability scopes; principal types are pluggable.

## 8. Integration

- `proxy_agent/src/k8s/identity_resolver.rs` — cgroup → pod mapping with caching.
- `proxy_agent/src/k8s/token_issuer.rs` — exchanges projected SA token for AAD access token.
- Hooks into the authorizer after canonicalization to enrich `Claims` with pod identity.
- Telemetry: per-pod allow/deny counters with namespace+SA labels (bounded cardinality).

## 9. Tests

- Two pods in different namespaces — each gets only its own scoped token.
- Pod with no matching grant → deny + structured audit event.
- Pod sandbox restart → cache reflects new pod identity within a bounded window.
- NetworkPolicy fail-open test: even if NP misconfigured, GPA still authoritatively decides.

## 10. Risks

- **CRI sockets vary** across runtimes. Mitigation: pluggable resolver, support containerd + cri-o.
- **Race between connect and pod-metadata cache fill**. Mitigation: brief synchronous lookup on cache miss; bounded by timeout.
- **AKS coordination** on default install and policy library.

## 11. Milestones

| M   | Deliverable                              | Exit                                           |
|-----|------------------------------------------|------------------------------------------------|
| M1  | Identity resolver (cgroup → pod) + tests | Demo: per-pod identity in audit log            |
| M2  | Token issuer + IMDS contract             | Workload Identity SDK passes integration tests |
| M3  | Helm + NetworkPolicy + Azure Policy      | Pilot on internal cluster                      |
| M4  | GA in AKS as opt-in                      | SLA met for 1 month                            |

Detail design for direction 5.1. Parent: [Innovation-Directions.md](Innovation-Directions.md).
