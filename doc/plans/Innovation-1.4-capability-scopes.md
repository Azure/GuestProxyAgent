## Sections

1.  [1. Overview](#overview)
2.  [2. Scope model](#model)
3.  [3. URL classifier](#classifier)
4.  [4. Rule schema](#schema)
5.  [5. Evaluation](#eval)
6.  [6. Static analysis](#analysis)
7.  [7. Migration](#migration)
8.  [8. Tests](#tests)
9.  [9. Risks](#risks)
10. [10. Milestones](#milestones)

**GPA** · **Direction 1.4** · **AuthZ**

# Detailed Design — Capability-style Scoped Grants

Move from "path X is allowed for identity Y" to verifiable, typed scopes (e.g. `imds:identity:read`). A classifier maps each request to a typed `(Action, Resource)` pair; the matcher just checks scope containment.

**Files affected:** new `proxy_agent/src/proxy/scope/` module, integrates with the canonical request model (2.1).

> **Prerequisites:** [2.1 Canonical request](Innovation-2.1-canonical-request.md)

## 1. Overview & Goals

| Impact                         | Effort     | Risk                   | Scope          |
|--------------------------------|------------|------------------------|----------------|
| **High** enables analyzability | **Medium** | **Low** additive layer | **agent only** |

### Goals

- Decouple "what the customer wants to allow" from "how the URL happens to be spelled."
- Make rules statically analyzable: "does any rule grant unauthenticated WireServer write?"
- Eliminate URL-encoding bypass categories because the classifier normalizes once per endpoint.

## 2. Scope Model

    // proxy_agent/src/proxy/scope/mod.rs
    pub struct Scope {
        pub service: ServiceId,     // imds | wireserver | hostga
        pub resource: ResourceId,   // instance | identity | goalstate | extensions | ...
        pub action: ActionId,       // read | write | invoke | enumerate
        pub qualifier: Option<String>, // e.g. tenant id, extension name
    }

    impl Scope {
        pub fn satisfies(&self, required: &Scope) -> bool;
        // exact match, or wildcard semantics: read < write < admin; * matches all.
    }

Wire form: `service:resource:action[:qualifier]` e.g. `imds:identity:read`, `wireserver:goalstate:read`, `hostga:extensions:status:write:GuestProxyAgent`.

## 3. URL Classifier

A single table maps `(Destination, CanonicalRequest)` → required `Scope`. Built from the canonical model (2.1) so the matcher never re-parses strings.

    // proxy_agent/src/proxy/scope/classifier.rs
    pub fn required_scope(req: &CanonicalRequest) -> Result<Scope, ClassifierError>;

    // Backing table (compile-time built):
    const IMDS_TABLE: &[(&[&str], Method, Scope)] = &[
        (&["metadata","instance"],            Method::GET,  scope!("imds:instance:read")),
        (&["metadata","identity","oauth2","token"], Method::GET, scope!("imds:identity:read")),
        (&["metadata","attested","document"], Method::GET,  scope!("imds:attested:read")),
        // ...
    ];

### 3.1 Unknown URLs

- Anything not in the table maps to a synthetic `imds:unknown:read` scope.
- Default rules deny unknown scopes; explicit allow-listing per scope keeps rules small.

## 4. Rule Schema

    {
      "version": 2,
      "grants": [
        {
          "identity": "walinuxagent",
          "scopes": ["wireserver:goalstate:read", "wireserver:extensions:status:write"]
        },
        {
          "identity": "*",
          "scopes": ["imds:instance:read"]
        }
      ]
    }

Legacy `privileges + roles + assignments` shape is compiled down to capability grants at load time.

## 5. Evaluation

    fn authorize(req: &CanonicalRequest, caller: &ResolvedIdentity) -> Decision {
        let required = classifier::required_scope(req)?;
        let granted  = caller.scopes(); // pre-computed at rule-load time
        if granted.iter().any(|g| g.satisfies(&required)) {
            Decision::Allow { matched_scope: required }
        } else {
            Decision::Deny { required }
        }
    }

- O(N_scopes) per request where N_scopes is typically ≤ 10 — much smaller than today's privilege list.
- Match metadata captured in the decision so audit and divergence telemetry can attribute precisely.

## 6. Static Analysis

Because scopes are typed and finite, a separate `gpa policy analyze` command can answer:

- "Which identities can write to WireServer?"
- "Are there grants for the synthetic `*:unknown:*` scope?"
- "Which scopes are unreachable given the URL classifier?"
- "Diff between current and proposed rule files in scope-space, not text-space."

## 7. Migration

1.  **Phase A:** ship classifier + scope evaluator behind feature flag; dual-evaluate (legacy + scope), log divergences (re-use the same shadow-mode plumbing as 2.1).
2.  **Phase B:** tool to auto-convert legacy `privileges` to scope grants; require human review of conversions.
3.  **Phase C:** flip enforcement to scopes; keep legacy adapter for one release.
4.  **Phase D:** delete legacy path.

## 8. Tests

- Property test: every canonical request produces exactly one required scope (totality).
- Golden vectors: every documented IMDS / WireServer endpoint has a stable scope mapping pinned in tests.
- Differential test: scope-evaluator decision == legacy decision for every request in a captured production trace.
- Pentest re-runs: `D1`/`C7` bypasses produce the same scope as the canonical form, so they cannot escape via spelling tricks.

## 9. Risks

- **Classifier table drift** when IMDS adds endpoints. Mitigation: scope mapping ships with the agent; an unknown URL falls into `:unknown:` and is denied by default — fail-closed.
- **Customer rules written in old style.** Mitigation: dual-run for one release; provide auto-converter.

## 10. Milestones

| M   | Deliverable                               | Exit                                         |
|-----|-------------------------------------------|----------------------------------------------|
| M1  | Scope + classifier types + table for IMDS | Unit tests green for IMDS endpoints          |
| M2  | Table for WireServer + HostGAPlugin       | Full endpoint coverage doc reviewed          |
| M3  | Dual-eval in shadow mode                  | Zero divergence vs legacy                    |
| M4  | Auto-converter + enforce                  | One release in enforce mode without rollback |
| M5  | Legacy removal + `policy analyze`         | Codebase reduction recorded                  |

Detail design for direction 1.4. Parent: [Innovation-Directions.md](Innovation-Directions.md).
