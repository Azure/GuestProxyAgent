## Sections

1.  [1. Overview](#overview)
2.  [2. Why Cedar](#why)
3.  [3. Entity model](#model)
4.  [4. Policy form](#policy)
5.  [5. Compile pipeline](#compile)
6.  [6. Integration](#integration)
7.  [7. Dual-eval](#dual)
8.  [8. Tests](#tests)
9.  [9. Risks](#risks)
10. [10. Milestones](#milestones)

**GPA** · **Direction 2.2** · **Policy**

# Detailed Design — Typed Policy Language (Cedar)

Replace the ad-hoc JSON rule shape with Cedar, a typed, analyzable, verified-evaluator policy language. Existing rules compile down to Cedar at load time; the matcher becomes a thin call into the Cedar evaluator over `CanonicalRequest`-derived entities.

**Files affected:** new `proxy_agent/src/proxy/policy/` module (Cedar adapter), integrates with 1.4 scopes and 2.1 canonical model.

> **Prerequisites:** [2.1 Canonical request](Innovation-2.1-canonical-request.md)[1.4 Capability scopes](Innovation-1.4-capability-scopes.md)

## 1. Overview & Goals

| Impact                     | Effort     | Risk                   | Scope          |
|----------------------------|------------|------------------------|----------------|
| **High** analyzable policy | **Medium** | **Low** shadow rollout | **agent only** |

### Goals

- Typed actions and entities — no more string-prefix matching surface.
- Formal analysis: "is policy P at least as strict as policy Q?" (Cedar's policy analyzer).
- Stable, versioned grammar; precise diagnostics on bad rules.
- Drop-in path: existing JSON rules continue to load via a compiler.

## 2. Why Cedar (vs Rego / OPA / Custom DSL)

| Option     | Pro                                                                                                  | Con                                                        |
|------------|------------------------------------------------------------------------------------------------------|------------------------------------------------------------|
| **Cedar**  | Rust-native crate, verified evaluator (Lean), built-in policy analyzer, deterministic, low footprint | Smaller community than OPA                                 |
| OPA / Rego | Huge ecosystem                                                                                       | Heavyweight runtime, Go dependency, less formal guarantees |
| Custom DSL | Tailored                                                                                             | Reinvents analyzer, parser, fuzz suite — long tail of bugs |

**Choice:** Cedar (`cedar-policy` crate). It runs in-process, has stable serialized form, and supports schema-based static type checking — directly enabling the analyses described in 1.4.

## 3. Entity Model

    // Cedar schema (simplified)
    entity Identity in [Role] = {
        name: String,
        userName?: String,
        groupName?: String,
        exeMeasurement?: { kind: String, value: String, enforce: Bool },
    };
    entity Role = { name: String };
    entity Service { };          // Imds, WireServer, HostGa
    entity Resource in [Service] = { service: Service, name: String };
    action read,write,invoke,enumerate appliesTo {
        principal: [Identity],
        resource:  [Resource],
        context: {
            url: String,         // canonical URL hash, not raw
            scope: String,       // from 1.4 capability classifier
            canon: { dest: String, segments: [String], query_keys: [String] }
        }
    };

## 4. Policy Form

    // Allow waagent to read goalstate
    permit (
        principal == Identity::"walinuxagent",
        action    == Action::"read",
        resource  == Resource::"WireServer::goalstate"
    );

    // Anyone may read instance metadata
    permit (
        principal,
        action    == Action::"read",
        resource  == Resource::"Imds::instance"
    );

    // Forbid identity matching that requires measurement when measurement missing
    forbid (principal, action, resource)
    when {
        principal.exeMeasurement has "enforce" &&
        principal.exeMeasurement.enforce &&
        context.canon.dest != "imds"   // example forbid condition
    };

## 5. Compile Pipeline

JSON rules (legacy v1) │ ▼ legacy_to_cedar // small translator; 1:1 mapping for permit shapes │ ▼ cedar::PolicySet // typed AST │ ▼ schema_validate // reject if a policy references unknown entities │ ▼ ArcSwap\<CompiledPolicy\>

- Compilation happens off the hot path (rule reload thread).
- Validation errors abort the swap; fail-closed: previous policy stays active.

## 6. Integration with 1.4 and 2.1

- **2.1 Canonical model** provides `CanonicalRequest`. The classifier (1.4) reduces it to a `Scope`.
- Cedar context = `{ url: hash, scope, canon: { dest, segments, query_keys } }`. Policies primarily key on `scope`; the rest is available for advanced rules.
- The evaluator returns `Decision::Allow | Deny` plus the matched policy id (for audit).

## 7. Dual-Evaluation Rollout

Same mechanism as direction 2.1:

- `policy.mode = off | shadow | enforce`.
- In shadow, legacy decides; Cedar's verdict is logged with policy-id reasoning.
- Cutover gate: ≥ 14 days zero divergence in production sample.

## 8. Tests

- Round-trip: any legacy rule file → Cedar policy set → produced JSON → same decisions on the request corpus.
- Cedar's own policy analyzer used in CI to verify invariants (e.g. no `permit` for `wireserver:*:write` by `principal: any`).
- Fuzz: random Cedar policies + random canonical requests — evaluator must not panic.
- Property test: enforce decisions monotone in policy strictness ("more strict policy never allows more").

## 9. Risks

- **Crate version churn.** Pin to a Cedar release line; vendor source if needed.
- **Customer-authored Cedar (future).** Out of scope for v1 — only auto-translated policies are accepted; advanced customers go through review.
- **Evaluator cost.** Cedar is fast (microseconds), but bench against the legacy matcher and gate p99.

## 10. Milestones

| M   | Deliverable                                | Exit                                                           |
|-----|--------------------------------------------|----------------------------------------------------------------|
| M1  | Cedar schema + translator for legacy rules | Lossless round-trip on test fixtures                           |
| M2  | Evaluator integrated behind feature flag   | Shadow-mode running in CI                                      |
| M3  | Dual-eval in production canary             | Zero divergence 14 days                                        |
| M4  | Enforce mode                               | Legacy matcher marked `#[deprecated]`                          |
| M5  | Remove legacy                              | Codebase reduction recorded; analyzer hooked into `gpa policy` |

Detail design for direction 2.2. Parent: [Innovation-Directions.md](Innovation-Directions.md).
