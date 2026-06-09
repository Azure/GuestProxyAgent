## Sections

1.  [1. Overview](#overview)
2.  [2. Today](#today)
3.  [3. CLI design](#cli)
4.  [4. Library mode](#lib)
5.  [5. Output format](#output)
6.  [6. Integration](#integration)
7.  [7. Tests](#tests)
8.  [8. Risks](#risks)
9.  [9. Milestones](#milestones)

**GPA** · **Direction 6.1** · **DX**

# Detailed Design — Policy Simulator CLI

A `gpa policy simulate` command that takes a rule file, a request, and a caller identity, and reports the exact decision plus the matched rule and canonicalization trace. Used by operators in CI before rolling rules and by support engineers to reproduce production decisions.

**Files affected:** new `proxy_agent/src/bin/gpa_policy.rs`, library reuse from `proxy_agent/src/authorization/`.

> **Prerequisites:** [2.1 Canonical request](Innovation-2.1-canonical-request.md)[2.2 Typed policy (Cedar)](Innovation-2.2-typed-policy-cedar.md)[2.3 Versioned snapshots](Innovation-2.3-versioned-snapshots.md)

## 1. Overview & Goals

| Impact                       | Effort    | Risk    | Scope   |
|------------------------------|-----------|---------|---------|
| **Medium** author confidence | **Small** | **Low** | **CLI** |

### Goals

- Same engine, same answer — the CLI uses the production authorizer (no reimplementation).
- Round-tripable input: stdin / file / args.
- Reproduces decisions captured in the audit log byte-for-byte.

## 2. Today

Rule authors have no offline way to test rule changes against canonical request inputs short of standing up a VM. Production debugging requires reading source. There is no "explain" output.

## 3. CLI Design

    gpa policy simulate \
      --rules ./rules.json \
      --request ./req.json \
      --caller ./caller.json \
      [--explain] [--json]

| Flag        | Meaning                                              |
|-------------|------------------------------------------------------|
| `--rules`   | Rules JSON, same schema as production                |
| `--request` | HTTP request shape: method, url, headers, body       |
| `--caller`  | Caller identity: pid + measurement + cgroup + claims |
| `--explain` | Emit canonicalization steps and matched rule         |
| `--json`    | Machine-readable output for CI                       |

Exit codes: `0` allow, `1` deny, `2` error (malformed input).

## 4. Library Mode

    // proxy_agent_shared/src/policy_eval.rs
    pub fn simulate(rules: &RuleSet, req: &CanonicalRequest, caller: &ResolvedIdentity)
        -> SimulationResult { /* ... */ }

    pub struct SimulationResult {
        pub decision: Decision,         // Allow / Deny
        pub matched_rule: Option<RuleId>,
        pub trace: Vec<TraceStep>,      // each canonicalization step
    }

- Same crate consumed by unit tests across the workspace and by the future VS Code extension (6.3).

## 5. Output Format

    $ gpa policy simulate --rules r.json --request req.json --caller c.json --explain
    DECISION: deny
    RULE:     none matched
    TRACE:
      url.raw        = http://169.254.169.254/metadata/instance?api-version=2021-12-13
      url.host_norm  = 169.254.169.254
      destination    = imds
      path.norm      = /metadata/instance
      scope          = imds:instance:read
      caller.id      = sha256:abcd... (binary unmeasured)
      caller.scopes  = []
      reason         = caller.scopes did not include imds:instance:read

## 6. Integration

- Same canonical types from direction 2.1.
- Reads remote rule format and the local override (`proxy_agent/src/authorization/local_rules.rs`) so simulation mirrors production resolution order.
- Importable from CI: `gpa policy simulate --rules ./new.json --suite ./golden/` applies a directory of test cases.

## 7. Tests

- Round-trip: every entry in `doc/audit-samples/` reproduces exactly under simulation.
- CI corpus: golden test cases checked in; PR-blocking if rules diverge from expectations.
- Fuzz: random rules + random requests; cross-check engine vs. simulator.

## 8. Risks

- **Drift** between simulator and production. Mitigation: same library; CI gates on equality of decisions.

## 9. Milestones

| M   | Deliverable                | Exit                           |
|-----|----------------------------|--------------------------------|
| M1  | `simulate()` library + CLI | Reproduces 20 audit samples    |
| M2  | Golden test runner         | Used in CI                     |
| M3  | VS Code integration (6.3)  | Inline decisions while editing |

Detail design for direction 6.1. Parent: [Innovation-Directions.md](Innovation-Directions.md).
