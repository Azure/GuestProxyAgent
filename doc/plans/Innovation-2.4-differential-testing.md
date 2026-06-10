## Sections

1.  [1. Overview](#overview)
2.  [2. Design](#design)
3.  [3. Mutator catalog](#mutators)
4.  [4. Runner](#runner)
5.  [5. Integration](#integration)
6.  [6. Failure handling](#failmode)
7.  [7. Perf budget](#perf)
8.  [8. Tests](#tests)
9.  [9. Risks](#risks)
10. [10. Milestones](#milestones)

**GPA** · **Direction 2.4** · **Self-test**

# Detailed Design — Differential & Property Testing of Rules

For each rule loaded, auto-generate "evil twin" requests (case toggles, percent-encoded slashes, IPv6 forms, Unicode confusables). Run the matcher on each variant; any mismatch with the canonical request indicates a latent bypass and blocks the rule from going live.

**Files affected:** new `proxy_agent/src/proxy/policy/selftest/` module, hooked into `local_rules.rs` reload path and CI.

> **Prerequisites:** [2.1 Canonical request](Innovation-2.1-canonical-request.md)[2.2 Typed policy (Cedar)](Innovation-2.2-typed-policy-cedar.md)

## 1. Overview & Goals

| Impact                                | Effort    | Risk    | Scope          |
|---------------------------------------|-----------|---------|----------------|
| **Medium** proactive bypass detection | **Small** | **Low** | **agent + CI** |

### Goals

- Every rule reload runs a self-test that proves the rule is robust to known bypass patterns.
- Same self-test runs in CI on the repository's bundled rule files.
- Fail-closed: a rule that fails self-test is rejected during reload, and the previous policy remains active.

## 2. Design

For every rule, the runner derives a small set of synthetic requests:

1.  **Canonical request** matching the rule's intent exactly.
2.  **Evil twins** — produced by mutators that should normalize to the same canonical form per 2.1.
3.  **Negative twins** — close-but-not-matching requests that should be rejected by the rule.

The runner asserts: *canonical and evil twins produce the same decision; negative twins produce a different decision.*

## 3. Mutator Catalog

| Mutator                              | Example                                 | Pentest mapping                    |
|--------------------------------------|-----------------------------------------|------------------------------------|
| Case-toggle                          | `/Metadata/Identity`                    | D1                                 |
| Percent-encoded slash                | `/metadata%2Fidentity`                  | D1                                 |
| Double-encoding                      | `%252e%252e`                            | D1                                 |
| Trailing dot / whitespace            | `/metadata./`                           | D1                                 |
| Matrix params                        | `/metadata;jsessionid=x/identity`       | D1                                 |
| Embedded query via `%3F`             | `/metadata/identity%3Fapi-version=2018` | D1 (now rejected by canonicalizer) |
| IPv4 numeric                         | `http://2852039166/...`                 | C7                                 |
| IPv4 hex                             | `http://0xa9fea9fe/...`                 | C7                                 |
| IPv4 octal                           | `http://0251.0376.0251.0376/...`        | C7                                 |
| IPv4-mapped IPv6                     | `http://[::ffff:169.254.169.254]/...`   | C7                                 |
| Unicode confusables in identity name | `"r\u00f6ot"` vs `"root"`               | D3                                 |

## 4. Runner

    pub struct SelfTestReport {
        pub rule_id: String,
        pub passed: bool,
        pub failures: Vec<SelfTestFailure>,
    }

    pub struct SelfTestFailure {
        pub mutator: &'static str,
        pub canonical_decision: Decision,
        pub mutated_decision: Decision,
        pub mutated_uri: String,
        pub reason: &'static str,
    }

    pub fn selftest(policy: &CompiledPolicy) -> Vec<SelfTestReport>;

- Runs over the compiled policy, not the raw JSON, so it tests the actual evaluator path.
- Per-rule budget: ≤ 1 ms for 30 mutators; total budget ≤ 100 ms per reload for typical rule counts.

## 5. Integration

- **Reload path** (`local_rules.rs`): selftest runs before `PolicyStore::install`. Failure → install aborted, previous snapshot stays.
- **CI**: `cargo test --features selftest -- --include-ignored` runs against every fixture rule file in `config/`.
- **Operator visibility**: `status.json` exposes `last_selftest_failures`; `gpa-doctor` (direction 6.2) surfaces this prominently.

## 6. Failure Handling

- Selftest failures during reload are non-fatal for serving (we keep the prior policy) but block the new one.
- Selftest failures in CI are fatal — block PR merges. Authors fix either the rule or the mutator.
- Each failure includes a *minimum-reproducer URI* for fast triage.

## 7. Performance

- Selftest runs off the hot path (rule-reload thread).
- Time-bounded; if budget exceeded, emit a warning and continue (don't deadlock on a pathological rule set).

## 8. Tests for the selftest itself

- Inject an intentionally-buggy matcher (e.g. case-sensitive substring) and confirm selftest catches the bypass.
- Inject a "perfect" matcher and confirm selftest reports zero failures.
- Property test: for any rule, mutated canonical request and original canonical request canonicalize to equal forms.

## 9. Risks

- **False positives** if a mutator generates a request that legitimately differs semantically. Mitigation: maintain mutators in a curated list, not generic fuzz.
- **Rule writers blocked** by unfamiliar failures. Mitigation: the report includes the reproducer URI and the mutator name; `gpa policy simulate` (6.1) provides a single-step debugger.

## 10. Milestones

| M   | Deliverable                                    | Exit                                        |
|-----|------------------------------------------------|---------------------------------------------|
| M1  | 10 mutators + report type                      | Runs in CI on bundled rules                 |
| M2  | Reload-path integration                        | Install aborted on failure; covered by test |
| M3  | Operator surface (`status.json`, `gpa-doctor`) | Documented in operator guide                |

Detail design for direction 2.4. Parent: [Innovation-Directions.md](Innovation-Directions.md).
