# Continuous review and adversarial verification

Status: draft local workflow; repository-owner review pending.
Contract revision: 1.

Use the existing GPA Coding -> GPA Guardian separation. Reviewers remain
read-only; early feedback does not approve the implementation or replace the
final integrated assessment. No new always-running process or PR event trigger
is introduced.

## Checkpoints

| Phase | When | Input and scope | Required output |
|---|---|---|---|
| `plan` | Before implementation for every task | Approved intent, proposed files/components, approach, invariants, target platforms, planned tests, uncertainties, and baseline snapshot | Design/operational gaps, risk reasons, human decisions, and initial failure hypotheses; no claim that code/tests exist |
| `increment` | After a meaningful implementation slice for R2/R3; also when scope, risk, or an invariant changes at any tier | Current snapshot, delta since last checkpoint, cumulative task paths, relevant context, and available validation | New slice risks, stale prior evidence, concrete adversarial test designs, and unresolved earlier findings |
| `final` | After implementation and available validation, before human review | Complete task delta, refreshed eight-section proof package, all checkpoint dispositions, adversarial test evidence, final snapshot | Integrated review of interactions across slices, deterministic failures/gaps, final findings, and human decisions |

R0/R1 normally use plan + final, not a review after every edit. For R2/R3, declare
logical increments in the plan; review each meaningful slice, not individual
lines/tool calls. A single-slice task may combine its increment and final review
only when the Guardian explicitly assesses both the slice and the full change
and returns a `final` result.

Use at most one initial assessment and one targeted reassessment per declared
checkpoint. This replaces the previous two-round limit for the entire task.
Do not rename a checkpoint to reset its budget. If feedback remains unresolved,
record it and request human direction rather than looping until "clean."
Wait without editing assessed files, and recheck snapshot identity on return.
New content invalidates conclusions about old content.

Plan review can proceed without a diff or executed tests; mark those as planned,
not missing implementation defects. Initial proof-package sections may contain
explicitly planned/unverified items. Final review requires the full implemented
task delta and current evidence, not just the last slice. If a final review is
unavailable, earlier reviews must not be presented as final verification.

All phases follow the [shared intake/result contract](agent-workflow.md).
Add `phase` (`plan`, `increment`, `final`) and caller-supplied `checkpoint_id`
to intake and results. Retain the full task snapshot plus the last-reviewed
snapshot for increment comparisons. Carry finding IDs/dispositions forward.

## Independent adversarial design, author-owned execution

At increment/final review, Guardian assumes the behavior is wrong and proposes
realistic ways it could fail, directly or through a bounded GPA Tests question.
Do not create a new agent fleet or manufacture five findings.

For every applicable hypothesis, return an `adversarial_cases` entry:

- `id`: stable scenario ID across checkpoints.
- `contract`: acceptance criterion or invariant being challenged.
- `preconditions`: platform, starting state, and feasible triggering conditions.
- `trigger`: deterministic event sequence/fault injection, including ordering.
- `expected_assertion`: observable result that distinguishes correct behavior.
- `test_design`: target test file/harness, setup, trigger, assertion, cleanup,
  and source/pseudocode where useful.
- `evidence`: existing test/source references or an explicit absence of coverage.
- `execution_state`: `proposed`, `implemented_not_run`, `passed`, `failed`,
  `unavailable`, or `not_applicable`, with reason/result reference.

The independent reviewer constructs the test design or candidate test code in
its response. GPA Coding inspects it, implements appropriate tests in the repo,
and runs them in an authorized environment. Reviewer tools do not change: no file
edits, shell commands, or direct test execution. The final Guardian checks the
assertions and supplied results independently; it must not claim personal
execution. A proposed test is not verified behavior.

Relevant GPA hypotheses include shutdown during reconnect/runtime replacement,
stale state after reconnect, duplicate notifications, suspend/resume, and restart
between persistence and acknowledgement. Consult
[regression contracts](common-regressions.md) instead of inventing incident history.
Use barriers, controlled clocks, mocks, or existing fault-injection seams where
available; do not rely on arbitrary sleeps to "prove" races absent.

Tests should fail for the hypothesized wrong behavior and pass for the intended
contract. Demonstrate that distinction where safe, without committing broken
production code. A test failure may identify a test/design error, environment
failure, or production defect: inspect the cause rather than assuming any one.
Use disposable approved environments for VM/kernel/service tests; never inject
faults into a developer's active services or production.

For non-runtime changes, challenge the actual artifact: broken links, malformed
agent configuration, incorrect metrics formulas, invalid input handling, or
stale evidence. Use reasoned Not applicable for unrelated lifecycle scenarios.

## Handoff and learning

In the proof package's Validation section, record checkpoint phase/ID/snapshot,
completeness, finding dispositions, and adversarial case/test/result mapping.
Keep unresolved hypotheses in Uncertainty, not silently counted as completed
verification. Do not write per-checkpoint tracking files unless requested.

Use [safe-decision metrics](safe-decision-metrics.md) to record actual human
attention, elapsed clocks, rework, finding dispositions, and observed outcomes.
Agents may report their actions but cannot invent human review time, retrospective
control data, or post-merge outcomes.
