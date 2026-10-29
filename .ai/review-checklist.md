# Reviewer checklist

Status, requested owner role, and evidence revision: [context registry](context.json).
This applies the [Guardian pilot proposal](../doc/plans/AI_PR_Guardian_Pilot_Plan.md);
it does not configure branch protection or authorize automated approval.

## Select context and risk before implementation

- [ ] Read the [index](README.md), select relevant topics, and verify linked source
  at the assessed commit. Identify missing or stale context.
- [ ] Capture intent, linked requirements, acceptance criteria, exclusions, planned
  files, preserved invariants, affected platforms, and uncertainties.
- [ ] Keep one logical change; prefer 100-300 meaningful changed lines where
  practical, but do not split behavior from its validation artificially.
- [ ] Assign a risk tier with reasons. R0: non-behavioral; R1: isolated low-impact
  test/diagnostic change; R2: bounded behavior/dependency/concurrency change;
  R3: critical trust, connectivity, or lifecycle boundary.
- [ ] Elevate authorization, keys/signing, canonicalization, eBPF/networking,
  privilege, provisioning, install/update/rollback, and permission/release-control
  changes to R3 review. Labels, file extensions, and diff size alone do not decide.
- [ ] For R2/R3, assess the plan and select failure/platform evidence with the owner.
  R3 requires the domain owner and relevant specialist under the proposed pilot.
- [ ] Follow [continuous review](continuous-review.md): plan review before coding,
  declared increment checkpoints for R2/R3 or changed scope/risk, and final review
  of the cumulative task. Retain checkpoint IDs, snapshots, and dispositions.

## Author proof package

- [ ] Complete all eight sections of the [proof package](proof-package.md) using
  the [PR template](../.github/pull_request_template.md). Replace placeholders;
  justify Not applicable instead of leaving empty sections.
- [ ] Explain before/after behavior, implementation, risk, and preserved contracts.
- [ ] Map each acceptance criterion to implementation and executed test evidence,
  or mark the evidence gap explicitly.
- [ ] Record exact commands, commit, OS/architecture, results, and artifact links.
  Apply the states in [testing requirements](testing-requirements.md).
- [ ] Prioritize up to three critical-code focus areas; retain every material
  unresolved human decision even when it falls outside the prioritized list.
- [ ] Apply [decision-focused review](decision-review.md): prioritize code locations
  implementing affected trust boundaries, state transitions, compatibility, and
  recovery. Bind line references to the assessed snapshot; disclose additional
  required inspection scope beyond the top three.
- [ ] Account for OP01-OP12 with applicability, expected behavior, actual evidence,
  and gaps; Unknown is not Not applicable. Link missing applicable validation to
  adversarial cases or human decisions.
- [ ] State assumptions, unverified scenarios, and AI-assisted/human-authored
  classification. Do not use model confidence as validation.
- [ ] Refresh the package after fixes and preserve independent-review provenance,
  unresolved finding IDs, dispositions, and stale evidence.

## Independent assessment and human review

- [ ] Assess independently from the coding agent. Consolidate output rather than
  posting every intermediate agent observation.
- [ ] Follow the [agent workflow](agent-workflow.md): GPA Coding automatically
  requests GPA Guardian with a pinned snapshot and bounded intake. Treat unavailable
  delegation as missing review, not permission for self-approval.
- [ ] Preserve deterministic failures. Check actual lint, build/test, dependency,
  [coverage](../.github/workflows/reusable-build.yml), and
  [binary-budget](../.github/workflows/bloat.yml) results and their scope.
- [ ] Check [security contracts](security-invariants.md), [compatibility](compatibility.md),
  and [deployment safety](deployment-safety.md) where relevant.
- [ ] Challenge realistic failure cases using [regression evidence](common-regressions.md).
  Distinguish a hypothesis, a test gap, and a reproduced defect.
- [ ] Map independently designed adversarial cases to implemented tests, actual
  results, and gaps. Reviewers propose tests; the coding agent executes them.
- [ ] Publish one compact package for the exact commit, with supported findings,
  uncertainty, and human decisions. Respect the pilot's five-comment default;
  avoid duplicate or low-confidence inline noise.
- [ ] Inspect critical implementation details; a summary does not remove human
  accountability. No risk tier permits autonomous approval or merge in this pilot.
- [ ] Present material decisions with options, recommendation, consequences,
  evidence, gaps, and owner role. Only actual authorized human-response evidence
  resolves/defers them; preserve provenance and reopen stale decisions.

## Disposition and learning

- [ ] Give findings stable IDs and record: Accepted and fixed, Valid risk accepted,
  Deferred with linked work item, False positive, Duplicate, or Not actionable.
- [ ] Record active reviewer effort, including Guardian dismissal time, separately
  from elapsed CI/review time.
- [ ] Use the [local metrics dictionary](safe-decision-metrics.md) and authorized
  records; preserve missing data and 30-day observation limits.
- [ ] Connect post-merge outcomes to the PR during the proposed 30-day observation
  window without copying sensitive incident payloads into repository context.
- [ ] Update affected guides and registry provenance when behavior changes.
  Missing owner approval, historical context, or telemetry remains explicit.
