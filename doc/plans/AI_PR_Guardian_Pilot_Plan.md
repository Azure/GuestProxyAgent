# **AI PR Guardian**

Metrics, Pilot Workflow, and Adoption Plan

*A practical framework for reducing PR review bottlenecks while preserving engineering quality and safety*

| North star: reduce human engineering attention required per safely delivered change. |
|----|

Prepared for an AI-assisted engineering pilot  
October 2026

# Executive Summary

AI coding agents make code generation fast, but they can shift the bottleneck to human review. The AI PR Guardian addresses this by converting an agent-generated pull request into a compact, evidence-backed decision package. It does not replace human engineering judgment. It helps reviewers focus on architecture, behavioral contracts, operational risk, unresolved uncertainty, and the few lines or decisions that matter most.

| Pilot hypothesis: reduce human review effort by at least 25% and PR review cycle time by at least 20%, without increasing escaped defects, rollback rates, security findings, or post-merge failures. |
|----|

## Recommended pilot at a glance

| **Dimension** | **Recommendation** |
|----|----|
| Duration | 6 weeks, preceded by a 2-week baseline or historical shadow evaluation |
| Scope | One repository, 6-10 engineers, approximately 40-60 PRs |
| Mode | Advisory only; no autonomous approval or merge |
| Primary outcomes | Human review time, review cycle time, valid findings, escaped defects |
| MVP capabilities | Summary, risk tier, scope check, requirement-to-test mapping, test gaps, dependencies, reviewer focus, evidence package |
| Decision | Expand, adjust, or stop based on predefined thresholds |

# Decision Proposal

| **Decision element** | **Proposal** |
|----|----|
| **Decision requested** | Authorize an advisory AI PR Guardian pilot in one repository, with no autonomous approval or merge authority. |
| **Pilot design** | Run a six-week treatment for 6-10 engineers and approximately 40-60 PRs, preceded by a two-week baseline or historical shadow evaluation of 20-30 PRs. Apply the scope, exclusions, control/treatment design, and R0-R3 segmentation defined in Pilot Design and PR Risk Tiers. |
| **Staffing and roles** | Name a pilot sponsor, product owner, engineering owner, repository owner, security/privacy owner, metrics owner, triage owner, pilot authors and reviewers, and on-call domain specialists. Roles and decision rights are defined in Roles, Accountability, and RACI. |
| **Expected value** | Target at least 25% less active human review effort and 20% shorter review cycle time while improving focus, evidence completeness, and valid defect discovery. Final evaluation uses the existing Metrics and Success Criteria and Pilot Decision Framework. |
| **Major risks** | False confidence, noisy or duplicate findings, incorrect risk classification, sensitive-data exposure, prompt injection, excessive latency or cost, architecture misunderstanding, and participants optimizing for the tool rather than engineering quality. |
| **Key guardrails** | Human approval remains mandatory; deterministic gates take precedence; approved context and model endpoints only; least-privilege retrieval; secrets and policy filtering; no production/customer data unless explicitly approved; maximum five visible comments by default; monitor quality, privacy, latency, and cost thresholds. |
| **Immediate next step** | Within one week, identify the repository and named accountable owners, approve security/data boundaries and instrumentation, select the baseline sample, and schedule the launch-readiness review against the Launch Checklist. |

# 1. Technical Architecture and Data Flow

The Guardian is an advisory orchestration layer around repository events, approved context, deterministic evidence, and risk-based AI review. It publishes one filtered evidence package and never replaces repository approval controls.

| **Step** | **Component** | **Data flow and control** |
|----|----|----|
| 1 | **PR event trigger** | Opened, updated, marked ready, or manually rerun event starts an idempotent assessment for the current commit. |
| 2 | **Orchestrator** | Validates repository enrollment, commit identity, permissions, policy version, retry budget, and execution correlation ID. |
| 3 | **Approved context retrieval** | Retrieves only the PR diff, work item, repository guidance, selected design records, and approved history within the enrolled repository and authorized tenant. |
| 4 | **Deterministic checks** | Ingests build, test, static analysis, security, dependency, license, coverage, scope, and repository-policy results. Failures remain authoritative. |
| 5 | **Risk-based AI reviewer agents** | Selects correctness, test, security, architecture, regression, compatibility, and adversarial reviews according to R0-R3 risk and approved token/latency budgets. |
| 6 | **Normalize, deduplicate, filter** | Maps outputs to a shared finding schema, removes duplicates, applies confidence/severity thresholds, redacts prohibited data, and enforces comment-volume and policy rules. |
| 7 | **Consolidated evidence package** | Publishes risk, intent, behavior change, evidence, focus areas, supported findings, uncertainty, and human decisions using the Reviewer Evidence Package Template. |
| 8 | **Disposition and telemetry** | Authors and reviewers disposition findings. Events, timings, policy decisions, model/check versions, costs, and outcomes enter the telemetry store and feed the Weekly Dashboard. |

## Failure and degradation behavior

- If approved context cannot be retrieved, publish an incomplete-evidence status, identify the missing sources, and require normal human review; do not infer missing evidence.

- If an AI reviewer, model endpoint, or normalization stage fails or times out, preserve deterministic results, mark the unavailable assessment, continue only in advisory degraded mode, and never auto-approve.

- If deterministic checks fail, secrets or prohibited data are detected, policy validation fails, or repository enrollment is invalid, suppress AI publication as needed and route to the triage or security/privacy owner.

- Retries must be bounded and idempotent by repository, PR, commit, policy version, and reviewer type. Stale results must not be attached to a newer commit.

- Telemetry or dashboard failure must not block normal repository review, but the affected PR is excluded from pilot outcome analysis until instrumentation is reconciled.

# 2. Security and Data Governance

Security and privacy approval is a launch prerequisite. These controls apply in addition to repository policy, the existing deterministic gates, and the stop conditions in the Pilot Decision Framework.

| **Control area** | **Pilot requirement** |
|----|----|
| **Approved endpoints and tenants** | Use only organization-approved model endpoints, identities, subscriptions, regions, and tenants documented in the pilot security review. Block unapproved consumer or third-party endpoints. |
| **Allowed inputs** | PR metadata and diff, linked requirements, repository-local guidance, deterministic results, and explicitly approved design, incident, or historical artifacts required for the review. |
| **Prohibited inputs** | Credentials, tokens, keys, private certificates, raw customer payloads, unrestricted production logs, personal data not required for review, unapproved repositories, and content outside documented data boundaries. |
| **Secrets scanning** | Scan retrieved content and generated output before model submission and publication. Quarantine or redact matches, stop the affected assessment, and follow the repository's credential-response process. |
| **Least-privilege retrieval** | Use workload identity, repository allowlists, read-only permissions where possible, per-request authorization, scoped queries, and auditable denial by default. |
| **Customer and production data** | Do not retrieve or submit customer or production data unless the security/privacy owner explicitly approves the source, purpose, minimization, handling, retention, and access path. Prefer synthetic or redacted evidence. |
| **Prompt-injection defenses** | Treat repository text, comments, issues, documentation, and generated files as untrusted data; separate instructions from content; allowlist tools and retrieval sources; validate outputs against policy; and prevent content from expanding permissions or destinations. |
| **Retention and training** | Retain prompts, outputs, evidence, and detailed telemetry only for the approved pilot period and investigation window, then delete or aggregate them per policy. Pilot content must not be used to train foundation models or shared outside the approved tenant. |
| **Audit logging** | Log actor/workload identity, repository and PR, commit, retrieval source, policy/model/check version, decision, publication target, disposition, cost, timestamps, failures, and administrative changes without recording prohibited payloads. |
| **Cross-repository boundaries** | Default to the enrolled repository. Cross-repository retrieval requires an explicit allowlist, documented purpose, compatible classification, and authorization for both repositories; broad orchestration remains out of MVP scope. |
| **Unsupported repositories** | Do not run where enrollment, ownership, data classification, approved endpoints, repository guidance, deterministic gates, or required audit telemetry is absent. Return an unsupported status and preserve the normal human-review path. |

# 3. Problem and Target Operating Model

The traditional workflow is increasingly inefficient: a human describes a task, an AI agent produces a large code change, and a human reviewer must reconstruct intent and validate hundreds of lines. The scalable model is intent-driven and evidence-driven:

| Human specifies intent -> Coding agent implements -> Independent checks verify -> CI proves -> Human reviews decisions and risk -> Merge |
|----|

## Design principles

- Keep agent work PR-sized and single-purpose. Separate refactoring from behavior changes.

- Require an evidence package, not merely an AI-generated summary.

- Separate the coding agent from the reviewing agent to reduce self-confirmation bias.

- Use deterministic tools first. AI findings supplement builds, tests, static analysis, security scans, and policy checks.

- Apply risk-based review so reviewer attention matches potential impact.

- Move review earlier by evaluating plans and partial implementations before the final PR.

- Measure safe delivery and reviewer effort, not percentage of code generated by AI.

# 4. AI PR Guardian Responsibilities

| **Capability** | **Expected output** |
|----|----|
| Explain the change | Intent, implementation approach, before/after behavior, and affected surfaces |
| Classify risk | R0-R3 rating with explicit reasons and affected engineering boundaries |
| Validate scope | Unexpected files, mixed refactoring, unrelated changes, oversized diffs |
| Trace intent | Acceptance criteria mapped to implementation and test evidence |
| Review correctness | State transitions, error handling, concurrency, resource lifecycle, and boundaries |
| Review tests | Missing scenarios, weak assertions, behavior versus implementation coupling |
| Review security and dependencies | Privilege, input validation, secrets, packages, vulnerabilities, and licenses |
| Review compatibility | API/configuration/serialization behavior, OS support, update and rollback |
| Perform adversarial analysis | Realistic production failure hypotheses and tests that could disprove them |
| Guide human review | Top focus areas, unresolved uncertainty, and explicit decisions required |

# 5. Innovation Strategy for AI-Native PR Review

The core challenge is not that AI writes poor code by default. It is that AI makes code production inexpensive while human understanding, verification, and accountability remain scarce. The required innovation is therefore a workflow redesign, not simply an additional AI reviewer.

## 5.1 Keep AI work small and reviewable

Agents should operate under an explicit change budget. Prefer one logical change per PR, approximately 100-300 meaningful changed lines when practical, and separate refactoring from behavior changes. Large features should be delivered as a chain of small, independently verifiable PRs.

Treat this range as a reviewability target, not a hard correctness gate. Explain larger cohesive changes rather than splitting them artificially. Separate generated or mechanical changes where useful, but keep behavior changes with the tests needed to validate them.

## 5.2 Require a proof package from the coding agent

Every AI-created PR should explain its intent, implementation, behavior change, risks, preserved invariants, validation evidence, reviewer focus areas, assumptions, and unresolved uncertainty. The key requirement is evidence sufficient for another engineer to trust or reject the change.

| **Required section** | **Question answered**                      |
|----------------------|--------------------------------------------|
| Intent               | What problem is being solved?              |
| Implementation       | What changed and why?                      |
| Behavior change      | What was the before and after behavior?    |
| Risk                 | What realistic failures are possible?      |
| Invariants           | What behavior must not change?             |
| Validation           | Which tests and checks support the result? |
| Reviewer attention   | Where should the human focus?              |
| Uncertainty          | What assumptions or gaps remain?           |

For this repository, the [default PR template](../../.github/pull_request_template.md)
implements these eight sections. The [author proof-package contract](../../.ai/proof-package.md)
defines acceptance-criteria mapping, snapshot identity, validation provenance,
failure/missing-evidence states, independent-review status, and freshness rules.
GPA Coding fills the package before requesting Guardian review and refreshes it
after fixes; GPA Guardian checks its substance against source and supplied results.
The final coding handoff is PR-ready Markdown, not an automatic PR publication.
Template and agent instructions guide adoption but do not enforce a CI gate or
certify safety; empty sections and unsupported claims remain evidence gaps.

## 5.3 Separate implementation from independent review

The same agent should not be solely responsible for implementing a change and declaring it safe. Independent reviewer roles can evaluate correctness, security, tests, architecture, and regression risk. Their output should be consolidated so only high-confidence, high-value findings reach the human reviewer.

These are review responsibilities, not a requirement to run six agents on every PR. Start with one independent assessment, select additional review depth by risk, and consolidate findings before publication. Avoid duplicate comments and unsupported "PASS" conclusions.

For this repository, the [independent agent workflow](../../.ai/agent-workflow.md)
implements local VS Code roles in [workspace agent definitions](../../.github/agents).
GPA Coding automatically requests GPA Guardian as a separate subagent after
implementation and available validation. Guardian reviews directly by default and
delegates only bounded specialist questions requiring separate context. Review
agents cannot edit files or run shell/test commands; their evidence package remains
advisory. Missing delegation is reported as review not performed, never substituted
with self-approval. This configuration does not deploy a GitHub PR bot.

| **Agent role** | **Responsibility** |
|----|----|
| Coding agent | Implement the approved intent |
| Correctness agent | Find logical, state, concurrency, and lifecycle defects |
| Security agent | Evaluate trust boundaries, privilege, input, and dependency risks |
| Test agent | Identify missing scenarios and weak assertions |
| Architecture agent | Validate design constraints and component boundaries |
| Regression agent | Use history, prior incidents, and known failure patterns |

## 5.4 Shift human review from lines to decisions

Human reviewers should spend less time reading predictable boilerplate and more time validating architecture, behavioral contracts, operational risk, and evidence. For infrastructure changes, review should explicitly consider reboot, upgrade and downgrade, network or host unavailability, partial installation, service restart, rollback, OS variation, stale state, duplication, and concurrency.

This does not remove responsibility for inspecting critical implementation details. The evidence package should direct reviewers to the lines that implement a trust boundary, state transition, compatibility guarantee, or recovery decision. A concise summary is a navigation aid, not proof that the remaining diff is correct.

The [decision-focused review contract](../../.ai/decision-review.md) implements
this in the local coding/Guardian workflow and
[PR template](../../.github/pull_request_template.md). It requires explicit
operational scenario applicability/evidence, snapshot-bound critical-code
navigation, and human decision records with options, consequences, evidence,
owner role, and response provenance. Up to three focus areas prioritize attention
without hiding additional critical scope or unresolved decisions. Agents recommend;
only actual authorized human responses resolve or defer decisions, and neither
deferral nor a concise summary waives mandatory gates or implementation inspection.

## 5.5 Build a repository-specific engineering brain

Generic model knowledge is insufficient for mature infrastructure repositories. The Guardian should consume machine-readable repository guidance covering architecture, coding rules, testing requirements, compatibility, security invariants, deployment safety, common regressions, and review checklists. It should also use approved design records, prior PRs, incidents, and test outcomes when available.

**Repository guidance entry point:** [Engineering context index](../../.ai/README.md),
with machine-readable topic ownership, revision, source provenance, and approved-history
metadata in [context.json](../../.ai/context.json). The initial guides are
implementation-grounded drafts awaiting owner review; this does not deploy a Guardian
service or approve external history retrieval.

**Implemented repository structure:**

- [Architecture](../../.ai/architecture.md)

- [Coding guidelines](../../.ai/coding-guidelines.md)

- [Testing requirements](../../.ai/testing-requirements.md)

- [Compatibility](../../.ai/compatibility.md)

- [Security invariants](../../.ai/security-invariants.md)

- [Deployment safety](../../.ai/deployment-safety.md)

- [Common regressions](../../.ai/common-regressions.md)

- [Review checklist](../../.ai/review-checklist.md)

The layout is not a prerequisite for other pilot repositories. These guides form a
curated index of existing documentation, source, and tests rather than duplicating
their full contents. Distinguish implemented behavior from proposals, identify the
owner and revision of critical guidance, and use only approved historical context.
Record the rationale for unusual code and regression contracts without claiming
unverified production incidents or copying customer data or unrestricted incident
logs. [Copilot repository instructions](../../.github/copilot-instructions.md) provide
context discovery; other Guardian integrations must explicitly load the registry.

## 5.6 Review continuously, not only after PR creation

The Guardian should evaluate the coding plan before implementation, review small increments while the agent works, and run a final integrated assessment before human review. The PR becomes the final verification point rather than the first place where architectural mistakes are discovered.

The [continuous review contract](../../.ai/continuous-review.md) implements explicit
`plan`, `increment`, and `final` requests in the local coding/Guardian workflow.
Plan review precedes editing; R2/R3 use declared logical increments, and any tier
revisits changed scope/risk. Final assessment covers the entire task rather than
only the latest slice. Each checkpoint permits one targeted reassessment, with
stable IDs, pinned snapshots, and unresolved decisions carried forward.

## 5.7 Add adversarial verification

After implementation, an independent agent should assume the change is wrong, propose realistic production failure modes, and construct tests that attempt to trigger them. For retry or signaling logic, examples include shutdown races, stale state after reconnect, duplicate events, resume behavior, and interruption between persistence and acknowledgement.

Guardian or a bounded GPA Tests review constructs
[adversarial test designs](../../.ai/continuous-review.md) with concrete
preconditions, event ordering, expected assertions, harness, and cleanup.
The coding agent implements and runs appropriate tests in an authorized environment;
review agents remain read-only. Proposed, unexecuted, failed, and unavailable cases
remain distinct from verified behavior in the proof package.

## 5.8 Measure safe-decision velocity

The primary organizational goal should not be percentage of code written by AI. It should be human engineering attention required per safely delivered change. Useful measures include issue-to-PR time, PR-to-review time, PR-to-merge time, active review minutes, PR size, rework, escaped defects, rollback rate, accepted AI findings, and false-positive rate.

The [local metric dictionary](../../.ai/safe-decision-metrics.md) defines strict,
versioned PR-level records. The [reporter](../../ci/guardian_metrics.mjs) validates
authorized local input and reports cohort/risk/size/language/authorship strata,
N/P50/P90, finding precision, false-positive rates, and mature safety outcomes
with explicit missing-data denominators. It performs no external collection and
does not infer active human effort from elapsed time. Pilot owners still adjudicate
outcomes and apply Appendix A's eligibility, clock, and observation rules.

## 5.9 Prioritize the first five investments

1. **Small, single-purpose changes:** Give the coding agent an explicit scope and reviewability budget, with justified exceptions.
2. **Author proof package:** Require intent, before/after behavior, preserved invariants, validation evidence, reviewer focus, and uncertainty.
3. **Independent review:** Separate implementation from assessment and publish one filtered result rather than multiple agent conversations.
4. **Repository-specific engineering context:** Curate architecture, compatibility constraints, security boundaries, deployment assumptions, and approved regression history.
5. **Risk-based human review:** Route critical changes to domain specialists while keeping routine changes lightweight.

Prove these practices before investing in more orchestration. Autonomous approval and merging remain outside this pilot, including for R0 changes. The objective is safe-decision velocity: changes that cost humans less effort to understand, verify, and trust.

# 6. PR Risk Tiers

| **Tier** | **Typical changes** | **Guardian depth** | **Human review** |
|----|----|----|----|
| R0 - Trivial | Documentation, comments, formatting | Summary and deterministic checks | Lightweight review |
| R1 - Low | Tests, telemetry, isolated bug fix | Summary, scope, test analysis | One reviewer |
| R2 - Medium | Behavior change, concurrency, retry logic, dependency update | Full multi-dimensional assessment | Owner or experienced reviewer |
| R3 - High | Privilege, networking, authentication, provisioning, update path, host/guest boundary | Full review plus threat, compatibility, and failure analysis | Domain owner plus required specialist |

Recommended default R3 triggers for Azure Guest Agent-style infrastructure include host/guest communication, provisioning paths, eBPF or networking behavior, update and rollback logic, service privilege or identity, persistent-state migration, OS compatibility, and changes capable of interrupting VM connectivity.

# 7. Metrics and Success Criteria

## 7.1 Human productivity

| **Metric** | **Definition** | **Pilot target** |
|----|----|----|
| Human review time | Active reviewer minutes spent understanding and evaluating a PR | -25% |
| Time to first meaningful review | Ready-for-review to first substantive review response | -30% |
| PR review cycle time | Ready-for-review to approval | -20% |
| Review iterations | Human-review and author-update cycles | -20% |
| Reviewer context switches | Separate sessions required to complete review | -20% |
| Normalized reviewer throughput | PRs reviewed per reviewer-week, adjusted for size and risk | +20% |

Active effort should be collected using a short reviewer prompt with time bands: 0-5, 6-15, 16-30, 31-60, or more than 60 minutes. Calendar duration alone is not a reliable measure of attention.

## 7.2 Quality and safety guardrails

| **Metric** | **Definition** | **Guardrail** |
|----|----|----|
| Escaped defect rate | Bugs attributable to pilot PRs within 30 days | No increase |
| Reopened work rate | Related work items reopened after merge | No increase |
| Rollback or hotfix rate | PRs requiring rollback or emergency correction | No increase |
| Post-approval defect discovery | Significant issues found after approval but before release | -10% |
| Security finding rate | Security issues introduced per PR | No increase |
| Post-merge build/test failure | Failures attributable to merged PRs | -10% |
| Human-found Guardian misses | Valid reviewer findings missed by Guardian | Baseline, then decrease |

## 7.3 Guardian effectiveness

| **Metric** | **Definition** | **Initial target** |
|----|----|----|
| Overall precision | Accepted valid findings / all Guardian findings | >=70% |
| High-severity precision | Accepted high-severity findings / high-severity findings | >=90% |
| Finding recall | Known defects detected / known defects in evaluated sample | Establish baseline |
| Duplicate-comment rate | Findings already reported elsewhere | \<10% |
| Noise-free PR rate | PRs with no rejected or irrelevant Guardian comments | >=75% |
| Summary correctness | Reviewer rates summary accurate | >=90% |
| Risk-tier agreement | Guardian tier agrees with human assessment | >=80% |
| Reviewer-focus usefulness | Focus areas direct attention correctly | >=80% |
| Evidence completeness | Required evidence fields populated and supported | >=95% |
| False-blocking rate | PRs incorrectly assessed as unsafe | \<5% |

## 7.4 Developer experience, cost, and latency

| **Area**                  | **Metric / target**                             |
|---------------------------|-------------------------------------------------|
| Reviewer usefulness       | Average >=4.0/5                                |
| Author usefulness         | Average >=3.8/5                                |
| Continue using            | >=75% of participants                          |
| Significant noise         | \<15% of participants                           |
| P90 Guardian latency      | \<10 minutes                                    |
| Critical-path CI addition | \<5 minutes                                     |
| Visible comment volume    | No more than 5 by default                       |
| Rerun amplification       | \<1.5 executions per PR update                  |
| Economics                 | Track cost per PR and cost per accepted finding |

## Finding disposition taxonomy

Each Guardian finding should be labeled by the author or reviewer. This creates the dataset needed to calculate precision and tune prompts and policies:

- Accepted and fixed

- Valid risk accepted

- Deferred with linked work item

- False positive

- Duplicate

- Not actionable

# 8. End-to-End Pilot Workflow

## Stage 0 - Baseline and shadow evaluation

Collect historical or two-week baseline data for 20-30 PRs. Run the Guardian silently against completed PRs and compare its findings with review comments, later bug fixes, test failures, incidents, and rollbacks.

## Stage 1 - AI-ready work item

Capture problem, desired behavior, exclusions, acceptance criteria, compatibility constraints, failure expectations, validation requirements, and risk areas. Preserve the team-owned work item or PRD as the source of truth.

## Stage 2 - Plan assessment

Before code changes, require the coding agent to list planned files, approach, tests, invariants, behavior changes, and uncertainties. For R2/R3 work, the Guardian evaluates the plan and identifies missing operational or architectural scenarios.

## Stage 3 - Pre-PR Guardian review

Run scope, traceability, correctness, test, security, dependency, compatibility, and adversarial assessments. The author resolves valid issues before requesting human review.

## Stage 4 - Deterministic gates

Run build, unit tests, integration tests, static analysis, security analysis, dependency and license checks, coverage comparison, and repository-specific validation. Deterministic failures always take precedence over AI conclusions.

## Stage 5 - Reviewer evidence package

Publish one consolidated assessment: risk, intent, behavior change, focus areas, findings, acceptance-criteria coverage, automated evidence, uncertainty, and human decisions required.

## Stage 6 - Human review

The reviewer validates direction, behavioral contract, high-risk implementation details, unresolved uncertainty, and sufficiency of evidence. The reviewer dispositions Guardian findings.

## Stage 7 - Post-merge observation

Monitor merged pilot PRs for 30 days. Connect bugs, incidents, rollbacks, hotfixes, and test failures back to the PR and determine whether available evidence could have enabled earlier detection.

# 9. Reviewer Evidence Package Template

<table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<thead>
<tr>
<th>AI PR Guardian<br />
<br />
Risk: R2 - Medium<br />
Confidence: 84%<br />
<br />
Intent<br />
Fix reconnect state loss after service restart.<br />
<br />
Behavioral change<br />
Before: Retry state was lost during restart.<br />
After: Retry state is restored from persisted state.<br />
<br />
Reviewer focus<br />
1. Validate the state transition in ConnectionState::Restore.<br />
2. Confirm persisted data remains backward compatible.<br />
3. Confirm cancellation cannot race with restoration.<br />
<br />
Risk findings<br />
- Medium: Corrupted state falls back to empty state without diagnostic telemetry.<br />
- Low: New timeout lacks a boundary test.<br />
<br />
Acceptance criteria<br />
- AC1: Passed, supported by tests A and B.<br />
- AC2: Passed, supported by integration test C.<br />
- AC3: Insufficient evidence.<br />
<br />
Automated evidence<br />
Build: Passed | Unit: Passed | Integration: Passed | Static analysis: Passed<br />
Security: Passed | New dependencies: None | Coverage delta: +1.2%<br />
<br />
Uncertainty<br />
Behavior on older supported OS builds was not validated.<br />
<br />
Human decisions required<br />
1. Is empty-state fallback acceptable for corrupted state?<br />
2. Is older-OS validation required before merge?</th>
</tr>
</thead>
<tbody>
</tbody>
</table>

# 10. Pilot Design

## Scope and participants

- One repository

- 6-10 engineers

- 40-60 PRs

- Six-week treatment period

- Mix of AI-assisted and human-authored PRs

- Exclude emergency hotfixes, very large migrations, generated dependency PRs, multi-repository changes, and changes lacking required test environments

## Control and treatment

| **Group** | **Workflow**                                             |
|-----------|----------------------------------------------------------|
| Control   | Existing CI and normal human review                      |
| Treatment | Existing CI plus AI PR Guardian plus normal human review |

Stratify comparisons by risk tier, changed lines, file count, language, author experience, and AI-generated versus human-authored code. Otherwise, the pilot may incorrectly penalize the Guardian if it receives disproportionately difficult PRs.

# 11. Roles, Accountability, and RACI

**Decision authority:** AI PR Guardian output is advisory. When Guardian output conflicts with human judgment, an authorized human reviewer or the repository owner has final decision authority, subject to mandatory security, privacy, compliance, and deterministic repository gates. Overrides must record the rationale and evidence.

| **Role** | **Primary accountability** | **RACI position** |
|----|----|----|
| **Pilot sponsor** | Authorize scope/resources, remove organizational blockers, and chair expand/adjust/stop decision. | A: pilot charter and final pilot decision |
| **Product owner** | Own user outcomes, backlog, adoption, requirements, and prioritization. | A/R: product requirements and adoption |
| **Engineering owner** | Own architecture, implementation, reliability, operations, model/check configuration, and remediation. | A/R: system delivery and technical operations |
| **Repository owner** | Approve enrollment, repository policy, risk triggers, specialists, and merge decision rights. | A: repository participation and final PR authority |
| **Security/privacy owner** | Approve endpoints, tenants, data boundaries, retention, audit controls, exceptions, and incident response. | A: security/privacy controls; C: launch and changes |
| **Metrics owner** | Own metric definitions, instrumentation quality, analysis, dashboard, caveats, and final results. | A/R: measurement and reporting |
| **Pilot authors** | Provide intent/evidence, resolve or disposition findings, report effort, and follow pilot handling rules. | R: PR evidence and author actions |
| **Reviewers** | Exercise independent engineering judgment, validate high-risk decisions/evidence, disposition findings, and record effort/usefulness. | R; A when authorized by repository policy for PR approval |
| **Triage owner** | Manage noisy/duplicate findings, operational failures, policy violations, escalation, and prompt/policy tuning queue. | R: daily triage; C: changes to thresholds |
| **Domain specialist** | Review R3 or specialized areas such as security, networking, provisioning, compatibility, update/rollback, or host/guest boundaries. | C/R as required by risk tier; approval required when policy mandates |

R = Responsible; A = Accountable; C = Consulted; I = Informed. The pilot sponsor, product owner, engineering owner, repository owner, security/privacy owner, and metrics owner are informed of weekly status and material exceptions.

# 12. Weekly Dashboard

## North-star indicators

1.  Human review minutes per safely merged PR

2.  Total lead time to verified change

3.  Valid Guardian findings per 10 PRs

4.  Escaped defects per 10 merged PRs

## Supporting breakdowns

- Median and P90 review time: control versus treatment

- Median time to approval

- Average review cycles

- Precision overall and by severity

- Risk-tier agreement

- Reviewer usefulness score

- P90 Guardian latency and cost per PR

- Escaped defect rate by risk tier

Always split results by R0-R3. Aggregate averages may hide strong R1/R2 performance and weak R3 performance.

# 13. Pilot Decision Framework

| **Decision** | **Conditions** |
|----|----|
| Expand | Review time improves >=25%; cycle time improves >=20%; high-severity precision >=90%; overall precision >=70%; no degradation in defects, rollbacks, or security; >=75% want to continue; P90 latency \<10 minutes. |
| Continue with adjustments | Productivity improves but precision is 50-70%; summaries are useful but inline comments are noisy; benefit varies significantly by risk tier; latency or cost is high but tractable. |
| Stop or redesign | Escaped defects increase materially; high-severity false positives exceed 10%; dismissal effort outweighs value; architecture is routinely misunderstood; teams optimize for the Guardian instead of quality; or approved data boundaries are violated. |

# 14. Minimum Viable Guardian and Roadmap

## MVP capabilities

- PR intent and change summary

- Risk classification

- Scope check

- Acceptance-criteria-to-test mapping

- Test-gap identification

- New dependency detection

- Reviewer focus areas

- Consolidated evidence package

- Finding disposition tracking

- Pilot telemetry

## Defer until after the pilot

- Autonomous code modifications

- Automated approval

- Autonomous merge

- Broad low-confidence inline comments

- Complex cross-repository orchestration

## Potential phase 2 enhancements

- Repository-specific engineering memory covering architecture, compatibility, security invariants, deployment safety, and prior regressions

- Independent correctness, security, test, architecture, and regression agents with consolidated output

- Continuous review during implementation rather than only at PR creation

- Risk-tier-specific model selection and token budgets

- Learning from accepted/rejected findings and post-merge outcomes

# 15. Launch Checklist

- [ ] Define pilot repository, owners, participants, privacy boundaries, and escalation contacts.

- [ ] Agree on risk-tier rules and identify R3 code paths.

- [ ] Confirm baseline metric collection and a lightweight review-time survey.

- [ ] Define acceptance-criteria format and evidence links.

- [ ] Integrate deterministic build, test, static analysis, security, dependency, license, and coverage results.

- [ ] Implement a single consolidated Guardian comment or status view.

- [ ] Add finding disposition controls and telemetry.

- [ ] Run shadow evaluation and calibrate severity and confidence thresholds.

- [ ] Begin advisory treatment with weekly review of metrics and examples.

- [ ] Perform a final decision review using predefined expand/adjust/stop thresholds.

# 16. Appendix A - Metric Instrumentation

This appendix operationalizes the metrics in Metrics and Success Criteria and the Weekly Dashboard. The metrics owner maintains the versioned data dictionary and records any definition change before analysis.

## Common population, timestamps, and reporting rules

- **Population:** Include enrolled control and treatment PRs that enter ready-for-review during the measurement window and meet Pilot Design criteria. Exclude bots/generated dependency PRs, emergency hotfixes, very large migrations, multi-repository changes, unavailable test environments, canceled/abandoned PRs, and instrumentation failures; report exclusion counts and reasons.

- **Draft and reopened PRs:** Draft time is excluded until the first ready-for-review timestamp. If returned to draft or changes are requested, pause calendar review clocks until ready again. A reopened PR retains the original PR identifier; report both cumulative lifecycle time and the reopened episode. Do not double-count it in PR-rate denominators.

- **Clock handling:** Store timestamps in UTC. For calendar-duration metrics, subtract explicit paused intervals and repository outages. Do not subtract nights/weekends unless a business-hours view is separately labeled.

- **Normalization:** Report raw results and strata by R0-R3, changed-line bands, file-count bands, language, AI-assisted versus human-authored, and control versus treatment. Use matched strata or regression adjustment only when specified before analysis; do not hide raw denominators.

- **Distribution:** Report N, P50, and P90 for duration, effort, latency, and cost; mean may be supplementary. For rates, report numerator/denominator and, where practical, confidence intervals.

- **Sample-size caveat:** Do not claim a threshold is proven from fewer than 20 eligible PRs per comparison arm or fewer than 10 observations in a risk/size stratum. Label smaller results directional; rare safety events require continued post-merge observation and qualitative review.

| **Metric** | **Operational definition and formula** | **Source** | **Owner** |
|----|----|----|----|
| **Human review time** | Sum active minutes reported by authorized reviewers for understanding/evaluating the PR, excluding coding, CI wait, meetings unrelated to the PR, and unattended elapsed time. Use exact minutes when available; otherwise use the midpoint of 0-5, 6-15, 16-30, and 31-60 bands and report >60 separately. PR denominator = eligible reviewed PRs with complete survey. | Reviewer prompt + PR identity/risk/size | Metrics owner |
| **First meaningful review** | First substantive human review timestamp minus first ready-for-review timestamp, less paused intervals. Substantive means approval, changes requested, or a comment addressing behavior, design, correctness, tests, security, operations, or compatibility; exclude assignment, acknowledgement, bot, and formatting-only activity. | PR event log and review records | Metrics owner |
| **Review cycle time** | Final required approval timestamp minus first ready-for-review timestamp, less draft/paused intervals. If approval is dismissed by a new commit, use the final valid approval. Report merged-but-unapproved exceptions separately. | PR state, commit, and review events | Metrics owner |
| **Review iterations** | Count cycles beginning with substantive human feedback or changes requested and ending with the author's next material update/response. Consolidate comments in one review session into one cycle; exclude bot-only updates and merge-base refreshes. | Review, comment, and commit events | Metrics owner |
| **Context switches** | Reviewer-reported distinct work sessions used to complete review, where a session is separated by at least 30 minutes or an explicit return later. Sum across required reviewers; exclude automated activity. | Reviewer prompt | Metrics owner |
| **Normalized throughput** | Eligible PRs completed per reviewer-week. Compare within predeclared risk and changed-line strata; if a weighted index is used, freeze baseline stratum weights before treatment and publish them. Do not treat raw PR count as normalized throughput. | PR events, reviewer roster, risk/size | Metrics owner |
| **Escaped defect rate** | Numerator = unique confirmed defects attributable by owner review to an eligible merged PR and detected within 30 days. Denominator = eligible merged PRs completing the 30-day window. Deduplicate related incidents/work items; classify severity and risk tier. | Bug/incident links, deployment and PR records | Repository owner |
| **Reopened work rate** | Numerator = eligible merged PRs with a linked work item reopened for a confirmed related issue within 30 days. Denominator = eligible merged PRs with complete linkage and observation. Count each PR once. | Work-item history and PR links | Product owner |
| **Rollback/hotfix rate** | Numerator = eligible merged PRs causing rollback, emergency disablement, or production hotfix within 30 days, confirmed by repository owner. Denominator = eligible merged PRs completing observation. Count one affected PR once even if multiple remediations occur. | Release/deployment, incident, and PR records | Repository owner |
| **Security finding rate** | Numerator = confirmed security issues introduced by eligible PRs, deduplicated and severity-classified. Denominator = eligible merged PRs completing the agreed observation window. Exclude pre-existing findings unless the PR worsened exposure. | Security tools, incidents, and validated reports | Security/privacy owner |
| **Post-merge failure rate** | Numerator = eligible merged PRs with a build or test failure confirmed attributable after merge and before release/within 30 days. Denominator = eligible merged PRs with available signals. Exclude flaky failures not attributed to the PR. | CI/test history and triage disposition | Engineering owner |
| **Finding precision** | Numerator = findings dispositioned Accepted and fixed, Valid risk accepted, or Deferred with linked work item. Denominator = all dispositioned Guardian findings, excluding unresolved dispositions. Report overall and high-severity precision; duplicates and not-actionable findings remain denominator negatives. | Guardian finding/disposition store | Triage owner |
| **Finding recall** | Numerator = benchmark defects or valid human findings detected by Guardian before the human finding. Denominator = adjudicated known defects/findings in the sampled PRs. Use only a labeled benchmark/shadow sample with independent adjudication; do not infer recall from production comments alone. | Benchmark set, human review, incidents | Metrics + triage owners |
| **Noise-free PR rate** | Numerator = eligible Guardian-reviewed PRs with zero findings dispositioned False positive, Duplicate, or Not actionable. Denominator = Guardian-reviewed PRs with all visible findings dispositioned. | Guardian finding/disposition store | Triage owner |
| **Summary, risk, focus, evidence** | Summary correctness = accurate ratings / completed ratings. Risk-tier agreement = exact Guardian/human tier matches / adjudicated PRs; also report within-one-tier agreement. Focus usefulness = ratings of 4-5 / completed ratings. Evidence completeness = required supported fields / required fields, with N/A allowed only by schema rule. | Reviewer rubric, risk adjudication, package schema | Metrics owner |
| **Experience/adoption** | Reviewer/author usefulness = mean and distribution of 1-5 responses. Continue using = Yes responses / participants responding to final survey. Significant noise = participants selecting the predefined significant-noise response / respondents. Report response rates and role split. | Per-PR and final participant surveys | Product + metrics owners |
| **Guardian latency** | Publication-complete timestamp minus accepted-trigger timestamp for each commit assessment. Include queue, retrieval, checks, model calls, normalization, and publication. Report successful and degraded/failed executions separately at P50/P90. | Orchestrator trace and publication log | Engineering owner |
| **Critical-path CI addition** | Counterfactual merge-gate completion with Guardian minus completion without Guardian, using the maximum finish time of required gates. If no reliable counterfactual exists, report the Guardian blocking duration explicitly rather than claiming added time. | CI timeline and Guardian trace | Engineering owner |
| **Cost per PR** | Total metered model, orchestration, storage, and incremental compute cost for all attempts on an eligible PR / eligible Guardian-reviewed PRs. Report P50/P90, model/check mix, and rerun count. | Metering, billing tags, execution telemetry | Engineering + metrics owners |
| **Cost per accepted finding** | Total Guardian cost for PRs with completed dispositions / accepted valid findings on those PRs. If numerator of findings is zero, report undefined rather than zero. Supplement with cost per reviewed PR to avoid penalizing clean PRs. | Cost telemetry + finding dispositions | Metrics owner |

Before pilot launch, the metrics owner must publish field names, event-source precedence, missing-data rules, risk/size bands, survey wording, and the baseline/treatment comparison plan. Any post-launch change must be versioned and results must show the affected population.

# 17. Internal References Used in the Plan

The plan was informed by the following internal materials surfaced during enterprise research:

- **AI-Ready PRD Workflow.docx:** Emphasizes authoritative requirements, PR-sized executable work, traceability, automated verification, and measuring total time to verified customer value.

- **Quality Gates for AI Code:** Recommends build, tests, static analysis, security, dependency, license, coverage, scope, size, and human-review gates.

- **AI Unlocked: Improving token efficiency: Principles and lessons from GitHub Agentic Workflows:** Highlights that repeatable agent workflows can be measured and optimized for token efficiency.

Note: This document is a proposed pilot framework. Targets should be calibrated to the repository baseline before they are used as organizational commitments.

# 18. Applying the Pilot to GuestProxyAgent

This section maps the framework to this repository. It is an adoption proposal, not evidence that the Guardian is already deployed or that configured checks currently pass. Repository owners must verify live check results, required-check settings, and approved infrastructure before launch.

## 18.1 Build on the existing evidence foundation

Implement the Guardian as an advisory evidence layer over existing CI, not as a replacement build pipeline.

| **Surface** | **Repository foundation** | **Guardian responsibility** |
|----|----|----|
| Workspace and components | Four Rust workspace members in [Cargo.toml](../../Cargo.toml): agent, shared library, extension, and setup tool | Identify affected components and cross-component contracts. |
| Formatting, linting, dependency vulnerabilities | Windows/Linux jobs in [ci.yml](../../.github/workflows/ci.yml) | Ingest actual results for the assessed commit; preserve failures. |
| Builds and unit tests | [reusable-build.yml](../../.github/workflows/reusable-build.yml), [build.cmd](../../build.cmd), and [build-linux.sh](../../build-linux.sh) | Distinguish compilation, test execution, target architecture, and missing runtime validation. |
| Coverage | Configured 70% checks for selected crates on x64 Windows/Linux in the reusable build workflow | Report measured scope and exclusions. Aggregate coverage is not acceptance-criteria coverage, and a threshold result is not a coverage delta. |
| Binary-size regression | Per-target/per-binary budgets and explicit crate-share overrides in [bloat.yml](../../.github/workflows/bloat.yml) | Surface dependency/feature growth and budget changes; use workflow values as the configured source of truth. |
| Static analysis | C/C++ and C# configuration in [codeql.yml](../../.github/workflows/codeql.yml) | Report the configured language scope and actual results; do not imply that this configuration analyzes the Rust workspace. |
| VM validation | Azure VM harness in [GuestProxyAgentTest.csproj](../../e2etest/GuestProxyAgentTest/GuestProxyAgentTest.csproj) and OS/architecture-specific [test maps](../../e2etest/GuestProxyAgentTest/TestMap) | Link executed E2E results where required. Building or packaging the harness does not prove that VM tests ran. |
| Architecture and design context | [README.md](../../README.md), [Linux guidance](../GettingStartedLinux.md), [Windows guidance](../GettingStartedWindows.md), and repository-local [design plans](.) | Retrieve relevant approved context without treating proposed designs as implemented behavior. |

Dependency vulnerability scanning does not establish license compliance or complete security assurance. If a required evidence source is absent, mark it unavailable and assign an owner rather than inferring success.

## 18.2 Apply GPA-specific risk rules

Use path-based risk floors together with an assessment of behavior and blast radius. A small diff can still change a critical trust boundary. Human adjudication may raise a tier; any lowering of a policy floor requires an authorized, recorded exception.

| **Tier** | **GPA examples** | **Expected focus** |
|----|----|----|
| R0 | Ordinary documentation, comments, formatting | Confirm no executable or policy behavior changed; retain human approval. |
| R1 | Isolated test additions or non-sensitive diagnostics | Validate assertions, scope, and absence of sensitive-data exposure. |
| R2 | Bounded behavior changes, dependency updates, internal retry or concurrency changes without critical-boundary impact | Validate failure semantics, compatibility, and targeted regression evidence. |
| R3 | Authorization, key/signing logic, request canonicalization, eBPF redirection, privilege, provisioning, install/update/rollback, or connectivity-affecting runtime changes | Require domain-owner and relevant specialist review, supported by failure and platform evidence. |

Examples of critical review surfaces:

- [Authorization](../../proxy_agent/src/proxy/proxy_authorizer.rs) and [request canonicalization](../../proxy_agent/src/proxy/canonical): preserve intended endpoint defaults, elevation requirements, audit/enforcement distinctions, and request-matching behavior. Do not invent a blanket denial policy that changes supported behavior.
- [Runtime coordination](../../proxy_agent/src/runtime_coordinator.rs) and [redirection](../../proxy_agent/src/redirector): examine listener/redirector pairing, port changes, cancellation, stale state, restart ordering, and partial failure.
- [Setup](../../proxy_agent_setup) and [extension](../../proxy_agent_extension): examine interrupted installation, upgrade/downgrade, service restart, recovery, and rollback.
- [Shared code](../../proxy_agent_shared): assess effects on every consuming component and both operating systems.
- [Workflow configuration](../../.github/workflows), release controls, and Guardian policy: elevate changes that alter permissions, publication, required checks, or trust boundaries. YAML and policy changes are not automatically R0.

Logging, telemetry, tests, and generated files also require elevated review when they expose secrets, weaken validation, or affect executable behavior.

## 18.3 Establish an author proof package

The author supplies intent and evidence before human review; the independent Guardian verifies the claims and generates the consolidated reviewer package in Section 9. Missing requirements must remain explicit rather than being reconstructed as if they were approved intent.

```text
Intent / linked requirement:
Acceptance criteria: AC1, AC2, ...
Implementation approach:
Before -> after behavior:
Preserved invariants:
Affected components / OS / architecture:
Validation: commands, commit identity, result links
Reviewer focus: up to three critical locations or decisions
Assumptions / unverified scenarios:
AI-assisted or human-authored classification:
```

For each acceptance criterion, map the requirement to implementation and supporting tests/results. Distinguish author-reported local validation from independently collected CI evidence.

Use explicit evidence states: **Passed, Failed, Pending, Not run, Unavailable, Not applicable**. A "Not applicable" entry requires a policy-supported reason. Every result must identify the assessed commit and relevant platform; do not extrapolate x64 unit-test success to ARM64 runtime behavior.

## 18.4 Deliver the MVP in three reviewable increments

| **Increment** | **Deliverable** | **Completion evidence** |
|----|----|----|
| 1. Evidence contract | PR template, GPA risk rules, curated documentation index, named owners, and reviewer-effort survey | Apply manually to a few representative PRs; confirm that reviewers can identify intent, risk, validation, and missing evidence. Approve data boundaries before any model assessment. |
| 2. Deterministic collector | Commit-bound diff metadata, dependency changes, affected surfaces, check/artifact links, and evidence states | Verify successful, failed, pending, missing, and stale-result cases. Preserve authoritative failures and identify absent evidence. |
| 3. Independent assessment | Approved model endpoint, structured findings, one updated reviewer package, dispositions, and pilot telemetry | Shadow-evaluate against an adjudicated sample; validate publication limits, failure behavior, data controls, and metric capture before treatment. |

Keep the Guardian non-required and advisory during the pilot. Preserve existing required checks and human approvals. Use read-only collection credentials and a separate narrowly scoped publisher; never execute untrusted PR code in a context containing model or publication credentials.

Bind assessments to repository, PR, commit SHA, and policy version. Recheck the current commit before publication, bound retries, and supersede stale assessments explicitly. Treat repository content as untrusted input, with approved retrieval sources and input/output scanning as required by Section 2.

A preliminary package may be published while CI is pending and updated when results arrive. Measure preliminary latency separately from the publication-complete latency defined in Appendix A; do not use the preliminary timestamp to claim the complete-package latency target was met.

## 18.5 Exercise realistic failure scenarios

For relevant R2/R3 changes, the independent assessment should propose realistic failure hypotheses and map each to an existing test, a new regression test, or an explicit evidence gap. Do not manufacture a fixed number of findings.

Examples include:

- Shutdown during reconnect or runtime replacement.
- Successful reconnect with stale authorization or connection state.
- Duplicate notifications or repeated reconciliation.
- Service restart between state persistence and acknowledgement.
- Host/network unavailability, timeout boundaries, and recovery.
- Interrupted installation or rollback with partially updated files or services.
- Relevant Windows/Linux, kernel, architecture, reboot, or resume differences.

For example, a timeout change should expose the previous and proposed values, evidence for slow-host behavior, and the human decision about compatibility. Illustrative test counts, time savings, or AI "PASS" labels are not pilot measurements or proof.

## 18.6 Launch and evaluate in the actual review workflow

Confirm the enrolled repository explicitly. The current checkout has `ZhidongPeng/GuestProxyAgent` as origin and `Azure/GuestProxyAgent` as upstream. A fork can validate mechanics, but productivity measurements must come from the enrolled repository where participating engineers actually conduct review. Upstream enrollment and cross-repository retrieval require separate authorization; neither is implied by a configured remote.

Follow Sections 10-16 for baseline selection, control/treatment assignment, sample-size caveats, dispositions, and the 30-day observation window. For historical shadow evaluation, provide only context available at the assessment point; reserve later fixes, review findings, and incidents as independently adjudicated evaluation labels.

Capture active reviewer minutes directly, including time spent understanding or dismissing Guardian output. PR timestamps measure elapsed workflow time, not human attention. Report insufficient sample sizes and unresolved instrumentation explicitly, and do not infer safety from the absence of rare incidents in a small sample.

The recommended first implementation step is the evidence contract and manual trial, followed by deterministic collection and then independent AI assessment. This sequence tests whether the workflow saves reviewer effort before adding orchestration complexity.
