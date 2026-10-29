# Decision-focused human review

Status: draft review contract; repository-owner review pending.
Contract revision: 1.

The purpose is to help humans decide whether the approach, behavioral contract,
operational risk, and supporting evidence are acceptable. It is not permission
to skip the diff, weaken required checks, or substitute AI judgment for approval.
Use this contract with the [proof package](proof-package.md) and
[review checklist](review-checklist.md).

## What the reviewer must be able to decide

| Area | Human question | Required navigation/evidence |
|---|---|---|
| Architecture | Does this behavior belong in this component, with the right responsibilities and complexity? | Changed component and relevant callers/shared consumers; rationale and material alternatives |
| Behavioral contract | Is the before/after behavior intentional and compatible with the approved requirement? | Acceptance criterion/invariant and the code implementing the decision |
| Operational risk | What happens when the guest, host, network, update, or service fails partway through? | Applicable scenarios below, recovery behavior, actual tests/results, and remaining gaps |
| Evidence | Does the evidence establish the claimed behavior for the assessed content and platforms? | Exact assertions/checks, provenance, scope, snapshot, and explicit missing evidence |

Do not turn every implementation detail into a human question. Escalate material
choices: a compatibility break, timeout/recovery tradeoff, unclear requirement,
accepted operational risk, or missing critical validation. A concrete defect
remains a finding to fix; it is not neutralized by labeling it a "decision."

## Critical-code navigation

Give up to three prioritized focus areas, not a list of every file. For each,
include `id`, `contract`, `reason`, `locations`, `evidence`, and related
`decision_ids` or finding IDs. Locations contain `file`, `symbol`, `line_start`,
`line_end`, and `snapshot_id`; use a commit permalink when one exists. Uncommitted
line numbers are snapshot-local. Never invent locations for code not yet written.

Inspect the implementation and relevant context for each affected boundary:

- **Trust boundary:** identity derivation, authorization/audit decisions, signing,
  redaction, or privilege. Examples: [authorizer](../proxy_agent/src/proxy/proxy_authorizer.rs)
  and [connection identity](../proxy_agent/src/proxy/proxy_connection.rs).
- **State transition:** selection, commit, notification, cancellation, ownership,
  or retry ordering. Example: [runtime coordinator](../proxy_agent/src/runtime_coordinator.rs).
- **Compatibility guarantee:** platform behavior, C/Rust layout, configuration,
  serialized status, or mixed-version consumers. See [compatibility](compatibility.md).
- **Recovery decision:** partial update, rollback, restore, or stale health
  handling. Examples: [extension monitor](../proxy_agent_extension/src/service_main.rs)
  and [setup](../proxy_agent_setup/src/main.rs).

The three-focus-area limit is a prioritization limit, not a coverage claim.
If more critical boundaries require inspection, disclose the additional scope,
retain all unresolved material decisions, and request appropriate human review.
Do not omit a critical boundary merely to keep the summary short.

For `plan` review, list proposed files/symbols and decisions without invented line
numbers. For `increment`, identify new and affected existing boundaries. For
`final`, refresh locations against the full assessed snapshot, including callers
outside the changed lines where needed.

## Operational scenario coverage

For infrastructure behavior changes, assess each scenario explicitly. The IDs
are stable across checkpoints. Applicability is **Applicable / Not applicable /
Unknown**; Unknown is a gap, not an exemption.

| ID | Scenario | Question to resolve |
|---|---|---|
| OP01 | Reboot | What state survives and what must initialize before interception/provisioning resumes? |
| OP02 | Upgrade | Can old and new artifacts/consumers overlap safely, including persisted state? |
| OP03 | Downgrade | Can the previous version consume changed configuration/state, or is downgrade explicitly unsupported? |
| OP04 | Network unavailable | Are retries, timeouts, cancellation, and recovery bounded and observable? |
| OP05 | Host unavailable | Are secure-channel/key/policy and provisioning behaviors preserved during host failure? |
| OP06 | Partial installation | What happens between file copies, dependency/service changes, and status publication? |
| OP07 | Service restart | Can repeated or interrupted startup/shutdown leave stale listeners, policy, or state? |
| OP08 | Rollback | Which artifacts/state are restored, what is retained, and what if recovery itself fails? |
| OP09 | OS variation | Which Windows/Linux, architecture, and kernel-specific paths differ or remain unverified? |
| OP10 | Stale state | How are old keys, policy, connection state, version, or health evidence detected and handled? |
| OP11 | Duplication | Are repeated events, handler invocations, and reconciliation safe/idempotent where required? |
| OP12 | Concurrency | Which feasible concurrent event sequences threaten ownership, ordering, notification, or cleanup? |

Each `operational_scenarios` result contains `id`, `applicability`, `reason`,
`expected_behavior`, `locations`, `evidence_state`, `evidence`, `gap`, and
`decision_ids`. `evidence_state` uses the deterministic states in
[testing requirements](testing-requirements.md). Not applicable requires a reason;
Applicable requires behavior/evidence or an explicit gap. Source reasoning is not
an executed test. A failed check cannot be relabeled Not applicable.

All twelve IDs must be accounted for. A non-infrastructure change can group
inapplicable rows in the human summary with a specific shared reason, but the
structured result still accounts for every ID. Challenge its actual artifacts
(configuration, links, metrics, instructions) separately. Do not require fake VM
tests for documentation or treat a grouped exemption as runtime verification.

Use the [adversarial test-design contract](continuous-review.md) for missing
applicable evidence; link scenario IDs to proposed/implemented tests and actual
results instead of duplicating test payloads.

## Decision records and human accountability

Each `human_decisions` entry contains:

- `id`: stable ID such as D1 across checkpoints.
- `question`, `contract`, and `impact`: what must be decided and why it matters.
- `options` and `recommendation`: meaningful alternatives and the agent's
  evidence-backed recommendation, clearly separate from authorization.
- `locations`, `evidence`, and `gaps`: critical code and support/limitations.
- `owner_role`: required human responsibility; do not invent an assigned person.
- `status`: `open`, `resolved`, or `deferred`.
- `human_response`: null until an actual authorized response is supplied, otherwise
  its minimized reference, selected option/rationale, and applicable snapshot.

The coding agent cannot resolve a human decision through its own recommendation.
Resolved requires actual human response evidence. Deferred requires a human
response and linked follow-up, and does not waive mandatory gates or approval.
Do not infer consent from silence, a green check, or no AI findings. Material
scope/content changes require rechecking prior decisions; if the response no longer
applies, reopen the decision and preserve the earlier reference.

## Placement in the existing package

- **Risk:** operational applicability and evidence/gap matrix.
- **Validation:** scenario-to-check/adversarial case links and actual results.
- **Reviewer attention:** up to three critical-code focus areas plus decision
  records; use stable IDs to cross-reference rather than duplicate prose.
- **Uncertainty:** unresolved decisions, untested scenarios, stale evidence, and
  additional inspection scope beyond the prioritized list.

Guardian independently checks the author's navigation and decision claims, then
returns `review_focus`, `operational_scenarios`, and `human_decisions` alongside
findings. Missing evidence is a gap; a summary is a navigation aid, not proof that
the rest of the implementation is correct. These are local agent/template rules,
not enforced PR gates or an automatic approval mechanism.
