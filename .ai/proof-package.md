# Author proof package

Status: draft author/reviewer contract; repository-owner review pending.
Contract revision: 3.

The [PR template](../.github/pull_request_template.md) is the canonical author
format. GPA Coding prepares it with explicitly planned/unknown evidence at early
checkpoints, completes it for final review, and refreshes it for the final
handoff. An engineer must be able to understand, verify, or reject the
change without reconstructing the author's intent from the entire diff.

## Required sections

Keep these eight level-two headings, in order, even for small or non-runtime
changes. Use a short explanation when a topic does not apply; never leave an
empty heading or an unresolved template placeholder as completed evidence.

| Section | Required substance |
|---|---|
| Intent | Problem, desired outcome, requirement reference or missing requirement, exclusions, authorship, and acceptance criteria with stable IDs |
| Implementation | What changed and why, affected files/components, assessed commit/comparison base, and working-tree identity when applicable |
| Behavior change | Observable before/after differences and affected OS/architecture; explicitly describe non-runtime effects for documentation/tooling changes |
| Risk | Proposed R0-R3 tier with reasons, realistic triggering scenarios, impact, verified or unverified recovery, and operational applicability/evidence matrix |
| Invariants | Contracts that must not change, linked implementation/test evidence, and remaining gaps |
| Validation | Acceptance-criteria traceability, exact checks/results/provenance, target and snapshot, dependency changes, independent review status, and unresolved findings |
| Reviewer attention | Up to three prioritized critical-code focus areas and material human decision records; disclose additional required inspection scope |
| Uncertainty | Assumptions, unverified behavior/platforms, unresolved human decisions/roles, and stale evidence |

Requirements come from the approved task or work item, not an agent's guess.
If acceptance criteria are missing, mark that explicitly, propose criteria for
confirmation, and do not label them approved or satisfied.

## Evidence rules

- Map every acceptance criterion to implementation and meaningful test/check
  evidence, or an explicit gap. Test existence or a green overall job alone
  does not establish that the criterion was tested.
- Use **Passed / Failed / Pending / Not run / Unavailable / Not applicable** for
  deterministic evidence. Explain every Not applicable entry.
- Identify exact commands or CI jobs, OS/architecture/configuration, UTC time,
  assessed commit or content identity, and result links when available.
  Separate author-run results, supplied CI evidence, and source inspection.
- Never replace an actual failure with Not applicable. Preserve failed, pending,
  canceled, missing, and skipped evidence explicitly; canceled execution is Not
  run or Unavailable with the cancellation reason, not Passed.
- A configured workflow, test source, or compiled E2E harness is not evidence
  that a check or VM scenario executed. Consult [testing requirements](testing-requirements.md).
- For documentation-only changes, state why runtime checks are Not applicable
  and record relevant documentation checks if available. Do not invent a unit
  test run to fill a row.
- Identify dependency/feature changes and the actual scope of vulnerability and
  license evidence. A vulnerability audit does not establish license approval.
- Preserve existing dirty-work boundaries. HEAD alone cannot identify uncommitted
  content: use the task paths and hashes defined in the [agent workflow](agent-workflow.md).
- After fixes, refresh behavior, risk, criterion mapping, and validation. Results
  for older content must be labeled stale or given their earlier scope; recheck
  the snapshot before presenting them as current.
- Do not paste credentials, customer payloads, sensitive command output, raw
  production logs, or unrestricted incident details into the package.

## Independent review is separate evidence

Apply the [decision-focused review contract](decision-review.md). Account for
all twelve operational scenarios, including reasoned exemptions for non-runtime
changes. Link affected trust boundaries, state transitions, compatibility, and
recovery decisions to the assessed code locations, assertions/results, and gaps.
Recommendations are not human decisions; preserve actual response provenance
and reopen decisions invalidated by material changes. A concise package does not
certify unlisted code or remove critical implementation inspection.

The author package contains claims and provenance; the Guardian's consolidated
assessment independently checks them. It is not a replacement for the author
package, and the coding agent cannot fill in a favorable Guardian result itself.

Use independent-review states **Not performed / Complete / Limited / Unavailable /
Stale**. These differ from deterministic check states. Complete means the supplied
scope was assessed, not a safety certification or approval. Give the assessed
snapshot and report reference when available, and carry unresolved finding IDs,
dispositions, limitations, and required human decisions forward.

GPA Guardian checks all eight sections for substantive evidence, not just heading
presence. Missing sections, placeholders, unsupported claims, and missing results
become evidence gaps and a limited assessment where material; they are not
automatically production defects. Deterministic failures remain authoritative.

## Delivery and enforcement limits

Within Validation, include the [continuous review](continuous-review.md)
checkpoint IDs/phases/snapshots/results and adversarial scenario-to-test/result
mapping. Distinguish plan/increment review from final integrated review. Within
Uncertainty, retain unexecuted hypotheses and unavailable final review explicitly.
For enrolled pilots, use [local metrics](safe-decision-metrics.md) to record actual
effort/dispositions/outcomes when available; null is not zero or permission to
invent reviewer time. Do not publish sensitive metrics records in a public PR.

GPA Coding returns the completed eight-section package as PR-ready Markdown in
chat, incorporating the actual Guardian result after review. Do not create a
per-change Markdown file, overwrite a PR body, or publish anything unless asked.
When creating/updating a PR is authorized, preserve existing useful author content
and apply the package to the PR description rather than duplicating it in comments.

GitHub normally offers the default template for new PRs after it is available on
the default branch. Existing PRs and CLI/API-created PRs may bypass it; explicitly
use the template in those cases. Repository instructions guide agent behavior but
do not enforce PR-body completeness. This implementation adds no CI gate, hook,
automatic PR publication, or merge approval. Humans still judge evidence quality.
