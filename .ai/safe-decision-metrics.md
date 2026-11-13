# Safe-decision velocity: local pilot measurement

Status: draft metric dictionary, version 1; metrics-owner approval pending.
Measure human attention per safely delivered change, not AI-generated code share.
The [local reporter](../ci/guardian_metrics.mjs) validates a supplied JSON document
and writes aggregate JSON to stdout. It reads no GitHub, work items, incidents,
network, model endpoint, or production data; it does not collect or persist records.
Use Node.js 22+; no package installation is required.

```powershell
node ci\guardian_metrics.mjs C:\approved-pilot-data\records.json
node --test ci\guardian_metrics.test.mjs
```

Keep actual records outside the repository in an approved location. Do not commit
reviewer identities, incident payloads, raw logs, or secrets. Obtain approval for
retention/access and nominate a metrics owner before treatment. Redacted evidence
references in records must still be authorized; the reporter never fetches them.

## Input document

One document contains `schema_version: 1`, `as_of` (UTC ISO timestamp with seconds
and optional three-digit milliseconds), and `records` (array). Supply one current
record per repository/PR, not one per rerun or checkpoint. Duplicate PRs, unknown
fields, invalid numbers, missing required fields, invalid timestamps, and unknown
enum values are errors with nonzero CLI exit. An empty array is allowed and produces
no estimates. Example shape (synthetic values, not pilot results):

```json
{
  "schema_version": 1,
  "as_of": "2026-10-28T20:00:00Z",
  "records": [{
    "repository": "example/repository",
    "pr_number": 1,
    "cohort": "treatment",
    "risk_tier": "R2",
    "eligibility": "eligible",
    "exclusion_reason": null,
    "ai_assisted": true,
    "language": "rust",
    "changed_lines": 120,
    "changed_files": 3,
    "merged_at": null,
    "issue_to_pr_minutes": null,
    "ready_to_first_review_minutes": null,
    "ready_to_approval_minutes": null,
    "pr_to_merge_minutes": null,
    "active_review_minutes": null,
    "rework_cycles": null,
    "escaped_defects": null,
    "rollback_or_hotfix": null,
    "evidence_reference": "synthetic example; not a measured PR",
    "findings": []
  }]
}
```

`cohort` is `control` or `treatment`; `risk_tier` is R0-R3; `eligibility` is
`eligible` or `excluded`. Excluded records require a nonempty `exclusion_reason`;
eligible records require null. `ai_assisted` is boolean; language is a nonempty
label. Changed lines (additions + deletions) and file count are nonnegative integers.
`evidence_reference` is a nonempty, minimized provenance reference, not a payload.

## Metric definitions and missing data

| Field | Definition |
|---|---|
| `issue_to_pr_minutes` | Work-item creation to PR creation; null when work-item linkage is unavailable |
| `ready_to_first_review_minutes` | Ready-for-review to first substantive human review, less explicit paused/outage intervals |
| `ready_to_approval_minutes` | Ready-for-review to final valid required approval, less explicit paused/outage intervals |
| `pr_to_merge_minutes` | PR creation to merge, raw calendar minutes including draft time; deliberately distinct from ready-to-approval |
| `active_review_minutes` | Sum exact active human review minutes, including understanding/dismissing Guardian output; exclude unattended CI wait and coding |
| `rework_cycles` | Substantive human feedback -> material author response/update cycles; exclude bot-only changes |
| `escaped_defects` | Owner-confirmed unique attributable defects detected within 30 days after merge |
| `rollback_or_hotfix` | Owner-confirmed attributable rollback, emergency disablement, or hotfix within the same window |

Durations are finite nonnegative numbers or null; rework/defect counts are
nonnegative integers or null. Never estimate active minutes from calendar time
or invent a midpoint for an open-ended survey band. This first format accepts
exact minutes only; leave band-only observations null and reconcile separately.

The reporter consumes already-adjudicated duration values; it cannot reconstruct
draft pauses, dismissed approvals, or outages. The metrics owner must apply the
pilot's Appendix A rules before entering values and preserve their provenance.
Missing fields are invalid; explicit null is missing evidence, not zero.
Instrument failures that prevent a reliable PR-level comparison should be excluded
with a reason; partial metric coverage remains visible in per-field denominators.

`merged_at` is null until merged, otherwise UTC and no later than `as_of`.
Merge duration and safety outcomes cannot be supplied for an unmerged PR.
Safety values must remain null until `as_of` is at least 30 days after merge.
The reporter shows mature, immature, and unmerged counts; mature unknown outcomes
remain missing, not defect-free. It reports unique defects per observed PR and
affected-PR rate separately, plus rollback/hotfix rate.

## Findings and precision

Each finding has exactly `id`, `severity` (`critical`, `high`, `medium`, `low`),
and `disposition` (null or one of the six strings below). IDs must be unique
within a PR; carry a stable ID across review checkpoints rather than recounting it.
Control records have no Guardian findings.

- Accepted and fixed
- Valid risk accepted
- Deferred with linked work item
- False positive
- Duplicate
- Not actionable

Overall precision = first three dispositions / all dispositioned findings.
Duplicates and not-actionable findings are denominator negatives. Unresolved
findings remain visible but are excluded from precision. High-severity precision
uses critical/high findings only. False-positive rate uses only False positive
as numerator; it is not the complement of precision because other negatives exist.
Empty denominators produce null, never 0% or 100%.

## Report and interpretation

Output includes eligible/excluded counts with reasons, then raw overall summaries
and cohort/risk/changed-line-band/file-count-band/language/authorship strata.
Line bands are 0-100, 101-300, 301-1000, and 1001+; file bands are 0-5, 6-15,
and 16+. Freeze these definitions before treatment; do not tune them to improve
the outcome. No cross-stratum weighting or causal-effect estimate is performed.

Durations/count distributions give N, missing count, P50, and P90 using the
nearest-rank percentile. Rates include numerator, denominator, and ratio.
The minimum of 20 eligible PRs per comparison arm and 10 per reported stratum
is a caveat, not proof of significance. The reporter labels comparisons
directional when either arm is small; even larger samples cannot establish the
absence of rare safety regressions.

Track raw PR size, active reviewer minutes per merged PR, rework, dispositions,
and mature safety outcomes together. Do not claim "safely delivered" solely
because a PR merged or has no recorded defect. Pilot expand/adjust/stop decisions
still require human adjudication, completed observation, and the broader metrics
in the [pilot plan](../doc/plans/AI_PR_Guardian_Pilot_Plan.md).
