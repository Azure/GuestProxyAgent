<!--
Author proof package. Complete all eight sections using .ai/proof-package.md.
Replace <...> placeholders. Never invent passing results or omit known failures.
Keep sensitive data and raw production logs out of the PR.
-->

## Intent

- Problem and desired outcome: <describe>
- Requirement/work item: <link, or explain that none is available>
- Exclusions: <what this change intentionally does not do>
- Authorship: <AI-assisted / human-authored>

| Criterion | Required observable behavior |
|---|---|
| AC1 | <acceptance criterion agreed with the owner> |

## Implementation

- Approach and rationale: <what changed and why>
- Affected components/files: <paths or permalinks>
- Assessed snapshot: <HEAD/base commits and comparison base>
- Working-tree delta: <if uncommitted, include task-owned paths and content identity>

## Behavior change

| Surface | Before | After | OS / architecture |
|---|---|---|---|
| <observable behavior> | <previous behavior> | <new behavior> | <affected targets> |

<!-- For non-runtime changes, explicitly state "No runtime behavior change" and explain the actual documentation/tooling effect. -->

## Risk

- Proposed tier: <R0 / R1 / R2 / R3, with reasons>
- Realistic failure scenarios and impact: <conditions and consequences>
- Mitigation/recovery: <evidence-backed approach, or explicitly unverified>

<!-- Applicability: Applicable / Not applicable / Unknown. Explain each exemption.
Evidence states follow Validation below. For non-infrastructure changes, rows
may be grouped with a specific shared reason; account for all twelve IDs.
-->

| Scenario | Applicability / reason | Expected behavior | Critical code / evidence state and reference / gap |
|---|---|---|---|
| OP01 Reboot | <assess> | <contract> | <evidence or gap> |
| OP02 Upgrade | <assess> | <contract> | <evidence or gap> |
| OP03 Downgrade | <assess> | <contract> | <evidence or gap> |
| OP04 Network unavailable | <assess> | <contract> | <evidence or gap> |
| OP05 Host unavailable | <assess> | <contract> | <evidence or gap> |
| OP06 Partial installation | <assess> | <contract> | <evidence or gap> |
| OP07 Service restart | <assess> | <contract> | <evidence or gap> |
| OP08 Rollback | <assess> | <contract> | <evidence or gap> |
| OP09 OS variation | <assess> | <contract> | <evidence or gap> |
| OP10 Stale state | <assess> | <contract> | <evidence or gap> |
| OP11 Duplication | <assess> | <contract> | <evidence or gap> |
| OP12 Concurrency | <assess> | <contract> | <evidence or gap> |

## Invariants

| Contract that must remain unchanged | Implementation / test evidence | Remaining gap |
|---|---|---|
| <authorization, compatibility, lifecycle, ABI, or other relevant contract> | <source/test/result link> | <gap or none identified within stated scope> |

## Validation

<!--
Allowed states: Passed / Failed / Pending / Not run / Unavailable / Not applicable.
For each claim, give provenance (author-run, supplied CI, or source inspection).
Source inspection is not test execution. Explain every Not applicable entry.
-->

| Criterion | Implementation | Test/check and meaningful assertion | Evidence / result | Gap |
|---|---|---|---|---|
| AC1 | <file/symbol> | <what would detect incorrect behavior> | <result and link, or Not run> | <remaining gap> |

| Check / exact command | State | Target / environment | Assessed commit or content identity / time | Provenance / evidence / limits |
|---|---|---|---|---|
| <relevant check> | Not run | <OS/architecture/configuration> | <snapshot and UTC time, or unavailable> | <result link or reason not run> |

- Required checks not yet available: <list failures, pending checks, skipped platforms, and unavailable results explicitly>
- Dependencies/features: <changes, vulnerability/license evidence, or no changes with inspected scope>
- Independent review: <Not performed / Complete / Limited / Unavailable / Stale>
- Guardian snapshot and report: <identity and report link, or reason unavailable>
- Unresolved Guardian findings: <IDs and dispositions, or no findings within the stated review scope>

| Checkpoint ID / phase | Snapshot | Assessment / unresolved decisions |
|---|---|---|
| <plan / increment / final> | <assessed content identity> | <result/report or explicitly unavailable> |

| Adversarial case / contract | Trigger and expected assertion | Test / actual result / gap |
|---|---|---|
| <scenario ID> | <feasible event ordering and observable outcome> | <test/result reference, proposed, or reason not applicable> |

- Pilot measurement: <record effort/dispositions in authorized local records if enrolled; never guess reviewer minutes or expose sensitive records here>

<!-- Complete means the supplied scope was assessed, not that the change is safe or approved. -->

## Reviewer attention

1. <focus ID, critical file/symbol and current snapshot line location or commit permalink, contract, why inspection matters, evidence and related decision/finding IDs>

<!-- Prioritize up to three focus areas. Disclose additional critical inspection
scope; the limit does not permit hiding material decisions or risks. Inspect
affected trust boundaries, state transitions, compatibility, and recovery code.
For plan review, use proposed locations without invented line numbers.
-->

| Decision ID / question / contract | Options / recommendation / impact | Critical code / evidence / gaps | Human owner role / status / response reference |
|---|---|---|---|
| <D1, material decision> | <alternatives and agent recommendation, not authorization> | <snapshot-bound locations and evidence> | <role; open/resolved/deferred; actual response or none supplied> |

<!-- If no material decisions exist, explain that within the stated scope rather
than inventing one. Only an authorized human response resolves or defers a decision;
deferral requires linked follow-up and does not waive mandatory gates.
-->

## Uncertainty

- Assumptions: <explicit assumptions and supporting evidence>
- Unverified behavior/platforms: <what remains untested or unknown>
- Human decisions / owner: <required decision and responsible role, not an invented approval>
- Evidence freshness: <results invalidated by later changes, or how the snapshot was rechecked>

<!-- Use a reasoned Not applicable where appropriate; empty sections and placeholders are incomplete evidence. -->
