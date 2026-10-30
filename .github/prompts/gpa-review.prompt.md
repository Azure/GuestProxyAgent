---
name: gpa-review
description: "Review local GuestProxyAgent changes against a refreshed comparison base with independent GPA Guardian assessment, without fixes or publication."
argument-hint: "Optional comparison base (default: upstream/dev), task scope, and approved intent"
agent: GPA Coding
---

Review the current local task against `upstream/dev`, unless the user supplies
another remote-branch comparison base. For this invocation, GPA Coding acts only
as evidence collector and validation coordinator, not as implementer or reviewer.
Follow the [independent agent workflow](../../.ai/agent-workflow.md).

1. Apply **only step 1** of the [PR preparation prompt](gpa-pr.prompt.md) to
   resolve and automatically fetch the comparison branch. Reuse its missing-remote
   setup, ambiguity, failure-stop, and no-stale-base rules. Do not apply its
   PR-generation steps. This invocation authorizes that fetch, not other external
   retrieval, remote changes, pulls, merges, rebases, or branch switches.
2. Establish approved intent, acceptance criteria, exclusions, and task-owned
   paths from the user's request or available conversation. Ask for clarification
   if scope is ambiguous; do not infer approval from code. Inspect Git status,
   the committed delta from the comparison branch's merge base to HEAD, staged
   and unstaged changes, and complete relevant new/untracked files. Preserve and
   distinguish unrelated dirty work. An empty tracked diff is not proof that
   there are no changes; if the complete scoped delta is empty, report that
   explicitly rather than inventing findings.
3. Prepare the pinned Guardian intake and an evidence summary using the
   [proof-package contract](../../.ai/proof-package.md). Record comparison-ref,
   merge-base, and HEAD commits, scoped line-numbered diff, file hashes, deletion
   markers, dirty-work boundaries, affected platforms, and unknowns. Select
   relevant guidance from the [context index](../../.ai/README.md).
4. Run the smallest appropriate existing checks under the
   [testing requirements](../../.ai/testing-requirements.md). Record exact
   commands, results, environment, time, snapshot, and provenance. Obtain required
   authorization for tool installation, service changes, or cloud resources.
   Do not use auto-fix/format-write commands or change source/test files. Preserve
   failed, skipped, unavailable, and unexecuted checks. Recheck the snapshot after
   validation; content drift invalidates earlier evidence.
5. Invoke GPA Guardian as a separate subagent for final assessment of the complete
   scoped delta, passing the intake and evidence summary. Use the
   [checkpoint contract](../../.ai/continuous-review.md) with a stable ID and
   existing review history; do not reset budgets or invent earlier checkpoints.
   Guardian assesses correctness, leaks/crashes, security, telemetry adequacy,
   tests, compatibility, and regression risk where applicable. Let Guardian select
   any necessary bounded specialist depth; do not launch all specialists.
   Wait without editing reviewed content and recheck snapshot identity afterward.
   If delegation is unavailable, report **Independent review not performed**;
   do not substitute self-review or fabricate a Guardian result.
6. Return a local review report in chat, not a PR title or description:
   - Assessed snapshot, comparison/merge base, scope, risk, and review status.
   - Supported findings with IDs, severity, locations, triggering conditions,
     consequences, evidence, and proposed fixes, ranked by severity/confidence.
   - Exact validation results and acceptance-criteria mapping, with provenance.
   - Evidence gaps, unverified scenarios, critical reviewer focus, and human
     decisions. Distinguish proposed adversarial tests from executed tests.
   - The actual Guardian structured result, preserving limitations and findings.

Do not implement fixes, edit files, create tests or report files, commit, push,
create/update PRs, publish reviews, approve, or merge. Report defects for a
separately authorized implementation task; do not enter an automatic fix/review
loop. No findings is not approval, and a changed snapshot makes the assessment
stale rather than current verification.
