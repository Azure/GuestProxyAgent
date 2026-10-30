---
name: gpa-pr
description: "Prepare an evidence-backed GuestProxyAgent PR proof package without committing, pushing, or publishing."
argument-hint: "Optional comparison base (default: upstream/dev) and approved task context"
agent: GPA Coding
---

Prepare the PR proof package for the current feature branch compared with
`upstream/dev`, unless the user supplies a different comparison base.
Use [GPA Coding](../agents/gpa-coding.agent.md) and follow the
[independent agent workflow](../../.ai/agent-workflow.md).

1. Refresh the comparison base before calculating the PR delta. Default to
   `upstream/dev`. Check that the `upstream` remote exists with
   `git remote get-url upstream`. If it is not configured, stop and return these
   setup commands to the user; do not add or change remotes automatically:

   ```powershell
   git remote add upstream https://github.com/Azure/GuestProxyAgent.git
   git fetch upstream
   ```

   When configured, automatically fetch the selected remote branch without a
   separate confirmation. For the default base, run:

   ```powershell
   git fetch upstream refs/heads/dev:refs/remotes/upstream/dev
   ```

   For an explicit remote-branch override such as `upstream/main`, fetch that
   branch into its corresponding remote-tracking ref instead. If the supplied
   base is not an unambiguous remote branch, ask for clarification. Verify the
   refreshed ref and record its commit. If remote lookup, fetch, or ref resolution
   fails, stop and report the error and corrective action; do not continue with
   stale evidence or silently substitute another base. This request authorizes
   fetching only: do not run `git pull`, merge, rebase, switch branches, or change
   working-tree files.
2. Establish the approved intent, acceptance criteria, comparison base, and
   task-owned paths. Inspect Git status and the complete task delta, including
   committed, staged, unstaged, and relevant new files. Preserve and distinguish
   unrelated work. If the base is unavailable or the task scope is ambiguous,
   ask for clarification rather than silently substituting another base or
   inferring approval from the code.
3. Read the [repository PR template](../pull_request_template.md) and
   [proof-package contract](../../.ai/proof-package.md). Fill a copy, preserving
   its headings, comments, tables, checklist items, and order. Do not edit the
   reusable template. Replace placeholders with verified facts, explicit gaps,
   or justified Not applicable entries.
4. Run appropriate existing validation according to the
   [testing requirements](../../.ai/testing-requirements.md). Record exact
   commands, targets, results, provenance, and the assessed snapshot. Obtain
   authorization before checks that modify services, install tools, or create
   cloud resources. Do not present missing, failed, or stale checks as passed.
5. Request final GPA Guardian review of the cumulative task with the pinned
   intake and draft proof package. Reuse earlier review evidence only if its
   scope and snapshot still apply. Follow the
   [checkpoint limits](../../.ai/continuous-review.md); do not invent earlier
   checkpoints or restart an exhausted review budget. If independent review
   cannot run, explicitly report Independent review not performed.
6. Return the completed PR description as raw, copy-and-paste-ready Markdown in
   one fenced code block labeled `markdown`. Use an outer fence longer than any
   code fence inside the description so nested examples remain intact. Put only
   the PR description inside the block: all eight completed template sections,
   comments, tables, and checklist items, with no surrounding chat commentary,
   tool transcripts, or unresolved placeholders. Use repository-relative links
   or GitHub permalinks rather than local absolute paths so links work on GitHub.
   Any setup/fetch error or clarification request is a separate response, not a
   completed PR description.

   Preserve supported findings,
   uncertainty, missing evidence, and human decisions. Distinguish proposed
   adversarial tests from executed tests. Report defects and proposed fixes;
   this preparation request does not authorize implementation changes.

Do not modify implementation files, make unrelated changes, commit, push,
create or edit a GitHub PR, or publish reviews. Do not write a separate package
file unless the user asks.
