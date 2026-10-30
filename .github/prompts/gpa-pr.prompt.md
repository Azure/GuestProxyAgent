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

1. Establish the approved intent, acceptance criteria, comparison base, and
   task-owned paths. Inspect Git status and the complete task delta, including
   committed, staged, unstaged, and relevant new files. Preserve and distinguish
   unrelated work. If the base is unavailable or the task scope is ambiguous,
   ask for clarification rather than silently substituting another base or
   inferring approval from the code.
2. Read the [repository PR template](../pull_request_template.md) and
   [proof-package contract](../../.ai/proof-package.md). Fill a copy, preserving
   its headings, comments, tables, checklist items, and order. Do not edit the
   reusable template. Replace placeholders with verified facts, explicit gaps,
   or justified Not applicable entries.
3. Run appropriate existing validation according to the
   [testing requirements](../../.ai/testing-requirements.md). Record exact
   commands, targets, results, provenance, and the assessed snapshot. Obtain
   authorization before checks that modify services, install tools, or create
   cloud resources. Do not present missing, failed, or stale checks as passed.
4. Request final GPA Guardian review of the cumulative task with the pinned
   intake and draft proof package. Reuse earlier review evidence only if its
   scope and snapshot still apply. Follow the
   [checkpoint limits](../../.ai/continuous-review.md); do not invent earlier
   checkpoints or restart an exhausted review budget. If independent review
   cannot run, explicitly report Independent review not performed.
5. Return the completed PR body in chat. Preserve supported findings,
   uncertainty, missing evidence, and human decisions. Distinguish proposed
   adversarial tests from executed tests. Report defects and proposed fixes;
   this preparation request does not authorize implementation changes.

Do not modify implementation files, make unrelated changes, commit, push,
create or edit a GitHub PR, or publish reviews. Do not write a separate package
file unless the user asks.
