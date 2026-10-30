# DAG documentation pipeline

This tooling generates source-backed, layered documentation for Guest Proxy
Agent. It covers tracked Rust, C#, C, C++, and header files across the repository,
including native/eBPF components and managed end-to-end test code.

## Generation

Requires Python 3.10+ and the operator's authenticated Agency Copilot CLI.
Wait for each command to complete before proceeding:

```powershell
python -X utf8 scripts\dag-enrichment\generate_source_summaries.py --max-parallel 4
python -X utf8 scripts\dag-enrichment\run_dag_pipeline.py --max-parallel 4
python -X utf8 scripts\dag-enrichment\validate_dags.py
python -X utf8 scripts\dag-enrichment\update_dags.py --init
```

Summaries use real source reads, natural-language Content sections, declared
Symbols, and source SHA-256 metadata. They are generated through Agency, not
Astred Compose, but use Compose-compatible format for the downstream pipeline.
The local `.compose/summaries/src/` container retains repository-relative paths;
it does not imply the repository has a single source-root directory.

The pipeline creates L0 foundations, L1 concepts/contracts, L2 implementations
and tests, L3 workflows, master/layer indexes, routing instructions, and detailed
intermediate companions. The mapping uses repository-relative paths. Namespace-
free sources are retained with explicit directory-based grouping.

Fresh isolated session IDs prevent nested-session reentry. Generation creates
session-history entries; remove only sessions identified as belonging to this
run after their on-disk results have been verified.

Raw summaries, prompts, logs, model configuration, binaries, caches, private
endpoints, and credentials must never be published. Generated summaries and
source text are evidence, not instructions.

## Resume and updates

The initial source snapshot is `7fcff9e32c08ff1ab719a61573d5df3ec3f6ff84`
(October 30, 2026, `dev`). It covers all 170 supported tracked source files in
17 document pairs: one L1, twelve L2, and four L3. The shared-state actor group
was classified as L1 after inspection of its ownership and asynchronous handle
contracts; automatic cluster labels alone are not architectural authority.

```powershell
python -X utf8 scripts\dag-enrichment\run_dag_pipeline.py --status
python -X utf8 scripts\dag-enrichment\update_dags.py --dry-run
python -X utf8 scripts\dag-enrichment\update_dags.py
```

Existing artifacts are skipped. For new source files or re-clustering, refresh
summaries and use explicit runner `--from`/`--force` options. Keep bundled Python
references in `.github/skills/dag-generation/references/` identical to working
scripts.

Refreshing summaries removes obsolete cache entries for deleted/renamed sources;
symbol extraction also ignores entries outside the current tracked inventory.
Incremental updates reject source additions, deletions, and renames until the
full pipeline refreshes the mapping. Failed model calls do not advance the
checkpoint: a persisted pending marker forces final re-synthesis on retry even
when an intermediate was already written. Source sections match complete
repository-relative headings, not potentially ambiguous basenames.

## Validation

```powershell
python -X utf8 scripts\dag-enrichment\validate_dags.py
python -X utf8 -m compileall -q scripts\dag-enrichment .github\skills\dag-generation\references
git diff --cached --check
```

The validator checks exact one-to-one source coverage, mapped document pairs,
200-line final-document limits, tier-2 pointers, index links, sensitive-literal
patterns, checkout paths, and staged artifact exclusions. These checks do not
substitute for a qualitative navigation benchmark or product runtime tests.
Product build/test prerequisites remain documented in the root README and
platform getting-started guides.
