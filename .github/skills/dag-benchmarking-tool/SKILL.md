---
name: dag-benchmarking-tool
description: "Assess Guest Proxy Agent DAG readiness with deterministic coverage, navigation, and document-shape checks."
---

# DAG readiness checks

Run from the repository root after generation:

```powershell
python -X utf8 scripts\dag-enrichment\validate_dags.py
python -X utf8 scripts\dag-enrichment\run_dag_pipeline.py --status
```

Report the source count, mapping count, missing/duplicate assignments, broken
links, document-length violations, and missing tier-2 pointers. Failure is
explicit and must block publication until resolved.

These are structural readiness checks, not a model-based navigation benchmark.
For qualitative review, use representative architecture, Windows/Linux platform,
request authorization, extension lifecycle, and eBPF questions. Cite the source
and document used for each answer; never fabricate a benchmark score.

No external benchmark service, private package feed, or credential is required.
