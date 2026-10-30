"""Validate mapping coverage, generated DAGs, navigation, and Git hygiene."""

import json
from pathlib import Path
import re
import subprocess

from generate_source_summaries import source_files


ROOT = Path(__file__).resolve().parents[2]


def main() -> None:
    errors = []
    mapping = json.loads(
        (ROOT / "scripts/dag-enrichment/compose_to_dag_mapping-symbols.json")
        .read_text(encoding="utf-8")
    )
    expected_sources = set(source_files())
    mapped_sources = []
    expected_final = set()
    expected_intermediate = set()
    for entry in mapping["mappings"]:
        relative = entry["dag_doc_new"]
        final = ROOT / "copilot-docs" / relative
        intermediate = ROOT / "intermediate-docs" / relative.replace(".md", ".content.md")
        expected_final.add(final)
        expected_intermediate.add(intermediate)
        mapped_sources.extend(
            path.removesuffix(".md") for path in entry["compose_files"]
        )
        for path in (final, intermediate):
            if not path.is_file() or not path.stat().st_size:
                errors.append(f"Missing/empty document: {path.relative_to(ROOT)}")
        if final.is_file():
            text = final.read_text(encoding="utf-8")
            if len(text.splitlines()) > 200:
                errors.append(f"Final exceeds 200 lines: {relative}")
            if "TIER2-POINTER:BEGIN" not in text:
                errors.append(f"Missing tier-2 pointer: {relative}")
    if set(mapped_sources) != expected_sources:
        errors.append("Mapping does not exactly cover tracked supported source files")
    if len(mapped_sources) != len(set(mapped_sources)):
        errors.append("Sources assigned to more than one primary mapping")
    actual_final = {
        path for path in (ROOT / "copilot-docs").glob("L[123]-*/*.md")
        if path.name != "docs-index.md"
    }
    if actual_final != expected_final:
        errors.append("Final document set differs from mapping")
    if set((ROOT / "intermediate-docs").rglob("*.content.md")) != expected_intermediate:
        errors.append("Intermediate document set differs from mapping")
    for folder in ("copilot-docs", "intermediate-docs"):
        for path in (ROOT / folder).rglob("*.md"):
            text = path.read_text(encoding="utf-8")
            if re.search(r"[A-Za-z]:[\\/](?:src|Users)[\\/]", text, re.IGNORECASE):
                errors.append(f"Absolute checkout path: {path.relative_to(ROOT)}")
            if re.search(
                r"""(?:api_key|AccountKey|SharedAccessSignature|password)\s*[:=]\s*["'][^"'<> \n]{12,}""",
                text, re.IGNORECASE,
            ):
                errors.append(f"Possible credential literal: {path.relative_to(ROOT)}")
            if folder == "copilot-docs":
                for target in re.findall(r"(?<!!)\[[^\]]+\]\(([^)]+)\)", text):
                    target = target.split("#", 1)[0].strip("<>")
                    if target and "://" not in target and "{" not in target:
                        if not (path.parent / target).exists():
                            errors.append(f"Broken link in {path.relative_to(ROOT)}: {target}")
    master = (ROOT / "copilot-docs/docs-index.md").read_text(encoding="utf-8")
    for relative in (
        "L0-foundations/codebase-primer.md", "L1-conceptual/docs-index.md",
        "L2-platform/docs-index.md", "L3-flows/docs-index.md",
    ):
        if relative not in master or not (ROOT / "copilot-docs" / relative).is_file():
            errors.append(f"Missing required index navigation: {relative}")
    staged = subprocess.check_output(
        ["git", "diff", "--cached", "--name-only", "-z"], cwd=ROOT,
    ).decode("utf-8").split("\0")
    for name in filter(None, staged):
        if (
            name.startswith((".compose", ".astred", ".vscode/", "enrichment-logs/", "scripts/dag-enrichment/output/"))
            or "__pycache__" in Path(name).parts
            or Path(name).suffix in (".pyc", ".dll", ".exe", ".log")
        ):
            errors.append(f"Private/generated runtime artifact staged: {name}")
    if errors:
        raise SystemExit("\n".join(errors))
    print(
        f"PASS: {len(expected_sources)} source files mapped exactly once; "
        f"{len(expected_final)} final/intermediate pairs; line limits, pointers, "
        "index links, sensitive-literal checks, and staged artifact exclusions."
    )


if __name__ == "__main__":
    main()
