#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT
"""
Enforce the binary-bloat budget for the GuestProxyAgent workspace.

Implements Innovation 7.3 (crate consolidation / bloat budget):

  * Hard ceiling on total stripped binary size.
  * Per-crate ceiling expressed as a share of the total text section.

Input is a JSON document produced by `cargo bloat --message-format json`.
The script exits non-zero (and prints a human-readable report) when the
budget is exceeded so it can gate CI.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Iterable


# Workspace-first-party crates are exempt from the per-crate share ceiling.
# Bloating one of our own crates is a code-review problem, not a dependency
# problem; the total-size ceiling still applies.
FIRST_PARTY_CRATES = {
    "azure_proxy_agent",
    "azure-proxy-agent",
    "ProxyAgentExt",
    "proxy_agent",
    "proxy_agent_extension",
    "proxy_agent_setup",
    "proxy_agent_shared",
}

# Synthetic buckets emitted by cargo-bloat that don't correspond to a tunable
# third-party dependency. The total-size ceiling still bounds them.
SYNTHETIC_BUCKETS = {
    "std",
    "[Unknown]",
    "?",
}

# Per-(target, crate, dependency) ceiling overrides are passed in via
# --crate-share-override on the command line; see main() below.
# Use this instead of a global allowlist so the policy stays narrow:
# raising the ceiling for clap in proxy_agent_setup must not also raise it
# for every other dependency in every other binary.


def _iter_crate_sizes(report: dict) -> Iterable[tuple[str, int]]:
    """Yield (crate_name, size_bytes) pairs from a cargo-bloat JSON report."""
    crates = report.get("crates")
    if crates is None:
        # cargo-bloat emits a "functions" array when run without --crates;
        # try to fall back gracefully so the script is still useful locally.
        for fn in report.get("functions", []):
            crate = fn.get("crate") or "?"
            size = int(fn.get("size", 0))
            yield crate, size
        return

    for entry in crates:
        name = entry.get("name") or "?"
        size = int(entry.get("size", 0))
        yield name, size


def _aggregate(report: dict) -> tuple[int, list[tuple[str, int]]]:
    """Return (total_text_size, sorted_crate_sizes_desc)."""
    totals: dict[str, int] = {}
    for crate, size in _iter_crate_sizes(report):
        totals[crate] = totals.get(crate, 0) + size

    total_text = int(report.get("text-section-size", sum(totals.values())))
    ranked = sorted(totals.items(), key=lambda kv: kv[1], reverse=True)
    return total_text, ranked


def _format_bytes(n: int) -> str:
    size = float(n)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if size < 1024 or unit == "GiB":
            if unit == "B":
                return f"{int(size):,d} {unit}"
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} GiB"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--bloat-json",
        type=Path,
        default=Path("bloat.json"),
        help="Path to cargo-bloat JSON output (default: bloat.json).",
    )
    parser.add_argument(
        "--max-binary-bytes",
        type=int,
        required=True,
        help="Hard ceiling on the stripped binary text section, in bytes.",
    )
    parser.add_argument(
        "--max-crate-share",
        type=float,
        required=True,
        help="Maximum fraction of text section any non-first-party crate may consume (0..1).",
    )
    parser.add_argument(
        "--crate-share-override",
        action="append",
        default=[],
        metavar="NAME=SHARE",
        help=(
            "Raise the share ceiling for a single crate (repeatable). "
            "Example: --crate-share-override clap_builder=0.35. "
            "Only the named crate is affected; all others stay at --max-crate-share."
        ),
    )
    parser.add_argument(
        "--top",
        type=int,
        default=10,
        help="How many top contributors to print in the report (default: 10).",
    )
    args = parser.parse_args(argv)

    if not args.bloat_json.exists():
        print(f"error: {args.bloat_json} not found", file=sys.stderr)
        return 2

    try:
        report = json.loads(args.bloat_json.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"error: {args.bloat_json} is not valid JSON: {exc}", file=sys.stderr)
        return 2

    if not 0 < args.max_crate_share <= 1:
        print("error: --max-crate-share must be in (0, 1]", file=sys.stderr)
        return 2

    # Parse --crate-share-override into a {crate -> ceiling} map. We index by
    # both the dashed and underscored crate name because cargo-bloat reports
    # use underscored forms while Cargo.toml entries use dashes.
    overrides: dict[str, float] = {}
    for spec in args.crate_share_override:
        name, sep, value = spec.partition("=")
        if not sep or not name:
            print(
                f"error: bad --crate-share-override {spec!r} (expected NAME=SHARE)",
                file=sys.stderr,
            )
            return 2
        try:
            share = float(value)
        except ValueError:
            print(
                f"error: bad share value in --crate-share-override {spec!r}",
                file=sys.stderr,
            )
            return 2
        if not 0 < share <= 1:
            print(
                f"error: share in --crate-share-override {spec!r} must be in (0, 1]",
                file=sys.stderr,
            )
            return 2
        overrides[name] = share
        overrides[name.replace("-", "_")] = share

    total_text, ranked = _aggregate(report)
    file_size = int(report.get("file-size", 0)) or total_text

    failures: list[str] = []

    if file_size > args.max_binary_bytes:
        failures.append(
            f"binary size {_format_bytes(file_size)} exceeds ceiling "
            f"{_format_bytes(args.max_binary_bytes)}"
        )

    if total_text > 0:
        for crate, size in ranked:
            share = size / total_text
            normalized = crate.replace("-", "_")
            # First-party crates can grow without tripping the share gate;
            # the absolute size ceiling still bounds them. Synthetic buckets
            # (std, [Unknown], ?) aren't tunable dependencies.
            if (
                crate in FIRST_PARTY_CRATES
                or normalized in FIRST_PARTY_CRATES
                or crate in SYNTHETIC_BUCKETS
            ):
                continue
            # Per-crate override (if any) wins over the global ceiling.
            ceiling = overrides.get(crate, overrides.get(normalized, args.max_crate_share))
            if share <= ceiling:
                continue
            tag = "" if ceiling == args.max_crate_share else " [override]"
            failures.append(
                f"crate '{crate}' is {share * 100:.1f}% of text "
                f"(> {ceiling * 100:.1f}% ceiling{tag})"
            )

    print("== bloat budget report ==")
    print(f"binary file size : {_format_bytes(file_size)}")
    print(f"text section size: {_format_bytes(total_text)}")
    if overrides:
        # Deduplicate the dashed/underscored aliases for display.
        shown: dict[str, float] = {}
        for name, share in overrides.items():
            shown.setdefault(name.replace("-", "_"), share)
        print("per-crate overrides:")
        for name, share in sorted(shown.items()):
            print(f"  {name}: {share * 100:.1f}%")
    print(f"top {args.top} contributors:")
    for crate, size in ranked[: args.top]:
        share = (size / total_text * 100) if total_text else 0.0
        print(f"  {share:5.1f}%  {_format_bytes(size):>10}  {crate}")

    if failures:
        print()
        print("FAIL: bloat budget exceeded")
        for f in failures:
            print(f"  - {f}")
        return 1

    print()
    print("OK: within bloat budget")
    return 0


if __name__ == "__main__":
    sys.exit(main())
