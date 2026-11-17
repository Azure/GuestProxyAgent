"""
Shared utilities for the DAG enrichment pipeline.

Provides common helpers used across multiple pipeline scripts:
- detect_compose_base(): auto-detect compose summaries directory
"""

import re
from pathlib import Path
from uuid import uuid4


def isolated_copilot_args() -> list[str]:
    """Keep model-backed subprocesses separate from the invoking agent session."""
    return ["--session-id", str(uuid4()), "--no-aec"]


def normalize_repo_paths(text: str, repo_root: Path) -> str:
    """Remove checkout-specific prefixes from generated documentation."""
    pattern = re.compile(
        r"[A-Za-z]:[\\/](?:[^\\/\n`]+[\\/])*?"
        + re.escape(repo_root.name) + r"[\\/]",
        re.IGNORECASE,
    )
    return pattern.sub("", text)


def detect_compose_base(repo_root: Path, override: str | None = None) -> Path:
    """Auto-detect the compose summaries base directory.

    Checks two locations in order:
      1. {repo_root}/.compose/summaries/src/  (--embed none output)
      2. {repo_root}/.astred/compose/summaries/{REPO_NAME}/src/  (--embed all output)

    Args:
        repo_root: Path to the repository root.
        override: If provided, use this path directly instead of auto-detecting.

    Returns:
        Path to the compose summaries src directory.
    """
    if override:
        return Path(override).resolve()
    # Check new path first: .compose/summaries/src/ (from --embed none)
    new_path = repo_root / ".compose" / "summaries" / "src"
    if new_path.exists():
        return new_path
    # Also check .compose/summaries/ for non-src layouts
    new_base = repo_root / ".compose" / "summaries"
    if new_base.exists():
        subdirs = [d for d in new_base.iterdir() if d.is_dir()]
        if subdirs:
            # If there's a src/ subdir, use it; otherwise use first subdir
            src_dir = new_base / "src"
            return src_dir if src_dir.exists() else subdirs[0]
    # Fall back to legacy path: .astred/compose/summaries/{REPO_NAME}/src/
    legacy_dir = repo_root / ".astred" / "compose" / "summaries"
    if legacy_dir.exists():
        subdirs = [d for d in legacy_dir.iterdir() if d.is_dir()]
        if len(subdirs) == 1:
            return subdirs[0] / "src"
        if len(subdirs) > 1:
            raise ValueError(
                f"Multiple summary dirs found: {[d.name for d in subdirs]}. "
                f"Use --compose-base to specify which one to use."
            )
    raise FileNotFoundError(
        f"No compose summaries found. Checked:\n"
        f"  {new_path}\n"
        f"  {legacy_dir}\n"
        f"Run astred compose first, or pass --compose-base <path>."
    )
