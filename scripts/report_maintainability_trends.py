#!/usr/bin/env python3
from __future__ import annotations

import os
import shutil
from pathlib import Path

from _script_support import repo_root, run, split_values


def main() -> int:
    root_dir = Path(os.environ.get("ROOT_DIR", repo_root(__file__))).resolve()
    quality_artifact_dir = Path(
        os.environ.get(
            "QUALITY_ARTIFACT_DIR",
            str(root_dir / ".artifacts" / "quality"),
        )
    )
    if not quality_artifact_dir.is_absolute():
        quality_artifact_dir = root_dir / quality_artifact_dir

    wily_targets = split_values(os.environ.get("WILY_TARGETS", "pulumi policy scripts"))
    wily_cache_dir = quality_artifact_dir / "wily-cache"
    wily_report = quality_artifact_dir / "wily-rank.txt"

    quality_artifact_dir.mkdir(parents=True, exist_ok=True)

    git_ready = run(
        ["git", "rev-parse", "--is-inside-work-tree"], cwd=root_dir, check=False
    )
    head_ready = run(
        ["git", "rev-parse", "--verify", "HEAD"], cwd=root_dir, check=False
    )
    if git_ready.returncode != 0 or head_ready.returncode != 0:
        wily_report.write_text(
            (
                "Wily maintainability report skipped: this workspace does not "
                "expose a resolvable git HEAD.\n"
                "Run the report from a normal repository checkout to build "
                "maintainability trends.\n"
            ),
            encoding="utf-8",
        )
        return 0

    if wily_cache_dir.exists():
        if wily_cache_dir.is_symlink() or not wily_cache_dir.is_dir():
            wily_cache_dir.unlink()
        else:
            shutil.rmtree(wily_cache_dir)

    run(
        [
            "uv",
            "run",
            "wily",
            "--path",
            str(root_dir),
            "--cache",
            str(wily_cache_dir),
            "build",
            "-n",
            "50",
            *wily_targets,
        ],
        cwd=root_dir,
    )

    result = run(
        [
            "uv",
            "run",
            "wily",
            "--path",
            str(root_dir),
            "--cache",
            str(wily_cache_dir),
            "rank",
            ".",
            "maintainability.mi",
            "--limit",
            "20",
        ],
        cwd=root_dir,
        capture_output=True,
    )
    wily_report.write_text(result.stdout, encoding="utf-8")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
