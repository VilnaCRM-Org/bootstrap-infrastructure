#!/usr/bin/env python3
"""Generate Wily advisory reports without requiring a pristine local worktree."""

from __future__ import annotations

import argparse
import shutil
import subprocess  # nosec B404 - this guardrail intentionally shells out.
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

DEFAULT_PATHS = ("pulumi/infra", "policy_pack", "scripts")
DEFAULT_OPERATORS = "raw,cyclomatic,maintainability"
DEFAULT_LIMIT = 20
DEFAULT_MAX_REVISIONS = 25


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build Wily trend reports for the repository.",
    )
    parser.add_argument(
        "paths",
        nargs="*",
        default=list(DEFAULT_PATHS),
        help="Repository paths to analyze with Wily.",
    )
    parser.add_argument(
        "--report-dir",
        default=".quality-reports/wily",
        help="Directory where Wily text reports will be written.",
    )
    parser.add_argument(
        "--max-revisions",
        type=int,
        default=DEFAULT_MAX_REVISIONS,
        help="Maximum number of historical commits to include in the trend cache.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=DEFAULT_LIMIT,
        help="Maximum number of ranked findings to emit per report.",
    )
    return parser.parse_args()


def run_command(command: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command,
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
    )  # nosec B603
    if result.returncode != 0:
        stderr = result.stderr.strip()
        raise RuntimeError(stderr or f"command failed: {' '.join(command)}")
    return result


def status_output_is_clean(output: str) -> bool:
    return output.strip() == ""


def worktree_is_clean(repo_root: Path) -> bool:
    result = run_command(
        ["git", "status", "--short", "--untracked-files=normal"],
        repo_root,
    )
    return status_output_is_clean(result.stdout)


@contextmanager
def wily_workspace(repo_root: Path) -> Iterator[tuple[Path, bool]]:
    if worktree_is_clean(repo_root):
        yield repo_root, False
        return

    with tempfile.TemporaryDirectory(prefix="wily-report-") as temp_dir:
        clone_root = Path(temp_dir) / "repo"
        run_command(
            [
                "git",
                "clone",
                "--quiet",
                "--no-hardlinks",
                str(repo_root),
                str(clone_root),
            ],
            repo_root,
        )
        yield clone_root, True


def write_report(report_path: Path, content: str) -> None:
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(content, encoding="utf-8")


def build_wily_reports(
    repo_root: Path,
    report_dir: Path,
    paths: list[str],
    max_revisions: int,
    limit: int,
) -> bool:
    report_dir.mkdir(parents=True, exist_ok=True)

    with wily_workspace(repo_root) as (workspace, cloned_head):
        shutil.rmtree(workspace / ".wily", ignore_errors=True)
        build_command = [
            "wily",
            "build",
            "--max-revisions",
            str(max_revisions),
            "--operators",
            DEFAULT_OPERATORS,
            "--archiver",
            "git",
            *paths,
        ]
        run_command(build_command, workspace)

        maintainability = run_command(
            ["wily", "rank", ".", "maintainability.mi", "--limit", str(limit)],
            workspace,
        )
        complexity = run_command(
            [
                "wily",
                "rank",
                ".",
                "cyclomatic.complexity",
                "--limit",
                str(limit),
                "--desc",
            ],
            workspace,
        )

        write_report(report_dir / "maintainability.txt", maintainability.stdout)
        write_report(report_dir / "complexity.txt", complexity.stdout)
        return cloned_head


def main() -> int:
    args = parse_args()
    repo_root = Path(__file__).resolve().parents[1]
    report_dir = repo_root / args.report_dir
    shutil.rmtree(report_dir, ignore_errors=True)
    cloned_head = build_wily_reports(
        repo_root=repo_root,
        report_dir=report_dir,
        paths=args.paths,
        max_revisions=args.max_revisions,
        limit=args.limit,
    )
    if cloned_head:
        print(
            "Wily report generated from a temporary clone of HEAD because the "
            "current worktree has local changes.",
        )
    else:
        print("Wily report generated from the current clean checkout.")
    print(f"Reports written to {report_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
