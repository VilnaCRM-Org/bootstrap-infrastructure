"""Prove the required PR secret scan includes merge-only changes."""

from __future__ import annotations

import subprocess
from pathlib import Path


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _scan(repo: Path, config: Path, log_opts: str) -> int:
    return subprocess.run(
        [
            "gitleaks",
            "git",
            ".",
            f"--log-opts={log_opts}",
            "--config",
            str(config),
            "--exit-code=7",
            "--no-banner",
            "--no-color",
            "--redact",
        ],
        cwd=repo,
        capture_output=True,
        text=True,
        check=False,
    ).returncode


def test_pr_range_finds_marker_added_only_in_merge_commit(tmp_path: Path) -> None:
    """A merge resolution must not disappear from the PR-range scan."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-qb", "trunk")
    _git(repo, "config", "user.name", "Synthetic Test")
    _git(repo, "config", "user.email", "synthetic@example.invalid")
    (repo / "baseline.txt").write_text("baseline\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "baseline")
    base = _git(repo, "rev-parse", "HEAD")

    _git(repo, "checkout", "-qb", "feature")
    (repo / "feature.txt").write_text("feature\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "feature")
    _git(repo, "checkout", "trunk")
    (repo / "main.txt").write_text("main\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "main")
    _git(repo, "merge", "--no-ff", "--no-commit", "feature")

    marker = repo / "resolution.txt"
    marker.write_text("SYNTHETIC_SENTINEL_123456789012\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "merge with synthetic marker")
    marker.unlink()
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "remove marker")
    head = _git(repo, "rev-parse", "HEAD")

    config = tmp_path / "gitleaks.toml"
    config.write_text(
        "title = 'Synthetic merge test'\n"
        "[[rules]]\n"
        "id = 'synthetic-marker'\n"
        "regex = '''SYNTHETIC_SENTINEL_[0-9]{12}'''\n",
        encoding="utf-8",
    )

    assert _scan(repo, config, "-1") == 0
    assert _scan(repo, config, f"{base}..{head}") == 0
    assert _scan(repo, config, f"--diff-merges=separate {base}..{head}") == 7
