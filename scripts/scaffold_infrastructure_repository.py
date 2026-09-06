#!/usr/bin/env python3
"""Create a complete reviewed service scaffold in a previously absent directory."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import tempfile
from pathlib import Path

RUNTIME_FILES = (
    "Dockerfile",
    ".dockerignore",
    "pyproject.toml",
    "uv.lock",
    ".github/actions/load-aws-ci-env/action.yml",
    ".github/workflows/governance-promotion.yml",
    "scripts/_script_support.py",
    "scripts/_pulumi_command_support.py",
    "scripts/_pulumi_stack_config.py",
    "scripts/_github_environment_controls.py",
    "scripts/_github_evidence_environment.py",
    "scripts/_github_repository_controls.py",
    "scripts/run_pulumi_command.py",
    "scripts/prepare_policy_pack.py",
    "scripts/pulumi_ci_guardrails.py",
    "scripts/pulumi_command_preflight.py",
    "scripts/pulumi_pr_comment.py",
    "scripts/governance_paths.py",
    "scripts/governance_promotion.py",
    "scripts/validate_ci_environment.py",
    "scripts/initialize_service_stack.py",
)


def _bind_python_project(staged: Path, repository: str) -> None:
    """Rename only the virtual project while preserving locked dependencies."""
    for relative, section in (
        ("pyproject.toml", r"\[project\]"),
        ("uv.lock", r"\[\[package\]\]"),
    ):
        path = staged / relative
        contents, count = re.subn(
            rf'(?m)^({section}\nname = )"bootstrap-infrastructure"$',
            rf'\g<1>"{repository}"',
            path.read_text(),
        )
        if count != 1:
            raise ValueError("Expected exactly one bootstrap Python project identity")
        path.write_text(contents)


def generate(root: Path, destination: Path, repository: str) -> dict:
    """Assemble an audited dependency closure without merging into existing data."""
    if not re.fullmatch(r"[a-z][a-z0-9-]*-infrastructure", repository):
        raise ValueError("Repository must be a lowercase *-infrastructure slug")
    if len(f"GitHubCiConfigRead-{repository}-prod-preview") > 64:
        raise ValueError(
            "Repository renders a config-read role longer than 64 characters"
        )
    if destination.exists() or destination.is_symlink():
        raise FileExistsError("Destination already exists; never overwrite a service")
    template = root / "pulumi/user-service-infrastructure"
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=destination.parent) as temporary:
        staged = Path(temporary) / "repository"
        shutil.copytree(template, staged, ignore=shutil.ignore_patterns("__pycache__"))
        for path in staged.rglob("*"):
            if path.is_file():
                path.write_text(
                    path.read_text().replace("user-service-infrastructure", repository)
                )
        for relative in RUNTIME_FILES:
            target = staged / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(root / relative, target)
        shutil.copytree(
            root / "policy",
            staged / "policy",
            ignore=shutil.ignore_patterns(".venv", "__pycache__", "*.pyc"),
        )
        _bind_python_project(staged, repository)
        manifest = {
            "schemaVersion": 1,
            "repository": repository,
            "pulumiProject": repository,
            "pulumiCliVersion": "3.223.0",
            "capabilities": "metadata-and-governance-owned-backend-only",
            "files": {
                path.relative_to(staged).as_posix(): hashlib.sha256(
                    path.read_bytes()
                ).hexdigest()
                for path in sorted(staged.rglob("*"))
                if path.is_file()
            },
        }
        (staged / "scaffold-manifest.json").write_text(
            json.dumps(manifest, indent=2) + "\n"
        )
        # Reserve an absent destination. Atomic directory rename refuses a
        # nonempty destination if a concurrent writer adds data after reservation.
        destination.mkdir()
        staged.rename(destination)
    return manifest


def main(argv: list[str] | None = None) -> int:
    """Generate a new repository; the operator reviews it before any publication."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", default="user-service-infrastructure")
    parser.add_argument("--destination", required=True, type=Path)
    args = parser.parse_args(argv)
    generate(Path(__file__).resolve().parents[1], args.destination, args.repository)
    print(f"Created complete scaffold: {args.destination}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
