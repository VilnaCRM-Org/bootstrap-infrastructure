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


def generate(root: Path, destination: Path, repository: str) -> dict:
    """Assemble an audited dependency closure without merging into existing data."""
    if not re.fullmatch(r"[a-z][a-z0-9-]*-infrastructure", repository):
        raise ValueError("Repository must be a lowercase *-infrastructure slug")
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
        # mkdir(exist_ok=False) closes the check/create race and refuses symlinks.
        destination.mkdir()
        shutil.copytree(staged, destination, dirs_exist_ok=True)
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
