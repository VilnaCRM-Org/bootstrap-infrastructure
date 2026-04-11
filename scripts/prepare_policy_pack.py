#!/usr/bin/env python3
from __future__ import annotations

import os
import subprocess  # nosec B404
import sys
from pathlib import Path

from _script_support import policy_import_probe, repo_root, run


def _link_policy_venv(policy_venv: Path, policy_link: Path) -> None:
    if policy_link.exists() and not policy_link.is_symlink():
        print(
            f"error: {policy_link} must be a symlink to the shared uv environment",
            file=sys.stderr,
        )
        print(
            (
                "hint: remove the existing path and rerun "
                "python3 scripts/prepare_policy_pack.py"
            ),
            file=sys.stderr,
        )
        raise SystemExit(1)

    if policy_link.is_symlink() or policy_link.exists():
        policy_link.unlink()
    policy_link.symlink_to(policy_venv)


def _imports_available(policy_python: Path, root_dir: Path) -> bool:
    result = subprocess.run(  # nosec B603
        [str(policy_python), *policy_import_probe(root_dir)],
        check=False,
        capture_output=True,
        text=True,
    )
    return result.returncode == 0


def main() -> int:
    root_dir = repo_root(__file__)
    policy_dir = root_dir / "policy"
    policy_venv = Path(
        os.environ.get("POLICY_VENV", f"{Path.home()}/.venvs/bootstrap-infrastructure")
    )
    policy_link = policy_dir / ".venv"
    policy_python = policy_venv / "bin" / "python"
    requirements_file = policy_dir / "requirements.txt"

    if not requirements_file.is_file():
        print(
            f"error: policy requirements file not found at {requirements_file}",
            file=sys.stderr,
        )
        return 1

    if not (policy_python.is_file() and os.access(policy_python, os.X_OK)):
        print(
            f"error: policy interpreter not found at {policy_python}", file=sys.stderr
        )
        print(
            "hint: rebuild the development image so the shared uv environment exists",
            file=sys.stderr,
        )
        return 1

    _link_policy_venv(policy_venv, policy_link)

    if not _imports_available(policy_python, root_dir):
        env = os.environ.copy()
        env["UV_PROJECT_ENVIRONMENT"] = str(policy_venv)
        run(["uv", "sync", "--frozen", "--all-groups"], cwd=root_dir, env=env)

    if not _imports_available(policy_python, root_dir):
        print(
            (
                "error: shared policy interpreter is missing Pulumi "
                "or repo-local policy modules"
            ),
            file=sys.stderr,
        )
        print(
            (
                "hint: rebuild the development image to refresh "
                "the uv-managed dependencies"
            ),
            file=sys.stderr,
        )
        return 1

    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
