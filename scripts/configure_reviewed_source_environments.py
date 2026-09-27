#!/usr/bin/env python3
"""Install only the main-bound GitHub environments for reviewed PR previews."""

from __future__ import annotations

import argparse
import json
from collections.abc import Mapping
from typing import Any

from _github_repository_controls import (
    unattended_main_environment_payload,
    unattended_main_environment_verification_blockers,
)
from configure_github_repository_controls import (
    _repo_admin_allowed,
    _run_gh_api,
    _validated_branch_policies,
)

REPOSITORY = "VilnaCRM-Org/bootstrap-infrastructure"
ENVIRONMENTS = ("reviewed-source-publisher", "reviewed-pr-preview")


def _inventory() -> set[str]:
    """Require a complete, unambiguous inventory before any environment write."""
    response = _run_gh_api([f"repos/{REPOSITORY}/environments?per_page=100"])
    if not isinstance(response, Mapping):
        raise ValueError("GitHub environment inventory is not an object.")
    rows = response.get("environments")
    count = response.get("total_count")
    if not isinstance(rows, list) or type(count) is not int or count != len(rows):
        raise ValueError("GitHub environment inventory is incomplete.")
    names = [row.get("name") for row in rows if isinstance(row, Mapping)]
    if (
        len(names) != len(rows)
        or any(not isinstance(name, str) or not name for name in names)
        or len({name.casefold() for name in names}) != len(names)
    ):
        raise ValueError("GitHub environment names are ambiguous.")
    for name in ENVIRONMENTS:
        if any(
            existing.casefold() == name.casefold() and existing != name
            for existing in names
        ):
            raise ValueError(f"GitHub environment {name} has a case variant.")
    return set(names)


def _verify(name: str) -> None:
    """Check exact branch and execution controls on an existing environment."""
    endpoint = f"repos/{REPOSITORY}/environments/{name}"
    environment = _run_gh_api([endpoint])
    if not isinstance(environment, Mapping) or environment.get("name") != name:
        raise ValueError(f"GitHub environment {name} identity differs.")
    policies = _validated_branch_policies(
        _run_gh_api([f"{endpoint}/deployment-branch-policies?per_page=100"])
    )
    observed: dict[str, Any] = {
        **environment,
        "deployment_branch_policies": policies,
    }
    blockers = unattended_main_environment_verification_blockers(observed, label=name)
    if blockers:
        raise ValueError(" ".join(blockers))


def _create(name: str) -> None:
    """Create an absent environment, then allow only the main branch."""
    endpoint = f"repos/{REPOSITORY}/environments/{name}"
    _run_gh_api(
        [endpoint, "--method", "PUT"],
        input_payload=unattended_main_environment_payload(),
    )
    policies = _validated_branch_policies(
        _run_gh_api([f"{endpoint}/deployment-branch-policies?per_page=100"])
    )
    if policies:
        raise RuntimeError(f"New GitHub environment {name} has unexpected policies.")
    _run_gh_api(
        [f"{endpoint}/deployment-branch-policies", "--method", "POST"],
        input_payload={"name": "main", "type": "branch"},
    )
    _verify(name)


def configure(*, apply: bool, verify_only: bool) -> dict[str, Any]:
    """Never rewrite an existing environment or an unrelated repository control."""
    if apply and not _repo_admin_allowed(REPOSITORY):
        raise RuntimeError(
            "Repository admin rights are required for environment setup."
        )
    existing = _inventory()
    for name in ENVIRONMENTS:
        if name in existing:
            _verify(name)
        elif verify_only:
            raise ValueError(f"GitHub environment {name} is missing.")
    missing = [name for name in ENVIRONMENTS if name not in existing]
    if apply:
        for name in missing:
            _create(name)
        missing = []
    return {
        "repository": REPOSITORY,
        "environments": list(ENVIRONMENTS),
        "missing": missing,
        "verified": apply or verify_only,
    }


def main() -> None:
    """Print a dry run, verify only, or create missing closed environments."""
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--apply", action="store_true")
    mode.add_argument("--verify-only", action="store_true")
    args = parser.parse_args()
    print(
        json.dumps(
            configure(apply=args.apply, verify_only=args.verify_only), sort_keys=True
        )
    )


if __name__ == "__main__":
    main()
