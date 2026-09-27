#!/usr/bin/env python3
"""Install only the main-bound GitHub environments for reviewed PR previews."""

from __future__ import annotations

import argparse
import json
import subprocess  # nosec B404
from collections.abc import Mapping
from typing import Any, cast

from _github_environment_controls import complete_branch_policies
from _github_repository_controls import (
    service_drift_environment_payload,
    service_drift_environment_verification_blockers,
)

REPOSITORY = "VilnaCRM-Org/bootstrap-infrastructure"
ENVIRONMENTS = ("reviewed-source-publisher", "reviewed-pr-preview")


def _gh(args: list[str], *, input_payload: Mapping[str, Any] | None = None) -> Any:
    """Call the GitHub API without exposing response bodies on errors."""
    command = ["gh", "api", *args]
    if input_payload is not None:
        command.extend(["--input", "-"])
    result = subprocess.run(  # nosec B603
        command,
        input=json.dumps(input_payload) if input_payload is not None else None,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError("GitHub API request failed for reviewed-source setup.")
    return json.loads(result.stdout) if result.stdout.strip() else {}


def _branch_policies(response: object) -> list[Any]:
    policies = complete_branch_policies(response)
    if policies is None:
        raise ValueError("GitHub branch-policy inventory is incomplete.")
    return policies


def _admin_allowed() -> bool:
    response = _gh([f"repos/{REPOSITORY}"])
    permissions = response.get("permissions") if isinstance(response, Mapping) else None
    return isinstance(permissions, Mapping) and permissions.get("admin") is True


def _inventory_rows(response: object) -> list[Any]:
    """Reject partial or malformed environment pages."""
    if not isinstance(response, Mapping):
        raise ValueError("GitHub environment inventory is not an object.")
    rows = response.get("environments")
    count = response.get("total_count")
    if not isinstance(rows, list) or type(count) is not int or count != len(rows):
        raise ValueError("GitHub environment inventory is incomplete.")
    return rows


def _inventory_names(rows: list[Any]) -> list[str]:
    """Reject duplicate and malformed names before selecting write targets."""
    names = [row.get("name") for row in rows if isinstance(row, Mapping)]
    if (
        len(names) != len(rows)
        or any(not isinstance(name, str) or not name for name in names)
        or len({name.casefold() for name in names}) != len(names)
    ):
        raise ValueError("GitHub environment names are ambiguous.")
    return cast(list[str], names)


def _inventory() -> set[str]:
    """Require a complete, unambiguous inventory before any environment write."""
    response = _gh([f"repos/{REPOSITORY}/environments?per_page=100"])
    names = _inventory_names(_inventory_rows(response))
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
    environment = _gh([endpoint])
    if not isinstance(environment, Mapping) or environment.get("name") != name:
        raise ValueError(f"GitHub environment {name} identity differs.")
    policies = _branch_policies(
        _gh([f"{endpoint}/deployment-branch-policies?per_page=100"])
    )
    observed = dict(cast(Mapping[str, Any], environment))
    observed["deployment_branch_policies"] = policies
    blockers = service_drift_environment_verification_blockers(observed)
    if blockers:
        raise ValueError(f"{name}: {' '.join(blockers)}")


def _create(name: str) -> None:
    """Create an absent environment, then allow only the main branch."""
    endpoint = f"repos/{REPOSITORY}/environments/{name}"
    _gh(
        [endpoint, "--method", "PUT"],
        input_payload=service_drift_environment_payload(),
    )
    policies = _branch_policies(
        _gh([f"{endpoint}/deployment-branch-policies?per_page=100"])
    )
    if policies:
        raise RuntimeError(f"New GitHub environment {name} has unexpected policies.")
    _gh(
        [f"{endpoint}/deployment-branch-policies", "--method", "POST"],
        input_payload={"name": "main", "type": "branch"},
    )
    _verify(name)


def _verify_existing(existing: set[str], *, require_present: bool) -> None:
    """Reject weak existing controls or a missing required environment."""
    for name in ENVIRONMENTS:
        if name in existing:
            _verify(name)
        elif require_present:
            raise ValueError(f"GitHub environment {name} is missing.")


def configure(*, apply: bool, verify_only: bool) -> dict[str, Any]:
    """Never rewrite an existing environment or an unrelated repository control."""
    if apply and not _admin_allowed():
        raise RuntimeError(
            "Repository admin rights are required for environment setup."
        )
    existing = _inventory()
    _verify_existing(existing, require_present=verify_only)
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
