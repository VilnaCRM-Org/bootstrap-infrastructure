#!/usr/bin/env python3
"""Configure GitHub repository controls required for production readiness."""

from __future__ import annotations

import argparse
import json
import subprocess  # nosec B404
import sys
from collections.abc import Mapping, Sequence
from typing import Any

import _github_repository_controls as _repository_controls

REQUIRED_STATUS_CHECKS = _repository_controls.REQUIRED_STATUS_CHECKS
prod_environment_payload = _repository_controls.prod_environment_payload
ruleset_payload = _repository_controls.ruleset_payload
_environment_reviewer_ids = _repository_controls.environment_reviewer_ids
_prod_environment_verification_blockers = (
    _repository_controls.prod_environment_verification_blockers
)
_required_status_check_items = _repository_controls.required_status_check_items
_required_status_contexts = _repository_controls.required_status_contexts
_reviewer_ids_from_items = _repository_controls.reviewer_ids_from_items
_ruleset_has_pull_request_reviews = (
    _repository_controls.ruleset_has_pull_request_reviews
)
_ruleset_verification_blockers = _repository_controls.ruleset_verification_blockers
_status_check_context = _repository_controls.status_check_context

__all__ = (
    "REQUIRED_STATUS_CHECKS",
    "build_parser",
    "configure",
    "main",
    "prod_environment_payload",
    "ruleset_payload",
    "_environment_reviewer_ids",
    "_prod_environment_verification_blockers",
    "_required_status_check_items",
    "_required_status_contexts",
    "_reviewer_ids_from_items",
    "_ruleset_has_pull_request_reviews",
    "_ruleset_verification_blockers",
    "_status_check_context",
)

DEFAULT_PROD_REVIEWER = "Kravalg"


def _run_gh_api(
    args: Sequence[str], *, input_payload: Mapping[str, Any] | None = None
) -> dict[str, Any] | list[Any]:
    """Run gh api and parse the JSON response."""
    command = ["gh", "api", *args]
    input_text = None
    if input_payload is not None:
        command.extend(["--input", "-"])
        input_text = json.dumps(input_payload)
    result = subprocess.run(  # nosec B603
        command,
        input=input_text,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "gh api failed"
        raise RuntimeError(detail)
    if not result.stdout.strip():
        return {}
    parsed = json.loads(result.stdout)
    if isinstance(parsed, (dict, list)):
        return parsed
    return {}


def _main_ruleset(repo: str) -> dict[str, Any] | None:
    """Return the full active main ruleset when it exists."""
    rulesets = _run_gh_api([f"repos/{repo}/rulesets"])
    if not isinstance(rulesets, list):
        return None
    for ruleset in rulesets:
        if not isinstance(ruleset, Mapping):
            continue
        if ruleset.get("name") == "main" and ruleset.get("target") == "branch":
            ruleset_id = ruleset.get("id")
            if isinstance(ruleset_id, int):
                full_ruleset = _run_gh_api([f"repos/{repo}/rulesets/{ruleset_id}"])
                return dict(full_ruleset) if isinstance(full_ruleset, Mapping) else None
    return None


def _github_user_id(login: str) -> int:
    """Resolve a GitHub login to a numeric user id."""
    user = _run_gh_api([f"users/{login}"])
    if isinstance(user, Mapping) and isinstance(user.get("id"), int):
        return user["id"]
    raise ValueError(f"Could not resolve GitHub user id for {login!r}.")


def _repo_admin_allowed(repo: str) -> bool:
    """Return whether the current gh token can administer the repository."""
    payload = _run_gh_api([f"repos/{repo}"])
    if not isinstance(payload, Mapping):
        return False
    permissions = payload.get("permissions")
    return isinstance(permissions, Mapping) and permissions.get("admin") is True


def _verify_applied_controls(repo: str, reviewer_id: int) -> dict[str, Any]:
    """Fetch and verify repository controls after an admin apply."""
    ruleset = _main_ruleset(repo)
    try:
        environment_payload = _run_gh_api([f"repos/{repo}/environments/prod"])
    except RuntimeError as exc:
        environment = None
        environment_blockers = [f"Production environment was not readable: {exc}."]
    else:
        environment = (
            environment_payload if isinstance(environment_payload, Mapping) else None
        )
        environment_blockers = _prod_environment_verification_blockers(
            environment, reviewer_id
        )
    blockers = [
        *_ruleset_verification_blockers(ruleset),
        *environment_blockers,
    ]
    if blockers:
        raise RuntimeError(" ".join(blockers))
    return {
        "requiredStatusChecks": sorted(_required_status_contexts(ruleset or {})),
        "prodReviewerId": reviewer_id,
        "prodEnvironment": "prod",
    }


def configure(
    repo: str, reviewer: str, *, apply: bool, verify_only: bool = False
) -> None:
    """Print or apply the GitHub repository controls."""
    if apply and not _repo_admin_allowed(repo):
        raise RuntimeError(
            "repository admin rights are required to update branch rulesets "
            "and protected environments."
        )

    reviewer_id = _github_user_id(reviewer)
    if verify_only:
        print(
            json.dumps(
                {"verification": _verify_applied_controls(repo, reviewer_id)},
                indent=2,
                sort_keys=True,
            )
        )
        return

    existing = _main_ruleset(repo)
    existing_rules = existing.get("rules", []) if existing else []
    if not isinstance(existing_rules, list):
        existing_rules = []

    payloads: dict[str, Any] = {"ruleset": ruleset_payload(existing_rules)}
    if apply:
        payloads["prodEnvironment"] = prod_environment_payload(reviewer_id)
        if existing and isinstance(existing.get("id"), int):
            _run_gh_api(
                [f"repos/{repo}/rulesets/{existing['id']}", "--method", "PUT"],
                input_payload=payloads["ruleset"],
            )
        else:
            _run_gh_api(
                [f"repos/{repo}/rulesets", "--method", "POST"],
                input_payload=payloads["ruleset"],
            )
        _run_gh_api(
            [f"repos/{repo}/environments/prod", "--method", "PUT"],
            input_payload=payloads["prodEnvironment"],
        )
        payloads["verification"] = _verify_applied_controls(repo, reviewer_id)
    else:
        payloads["prodEnvironment"] = prod_environment_payload(reviewer_id)
        payloads["prodEnvironmentReviewerLogin"] = reviewer

    print(json.dumps(payloads, indent=2, sort_keys=True))


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI parser."""
    parser = argparse.ArgumentParser(
        description="Configure GitHub branch and production environment controls."
    )
    parser.add_argument("--repo", required=True, help="Repository in owner/name form.")
    parser.add_argument(
        "--prod-reviewer",
        default=DEFAULT_PROD_REVIEWER,
        help="GitHub login required to approve prod deployments.",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--apply",
        action="store_true",
        help="Apply changes with gh api. Without this flag, print the payloads.",
    )
    mode.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the ruleset and prod environment payloads without applying.",
    )
    mode.add_argument(
        "--verify-only",
        action="store_true",
        help="Verify existing ruleset and prod environment controls without applying.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command line interface."""
    args = build_parser().parse_args(argv)
    try:
        configure(
            args.repo,
            args.prod_reviewer,
            apply=args.apply,
            verify_only=args.verify_only,
        )
        return 0
    except (ValueError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
