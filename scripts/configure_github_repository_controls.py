#!/usr/bin/env python3
"""Configure GitHub repository controls required for production readiness."""

from __future__ import annotations

import argparse
import json
import subprocess  # nosec B404
import sys
from collections.abc import Mapping, Sequence
from typing import Any

REQUIRED_STATUS_CHECKS = (
    "Preview",
    "Destructive Diff Gate",
    "IAM Validation",
    "Secrets Scan",
    "Dependency Audit",
    "Bandit",
    "Actionlint",
    "CodeQL (python)",
    "CodeQL (actions)",
)
DEFAULT_PROD_REVIEWER = "Kravalg"


def _required_status_checks_rule() -> dict[str, object]:
    """Return the ruleset rule that enforces the documented PR gates."""
    return {
        "type": "required_status_checks",
        "parameters": {
            "strict_required_status_checks_policy": True,
            "required_status_checks": [
                {"context": context} for context in REQUIRED_STATUS_CHECKS
            ],
        },
    }


def _default_pull_request_rule() -> dict[str, object]:
    """Return the minimum pull-request review rule expected by the project."""
    return {
        "type": "pull_request",
        "parameters": {
            "allowed_merge_methods": ["squash"],
            "dismiss_stale_reviews_on_push": False,
            "require_code_owner_review": True,
            "require_last_push_approval": False,
            "required_approving_review_count": 1,
            "required_review_thread_resolution": True,
            "required_reviewers": [],
        },
    }


def ruleset_payload(existing_rules: Sequence[Mapping[str, Any]] = ()) -> dict[str, Any]:
    """Build the branch ruleset payload while preserving known stronger rules."""
    rules_by_type = {
        rule.get("type"): dict(rule)
        for rule in existing_rules
        if isinstance(rule.get("type"), str)
    }
    rules = [
        rules_by_type.get("deletion", {"type": "deletion"}),
        rules_by_type.get("non_fast_forward", {"type": "non_fast_forward"}),
        rules_by_type.get("pull_request", _default_pull_request_rule()),
        _required_status_checks_rule(),
    ]
    for optional_rule_type in ("code_quality", "code_scanning"):
        rule = rules_by_type.get(optional_rule_type)
        if rule is not None:
            rules.append(rule)

    return {
        "name": "main",
        "target": "branch",
        "enforcement": "active",
        "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
        "rules": rules,
    }


def prod_environment_payload(reviewer_id: int) -> dict[str, Any]:
    """Build the protected production GitHub environment payload."""
    return {
        "wait_timer": 0,
        "prevent_self_review": True,
        "reviewers": [{"type": "User", "id": reviewer_id}],
        "deployment_branch_policy": {
            "protected_branches": True,
            "custom_branch_policies": False,
        },
    }


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


def configure(repo: str, reviewer: str, *, apply: bool) -> int:
    """Print or apply the GitHub repository controls."""
    existing = _main_ruleset(repo)
    existing_rules = existing.get("rules", []) if existing else []
    if not isinstance(existing_rules, list):
        existing_rules = []

    payloads: dict[str, Any] = {"ruleset": ruleset_payload(existing_rules)}
    if apply:
        reviewer_id = _github_user_id(reviewer)
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
    else:
        payloads["prodEnvironment"] = prod_environment_payload(0)
        payloads["prodEnvironmentReviewerLogin"] = reviewer

    print(json.dumps(payloads, indent=2, sort_keys=True))
    return 0


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
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Apply changes with gh api. Without this flag, print the payloads.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command line interface."""
    args = build_parser().parse_args(argv)
    try:
        return configure(args.repo, args.prod_reviewer, apply=args.apply)
    except (ValueError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
