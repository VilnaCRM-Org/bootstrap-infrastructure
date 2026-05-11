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
    "Ruff",
    "Ty",
    "Maintainability",
    "Architecture",
    "Structural",
    "Dependency Hygiene",
    "Coverage",
    "Local Battery",
    "Mutation",
    "Run Bats Tests",
    "Secrets Scan",
    "Dependency Audit",
    "Bandit",
    "Dependency Review",
    "Actionlint",
    "Yamllint",
    "Hadolint",
    "Preview",
    "Destructive Diff Gate",
    "IAM Validation",
    "Policy",
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


def _repo_admin_allowed(repo: str) -> bool:
    """Return whether the current gh token can administer the repository."""
    payload = _run_gh_api([f"repos/{repo}"])
    if not isinstance(payload, Mapping):
        return False
    permissions = payload.get("permissions")
    return isinstance(permissions, Mapping) and permissions.get("admin") is True


def _required_status_check_items(rule: object) -> Sequence[object]:
    """Return required status check items from one ruleset rule."""
    if not isinstance(rule, Mapping) or rule.get("type") != "required_status_checks":
        return ()
    parameters = rule.get("parameters")
    if not isinstance(parameters, Mapping):
        return ()
    checks = parameters.get("required_status_checks")
    return checks if isinstance(checks, list) else ()


def _status_check_context(check: object) -> str | None:
    """Return the status-check context from GitHub ruleset metadata."""
    if not isinstance(check, Mapping):
        return None
    context = check.get("context") or check.get("name")
    return str(context) if context else None


def _required_status_contexts(ruleset: Mapping[str, Any]) -> set[str]:
    """Return required status contexts from a ruleset payload."""
    rules = ruleset.get("rules")
    if not isinstance(rules, list):
        return set()
    contexts: set[str] = set()
    for rule in rules:
        for check in _required_status_check_items(rule):
            context = _status_check_context(check)
            if context:
                contexts.add(context)
    return contexts


def _ruleset_has_pull_request_reviews(ruleset: Mapping[str, Any]) -> bool:
    """Return whether the ruleset requires PR reviews and thread resolution."""
    rules = ruleset.get("rules")
    if not isinstance(rules, list):
        return False
    for rule in rules:
        if not isinstance(rule, Mapping) or rule.get("type") != "pull_request":
            continue
        parameters = rule.get("parameters")
        if not isinstance(parameters, Mapping):
            continue
        review_count = parameters.get("required_approving_review_count")
        return (
            isinstance(review_count, int)
            and review_count >= 1
            and parameters.get("required_review_thread_resolution") is True
        )
    return False


def _ruleset_verification_blockers(ruleset: Mapping[str, Any] | None) -> list[str]:
    """Return blockers when the active main ruleset does not match expectations."""
    if ruleset is None:
        return ["Active main branch ruleset was not found after apply."]
    contexts = _required_status_contexts(ruleset)
    missing_contexts = sorted(set(REQUIRED_STATUS_CHECKS) - contexts)
    blockers: list[str] = []
    if missing_contexts:
        blockers.append(
            "Active main branch ruleset is missing required status checks: "
            f"{', '.join(missing_contexts)}."
        )
    if not _ruleset_has_pull_request_reviews(ruleset):
        blockers.append(
            "Active main branch ruleset does not require pull request reviews "
            "and thread resolution."
        )
    return blockers


def _environment_reviewer_ids(environment: Mapping[str, Any]) -> set[int]:
    """Return required reviewer user IDs from a GitHub environment payload."""
    reviewer_ids: set[int] = set()
    top_level_reviewers = environment.get("reviewers")
    if isinstance(top_level_reviewers, list):
        reviewer_ids.update(_reviewer_ids_from_items(top_level_reviewers))

    protection_rules = environment.get("protection_rules")
    if isinstance(protection_rules, list):
        for rule in protection_rules:
            if not isinstance(rule, Mapping):
                continue
            reviewers = rule.get("reviewers")
            if isinstance(reviewers, list):
                reviewer_ids.update(_reviewer_ids_from_items(reviewers))
    return reviewer_ids


def _reviewer_ids_from_items(items: Sequence[object]) -> set[int]:
    """Return user IDs from reviewer objects in environment metadata."""
    reviewer_ids: set[int] = set()
    for item in items:
        if not isinstance(item, Mapping):
            continue
        reviewer_type = item.get("type")
        reviewer_id = item.get("id")
        if reviewer_type == "User" and isinstance(reviewer_id, int):
            reviewer_ids.add(reviewer_id)
            continue
        nested_user = item.get("reviewer")
        if isinstance(nested_user, Mapping) and isinstance(nested_user.get("id"), int):
            reviewer_ids.add(nested_user["id"])
    return reviewer_ids


def _prod_environment_verification_blockers(
    environment: Mapping[str, Any] | None, reviewer_id: int
) -> list[str]:
    """Return blockers when the prod environment does not match expectations."""
    if environment is None:
        return ["Production environment was not readable after apply."]
    blockers: list[str] = []
    if environment.get("prevent_self_review") is not True:
        blockers.append("Production environment does not prevent self-review.")
    branch_policy = environment.get("deployment_branch_policy")
    if not isinstance(branch_policy, Mapping):
        blockers.append("Production environment does not report a branch policy.")
    elif (
        branch_policy.get("protected_branches") is not True
        or branch_policy.get("custom_branch_policies") is not False
    ):
        blockers.append(
            "Production environment does not restrict deployments to protected "
            "branches."
        )
    if reviewer_id not in _environment_reviewer_ids(environment):
        blockers.append(
            "Production environment does not require the configured reviewer."
        )
    return blockers


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
