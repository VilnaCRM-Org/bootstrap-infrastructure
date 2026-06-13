from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from _github_environment_controls import environment_prevents_self_review

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
    "Test Account Evidence",
    # Posted by the dedicated governance runner (pulumi-governance.yml) to the
    # approved head SHA via `gh api .../statuses/{head_sha}`. The runner fires on
    # repository_dispatch and cannot natively report a check, so a required check
    # with no reporter would make governance PRs permanently unmergeable
    # (FEASIBILITY-1, architecture §7.5). The context string here is byte-for-byte
    # identical to the runner's status-post.
    "Governance Apply",
)

OPERATIONS_ALERT_RECONCILE_ENVIRONMENT = "operations-alert-reconcile"
GOVERNANCE_ENVIRONMENT = "governance"


def required_status_checks_rule() -> dict[str, object]:
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


def default_pull_request_rule() -> dict[str, object]:
    """Return the minimum pull-request review rule expected by the project."""
    return {
        "type": "pull_request",
        "parameters": {
            "allowed_merge_methods": ["squash"],
            "dismiss_stale_reviews_on_push": True,
            "require_code_owner_review": True,
            "require_last_push_approval": True,
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
        rules_by_type.get("pull_request", default_pull_request_rule()),
        required_status_checks_rule(),
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


def protected_reviewer_environment_payload(reviewer_id: int) -> dict[str, Any]:
    """Build a protected GitHub environment payload requiring one reviewer."""
    return {
        "wait_timer": 0,
        "prevent_self_review": True,
        "reviewers": [{"type": "User", "id": reviewer_id}],
        "deployment_branch_policy": {
            "protected_branches": True,
            "custom_branch_policies": False,
        },
    }


def prod_environment_payload(reviewer_id: int) -> dict[str, Any]:
    """Build the protected production GitHub environment payload."""
    return protected_reviewer_environment_payload(reviewer_id)


def operations_alert_reconcile_environment_payload(
    reviewer_id: int,
) -> dict[str, Any]:
    """Build the protected operations-alert reconcile environment payload."""
    return protected_reviewer_environment_payload(reviewer_id)


def governance_environment_payload(reviewer_id: int) -> dict[str, Any]:
    """Build the protected governance GitHub environment payload."""
    return protected_reviewer_environment_payload(reviewer_id)


def required_status_check_items(rule: object) -> Sequence[object]:
    """Return required status check items from one ruleset rule."""
    if not isinstance(rule, Mapping) or rule.get("type") != "required_status_checks":
        return ()
    parameters = rule.get("parameters")
    if not isinstance(parameters, Mapping):
        return ()
    checks = parameters.get("required_status_checks")
    return checks if isinstance(checks, list) else ()


def status_check_context(check: object) -> str | None:
    """Return the status-check context from GitHub ruleset metadata."""
    if not isinstance(check, Mapping):
        return None
    context = check.get("context") or check.get("name")
    return str(context) if context else None


def required_status_contexts(ruleset: Mapping[str, Any]) -> set[str]:
    """Return required status contexts from a ruleset payload."""
    rules = ruleset.get("rules")
    if not isinstance(rules, list):
        return set()
    contexts: set[str] = set()
    for rule in rules:
        for check in required_status_check_items(rule):
            context = status_check_context(check)
            if context:
                contexts.add(context)
    return contexts


def is_active_branch_ruleset(ruleset: Mapping[str, Any]) -> bool:
    """Return whether a ruleset is an active branch ruleset."""
    return ruleset.get("target") == "branch" and ruleset.get("enforcement") == "active"


def ruleset_contains_pull_request_rule(ruleset: Mapping[str, Any]) -> bool:
    """Return whether a ruleset contains any pull-request rule."""
    rules = ruleset.get("rules") or []
    return any(
        isinstance(rule, Mapping) and rule.get("type") == "pull_request"
        for rule in rules
    )


def rulesets_have_pull_request_rule(rulesets: Sequence[Mapping[str, Any]]) -> bool:
    """Return whether any active branch ruleset contains a pull-request rule."""
    return any(
        is_active_branch_ruleset(ruleset)
        and ruleset_contains_pull_request_rule(ruleset)
        for ruleset in rulesets
    )


def required_status_contexts_for_rulesets(
    rulesets: Sequence[Mapping[str, Any]],
) -> set[str]:
    """Return required status contexts from active branch rulesets."""
    contexts: set[str] = set()
    for ruleset in rulesets:
        if is_active_branch_ruleset(ruleset):
            contexts.update(required_status_contexts(ruleset))
    return contexts


def active_branch_ruleset_count(rulesets: Sequence[Mapping[str, Any]]) -> int:
    """Return active branch ruleset count."""
    return sum(1 for ruleset in rulesets if is_active_branch_ruleset(ruleset))


def ruleset_has_pull_request_reviews(ruleset: Mapping[str, Any]) -> bool:
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


def ruleset_verification_blockers(ruleset: Mapping[str, Any] | None) -> list[str]:
    """Return blockers when the active main ruleset does not match expectations."""
    if ruleset is None:
        return ["Active main branch ruleset was not found after apply."]
    contexts = required_status_contexts(ruleset)
    missing_contexts = sorted(set(REQUIRED_STATUS_CHECKS) - contexts)
    blockers: list[str] = []
    if missing_contexts:
        blockers.append(
            "Active main branch ruleset is missing required status checks: "
            f"{', '.join(missing_contexts)}."
        )
    if not ruleset_has_pull_request_reviews(ruleset):
        blockers.append(
            "Active main branch ruleset does not require pull request reviews "
            "and thread resolution."
        )
    return blockers


def environment_reviewer_ids(environment: Mapping[str, Any]) -> set[int]:
    """Return required reviewer user IDs from a GitHub environment payload."""
    reviewer_ids: set[int] = set()
    top_level_reviewers = environment.get("reviewers")
    if isinstance(top_level_reviewers, list):
        reviewer_ids.update(reviewer_ids_from_items(top_level_reviewers))

    protection_rules = environment.get("protection_rules")
    if isinstance(protection_rules, list):
        for rule in protection_rules:
            if not isinstance(rule, Mapping):
                continue
            reviewers = rule.get("reviewers")
            if isinstance(reviewers, list):
                reviewer_ids.update(reviewer_ids_from_items(reviewers))
    return reviewer_ids


def reviewer_ids_from_items(items: Sequence[object]) -> set[int]:
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


def protected_environment_verification_blockers(
    environment: Mapping[str, Any] | None,
    reviewer_id: int,
    *,
    label: str,
) -> list[str]:
    """Return blockers when a protected environment does not match expectations."""
    if environment is None:
        return [f"{label} was not readable after apply."]
    blockers: list[str] = []
    if not environment_prevents_self_review(environment):
        blockers.append(f"{label} does not prevent self-review.")
    branch_policy = environment.get("deployment_branch_policy")
    if not isinstance(branch_policy, Mapping):
        blockers.append(f"{label} does not report a branch policy.")
    elif (
        branch_policy.get("protected_branches") is not True
        or branch_policy.get("custom_branch_policies") is not False
    ):
        blockers.append(f"{label} does not restrict deployments to protected branches.")
    if reviewer_id not in environment_reviewer_ids(environment):
        blockers.append(f"{label} does not require the configured reviewer.")
    return blockers


def prod_environment_verification_blockers(
    environment: Mapping[str, Any] | None, reviewer_id: int
) -> list[str]:
    """Return blockers when the prod environment does not match expectations."""
    return protected_environment_verification_blockers(
        environment,
        reviewer_id,
        label="Production environment",
    )


def operations_alert_reconcile_environment_verification_blockers(
    environment: Mapping[str, Any] | None, reviewer_id: int
) -> list[str]:
    """Return blockers when the operations-alert reconcile environment is weak."""
    return protected_environment_verification_blockers(
        environment,
        reviewer_id,
        label="Operations alert reconcile environment",
    )


def governance_environment_verification_blockers(
    environment: Mapping[str, Any] | None, reviewer_id: int
) -> list[str]:
    """Return blockers when the governance environment does not match expectations."""
    return protected_environment_verification_blockers(
        environment,
        reviewer_id,
        label="Governance environment",
    )
