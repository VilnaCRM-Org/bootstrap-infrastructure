from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, cast

from _github_environment_controls import (
    environment_is_main_only,
    environment_prevents_self_review,
)

GOVERNANCE_PROMOTION_CONTEXT = "Governance Promotion"

REQUIRED_STATUS_CHECKS = (
    GOVERNANCE_PROMOTION_CONTEXT,
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
)

OPERATIONS_ALERT_RECONCILE_ENVIRONMENT = "operations-alert-reconcile"
GOVERNANCE_ENVIRONMENT = "governance"
SERVICE_DRIFT_ENVIRONMENTS = ("test-drift", "prod-drift")


def required_status_checks_rule(*, promotion_app_id: int) -> dict[str, Any]:
    """Return the ruleset rule that enforces the documented PR gates."""
    return {
        "type": "required_status_checks",
        "parameters": {
            "strict_required_status_checks_policy": True,
            "required_status_checks": [
                (
                    {"context": context, "integration_id": promotion_app_id}
                    if context == GOVERNANCE_PROMOTION_CONTEXT
                    else {"context": context}
                )
                for context in REQUIRED_STATUS_CHECKS
            ],
        },
    }


def _harden_status_check(item: object, *, promotion_app_id: int) -> dict[str, Any]:
    """Preserve one valid required check and reconcile its promotion issuer."""
    if not isinstance(item, Mapping):
        raise ValueError("Existing required status check is malformed.")
    context = item.get("context")
    if not isinstance(context, str) or not context.strip():
        raise ValueError("Existing required status check is malformed.")
    check = dict(item)
    if check["context"] == GOVERNANCE_PROMOTION_CONTEXT:
        if check.get("integration_id") not in (None, promotion_app_id):
            raise ValueError(
                "Existing promotion issuer requires explicit reconciliation."
            )
        check["integration_id"] = promotion_app_id
    return check


def harden_required_status_checks_rule(
    existing: Mapping[str, Any], *, promotion_app_id: int
) -> dict[str, Any]:
    """Keep existing contexts and issuers while adding missing required checks."""
    parameters = existing.get("parameters", {})
    if not isinstance(parameters, Mapping):
        raise ValueError("Existing status-check parameters must be an object.")
    original = parameters.get("required_status_checks", [])
    if not isinstance(original, list):
        raise ValueError("Existing required status checks must be a list.")
    checks = [
        _harden_status_check(item, promotion_app_id=promotion_app_id)
        for item in original
    ]
    baseline = required_status_checks_rule(promotion_app_id=promotion_app_id)
    contexts = {check["context"] for check in checks}
    checks.extend(
        check
        for check in baseline["parameters"]["required_status_checks"]
        if check["context"] not in contexts
    )
    return {
        **existing,
        "type": "required_status_checks",
        "parameters": {
            **parameters,
            "strict_required_status_checks_policy": True,
            "required_status_checks": checks,
        },
    }


def default_pull_request_rule() -> dict[str, Any]:
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


def harden_pull_request_rule(existing: Mapping[str, Any]) -> dict[str, Any]:
    """Preserve stronger review counts while enforcing all current safety gates."""
    rule = default_pull_request_rule()
    parameters = {**existing.get("parameters", {}), **rule["parameters"]}
    parameters["required_reviewers"] = existing.get("parameters", {}).get(
        "required_reviewers", []
    )
    parameters["required_approving_review_count"] = max(
        1, existing.get("parameters", {}).get("required_approving_review_count", 1)
    )
    return {**existing, **rule, "parameters": parameters}


def ruleset_payload(
    existing_rules: Sequence[Mapping[str, Any]] = (), *, promotion_app_id: int
) -> dict[str, Any]:
    """Build the branch ruleset payload while preserving additional rule types."""
    if promotion_app_id <= 0 or promotion_app_id == 15368:
        raise ValueError("A dedicated promotion GitHub App ID is required.")
    if sum(rule.get("type") == "required_status_checks" for rule in existing_rules) > 1:
        raise ValueError("Multiple existing status-check rules require reconciliation.")
    rules_by_type = {
        rule.get("type"): dict(rule)
        for rule in existing_rules
        if isinstance(rule.get("type"), str)
    }
    rules = [
        rules_by_type.get("deletion", {"type": "deletion"}),
        rules_by_type.get("non_fast_forward", {"type": "non_fast_forward"}),
        harden_pull_request_rule(rules_by_type.get("pull_request", {})),
        harden_required_status_checks_rule(
            rules_by_type.get("required_status_checks", {}),
            promotion_app_id=promotion_app_id,
        ),
    ]
    replaced_types = {
        "deletion",
        "non_fast_forward",
        "pull_request",
        "required_status_checks",
    }
    rules.extend(
        dict(rule)
        for rule in existing_rules
        if isinstance(rule.get("type"), str) and rule["type"] not in replaced_types
    )

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
        "can_admins_bypass": False,
        "reviewers": [{"type": "User", "id": reviewer_id}],
        "deployment_branch_policy": {
            "protected_branches": False,
            "custom_branch_policies": True,
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


def service_drift_environment_payload() -> dict[str, Any]:
    """Unattended drift has no approval gate and only the main branch."""
    return {
        "wait_timer": 0,
        "can_admins_bypass": False,
        "reviewers": [],
        "deployment_branch_policy": {
            "protected_branches": False,
            "custom_branch_policies": True,
        },
    }


def service_drift_environment_verification_blockers(
    environment: Mapping[str, Any],
) -> list[str]:
    """Fail closed on weaker boundaries or additional unattended execution gates."""
    blockers = []
    if not environment_is_main_only(environment):
        blockers.append("Scheduled drift environment must allow only main.")
    if environment.get("can_admins_bypass") is not False:
        blockers.append("Scheduled drift environment must disable admin bypass.")
    if environment.get("reviewers", []) != []:
        blockers.append("Scheduled drift environment must not require reviewers.")
    if (
        type(environment.get("wait_timer", 0)) is not int
        or environment.get("wait_timer", 0) != 0
    ):
        blockers.append("Scheduled drift environment must not have a wait timer.")
    rules = environment.get("protection_rules", [])
    if not isinstance(rules, list) or any(
        not isinstance(rule, Mapping) or rule.get("type") != "branch_policy"
        for rule in rules
    ):
        blockers.append("Scheduled drift environment has an unknown execution gate.")
    return blockers


def required_status_check_items(rule: object) -> Sequence[object]:
    """Return required status check items from one ruleset rule."""
    if not isinstance(rule, Mapping):
        return ()
    rule = cast(Mapping[str, Any], rule)
    if rule.get("type") != "required_status_checks":
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
    check = cast(Mapping[str, Any], check)
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
            and all(
                parameters.get(flag) is True
                for flag in (
                    "required_review_thread_resolution",
                    "dismiss_stale_reviews_on_push",
                    "require_code_owner_review",
                    "require_last_push_approval",
                )
            )
        )
    return False


def _ruleset_has_promotion_issuer(
    ruleset: Mapping[str, Any], promotion_app_id: int
) -> bool:
    """Require the configured issuer on a concrete promotion status check."""
    promotion_checks = [
        cast(Mapping[str, Any], item)
        for rule in ruleset.get("rules", [])
        for item in required_status_check_items(rule)
        if isinstance(item, Mapping)
        and status_check_context(item) == GOVERNANCE_PROMOTION_CONTEXT
    ]
    return any(
        item.get("integration_id") == promotion_app_id for item in promotion_checks
    )


def _ruleset_requires_strict_checks(ruleset: Mapping[str, Any]) -> bool:
    """Inspect strictness independently from the names and issuers of checks."""
    return any(
        isinstance(rule, Mapping)
        and rule.get("type") == "required_status_checks"
        and isinstance(rule.get("parameters"), Mapping)
        and rule["parameters"].get("strict_required_status_checks_policy") is True
        for rule in ruleset.get("rules", [])
    )


def ruleset_verification_blockers(
    ruleset: Mapping[str, Any] | None, *, promotion_app_id: int
) -> list[str]:
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
    if not _ruleset_has_promotion_issuer(ruleset, promotion_app_id):
        blockers.append(
            "Governance Promotion must require the dedicated GitHub App issuer."
        )
    if not _ruleset_requires_strict_checks(ruleset):
        blockers.append("Active main branch ruleset must require strict status checks.")
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
        item = cast(Mapping[str, Any], item)
        reviewer_type = item.get("type")
        reviewer_id = item.get("id")
        if reviewer_type == "User" and isinstance(reviewer_id, int):
            reviewer_ids.add(reviewer_id)
            continue
        nested_user = item.get("reviewer")
        if isinstance(nested_user, Mapping) and isinstance(nested_user.get("id"), int):
            reviewer_ids.add(nested_user["id"])
    return reviewer_ids


def _is_user_reviewer(item: object) -> bool:
    """Validate one direct or nested GitHub reviewer without hiding its type."""
    if not isinstance(item, Mapping):
        return False
    item = cast(Mapping[str, Any], item)
    if item.get("type") != "User":
        return False
    person = item.get("reviewer", item)
    if not isinstance(person, Mapping) or person.get("type") != "User":
        return False
    identity = person.get("id")
    if "reviewer" in item and "id" in item:
        if type(item["id"]) is not int or item["id"] != identity:
            return False
    return type(identity) is int and identity > 0


def _environment_reviewer_groups(
    environment: Mapping[str, Any],
) -> list[object] | None:
    """Collect all reviewer groups, rejecting malformed protection rules."""
    groups = []
    if "reviewers" in environment:
        groups.append(environment["reviewers"])
    rules = environment.get("protection_rules", [])
    if not isinstance(rules, list):
        return None
    for rule in rules:
        if not isinstance(rule, Mapping):
            return None
        if rule.get("type") == "required_reviewers" and "reviewers" not in rule:
            return None
        if "reviewers" in rule:
            groups.append(rule["reviewers"])
    return groups


def environment_has_only_user_reviewers(environment: Mapping[str, Any]) -> bool:
    """Reject team or malformed reviewers that a user-ID projection would hide."""
    groups = _environment_reviewer_groups(environment)
    return groups is not None and all(
        isinstance(items, list) and all(_is_user_reviewer(item) for item in items)
        for items in groups
    )


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
    if not environment_is_main_only(environment):
        blockers.append(f"{label} does not allow only the main branch.")
    if environment.get("can_admins_bypass") is not False:
        blockers.append(f"{label} allows administrator bypass.")
    if not environment_has_only_user_reviewers(environment):
        blockers.append(f"{label} includes a malformed or non-user reviewer.")
    if environment_reviewer_ids(environment) != {reviewer_id}:
        blockers.append(f"{label} does not require only the configured reviewer.")
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
