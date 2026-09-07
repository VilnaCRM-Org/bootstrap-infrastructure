from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def complete_branch_policies(response: object) -> list[Any] | None:
    """Accept only a complete GitHub branch-policy response, never a partial page."""
    if not isinstance(response, Mapping):
        return None
    policies = response.get("branch_policies")
    count = response.get("total_count")
    if (
        not isinstance(policies, list)
        or type(count) is not int
        or count != len(policies)
    ):
        return None
    return policies


def environment_is_main_only(environment: Mapping[str, Any]) -> bool:
    """Require an exact main branch rule, including separately fetched policies."""
    policies = environment.get("deployment_branch_policies")
    return (
        environment.get("deployment_branch_policy")
        == {"protected_branches": False, "custom_branch_policies": True}
        and isinstance(policies, list)
        and len(policies) == 1
        and isinstance(policies[0], Mapping)
        and policies[0].get("name") == "main"
        and policies[0].get("type") == "branch"
    )


def environment_prevents_self_review(environment: Mapping[str, Any]) -> bool:
    """Return whether a GitHub required-reviewer rule prevents self-review."""
    if environment.get("prevent_self_review") is True:
        return True
    protection_rules = environment.get("protection_rules")
    if not isinstance(protection_rules, list):
        return False
    return any(
        isinstance(rule, Mapping)
        and rule.get("type") == "required_reviewers"
        and rule.get("prevent_self_review") is True
        for rule in protection_rules
    )
