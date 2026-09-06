"""Main-only environment boundary for the isolated promotion App key."""

from __future__ import annotations

from typing import Any

from _github_environment_controls import environment_is_main_only

NAME = "governance-evidence"


def payload() -> dict[str, Any]:
    """Keep the App key available only to workflows running on main."""
    return {
        "wait_timer": 0,
        "can_admins_bypass": False,
        "reviewers": [],
        "deployment_branch_policy": {
            "protected_branches": False,
            "custom_branch_policies": True,
        },
    }


def verification_blockers(environment: dict, policies: dict) -> list[str]:
    """Reject a missing restriction, wildcard branch, tag, or admin bypass."""
    blockers = []
    if environment.get("can_admins_bypass") is not False:
        blockers.append("Evidence environment must disable administrator bypass.")
    if (
        environment.get("deployment_branch_policy")
        != payload()["deployment_branch_policy"]
    ):
        blockers.append("Evidence environment must use custom branch restrictions.")
    if not environment_is_main_only(
        {**environment, "deployment_branch_policies": policies.get("branch_policies")}
    ):
        blockers.append("Evidence environment must allow only the main branch.")
    return blockers
