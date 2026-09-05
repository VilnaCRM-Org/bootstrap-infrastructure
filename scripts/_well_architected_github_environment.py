from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Sequence, cast

from _github_environment_controls import (
    environment_is_main_only,
    environment_prevents_self_review,
)


@dataclass(frozen=True)
class ProductionEnvironmentMetadata:
    """Protected production environment settings relevant to WAF evidence."""

    environment: str
    reviewer_login: str | None
    reviewer_logins: Sequence[str]
    reviewer_count: int
    prevents_self_review: bool
    protected_branches: bool
    custom_branch_policies: bool
    main_branch_only: bool = False
    can_admins_bypass: bool = True

    @property
    def protected_branches_only(self) -> bool:
        """Return whether deployment is limited to protected branches."""
        return self.protected_branches and not self.custom_branch_policies


def production_environment_metadata(
    payload: dict[str, Any],
    *,
    environment: str,
    reviewer_login: str | None,
) -> ProductionEnvironmentMetadata:
    """Return normalized production environment metadata from GitHub payloads."""
    branch_policy = payload.get("deployment_branch_policy") or {}
    return ProductionEnvironmentMetadata(
        environment=environment,
        reviewer_login=reviewer_login,
        reviewer_logins=_environment_required_reviewer_logins(payload),
        reviewer_count=_environment_required_reviewer_count(payload),
        prevents_self_review=environment_prevents_self_review(payload),
        protected_branches=bool(branch_policy.get("protected_branches")),
        custom_branch_policies=bool(branch_policy.get("custom_branch_policies")),
        main_branch_only=environment_is_main_only(payload),
        can_admins_bypass=payload.get("can_admins_bypass") is not False,
    )


def production_environment_blockers(
    metadata: ProductionEnvironmentMetadata,
) -> list[str]:
    """Return blockers for protected production environment metadata."""
    blockers: list[str] = []
    if metadata.reviewer_count < 1:
        blockers.append(
            f"GitHub environment {metadata.environment!r} does not require reviewers."
        )
    elif metadata.reviewer_login and (
        metadata.reviewer_count != 1
        or list(metadata.reviewer_logins) != [metadata.reviewer_login]
    ):
        blockers.append(
            f"GitHub environment {metadata.environment!r} required reviewers do not "
            f"contain only {metadata.reviewer_login}."
        )
    if not metadata.prevents_self_review:
        blockers.append(
            f"GitHub environment {metadata.environment!r} does not prevent self-review."
        )
    if not metadata.main_branch_only:
        blockers.append(
            f"GitHub environment {metadata.environment!r} is not limited to the main "
            "branch."
        )
    if metadata.can_admins_bypass:
        blockers.append(
            f"GitHub environment {metadata.environment!r} allows administrator bypass."
        )
    return blockers


def production_environment_evidence(
    metadata: ProductionEnvironmentMetadata,
) -> dict[str, object]:
    """Return non-secret protected production environment evidence."""
    return {
        "environment": metadata.environment,
        "readable": True,
        "requiredReviewerCount": metadata.reviewer_count,
        "requiredReviewerLogins": list(metadata.reviewer_logins),
        "expectedReviewerLogin": metadata.reviewer_login,
        "preventSelfReview": metadata.prevents_self_review,
        "protectedBranchesOnly": metadata.protected_branches_only,
        "mainBranchOnly": metadata.main_branch_only,
        "canAdminsBypass": metadata.can_admins_bypass,
    }


def _environment_required_reviewer_count(payload: dict[str, Any]) -> int:
    """Return required reviewer count from either environment response shape."""
    reviewers = _environment_required_reviewers(payload)
    return len(reviewers)


def _environment_required_reviewer_logins(payload: dict[str, Any]) -> list[str]:
    """Return required reviewer logins exposed by the environment response."""
    logins: set[str] = set()
    for reviewer in _environment_required_reviewers(payload):
        reviewer_payload = reviewer.get("reviewer")
        if isinstance(reviewer_payload, dict) and isinstance(
            reviewer_payload.get("login"), str
        ):
            logins.add(reviewer_payload["login"])
        elif isinstance(reviewer.get("login"), str):
            logins.add(reviewer["login"])
    return sorted(logins)


def _environment_required_reviewers(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Return required reviewer entries from GitHub environment metadata."""
    direct_reviewers = _dict_items(payload.get("reviewers"))
    if direct_reviewers:
        return direct_reviewers
    for rule in _dict_items(payload.get("protection_rules")):
        if rule.get("type") == "required_reviewers":
            rule_reviewers = _dict_items(rule.get("reviewers"))
            if rule_reviewers:
                return rule_reviewers
    return []


def _dict_items(value: object) -> list[dict[str, Any]]:
    """Return dictionary entries from a list-shaped API field."""
    if not isinstance(value, list):
        return []
    items: list[dict[str, Any]] = []
    for item in value:
        if isinstance(item, dict):
            items.append(cast(dict[str, Any], item))
    return items
