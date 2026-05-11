from __future__ import annotations

from collections.abc import Sequence
from typing import Any

import _github_repository_controls as _repository_controls
import _well_architected_github_environment as _github_environment
from _script_support import run
from _well_architected_evidence_common import Runner, _check, _run_json

DEFAULT_REQUIRED_STATUS_CHECKS = _repository_controls.REQUIRED_STATUS_CHECKS
_active_branch_ruleset_count = _repository_controls.active_branch_ruleset_count
_ruleset_required_status_check_contexts = (
    _repository_controls.required_status_contexts_for_rulesets
)
_ruleset_has_pull_request_reviews = _repository_controls.rulesets_have_pull_request_rule
DEFAULT_PRODUCTION_ENVIRONMENT = "prod"
DEFAULT_PRODUCTION_REVIEWER = "Kravalg"


def _github_rulesets(
    repo: str, *, runner: Runner = run
) -> tuple[list[dict], list[str]]:
    """Return detailed repository ruleset metadata where the token can read it."""
    ok, payload, error = _run_json(
        ["gh", "api", f"repos/{repo}/rulesets"], runner=runner
    )
    if not ok or not isinstance(payload, list):
        return [], [error]

    rulesets = []
    errors = []
    for item in payload:
        if not isinstance(item, dict) or item.get("id") is None:
            continue
        detail_ok, detail, detail_error = _run_json(
            ["gh", "api", f"repos/{repo}/rulesets/{item['id']}"],
            runner=runner,
        )
        if detail_ok and isinstance(detail, dict):
            rulesets.append(detail)
        else:
            errors.append(detail_error)
    return rulesets, errors


def github_branch_protection(
    repo: str,
    branch: str,
    expected_required_status_checks: Sequence[str] = DEFAULT_REQUIRED_STATUS_CHECKS,
    *,
    runner: Runner = run,
) -> dict[str, object]:
    """Collect branch-protection evidence for required checks and reviews."""
    protection_ok, payload, protection_error = _run_json(
        ["gh", "api", f"repos/{repo}/branches/{branch}/protection"],
        runner=runner,
    )
    rulesets, ruleset_errors = _github_rulesets(repo, runner=runner)
    if (
        (not protection_ok or not isinstance(payload, dict))
        and not rulesets
        and ruleset_errors
    ):
        return _check(
            "github_branch_protection",
            status="unknown",
            blockers=[protection_error, *ruleset_errors],
        )

    protection = _protection_payload(protection_ok, payload)
    contexts = _classic_required_check_contexts(protection)
    contexts.update(_ruleset_required_status_check_contexts(rulesets))
    required_reviews = protection.get("required_pull_request_reviews")
    ruleset_reviews = _ruleset_has_pull_request_reviews(rulesets)
    enforce_admins = protection.get("enforce_admins") or {}
    missing_required_checks = sorted(
        set(expected_required_status_checks) - set(contexts)
    )
    blockers = _branch_protection_blockers(
        contexts=contexts,
        missing_required_checks=missing_required_checks,
        requires_reviews=bool(required_reviews or ruleset_reviews),
    )
    return _check(
        "github_branch_protection",
        status="passed" if not blockers else "failed",
        evidence={
            "branch": branch,
            "classicProtectionReadable": protection_ok,
            "activeRulesetCount": _active_branch_ruleset_count(rulesets),
            "requiredStatusCheckCount": len(contexts),
            "requiredStatusChecks": sorted(contexts),
            "expectedRequiredStatusChecks": list(expected_required_status_checks),
            "missingRequiredStatusChecks": missing_required_checks,
            "requiresPullRequestReviews": bool(required_reviews or ruleset_reviews),
            "enforceAdmins": bool(enforce_admins.get("enabled")),
        },
        blockers=blockers,
    )


def _protection_payload(protection_ok: bool, payload: Any) -> dict[str, Any]:
    """Return classic protection payload when readable."""
    return payload if protection_ok and isinstance(payload, dict) else {}


def _classic_required_check_contexts(protection: dict[str, Any]) -> set[str]:
    """Return classic branch-protection required status contexts."""
    required_checks = protection.get("required_status_checks") or {}
    return {
        str(context)
        for context in required_checks.get("contexts") or []
        if isinstance(context, str) and context
    }


def _branch_protection_blockers(
    *,
    contexts: set[str],
    missing_required_checks: Sequence[str],
    requires_reviews: bool,
) -> list[str]:
    """Return blockers for branch-protection metadata."""
    blockers = []
    if not contexts:
        blockers.append("Branch protection does not report required status checks.")
    elif missing_required_checks:
        blockers.append(
            "Branch protection is missing required status checks: "
            f"{', '.join(missing_required_checks)}."
        )
    if not requires_reviews:
        blockers.append("Branch protection does not require pull request reviews.")
    return blockers


def github_production_environment(
    repo: str,
    environment: str = DEFAULT_PRODUCTION_ENVIRONMENT,
    reviewer_login: str | None = DEFAULT_PRODUCTION_REVIEWER,
    *,
    runner: Runner = run,
) -> dict[str, object]:
    """Collect protected production environment evidence from GitHub."""
    ok, payload, error = _run_json(
        ["gh", "api", f"repos/{repo}/environments/{environment}"],
        runner=runner,
    )
    if not ok or not isinstance(payload, dict):
        return _check(
            "github_production_environment",
            status="failed",
            evidence={"environment": environment, "readable": False},
            blockers=[
                f"GitHub environment {environment!r} is not configured "
                f"or readable: {error}."
            ],
        )

    metadata = _github_environment.production_environment_metadata(
        payload,
        environment=environment,
        reviewer_login=reviewer_login,
    )
    blockers = _github_environment.production_environment_blockers(metadata)
    return _check(
        "github_production_environment",
        status="passed" if not blockers else "failed",
        evidence=_github_environment.production_environment_evidence(metadata),
        blockers=blockers,
    )
