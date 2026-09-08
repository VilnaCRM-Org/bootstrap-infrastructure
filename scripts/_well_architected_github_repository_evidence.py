from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, cast

import _github_repository_controls as _repository_controls
import _well_architected_github_environment as _github_environment
from _github_environment_controls import complete_branch_policies
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


def _current_promotion(pr_number: int, head: str) -> dict[str, Any]:
    """Central-only import keeps generated-service runtime dependencies separate."""
    from deployment_promotion_scope import (
        verify_current_promotion,
        verify_current_promotion_status,
    )

    snapshot = verify_current_promotion(pr_number, expected_head_sha=head)
    verify_current_promotion_status(snapshot)
    return snapshot


def with_current_promotion(
    check: dict[str, object], pr_number: int
) -> dict[str, object]:
    """Bind current head/base/selection and the App status without waiving any gate."""
    evidence = dict(cast(dict[str, Any], check.get("evidence", {})))
    blockers = list(cast(list[str], check.get("blockers", [])))
    head = evidence.get("headRefOid")
    try:
        if not isinstance(head, str) or len(head) != 40:
            raise ValueError(
                "Current PR head is unavailable for promotion verification"
            )
        evidence["promotion"] = _current_promotion(pr_number, head)
    except (ValueError, RuntimeError) as error:
        blockers.append(f"Current Infrastructure Promotion is not verified: {error}")
    return {
        **check,
        "status": "failed" if blockers else check["status"],
        "evidence": evidence,
        "blockers": blockers,
    }


def _github_rulesets(
    repo: str, *, runner: Runner = run
) -> tuple[list[dict], list[str]]:
    """Return detailed repository ruleset metadata where the token can read it."""
    central = repo == _repository_controls.CENTRAL_REPOSITORY
    suffix = "?per_page=100" if central else ""
    ok, payload, error = _run_json(
        ["gh", "api", f"repos/{repo}/rulesets{suffix}"], runner=runner
    )
    if not ok or not isinstance(payload, list):
        return [], [error]
    inventory_errors = _ruleset_inventory_errors(payload, central=central)
    if inventory_errors:
        return [], inventory_errors
    return _ruleset_details(repo, payload, runner=runner)


def _ruleset_inventory_errors(payload: list, *, central: bool) -> list[str]:
    """Central evidence needs every ruleset rather than a partial first page."""
    if not central:
        return []
    if len(payload) >= 100:
        return ["Repository ruleset inventory is incomplete."]
    identifiers = [item.get("id") for item in payload if isinstance(item, dict)]
    if len(identifiers) != len(payload) or any(
        type(identifier) is not int or identifier <= 0 for identifier in identifiers
    ):
        return ["Repository ruleset identity is malformed."]
    if len(set(identifiers)) != len(identifiers):
        return ["Repository ruleset identity is duplicated."]
    return []


def _ruleset_details(
    repo: str, summaries: list, *, runner: Runner
) -> tuple[list, list]:
    """Read each detailed policy without treating a failed read as absence."""
    rulesets = []
    errors = []
    for item in summaries:
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
    expected_required_status_checks: Sequence[str] | None = None,
    *,
    runner: Runner = run,
) -> dict[str, object]:
    """Collect branch-protection evidence for required checks and reviews."""
    expected_required_status_checks = _expected_checks(
        repo, expected_required_status_checks
    )
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
    blockers.extend(
        _promotion_gate_blockers(repo, protection, rulesets, branch, ruleset_errors)
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


def _expected_checks(repo: str, expected: Sequence[str] | None) -> Sequence[str]:
    """Resolve repository defaults without changing explicit service audit inputs."""
    return (
        _repository_controls.required_status_checks_for_repository(repo)
        if expected is None
        else expected
    )


def _classic_promotion_requirements(protection: dict[str, Any]) -> list[bool]:
    """Classic contexts require the concrete dedicated App entry too."""
    controls = _repository_controls
    context = controls.promotion_context_for_repository(controls.CENTRAL_REPOSITORY)
    required = protection.get("required_status_checks") or {}
    checks = required.get("checks") or []
    entries = [
        item
        for item in checks
        if isinstance(item, dict)
        and item.get("context") in {context, controls.GOVERNANCE_PROMOTION_CONTEXT}
    ]
    if not entries:
        mentioned = {context, controls.GOVERNANCE_PROMOTION_CONTEXT}.intersection(
            _classic_required_check_contexts(protection)
        )
        return [False] if mentioned else []
    return [
        len(entries) == 1 and _dedicated_classic_check(entries[0], context),
        controls.GOVERNANCE_PROMOTION_CONTEXT
        not in _classic_required_check_contexts(protection),
    ]


def _dedicated_classic_check(check: dict, context: str) -> bool:
    """A context string without the immutable App identifier is not an issuer gate."""
    return (
        check.get("context") == context
        and type(check.get("app_id")) is int
        and check["app_id"] == _repository_controls.CENTRAL_PROMOTION_APP_ID
    )


def _ruleset_promotion_requirement(ruleset: dict, branch: str) -> bool | None:
    """An unrelated or non-enforcing policy cannot establish the central gate."""
    controls = _repository_controls
    if not controls.is_active_branch_ruleset(ruleset):
        return None
    conditions = ruleset.get("conditions")
    if not isinstance(conditions, Mapping):
        return False
    refs = conditions.get("ref_name")
    if not isinstance(refs, Mapping) or not _valid_rule_refs(refs):
        return False
    if not set(refs["include"]).intersection(
        {"~ALL", "~DEFAULT_BRANCH", f"refs/heads/{branch}"}
    ):
        return None
    contexts = controls.required_status_contexts(ruleset)
    if not contexts.intersection(
        {
            controls.INFRASTRUCTURE_PROMOTION_CONTEXT,
            controls.GOVERNANCE_PROMOTION_CONTEXT,
        }
    ):
        return None
    return (
        not refs["exclude"]
        and ruleset.get("bypass_actors") == []
        and controls.ruleset_requires_strict_checks(ruleset)
        and controls.ruleset_has_promotion_issuer(
            ruleset,
            controls.CENTRAL_PROMOTION_APP_ID,
            repository=controls.CENTRAL_REPOSITORY,
        )
    )


def _valid_rule_refs(refs: Mapping[str, Any]) -> bool:
    """Malformed applicability cannot count as an unrelated, ignorable policy."""
    return all(
        isinstance(refs.get(key), list)
        and all(isinstance(item, str) for item in refs[key])
        for key in ("include", "exclude")
    )


def _promotion_gate_blockers(
    repo: str,
    protection: dict[str, Any],
    rulesets: Sequence[dict],
    branch: str,
    errors: Sequence[str],
) -> list[str]:
    """Require the installed central App gate, including explicit custom audits."""
    if repo != _repository_controls.CENTRAL_REPOSITORY:
        return []
    requirements = _classic_promotion_requirements(protection)
    requirements.extend(
        result
        for ruleset in rulesets
        if (result := _ruleset_promotion_requirement(ruleset, branch)) is not None
    )
    blockers = list(errors)
    if not requirements or not all(requirements):
        blockers.append(
            "Infrastructure Promotion must be required from App 4840884 on the "
            "current branch; legacy or ambiguous promotion requirements are invalid."
        )
    return blockers


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

    branch_ok, branch_payload, _branch_error = _run_json(
        [
            "gh",
            "api",
            f"repos/{repo}/environments/{environment}/deployment-branch-policies",
        ],
        runner=runner,
    )
    payload["deployment_branch_policies"] = (
        complete_branch_policies(branch_payload) if branch_ok else None
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
