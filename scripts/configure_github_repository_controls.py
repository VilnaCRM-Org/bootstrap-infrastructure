#!/usr/bin/env python3
"""Configure GitHub repository controls required for production readiness."""

from __future__ import annotations

import argparse
import json
import subprocess  # nosec B404
import sys
from collections.abc import Callable, Mapping, Sequence
from typing import Any, cast

import _github_evidence_environment as _evidence_environment
import _github_repository_controls as _repository_controls
from _github_environment_controls import complete_branch_policies

REQUIRED_STATUS_CHECKS = _repository_controls.REQUIRED_STATUS_CHECKS
OPERATIONS_ALERT_RECONCILE_ENVIRONMENT = (
    _repository_controls.OPERATIONS_ALERT_RECONCILE_ENVIRONMENT
)
GOVERNANCE_ENVIRONMENT = _repository_controls.GOVERNANCE_ENVIRONMENT
operations_alert_reconcile_environment_payload = (
    _repository_controls.operations_alert_reconcile_environment_payload
)
governance_environment_payload = _repository_controls.governance_environment_payload
protected_reviewer_environment_payload = (
    _repository_controls.protected_reviewer_environment_payload
)
prod_environment_payload = _repository_controls.prod_environment_payload
ruleset_payload = _repository_controls.ruleset_payload
_environment_reviewer_ids = _repository_controls.environment_reviewer_ids
_operations_alert_reconcile_environment_verification_blockers = (
    _repository_controls.operations_alert_reconcile_environment_verification_blockers
)
_governance_environment_verification_blockers = (
    _repository_controls.governance_environment_verification_blockers
)
_protected_environment_verification_blockers = (
    _repository_controls.protected_environment_verification_blockers
)
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
    "OPERATIONS_ALERT_RECONCILE_ENVIRONMENT",
    "GOVERNANCE_ENVIRONMENT",
    "build_parser",
    "configure",
    "main",
    "governance_environment_payload",
    "operations_alert_reconcile_environment_payload",
    "prod_environment_payload",
    "protected_reviewer_environment_payload",
    "ruleset_payload",
    "_environment_reviewer_ids",
    "_governance_environment_verification_blockers",
    "_operations_alert_reconcile_environment_verification_blockers",
    "_protected_environment_verification_blockers",
    "_prod_environment_verification_blockers",
    "_required_status_check_items",
    "_required_status_contexts",
    "_reviewer_ids_from_items",
    "_ruleset_has_pull_request_reviews",
    "_ruleset_verification_blockers",
    "_status_check_context",
)

DEFAULT_PROD_REVIEWER = "Kravalg"
ADDITIONAL_PROTECTED_ENVIRONMENTS = (
    "test",
    "test-preview",
    "prod-preview",
    "governance-preview",
)
SERVICE_PROTECTED_ENVIRONMENTS = ("test", "test-preview", "prod", "prod-preview")


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


def _environment_verification_blockers(
    repo: str,
    *,
    environment_name: str,
    reviewer_id: int,
    blocker_fn: Callable[[Mapping[str, Any] | None, int], list[str]],
) -> list[str]:
    """Return verification blockers for one protected GitHub environment."""
    try:
        environment_payload = _run_gh_api(
            [f"repos/{repo}/environments/{environment_name}"]
        )
        branch_response = _run_gh_api(
            [f"repos/{repo}/environments/{environment_name}/deployment-branch-policies"]
        )
    except RuntimeError as exc:
        return [f"{environment_name} environment was not readable: {exc}."]
    environment = (
        dict(environment_payload) if isinstance(environment_payload, Mapping) else None
    )
    if environment is not None and isinstance(branch_response, Mapping):
        environment["deployment_branch_policies"] = complete_branch_policies(
            branch_response
        )
    return blocker_fn(environment, reviewer_id)


def _configure_evidence_environment(repo: str) -> None:
    """Converge the App-key environment to the main branch without wildcard access."""
    endpoint = f"repos/{repo}/environments/{_evidence_environment.NAME}"
    _run_gh_api(
        [endpoint, "--method", "PUT"], input_payload=_evidence_environment.payload()
    )
    _configure_main_branch_policy(endpoint)


def _positive_policy_id(value: object) -> bool:
    """Require an exact positive API identity, excluding booleans and strings."""
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _validated_branch_policy(value: object) -> dict[str, Any]:
    """Validate one record without permitting its fields to select arbitrary URLs."""
    if not isinstance(value, dict):
        raise ValueError("Environment branch-policy record must be an object.")
    record = cast(dict[str, Any], value)
    if not _positive_policy_id(record.get("id")):
        raise ValueError("Environment branch-policy id must be a positive integer.")
    name = record.get("name")
    if not isinstance(name, str) or not name.strip() or name != name.strip():
        raise ValueError("Environment branch-policy name must be a non-empty string.")
    if record.get("type") not in ("branch", "tag"):
        raise ValueError("Environment branch-policy type must be branch or tag.")
    return record.copy()


def _validated_branch_policies(response: object) -> list[dict[str, Any]]:
    """Validate the entire response before allowing any policy-list mutation."""
    if not isinstance(response, dict):
        raise ValueError("Environment branch-policy response must be an object.")
    policies = response.get("branch_policies")
    if not isinstance(policies, list):
        raise ValueError("Environment branch_policies must be an array.")
    result = [_validated_branch_policy(policy) for policy in policies]
    ids = [policy["id"] for policy in result]
    if len(set(ids)) != len(ids):
        raise ValueError("Environment branch-policy ids must be unique.")
    if complete_branch_policies(response) is None:
        raise ValueError("Environment branch-policy listing is incomplete.")
    return sorted(result, key=lambda policy: policy["id"])


def _configure_main_branch_policy(endpoint: str) -> None:
    """Converge validated policies to one main rule, keeping its smallest ID."""
    response = _run_gh_api([f"{endpoint}/deployment-branch-policies"])
    policies = _validated_branch_policies(response)
    main_exists = False
    for policy in policies:
        if not main_exists and policy["name"] == "main" and policy["type"] == "branch":
            main_exists = True
        else:
            _run_gh_api(
                [
                    f"{endpoint}/deployment-branch-policies/{policy['id']}",
                    "--method",
                    "DELETE",
                ]
            )
    if not main_exists:
        _run_gh_api(
            [f"{endpoint}/deployment-branch-policies", "--method", "POST"],
            input_payload={"name": "main", "type": "branch"},
        )


def _evidence_environment_blockers(repo: str) -> list[str]:
    """Read back both the environment and its independently configured branch rules."""
    endpoint = f"repos/{repo}/environments/{_evidence_environment.NAME}"
    try:
        environment = _run_gh_api([endpoint])
        policies = _run_gh_api([f"{endpoint}/deployment-branch-policies"])
    except RuntimeError as exc:
        return [f"Evidence environment was not readable: {exc}"]
    if not isinstance(environment, dict) or not isinstance(policies, dict):
        return ["Evidence environment metadata must be JSON objects."]
    return _evidence_environment.verification_blockers(environment, policies)


def _verify_applied_controls(
    repo: str, reviewer_id: int, *, promotion_app_id: int
) -> dict[str, Any]:
    """Fetch and verify repository controls after an admin apply."""
    ruleset = _main_ruleset(repo)
    prod_environment_blockers = _environment_verification_blockers(
        repo,
        environment_name="prod",
        reviewer_id=reviewer_id,
        blocker_fn=_prod_environment_verification_blockers,
    )
    reconcile_environment_blockers = _environment_verification_blockers(
        repo,
        environment_name=OPERATIONS_ALERT_RECONCILE_ENVIRONMENT,
        reviewer_id=reviewer_id,
        blocker_fn=_operations_alert_reconcile_environment_verification_blockers,
    )
    governance_environment_blockers = _environment_verification_blockers(
        repo,
        environment_name=GOVERNANCE_ENVIRONMENT,
        reviewer_id=reviewer_id,
        blocker_fn=_governance_environment_verification_blockers,
    )
    additional_blockers = []
    for environment_name in ADDITIONAL_PROTECTED_ENVIRONMENTS:
        additional_blockers.extend(
            _environment_verification_blockers(
                repo,
                environment_name=environment_name,
                reviewer_id=reviewer_id,
                blocker_fn=lambda payload, reviewer: (
                    _protected_environment_verification_blockers(
                        payload, reviewer, label="Command environment"
                    )
                ),
            )
        )
    blockers = [
        *_evidence_environment_blockers(repo),
        *additional_blockers,
        *_ruleset_verification_blockers(ruleset, promotion_app_id=promotion_app_id),
        *prod_environment_blockers,
        *reconcile_environment_blockers,
        *governance_environment_blockers,
    ]
    if blockers:
        raise RuntimeError(" ".join(blockers))
    return {
        "requiredStatusChecks": sorted(_required_status_contexts(ruleset or {})),
        "prodReviewerId": reviewer_id,
        "prodEnvironment": "prod",
        "operationsAlertReconcileReviewerId": reviewer_id,
        "operationsAlertReconcileEnvironment": OPERATIONS_ALERT_RECONCILE_ENVIRONMENT,
        "governanceReviewerId": reviewer_id,
        "governanceEnvironment": GOVERNANCE_ENVIRONMENT,
    }


def _existing_rules(existing: dict[str, Any] | None) -> list:
    """Normalize the optional ruleset rules before preserving existing controls."""
    rules = existing.get("rules", []) if existing else []
    return rules if isinstance(rules, list) else []


def _service_protected_blockers(repo: str, reviewer_id: int) -> list[str]:
    """A drift-only setup must preserve the existing protected service quartet."""
    blockers = []
    for name in SERVICE_PROTECTED_ENVIRONMENTS:
        blockers.extend(
            _environment_verification_blockers(
                repo,
                environment_name=name,
                reviewer_id=reviewer_id,
                blocker_fn=lambda payload, reviewer: (
                    _protected_environment_verification_blockers(
                        payload, reviewer, label="Service deployment environment"
                    )
                ),
            )
        )
    return blockers


def _service_environment_names(repo: str) -> set[str]:
    """Require a complete inventory before treating an environment as absent."""
    response = _run_gh_api([f"repos/{repo}/environments?per_page=100"])
    if not isinstance(response, dict):
        raise ValueError("Service environment inventory must be an object.")
    rows = response.get("environments")
    count = response.get("total_count")
    if not isinstance(rows, list) or type(count) is not int or count != len(rows):
        raise ValueError("Service environment inventory must be complete.")
    return _validated_service_names(rows)


def _validated_service_names(rows: list) -> set[str]:
    names = [row.get("name") for row in rows if isinstance(row, dict)]
    if len(names) != len(rows) or any(not isinstance(n, str) or not n for n in names):
        raise ValueError("Service environment names must be non-empty strings.")
    if len({name.casefold() for name in names}) != len(names):
        raise ValueError("Service environment inventory contains duplicate names.")
    _reject_service_drift_aliases(names)
    return set(names)


def _reject_service_drift_aliases(names: list[str]) -> None:
    reserved = set(_repository_controls.SERVICE_DRIFT_ENVIRONMENTS)
    if any(name.casefold() in reserved and name not in reserved for name in names):
        raise ValueError("Scheduled drift environment names must use exact casing.")


def _service_drift_blockers(repo: str, name: str) -> list[str]:
    """Validate actual environment and complete branch-policy readback."""
    endpoint = f"repos/{repo}/environments/{name}"
    environment = _run_gh_api([endpoint])
    if not isinstance(environment, dict):
        return ["Scheduled drift environment must be a JSON object."]
    policies = _validated_branch_policies(
        _run_gh_api([f"{endpoint}/deployment-branch-policies"])
    )
    return _repository_controls.service_drift_environment_verification_blockers(
        {**environment, "deployment_branch_policies": policies}
    )


def configure_service_drift(
    repo: str, reviewer: str, *, apply: bool, verify_only: bool
) -> None:
    """Create only missing drift environments; never rewrite existing controls."""
    if apply and not _repo_admin_allowed(repo):
        raise RuntimeError(
            "repository admin rights are required for service drift setup."
        )
    reviewer_id = _github_user_id(reviewer)
    blockers = _service_protected_blockers(repo, reviewer_id)
    existing = _service_environment_names(repo)
    names = _repository_controls.SERVICE_DRIFT_ENVIRONMENTS
    blockers.extend(_existing_service_drift_blockers(repo, existing, verify_only))
    if blockers:
        raise RuntimeError(" ".join(blockers))
    payload = _repository_controls.service_drift_environment_payload()
    if apply:
        _apply_missing_service_drift(repo, existing)
        blockers = _service_protected_blockers(repo, reviewer_id)
        blockers.extend(_existing_service_drift_blockers(repo, set(names), True))
        if blockers:
            raise RuntimeError(" ".join(blockers))
    print(
        json.dumps(
            {
                "mode": "service-drift-only",
                "environments": {name: payload for name in names},
                "branchPolicies": [{"name": "main", "type": "branch"}],
                "verified": apply or verify_only,
            },
            indent=2,
        )
    )


def _apply_missing_service_drift(repo: str, existing: set[str]) -> None:
    for name in _repository_controls.SERVICE_DRIFT_ENVIRONMENTS:
        if name not in existing:
            _create_service_drift_environment(repo, name)


def _existing_service_drift_blockers(
    repo: str, existing: set[str], require_present: bool
) -> list[str]:
    blockers = []
    for name in _repository_controls.SERVICE_DRIFT_ENVIRONMENTS:
        if name in existing:
            blockers.extend(_service_drift_blockers(repo, name))
        elif require_present:
            blockers.append(f"Scheduled drift environment {name} is missing.")
    return blockers


def _create_service_drift_environment(repo: str, name: str) -> None:
    endpoint = f"repos/{repo}/environments/{name}"
    _run_gh_api(
        [endpoint, "--method", "PUT"],
        input_payload=_repository_controls.service_drift_environment_payload(),
    )
    policies = _validated_branch_policies(
        _run_gh_api([f"{endpoint}/deployment-branch-policies"])
    )
    if policies:
        raise RuntimeError("New drift environment has unexpected branch policies.")
    _run_gh_api(
        [f"{endpoint}/deployment-branch-policies", "--method", "POST"],
        input_payload={"name": "main", "type": "branch"},
    )


def _apply_ruleset(
    repo: str, existing: dict[str, Any] | None, payload: dict[str, Any]
) -> None:
    """Update the discovered ruleset or create one when no identity exists."""
    if existing and isinstance(existing.get("id"), int):
        endpoint, method = f"repos/{repo}/rulesets/{existing['id']}", "PUT"
    else:
        endpoint, method = f"repos/{repo}/rulesets", "POST"
    _run_gh_api([endpoint, "--method", method], input_payload=payload)


def configure(
    repo: str,
    reviewer: str,
    *,
    apply: bool,
    promotion_app_id: int,
    verify_only: bool = False,
) -> None:
    """Print or apply the GitHub repository controls."""
    # Validate the dedicated issuer before any read or write in every mode.
    ruleset_payload(promotion_app_id=promotion_app_id)
    if apply and not _repo_admin_allowed(repo):
        raise RuntimeError(
            "repository admin rights are required to update branch rulesets "
            "and protected environments."
        )

    reviewer_id = _github_user_id(reviewer)
    if verify_only:
        print(
            json.dumps(
                {
                    "verification": _verify_applied_controls(
                        repo, reviewer_id, promotion_app_id=promotion_app_id
                    )
                },
                indent=2,
                sort_keys=True,
            )
        )
        return

    existing = _main_ruleset(repo)
    payloads: dict[str, Any] = {
        "ruleset": ruleset_payload(
            _existing_rules(existing), promotion_app_id=promotion_app_id
        )
    }
    if apply:
        payloads["prodEnvironment"] = prod_environment_payload(reviewer_id)
        payloads["operationsAlertReconcileEnvironment"] = (
            operations_alert_reconcile_environment_payload(reviewer_id)
        )
        payloads["governanceEnvironment"] = governance_environment_payload(reviewer_id)
        _apply_ruleset(repo, existing, payloads["ruleset"])
        _run_gh_api(
            [f"repos/{repo}/environments/prod", "--method", "PUT"],
            input_payload=payloads["prodEnvironment"],
        )
        _run_gh_api(
            [
                f"repos/{repo}/environments/{OPERATIONS_ALERT_RECONCILE_ENVIRONMENT}",
                "--method",
                "PUT",
            ],
            input_payload=payloads["operationsAlertReconcileEnvironment"],
        )
        _run_gh_api(
            [
                f"repos/{repo}/environments/{GOVERNANCE_ENVIRONMENT}",
                "--method",
                "PUT",
            ],
            input_payload=payloads["governanceEnvironment"],
        )
        for name in ADDITIONAL_PROTECTED_ENVIRONMENTS:
            _run_gh_api(
                [f"repos/{repo}/environments/{name}", "--method", "PUT"],
                input_payload=protected_reviewer_environment_payload(reviewer_id),
            )
        for name in (
            "prod",
            OPERATIONS_ALERT_RECONCILE_ENVIRONMENT,
            GOVERNANCE_ENVIRONMENT,
            *ADDITIONAL_PROTECTED_ENVIRONMENTS,
        ):
            _configure_main_branch_policy(f"repos/{repo}/environments/{name}")
        _configure_evidence_environment(repo)
        payloads["verification"] = _verify_applied_controls(
            repo, reviewer_id, promotion_app_id=promotion_app_id
        )
    else:
        payloads["prodEnvironment"] = prod_environment_payload(reviewer_id)
        payloads["operationsAlertReconcileEnvironment"] = (
            operations_alert_reconcile_environment_payload(reviewer_id)
        )
        payloads["governanceEnvironment"] = governance_environment_payload(reviewer_id)
        payloads["prodEnvironmentReviewerLogin"] = reviewer
        payloads["operationsAlertReconcileEnvironmentReviewerLogin"] = reviewer
        payloads["governanceEnvironmentReviewerLogin"] = reviewer

    payloads["governanceEvidenceEnvironment"] = _evidence_environment.payload()
    payloads["governanceEvidenceBranchPolicies"] = [{"name": "main", "type": "branch"}]
    payloads["protectedEnvironmentBranchPolicies"] = {
        name: [{"name": "main", "type": "branch"}]
        for name in (
            "prod",
            OPERATIONS_ALERT_RECONCILE_ENVIRONMENT,
            GOVERNANCE_ENVIRONMENT,
            *ADDITIONAL_PROTECTED_ENVIRONMENTS,
        )
    }
    payloads["promotionAppId"] = promotion_app_id
    payloads["additionalProtectedEnvironments"] = {
        name: protected_reviewer_environment_payload(reviewer_id)
        for name in ADDITIONAL_PROTECTED_ENVIRONMENTS
    }
    print(json.dumps(payloads, indent=2, sort_keys=True))


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI parser."""
    parser = argparse.ArgumentParser(
        description=(
            "Configure GitHub branch rules and protected environment controls."
        )
    )
    parser.add_argument("--repo", required=True, help="Repository in owner/name form.")
    parser.add_argument(
        "--promotion-app-id",
        type=int,
        help="Dedicated GitHub App ID allowed to publish promotion proof.",
    )
    parser.add_argument(
        "--service-drift-only",
        action="store_true",
        help=(
            "Configure only governed-service drift environments; "
            "preserve protected deployments."
        ),
    )
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
        help=("Print the ruleset and protected environment payloads without applying."),
    )
    mode.add_argument(
        "--verify-only",
        action="store_true",
        help=(
            "Verify existing ruleset and protected environment controls "
            "without applying."
        ),
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command line interface."""
    args = build_parser().parse_args(argv)
    try:
        if args.service_drift_only:
            configure_service_drift(
                args.repo,
                args.prod_reviewer,
                apply=args.apply,
                verify_only=args.verify_only,
            )
            return 0
        if args.promotion_app_id is None:
            raise ValueError(
                "--promotion-app-id is required for normal controls setup."
            )
        configure(
            args.repo,
            args.prod_reviewer,
            apply=args.apply,
            promotion_app_id=args.promotion_app_id,
            verify_only=args.verify_only,
        )
        return 0
    except (ValueError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
