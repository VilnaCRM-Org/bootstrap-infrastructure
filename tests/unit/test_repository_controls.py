"""Unit tests for the GitHub repository controls helpers (governance gate)."""

from __future__ import annotations

import copy
import importlib
import json
import sys
from pathlib import Path

import pytest
import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS_DIR = PROJECT_ROOT / "scripts"
GOVERNANCE_WORKFLOW = PROJECT_ROOT / ".github" / "workflows" / "pulumi-governance.yml"
GOVERNANCE_STATUS_CONTEXT = "Governance Apply"
# The complete global required-status-check set enforced by the live `main`
# ruleset. "Governance Apply" is intentionally NOT here: it is an informational
# legacy informational status; central promotion now belongs to the protected
# aggregate publisher. Retiring the old runner must not weaken repository controls.
LEGACY_REQUIRED_STATUS_CHECKS = (
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

REVIEWER_ID = 9444106


def load_script_module(monkeypatch: pytest.MonkeyPatch, module_name: str):
    """Import a script module from the repo-local scripts directory."""
    monkeypatch.syspath_prepend(str(SCRIPTS_DIR))
    importlib.invalidate_caches()
    sys.modules.pop(module_name, None)
    return importlib.import_module(module_name)


def _governance_environment(reviewer_id: int = REVIEWER_ID) -> dict[str, object]:
    """Return a well-formed governance environment payload from GitHub."""
    return {
        "prevent_self_review": True,
        "deployment_branch_policy": {
            "protected_branches": False,
            "custom_branch_policies": True,
        },
        "can_admins_bypass": False,
        "deployment_branch_policies": [{"name": "main", "type": "branch"}],
        "protection_rules": [
            {
                "type": "required_reviewers",
                "reviewers": [
                    {
                        "type": "User",
                        "reviewer": {
                            "type": "User",
                            "id": reviewer_id,
                            "login": "Kravalg",
                        },
                    }
                ],
            }
        ],
    }


def test_governance_environment_payload_single_kravalg_reviewer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The governance environment requires exactly @Kravalg and explicit branches."""
    controls = load_script_module(monkeypatch, "_github_repository_controls")

    assert controls.GOVERNANCE_ENVIRONMENT == "governance"  # nosec B101

    payload = controls.governance_environment_payload(REVIEWER_ID)
    assert payload == {  # nosec B101
        "wait_timer": 0,
        "prevent_self_review": True,
        "reviewers": [{"type": "User", "id": REVIEWER_ID}],
        "deployment_branch_policy": {
            "protected_branches": False,
            "custom_branch_policies": True,
        },
        "can_admins_bypass": False,
    }
    # Exactly one reviewer (sole @Kravalg).
    assert payload["reviewers"] == [{"type": "User", "id": REVIEWER_ID}]  # nosec B101
    assert len(payload["reviewers"]) == 1  # nosec B101
    # Reuse of the shared protected-reviewer helper.
    assert payload == controls.protected_reviewer_environment_payload(  # nosec B101
        REVIEWER_ID
    )


def test_default_pull_request_rule_binds_approval_to_diff(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SECURITY-3: stale reviews dismissed and last push approval required."""
    controls = load_script_module(monkeypatch, "_github_repository_controls")

    parameters = controls.default_pull_request_rule()["parameters"]
    assert parameters["dismiss_stale_reviews_on_push"] is True  # nosec B101
    assert parameters["require_last_push_approval"] is True  # nosec B101
    # The rest of the contract must remain intact.
    assert parameters["require_code_owner_review"] is True  # nosec B101
    assert parameters["required_approving_review_count"] == 1  # nosec B101
    assert parameters["required_review_thread_resolution"] is True  # nosec B101


def test_governance_environment_verification_passes_for_kravalg(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A compliant governance environment yields no blockers."""
    controls = load_script_module(monkeypatch, "_github_repository_controls")

    blockers = controls.governance_environment_verification_blockers(
        _governance_environment(), REVIEWER_ID
    )
    assert blockers == []  # nosec B101


def test_governance_environment_verification_flags_self_review(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Self-review-allowed raises a governance-labelled blocker."""
    controls = load_script_module(monkeypatch, "_github_repository_controls")

    environment = _governance_environment()
    environment["prevent_self_review"] = False
    blockers = controls.governance_environment_verification_blockers(
        environment, REVIEWER_ID
    )
    assert blockers == [  # nosec B101
        "Governance environment does not prevent self-review."
    ]


def test_governance_environment_verification_flags_extra_reviewer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A reviewer other than @Kravalg (>1 reviewer) raises a governance blocker."""
    controls = load_script_module(monkeypatch, "_github_repository_controls")

    other_reviewer = REVIEWER_ID + 1
    environment = _governance_environment(reviewer_id=other_reviewer)
    blockers = controls.governance_environment_verification_blockers(
        environment, REVIEWER_ID
    )
    assert blockers == [  # nosec B101
        "Governance environment does not require only the configured reviewer."
    ]


def test_governance_environment_verification_flags_unrestricted_branches(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unrestricted governance environment raises a blocker."""
    controls = load_script_module(monkeypatch, "_github_repository_controls")

    environment = _governance_environment()
    environment["deployment_branch_policy"] = {
        "protected_branches": False,
        "custom_branch_policies": False,
    }
    blockers = controls.governance_environment_verification_blockers(
        environment, REVIEWER_ID
    )
    assert blockers == [  # nosec B101
        "Governance environment does not allow only the main branch."
    ]


def test_governance_environment_verification_handles_missing_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A missing governance environment reports a readability blocker."""
    controls = load_script_module(monkeypatch, "_github_repository_controls")

    blockers = controls.governance_environment_verification_blockers(None, REVIEWER_ID)
    assert blockers == ["Governance environment was not readable after apply."]  # nosec B101


def test_configure_emits_governance_environment_in_dry_run(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The --dry-run snapshot includes the governanceEnvironment payload, no calls."""
    module = load_script_module(monkeypatch, "configure_github_repository_controls")

    monkeypatch.setattr(module, "_main_ruleset", lambda _repo: None)
    monkeypatch.setattr(module, "_github_user_id", lambda _reviewer: REVIEWER_ID)

    def _forbid_gh_api(_args, **_kwargs):
        raise AssertionError("dry-run must not call gh api")

    monkeypatch.setattr(module, "_run_gh_api", _forbid_gh_api)

    assert (  # nosec B101
        module.main(
            [
                "--promotion-app-id",
                "4840884",
                "--repo",
                "VilnaCRM-Org/bootstrap-infrastructure",
                "--dry-run",
            ]
        )
        == 0
    )
    rendered = json.loads(capsys.readouterr().out)
    assert rendered["governanceEnvironment"] == {  # nosec B101
        "wait_timer": 0,
        "prevent_self_review": True,
        "reviewers": [{"type": "User", "id": REVIEWER_ID}],
        "deployment_branch_policy": {
            "protected_branches": False,
            "custom_branch_policies": True,
        },
        "can_admins_bypass": False,
    }
    assert rendered["governanceEnvironmentReviewerLogin"] == "Kravalg"  # nosec B101


def test_configure_emits_and_applies_governance_environment(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The apply branch emits and PUTs the governance environment."""
    module = load_script_module(monkeypatch, "configure_github_repository_controls")

    calls: list[tuple[tuple[str, ...], object]] = []

    def _record_gh_api(args, *, input_payload=None):
        calls.append((tuple(args), input_payload))
        return {"total_count": 0, "branch_policies": []} if len(args) == 1 else {}

    monkeypatch.setattr(module, "_repo_admin_allowed", lambda _repo: True)
    monkeypatch.setattr(module, "_github_user_id", lambda _reviewer: REVIEWER_ID)
    monkeypatch.setattr(module, "_main_ruleset", lambda _repo: None)
    monkeypatch.setattr(module, "_run_gh_api", _record_gh_api)
    monkeypatch.setattr(
        module,
        "_verify_applied_controls",
        lambda repo, reviewer_id, **kwargs: {"governanceEnvironment": "governance"},
    )

    assert (  # nosec B101
        module.main(
            ["--promotion-app-id", "12345", "--repo", "example/repo", "--apply"]
        )
        == 0
    )
    rendered = json.loads(capsys.readouterr().out)
    assert rendered["governanceEnvironment"]["reviewers"][0]["id"] == (  # nosec B101
        REVIEWER_ID
    )

    governance_put = next(
        payload
        for args, payload in calls
        if args
        == (
            "repos/example/repo/environments/governance",
            "--method",
            "PUT",
        )
    )
    assert governance_put["reviewers"] == [  # nosec B101
        {"type": "User", "id": REVIEWER_ID}
    ]
    assert governance_put["prevent_self_review"] is True  # nosec B101


def test_verify_applied_controls_reports_governance_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Applied-control verification reports the governance environment + reviewer."""
    module = load_script_module(monkeypatch, "configure_github_repository_controls")
    ruleset = module.ruleset_payload(promotion_app_id=12345)
    monkeypatch.setattr(module, "_evidence_environment_blockers", lambda repo: [])

    monkeypatch.setattr(module, "_main_ruleset", lambda _repo: ruleset)
    monkeypatch.setattr(
        module,
        "_run_gh_api",
        lambda _args, **_kwargs: (
            {"total_count": 1, "branch_policies": [{"name": "main", "type": "branch"}]}
            if _args[0].endswith("/deployment-branch-policies")
            else _governance_environment()
        ),
    )

    verification = module._verify_applied_controls(  # noqa: SLF001
        "example/repo", REVIEWER_ID, promotion_app_id=12345
    )
    assert verification["governanceEnvironment"] == "governance"  # nosec B101
    assert verification["governanceReviewerId"] == REVIEWER_ID  # nosec B101


def test_verify_applied_controls_blocks_on_weak_governance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A self-review-allowed governance environment blocks applied verification."""
    module = load_script_module(monkeypatch, "configure_github_repository_controls")
    ruleset = module.ruleset_payload(promotion_app_id=12345)
    weak = _governance_environment()
    weak["prevent_self_review"] = False

    monkeypatch.setattr(module, "_main_ruleset", lambda _repo: ruleset)
    monkeypatch.setattr(module, "_run_gh_api", lambda _args, **_kwargs: weak)

    with pytest.raises(RuntimeError, match="Governance environment"):
        module._verify_applied_controls(
            "example/repo", REVIEWER_ID, promotion_app_id=12345
        )  # noqa: SLF001


def test_required_status_checks_keep_existing_contexts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No regression: every legacy required check survives in the required set."""
    controls = load_script_module(monkeypatch, "_github_repository_controls")

    for context in LEGACY_REQUIRED_STATUS_CHECKS:
        assert context in controls.REQUIRED_STATUS_CHECKS  # nosec B101
    # Command feedback stays informational; promotion is the new required proof.
    assert set(controls.REQUIRED_STATUS_CHECKS) == (
        set(LEGACY_REQUIRED_STATUS_CHECKS) | {"Governance Promotion"}
    )


def test_retired_governance_has_no_status_authority() -> None:
    """Old informational status cannot overwrite aggregate promotion evidence."""
    legacy = yaml.safe_load(GOVERNANCE_WORKFLOW.read_text())
    assert legacy["permissions"] == {}
    assert set(legacy["jobs"]) == {"retired"}
    retired = legacy["jobs"]["retired"]
    assert retired["permissions"] == {}
    assert "exit 1" in retired["steps"][0]["run"]
    assert "statuses/" not in json.dumps(legacy)
    root = yaml.safe_load(
        (GOVERNANCE_WORKFLOW.parent / "pulumi-pr-command-runner.yml").read_text()
    )
    comment = root["jobs"]["comment_result"]
    assert "feedback_pull_request_number" in comment["if"]
    assert "statuses/" not in json.dumps(comment)
    publisher = root["jobs"]["publish_promotion"]
    assert publisher["environment"] == "governance-evidence"
    assert "deployment_promotion_emitter.py" in json.dumps(publisher)
    assert "prepare_promotion" in publisher["needs"]


def test_existing_weak_review_rules_are_hardened(monkeypatch):
    controls = load_script_module(monkeypatch, "_github_repository_controls")
    existing = {
        "type": "pull_request",
        "parameters": {
            "required_approving_review_count": 3,
            "required_reviewers": [{"reviewer_id": 123}],
            "dismiss_stale_reviews_on_push": False,
            "require_code_owner_review": False,
            "require_last_push_approval": False,
        },
    }
    payload = controls.ruleset_payload([existing], promotion_app_id=12345)
    parameters = next(
        rule["parameters"]
        for rule in payload["rules"]
        if rule["type"] == "pull_request"
    )
    assert parameters["required_approving_review_count"] == 3
    assert parameters["required_reviewers"] == [{"reviewer_id": 123}]
    for flag in (
        "dismiss_stale_reviews_on_push",
        "require_code_owner_review",
        "require_last_push_approval",
    ):
        assert parameters[flag] is True
        parameters[flag] = False
        assert controls.ruleset_verification_blockers(payload, promotion_app_id=12345)
        parameters[flag] = True


def test_dry_run_provisions_disjoint_protected_command_environments(
    monkeypatch, capsys
):
    module = load_script_module(monkeypatch, "configure_github_repository_controls")
    monkeypatch.setattr(module, "_github_user_id", lambda login: REVIEWER_ID)
    monkeypatch.setattr(module, "_main_ruleset", lambda repo: None)
    module.configure("example/repo", "Kravalg", apply=False, promotion_app_id=12345)
    environments = json.loads(capsys.readouterr().out)[
        "additionalProtectedEnvironments"
    ]
    assert set(environments) == {
        "test",
        "test-preview",
        "prod-preview",
        "governance-preview",
        "test-operator-preview",
        "test-operator",
        "test-operator-drift",
        "prod-operator-preview",
        "prod-operator",
        "prod-operator-drift",
        "test-governance-preview",
        "test-governance",
        "test-governance-drift",
        "prod-governance-preview",
        "prod-governance",
        "prod-governance-drift",
    }
    for payload in environments.values():
        assert payload["prevent_self_review"] is True
        assert payload["reviewers"] == [{"type": "User", "id": REVIEWER_ID}]


def test_required_promotion_issuer_and_deployment_rules_are_preserved(monkeypatch):
    controls = load_script_module(monkeypatch, "_github_repository_controls")
    deployments = {
        "type": "required_deployments",
        "parameters": {
            "required_deployment_environments": ["test", "prod"],
        },
    }
    ruleset = controls.ruleset_payload([deployments], promotion_app_id=12345)
    assert deployments in ruleset["rules"]
    checks = next(
        rule["parameters"]["required_status_checks"]
        for rule in ruleset["rules"]
        if rule["type"] == "required_status_checks"
    )
    promotion_check = next(
        check for check in checks if check["context"] == "Governance Promotion"
    )
    assert promotion_check["integration_id"] == 12345
    assert controls.ruleset_verification_blockers(ruleset, promotion_app_id=12345) == []
    promotion_check.pop("integration_id")
    assert "issuer" in " ".join(
        controls.ruleset_verification_blockers(ruleset, promotion_app_id=12345)
    )


def _live_central_rules():
    """Public rule snapshot from main ruleset13906584, read 2026-09-08."""
    return [
        {"type": "deletion"},
        {"type": "non_fast_forward"},
        {
            "type": "pull_request",
            "parameters": {
                "allowed_merge_methods": ["squash"],
                "dismiss_stale_reviews_on_push": True,
                "dismissal_restriction": {"allowed_actors": [], "enabled": False},
                "require_code_owner_review": True,
                "require_extra_approval_for_unattributed_changes": True,
                "require_last_push_approval": True,
                "required_approving_review_count": 2,
                "required_review_thread_resolution": True,
                "required_reviewers": [],
            },
        },
        {"type": "code_quality", "parameters": {"severity": "errors"}},
        {
            "type": "code_scanning",
            "parameters": {
                "code_scanning_tools": [
                    {
                        "alerts_threshold": "errors",
                        "security_alerts_threshold": "high_or_higher",
                        "tool": "CodeQL",
                    }
                ]
            },
        },
        {
            "type": "required_status_checks",
            "parameters": {
                "do_not_enforce_on_create": False,
                "strict_required_status_checks_policy": True,
                "required_status_checks": [
                    {
                        "context": context,
                        **(
                            {"integration_id": 4840884}
                            if context == "Test Account Evidence"
                            else {}
                        ),
                    }
                    for context in LEGACY_REQUIRED_STATUS_CHECKS
                ]
                + [{"context": "Governance Promotion", "integration_id": 4840884}],
            },
        },
        {
            "type": "required_deployments",
            "parameters": {"required_deployment_environments": ["test", "prod"]},
        },
    ]


def _central_checks(payload):
    """Return the one concrete rule's entries for issuer assertions."""
    return next(
        rule["parameters"]["required_status_checks"]
        for rule in payload["rules"]
        if rule["type"] == "required_status_checks"
    )


def test_central_migration_preserves_actual_main_protections(monkeypatch):
    controls = load_script_module(monkeypatch, "_github_repository_controls")
    original = _live_central_rules()
    untouched = copy.deepcopy(original)
    result = controls.ruleset_payload(
        original, promotion_app_id=4840884, repository=controls.CENTRAL_REPOSITORY
    )
    assert original == untouched
    contexts = {c["context"]: c for c in _central_checks(result)}
    assert set(contexts) == set(LEGACY_REQUIRED_STATUS_CHECKS) | {
        "Infrastructure Promotion"
    }
    for name in ("Infrastructure Promotion", "Test Account Evidence"):
        assert contexts[name] == {"context": name, "integration_id": 4840884}
    preserved = [
        r
        for r in original
        if r["type"] not in {"required_deployments", "required_status_checks"}
    ]
    assert all(rule in result["rules"] for rule in preserved)
    assert not any(rule["type"] == "required_deployments" for rule in result["rules"])
    assert result["name"] == "main" and result["enforcement"] == "active"
    assert result["conditions"] == {
        "ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}
    }
    assert not result.get("bypass_actors")
    assert (
        controls.ruleset_verification_blockers(
            result, promotion_app_id=4840884, repository=controls.CENTRAL_REPOSITORY
        )
        == []
    )
    assert (
        controls.ruleset_payload(
            result["rules"],
            promotion_app_id=4840884,
            repository=controls.CENTRAL_REPOSITORY,
        )
        == result
    )


@pytest.mark.parametrize(
    "repository",
    [
        None,
        "VilnaCRM-Org/user-service-infrastructure",
        "Other/bootstrap-infrastructure",
        "vilnacrm-org/bootstrap-infrastructure",
        "VilnaCRM-Org/bootstrap-infrastructure-extra",
    ],
)
def test_services_keep_legacy_protocol_and_required_deployments(
    monkeypatch, repository
):
    controls = load_script_module(monkeypatch, "_github_repository_controls")
    original = _live_central_rules()
    result = controls.ruleset_payload(
        original, promotion_app_id=4840884, repository=repository
    )
    assert (
        controls.promotion_context_for_repository(repository) == "Governance Promotion"
    )
    assert (
        controls.required_status_checks_for_repository(repository)
        == controls.REQUIRED_STATUS_CHECKS
    )
    assert {c["context"] for c in _central_checks(result)} == set(
        controls.REQUIRED_STATUS_CHECKS
    )
    assert original[-1] in result["rules"]


@pytest.mark.parametrize("app_id", [12345, 15368, True, None, "4840884", -1, 0])
def test_central_rejects_unapproved_issuer_before_any_configuration_read(
    monkeypatch, app_id
):
    module = load_script_module(monkeypatch, "configure_github_repository_controls")

    def no_read(*args, **kwargs):
        """No read or write is reachable for an invalid issuer."""
        pytest.fail("Invalid issuer reached repository metadata")

    monkeypatch.setattr(module, "_github_user_id", no_read)
    monkeypatch.setattr(module, "_repo_admin_allowed", no_read)
    with pytest.raises(ValueError):
        module.configure(
            "VilnaCRM-Org/bootstrap-infrastructure",
            "Kravalg",
            apply=True,
            promotion_app_id=app_id,
        )


@pytest.mark.parametrize(
    "context",
    ["Governance Promotion", "Infrastructure Promotion", "Test Account Evidence"],
)
@pytest.mark.parametrize("issuer", [12345, True, "4840884"])
def test_central_existing_foreign_issuer_cannot_be_removed_or_overwritten(
    monkeypatch, context, issuer
):
    controls = load_script_module(monkeypatch, "_github_repository_controls")
    existing = [
        {
            "type": "required_status_checks",
            "parameters": {
                "required_status_checks": [
                    {"context": context, "integration_id": issuer}
                ]
            },
        }
    ]
    with pytest.raises(ValueError, match="issuer"):
        controls.ruleset_payload(
            existing, promotion_app_id=4840884, repository=controls.CENTRAL_REPOSITORY
        )


def test_central_reconciles_both_protocol_entries_and_preserves_other_checks(
    monkeypatch,
):
    controls = load_script_module(monkeypatch, "_github_repository_controls")
    rules = _live_central_rules()
    checks = next(
        r["parameters"]["required_status_checks"]
        for r in rules
        if r["type"] == "required_status_checks"
    )
    checks.extend(
        [
            {"context": "Infrastructure Promotion", "integration_id": 4840884},
            {"context": "Independent security approval", "integration_id": 9999},
        ]
    )
    result = controls.ruleset_payload(
        rules, promotion_app_id=4840884, repository=controls.CENTRAL_REPOSITORY
    )
    selected = [
        c for c in _central_checks(result) if c["context"] == "Infrastructure Promotion"
    ]
    assert selected == [
        {"context": "Infrastructure Promotion", "integration_id": 4840884}
    ]
    assert checks[-1] in _central_checks(result)
    checks.append({"context": "Independent security approval", "integration_id": 8888})
    with pytest.raises(ValueError, match="Conflicting duplicate"):
        controls.ruleset_payload(
            rules, promotion_app_id=4840884, repository=controls.CENTRAL_REPOSITORY
        )


def test_central_retires_only_test_prod_deployment_conditions(monkeypatch):
    controls = load_script_module(monkeypatch, "_github_repository_controls")
    original = {
        "type": "required_deployments",
        "parameters": {
            "required_deployment_environments": ["test", "security-review", "prod"],
            "future_protection": True,
        },
    }
    result = controls.ruleset_payload(
        [original], promotion_app_id=4840884, repository=controls.CENTRAL_REPOSITORY
    )
    assert {
        "type": "required_deployments",
        "parameters": {
            "required_deployment_environments": ["security-review"],
            "future_protection": True,
        },
    } in result["rules"]
    assert (
        controls.ruleset_verification_blockers(
            result, promotion_app_id=4840884, repository=controls.CENTRAL_REPOSITORY
        )
        == []
    )


@pytest.mark.parametrize(
    "parameters",
    [
        None,
        {},
        {"required_deployment_environments": "prod"},
        {"required_deployment_environments": [False]},
        {"required_deployment_environments": [""]},
        {"required_deployment_environments": [" prod"]},
    ],
)
def test_central_malformed_deployment_rules_fail_closed(monkeypatch, parameters):
    controls = load_script_module(monkeypatch, "_github_repository_controls")
    with pytest.raises(ValueError, match="Malformed existing deployment"):
        controls.ruleset_payload(
            [{"type": "required_deployments", "parameters": parameters}],
            promotion_app_id=4840884,
            repository=controls.CENTRAL_REPOSITORY,
        )


@pytest.mark.parametrize(
    "kind",
    [
        "legacy",
        "deployment",
        "inactive",
        "branch",
        "duplicate",
        "foreign",
        "evidence",
        "bypass",
    ],
)
def test_central_readback_rejects_partial_or_weakened_cutover(monkeypatch, kind):
    controls = load_script_module(monkeypatch, "_github_repository_controls")
    result = controls.ruleset_payload(
        promotion_app_id=4840884, repository=controls.CENTRAL_REPOSITORY
    )
    if kind == "legacy":
        _central_checks(result).append(
            {"context": "Governance Promotion", "integration_id": 4840884}
        )
    elif kind == "deployment":
        result["rules"].append(_live_central_rules()[-1])
    elif kind == "inactive":
        result["enforcement"] = "evaluate"
    elif kind == "branch":
        result["conditions"]["ref_name"]["exclude"] = ["refs/heads/main"]
    elif kind == "duplicate":
        _central_checks(result).append(
            {"context": "Infrastructure Promotion", "integration_id": 4840884}
        )
    elif kind == "bypass":
        result["bypass_actors"] = [
            {"actor_type": "RepositoryRole", "actor_id": 5, "bypass_mode": "always"}
        ]
    elif kind == "evidence":
        next(
            c
            for c in _central_checks(result)
            if c["context"] == "Test Account Evidence"
        )["integration_id"] = 12345
    else:
        next(
            c
            for c in _central_checks(result)
            if c["context"] == "Infrastructure Promotion"
        )["integration_id"] = 12345
    assert controls.ruleset_verification_blockers(
        result, promotion_app_id=4840884, repository=controls.CENTRAL_REPOSITORY
    )


def test_central_public_issuer_predicate_rejects_wrong_requested_app(monkeypatch):
    controls = load_script_module(monkeypatch, "_github_repository_controls")
    ruleset = controls.ruleset_payload(
        promotion_app_id=4840884, repository=controls.CENTRAL_REPOSITORY
    )
    assert not controls.ruleset_has_promotion_issuer(
        ruleset, 12345, repository=controls.CENTRAL_REPOSITORY
    )


def test_central_does_not_discard_unknown_deployment_protections(monkeypatch):
    controls = load_script_module(monkeypatch, "_github_repository_controls")
    rule = {
        "type": "required_deployments",
        "parameters": {
            "required_deployment_environments": ["test", "prod"],
            "unknown_protection": True,
        },
    }
    with pytest.raises(ValueError, match="Unknown deployment protection"):
        controls.ruleset_payload(
            [rule], promotion_app_id=4840884, repository=controls.CENTRAL_REPOSITORY
        )


def test_central_verify_only_requires_completed_migration(monkeypatch):
    module = load_script_module(monkeypatch, "configure_github_repository_controls")
    monkeypatch.setattr(
        module, "_environment_verification_blockers", lambda *args, **kwargs: []
    )
    monkeypatch.setattr(module, "_evidence_environment_blockers", lambda repo: [])
    legacy = {"id": 13906584, "rules": _live_central_rules()}
    monkeypatch.setattr(module, "_main_ruleset", lambda repo: legacy)
    with pytest.raises(RuntimeError, match="Infrastructure Promotion"):
        module._verify_applied_controls(
            "VilnaCRM-Org/bootstrap-infrastructure",
            REVIEWER_ID,
            promotion_app_id=4840884,
        )
    current = module.ruleset_payload(
        legacy["rules"],
        promotion_app_id=4840884,
        repository="VilnaCRM-Org/bootstrap-infrastructure",
    )
    monkeypatch.setattr(module, "_main_ruleset", lambda repo: current)
    result = module._verify_applied_controls(
        "VilnaCRM-Org/bootstrap-infrastructure", REVIEWER_ID, promotion_app_id=4840884
    )
    assert "Infrastructure Promotion" in result["requiredStatusChecks"]
    assert "Governance Promotion" not in result["requiredStatusChecks"]


def test_central_configuration_preview_uses_repository_specific_migration(
    monkeypatch, capsys
):
    module = load_script_module(monkeypatch, "configure_github_repository_controls")
    monkeypatch.setattr(
        module,
        "_main_ruleset",
        lambda repo: {"id": 13906584, "rules": _live_central_rules()},
    )
    monkeypatch.setattr(module, "_github_user_id", lambda reviewer: REVIEWER_ID)
    module.configure(
        "VilnaCRM-Org/bootstrap-infrastructure",
        "Kravalg",
        apply=False,
        promotion_app_id=4840884,
    )
    result = json.loads(capsys.readouterr().out)
    checks = _central_checks(result["ruleset"])
    assert "Infrastructure Promotion" in {c["context"] for c in checks}
    assert "Governance Promotion" not in {c["context"] for c in checks}
    assert result["prodEnvironment"]["prevent_self_review"] is True
    assert result["prodEnvironment"]["can_admins_bypass"] is False
    assert result["protectedEnvironmentBranchPolicies"]["prod"] == [
        {"name": "main", "type": "branch"}
    ]
