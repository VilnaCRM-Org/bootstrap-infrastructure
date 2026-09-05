"""Unit tests for the GitHub repository controls helpers (governance gate)."""

from __future__ import annotations

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
# commit status posted by the governance runner, and the governance merge gate
# is CODEOWNERS + the protected `governance` environment, not a global check.
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
                        "reviewer": {"id": reviewer_id, "login": "Kravalg"},
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
                "12345",
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
        return {}

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
            {"branch_policies": [{"name": "main", "type": "branch"}]}
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


def _governance_status_run_text() -> str:
    """Concatenate every `run` body in the governance-status job for assertions."""
    workflow = yaml.safe_load(GOVERNANCE_WORKFLOW.read_text(encoding="utf-8"))
    status_job = workflow["jobs"]["governance_status"]
    return "\n".join(step.get("run", "") for step in status_job.get("steps", []))


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


def test_governance_runner_posts_governance_apply_status_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The runner posts the `Governance Apply` commit status to the head SHA.

    This is an INFORMATIONAL status (it surfaces the gated apply result), not a
    global required check: the governance runner fires on `repository_dispatch`
    and posts that exact context to the verified head SHA (architecture §7.5).
    """
    run_text = _governance_status_run_text()

    # The runner posts a commit status to the verified head SHA.
    assert "statuses/${HEAD_SHA}" in run_text  # nosec B101
    # The runner still posts the informational `Governance Apply` context.
    assert f'context="{GOVERNANCE_STATUS_CONTEXT}"' in run_text  # nosec B101


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
