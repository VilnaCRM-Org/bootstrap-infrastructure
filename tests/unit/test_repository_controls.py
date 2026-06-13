"""Unit tests for the GitHub repository controls helpers (governance gate)."""

from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS_DIR = PROJECT_ROOT / "scripts"

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
            "protected_branches": True,
            "custom_branch_policies": False,
        },
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
    """The governance environment requires exactly @Kravalg, protected-branch only."""
    controls = load_script_module(monkeypatch, "_github_repository_controls")

    assert controls.GOVERNANCE_ENVIRONMENT == "governance"  # nosec B101

    payload = controls.governance_environment_payload(REVIEWER_ID)
    assert payload == {  # nosec B101
        "wait_timer": 0,
        "prevent_self_review": True,
        "reviewers": [{"type": "User", "id": REVIEWER_ID}],
        "deployment_branch_policy": {
            "protected_branches": True,
            "custom_branch_policies": False,
        },
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
        "Governance environment does not require the configured reviewer."
    ]


def test_governance_environment_verification_flags_unrestricted_branches(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A non-protected-branch governance environment raises a blocker."""
    controls = load_script_module(monkeypatch, "_github_repository_controls")

    environment = _governance_environment()
    environment["deployment_branch_policy"] = {
        "protected_branches": False,
        "custom_branch_policies": True,
    }
    blockers = controls.governance_environment_verification_blockers(
        environment, REVIEWER_ID
    )
    assert blockers == [  # nosec B101
        "Governance environment does not restrict deployments to protected branches."
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
        module.main(["--repo", "VilnaCRM-Org/bootstrap-infrastructure", "--dry-run"])
        == 0
    )
    rendered = json.loads(capsys.readouterr().out)
    assert rendered["governanceEnvironment"] == {  # nosec B101
        "wait_timer": 0,
        "prevent_self_review": True,
        "reviewers": [{"type": "User", "id": REVIEWER_ID}],
        "deployment_branch_policy": {
            "protected_branches": True,
            "custom_branch_policies": False,
        },
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
        lambda repo, reviewer_id: {"governanceEnvironment": "governance"},
    )

    assert (  # nosec B101
        module.main(["--repo", "example/repo", "--apply"]) == 0
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
    ruleset = module.ruleset_payload()

    monkeypatch.setattr(module, "_main_ruleset", lambda _repo: ruleset)
    monkeypatch.setattr(
        module,
        "_run_gh_api",
        lambda _args, **_kwargs: _governance_environment(),
    )

    verification = module._verify_applied_controls(  # noqa: SLF001
        "example/repo", REVIEWER_ID
    )
    assert verification["governanceEnvironment"] == "governance"  # nosec B101
    assert verification["governanceReviewerId"] == REVIEWER_ID  # nosec B101


def test_verify_applied_controls_blocks_on_weak_governance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A self-review-allowed governance environment blocks applied verification."""
    module = load_script_module(monkeypatch, "configure_github_repository_controls")
    ruleset = module.ruleset_payload()
    weak = _governance_environment()
    weak["prevent_self_review"] = False

    monkeypatch.setattr(module, "_main_ruleset", lambda _repo: ruleset)
    monkeypatch.setattr(module, "_run_gh_api", lambda _args, **_kwargs: weak)

    with pytest.raises(RuntimeError, match="Governance environment"):
        module._verify_applied_controls("example/repo", REVIEWER_ID)  # noqa: SLF001
