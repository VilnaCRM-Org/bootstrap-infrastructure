"""The isolated App key must be inaccessible to feature-branch workflow jobs."""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
boundary = importlib.import_module("_github_evidence_environment")
controls = importlib.import_module("configure_github_repository_controls")
promotion = importlib.import_module("governance_promotion")


def test_valid_boundary_has_no_all_pr_review_bottleneck():
    environment = boundary.payload()
    assert environment["reviewers"] == []
    assert (
        boundary.verification_blockers(
            environment,
            {
                "total_count": 1,
                "branch_policies": [{"name": "main", "type": "branch"}],
            },
        )
        == []
    )


@pytest.mark.parametrize(
    "policies",
    [
        None,
        1,
        "main",
        {},
        [None],
        ["main"],
        [{}],
        [],
        [{"name": "*", "type": "branch"}],
        [{"name": "main", "type": "tag"}],
        [{"name": "main", "type": "branch"}, {"name": "feature", "type": "branch"}],
    ],
)
def test_wildcards_tags_other_branches_and_missing_policy_rejected(policies):
    assert boundary.verification_blockers(
        boundary.payload(),
        {
            "total_count": len(policies) if isinstance(policies, list) else 0,
            "branch_policies": policies,
        },
    )


def test_admin_bypass_and_missing_branch_restrictions_rejected():
    assert len(boundary.verification_blockers({}, {})) == 3


@pytest.mark.parametrize("existing", [False, True])
def test_configure_converges_main_only_policy(monkeypatch, existing):
    calls = []
    policies = [{"name": "*", "type": "branch", "id": 1}]
    if existing:
        policies.append({"name": "main", "type": "branch", "id": 2})

    def api(args, **kwargs):
        calls.append((args, kwargs))
        return {
            "total_count": len(policies) if isinstance(policies, list) else 0,
            "branch_policies": policies,
        }

    monkeypatch.setattr(controls, "_run_gh_api", api)
    controls._configure_evidence_environment("org/repo")
    assert calls[0][1]["input_payload"] == boundary.payload()
    assert any(args[-1] == "DELETE" and args[0].endswith("/1") for args, _ in calls)
    assert sum(args[-1] == "POST" for args, _ in calls) == (0 if existing else 1)


def test_configure_rejects_malformed_policy_metadata(monkeypatch):
    monkeypatch.setattr(controls, "_run_gh_api", lambda *args, **kwargs: [])
    with pytest.raises(ValueError, match="object"):
        controls._configure_evidence_environment("org/repo")


def test_verification_reads_environment_and_branch_policies(monkeypatch):
    def api(args):
        return (
            {"total_count": 1, "branch_policies": [{"name": "main", "type": "branch"}]}
            if args[0].endswith("deployment-branch-policies")
            else boundary.payload()
        )

    monkeypatch.setattr(controls, "_run_gh_api", api)
    assert controls._evidence_environment_blockers("org/repo") == []
    monkeypatch.setattr(controls, "_run_gh_api", lambda *args: [])
    assert "JSON objects" in controls._evidence_environment_blockers("org/repo")[0]

    def failure(*args):
        raise RuntimeError("Not Found")

    monkeypatch.setattr(controls, "_run_gh_api", failure)
    assert "not readable" in controls._evidence_environment_blockers("org/repo")[0]


def test_reporter_rechecks_boundary_before_using_app_key(monkeypatch):
    monkeypatch.setenv("GITHUB_REPOSITORY", "org/repo")
    monkeypatch.setattr(
        promotion,
        "gh",
        lambda path: (
            {"total_count": 1, "branch_policies": [{"name": "main", "type": "branch"}]}
            if path.endswith("deployment-branch-policies")
            else boundary.payload()
        ),
    )
    assert promotion.main(["verify-environment"]) == 0
    monkeypatch.setattr(promotion, "gh", lambda *args: {})
    with pytest.raises(ValueError, match="main branch"):
        promotion.main(["verify-environment"])


@pytest.mark.parametrize("app_id", [0, -1, 15368])
def test_generic_actions_issuer_cannot_be_required_promotion_app(app_id):
    with pytest.raises(ValueError, match="dedicated"):
        controls.ruleset_payload(promotion_app_id=app_id)
