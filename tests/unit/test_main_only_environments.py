"""Reject deployment environment configurations that expose privileged credentials."""

from __future__ import annotations

import importlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
controls = importlib.import_module("_github_repository_controls")
preflight = importlib.import_module("pulumi_command_preflight")
configure = importlib.import_module("configure_github_repository_controls")
evidence = importlib.import_module("_well_architected_github_repository_evidence")


def environment():
    """Return a protected environment with independently fetched branch rules."""
    return {
        "prevent_self_review": True,
        "reviewers": [{"type": "User", "id": 10}],
        "can_admins_bypass": False,
        "deployment_branch_policy": {
            "protected_branches": False,
            "custom_branch_policies": True,
        },
        "deployment_branch_policies": [{"name": "main", "type": "branch"}],
    }


@pytest.mark.parametrize(
    "policies",
    [
        None,
        {},
        [],
        [None],
        [{}],
        [{"name": "main"}],
        [{"name": "main", "type": "tag"}],
        [{"name": "*", "type": "branch"}],
        [{"name": "main*", "type": "branch"}],
        [{"name": "refs/heads/main", "type": "branch"}],
        [{"name": "main", "type": "branch"}, {"name": "dev", "type": "branch"}],
    ],
)
def test_rejects_missing_malformed_tag_and_wildcard_branch_rules(policies):
    payload = environment()
    payload["deployment_branch_policies"] = policies
    assert controls.protected_environment_verification_blockers(
        payload, 10, label="test"
    ) == ["test does not allow only the main branch."]


def test_rejects_protected_only_mode_even_with_a_main_rule():
    payload = environment()
    payload["deployment_branch_policy"] = {
        "protected_branches": True,
        "custom_branch_policies": False,
    }
    assert controls.protected_environment_verification_blockers(
        payload, 10, label="test"
    ) == ["test does not allow only the main branch."]


@pytest.mark.parametrize("bypass", [None, True, "false"])
def test_rejects_missing_or_enabled_administrator_bypass(bypass):
    payload = environment()
    payload["can_admins_bypass"] = bypass
    assert controls.protected_environment_verification_blockers(
        payload, 10, label="test"
    ) == ["test allows administrator bypass."]


@pytest.mark.parametrize("branch_response", [None, [], {}, {"branch_policies": []}])
def test_comment_preflight_requires_independently_readable_main_rule(
    monkeypatch, branch_response
):
    monkeypatch.setenv("GITHUB_REPOSITORY", "org/repo")

    def api(path):
        if path == "users/Kravalg":
            return {"id": 10}
        if path.endswith("/deployment-branch-policies"):
            return branch_response
        return environment()

    monkeypatch.setattr(preflight, "gh", api)
    with pytest.raises(ValueError):
        preflight.verify_environments(
            {"command": "plan", "target_environment": "test"}, governance=False
        )


def test_branch_rule_convergence_removes_tags_and_wildcards(monkeypatch):
    calls = []
    endpoint = "repos/org/repo/environments/test"

    def api(args, **kwargs):
        calls.append((args, kwargs))
        return {
            "branch_policies": [
                {"id": 1, "name": "main", "type": "branch"},
                {"id": 2, "name": "main", "type": "tag"},
                {"id": 3, "name": "*", "type": "branch"},
            ]
        }

    monkeypatch.setattr(configure, "_run_gh_api", api)
    configure._configure_main_branch_policy(endpoint)
    assert [call[0] for call in calls] == [
        [f"{endpoint}/deployment-branch-policies"],
        [f"{endpoint}/deployment-branch-policies/2", "--method", "DELETE"],
        [f"{endpoint}/deployment-branch-policies/3", "--method", "DELETE"],
    ]


def test_branch_rule_convergence_rejects_malformed_response(monkeypatch):
    monkeypatch.setattr(configure, "_run_gh_api", lambda *args: [])
    with pytest.raises(ValueError, match="must be an object"):
        configure._configure_main_branch_policy("repos/org/repo/environments/test")


@pytest.mark.parametrize("returncode,payload", [(1, {}), (0, []), (0, {})])
def test_evidence_rejects_unreadable_branch_rules_even_with_environment_metadata(
    returncode, payload
):
    """Only a successful independent branch-rule response proves restriction."""

    def runner(command, **_kwargs):
        if command[-1].endswith("/deployment-branch-policies"):
            return subprocess.CompletedProcess(
                command, returncode, json.dumps(payload), ""
            )
        return subprocess.CompletedProcess(command, 0, json.dumps(environment()), "")

    result = evidence.github_production_environment(
        "org/repo", "prod", reviewer_login=None, runner=runner
    )
    assert result["status"] == "failed"
    assert result["evidence"]["mainBranchOnly"] is False
    assert any("limited to the main branch" in item for item in result["blockers"])
