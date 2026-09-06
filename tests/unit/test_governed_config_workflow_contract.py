"""Bind governed config readers to the actual service scaffold workflow callers."""

import json
from dataclasses import replace
from pathlib import Path

import pytest
import yaml
from pulumi.runtime.stack import wait_for_rpcs
from pulumi.runtime.sync_await import _sync_await
from test_ci_config_trust_review import PREFIX
from test_governance_repo_component import (
    _build_repo_governance,
    _governance_settings,
    _no_existing_resources,
    _synthetic_repo,
)


def template_callers():
    root = Path(__file__).resolve().parents[2]
    directory = root / "pulumi/user-service-infrastructure/.github/workflows"
    callers = []
    for path in sorted(directory.glob("*.yml")):
        document = yaml.safe_load(path.read_text())
        for job in document.get("jobs", {}).values():
            for step in job.get("steps", []):
                if "load-aws-ci-env" not in step.get("uses", ""):
                    continue
                suffix = step["with"]["environment"]
                if suffix == "${{ inputs.environment }}":
                    event = document.get("on", document.get(True))
                    suffixes = event["workflow_dispatch"]["inputs"]["environment"][
                        "options"
                    ]
                    assert suffixes == ["test", "prod"]
                else:
                    suffixes = [suffix]
                callers.extend((selected, document["name"]) for selected in suffixes)
    assert len(callers) == 8
    assert set(callers) == {
        ("test", "Service Self Deploy"),
        ("prod-preview", "Service Self Deploy"),
        ("prod", "Service Self Deploy"),
        ("test", "Initialize Service Stack"),
        ("prod", "Initialize Service Stack"),
    }
    return callers


@pytest.mark.parametrize("environment", ["test", "prod"])
def test_actual_governed_readers_allow_template_calls_with_service_identity(
    pulumi_mocks, monkeypatch, environment
):
    _no_existing_resources(monkeypatch)
    repo = replace(
        _synthetic_repo(),
        default_branch="release",
        repository_id="2222222222",
        repository_owner_id="333333333",
    )
    start = len(pulumi_mocks.resources)
    _build_repo_governance(
        "workflow-contract", repo=repo, settings=_governance_settings(environment)
    )
    _sync_await(wait_for_rpcs())
    roles = {
        state["tags"]["CiConfigSuffix"]: state
        for kind, _name, state in pulumi_mocks.resources[start:]
        if kind == "aws:iam/role:Role"
        and state.get("tags", {}).get("Purpose") == "github-ci-configuration-read"
    }
    assert set(roles) == (
        {"test-pr", "test"} if environment == "test" else {"prod-preview", "prod"}
    )
    for suffix, role in roles.items():
        condition = json.loads(role["assumeRolePolicy"])["Statement"][0]["Condition"][
            "StringEquals"
        ]
        assert (
            condition[PREFIX + "repository"]
            == "VilnaCRM-Org/user-service-infrastructure"
        )
        assert condition[PREFIX + "repository_id"] == repo.repository_id
        assert condition[PREFIX + "repository_owner_id"] == repo.repository_owner_id
        if suffix != "test-pr":
            assert condition[PREFIX + "ref"] == "refs/heads/release"
            assert set(condition[PREFIX + "workflow"]) == {
                name for selected, name in template_callers() if selected == suffix
            }
            assert "Pulumi Production" not in condition[PREFIX + "workflow"]
        else:
            assert PREFIX + "ref" not in condition
            assert condition[PREFIX + "workflow"] == [
                "Pulumi PR Guardrails",
                "Well-Architected Evidence",
            ]
