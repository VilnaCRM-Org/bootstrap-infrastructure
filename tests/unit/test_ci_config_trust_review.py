"""Config-read trust regressions for review comments 3942446541 and 3942446514."""

import json
from dataclasses import replace
from pathlib import Path

import pytest
import yaml
from infra import ci_config
from test_secret_read_deny import _settings

PREFIX = "token.actions.githubusercontent.com:"
PROVIDER = "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
WORKFLOWS = {
    "test-pr": ["Pulumi PR Guardrails", "Well-Architected Evidence"],
    "test": [
        "Pulumi PR Guardrails",
        "Pulumi Test Deploy",
        "Nightly Guardrails",
        "Pulumi PR Command Runner",
        "Operations Alert Issue Triage",
        "Well-Architected Evidence",
    ],
    "prod-preview": [
        "Pulumi Production",
        "Nightly Guardrails",
        "Pulumi PR Command Runner",
    ],
    "prod": ["Pulumi Production", "Pulumi PR Command Runner"],
}


def scoped_settings(environment="test"):
    return replace(
        _settings(environment),
        repo="service-infrastructure",
        github_branch="release",
        github_repository_id="2222222222",
        github_repository_owner_id="333333333",
    )


def conditions(settings, suffix, repo=None, **kwargs):
    return json.loads(
        ci_config._ci_config_read_assume_role_policy(
            PROVIDER, settings, suffix, repo, **kwargs
        )
    )["Statement"][0]["Condition"]["StringEquals"]


def matches(condition, claims):
    return all(
        claims.get(key) in (value if isinstance(value, list) else [value])
        for key, value in condition.items()
    )


@pytest.mark.parametrize("environment", ["test", "prod"])
@pytest.mark.parametrize("suffix", WORKFLOWS)
def test_workflow_conjunct_preserves_repository_identity_and_context(
    environment, suffix
):
    settings = scoped_settings(environment)
    condition = conditions(settings, suffix, settings.repo)
    assert condition[PREFIX + "workflow"] == WORKFLOWS[suffix]
    assert condition[PREFIX + "repository"] == "VilnaCRM-Org/service-infrastructure"
    assert condition[PREFIX + "repository_id"] == "2222222222"
    assert condition[PREFIX + "repository_owner_id"] == "333333333"
    assert condition[PREFIX + "aud"] == "sts.amazonaws.com"
    assert all("*" not in subject for subject in condition[PREFIX + "sub"])
    claims = {
        key: value[0] if isinstance(value, list) else value
        for key, value in condition.items()
    }
    for workflow in WORKFLOWS[suffix]:
        for subject in condition[PREFIX + "sub"]:
            assert matches(
                condition,
                {**claims, PREFIX + "workflow": workflow, PREFIX + "sub": subject},
            )
    assert not matches(condition, {**claims, PREFIX + "workflow": "Other workflow"})
    assert not matches(
        condition,
        {key: value for key, value in claims.items() if key != PREFIX + "workflow"},
    )
    for key in ("repository", "repository_id", "repository_owner_id", "aud", "sub"):
        assert not matches(condition, {**claims, PREFIX + key: "foreign"})
    if suffix == "test-pr":
        assert PREFIX + "ref" not in condition
        assert all(
            subject.endswith(":pull_request") for subject in condition[PREFIX + "sub"]
        )
        assert matches(condition, {**claims, PREFIX + "ref": "refs/pull/123/merge"})
    else:
        assert condition[PREFIX + "ref"] == "refs/heads/release"
        assert not matches(condition, {**claims, PREFIX + "ref": "refs/heads/main"})
        assert not any(
            subject.endswith(":pull_request") for subject in condition[PREFIX + "sub"]
        )


@pytest.mark.parametrize("repo", [None, "service-infrastructure"])
def test_matching_or_default_repository_uses_identical_scoped_claims(repo):
    settings = scoped_settings()
    assert conditions(settings, "test", repo) == conditions(
        settings, "test", settings.repo
    )


def test_mismatched_trust_override_requires_scoped_settings():
    with pytest.raises(ValueError, match="repository-scoped settings"):
        conditions(_settings(), "test", "service-infrastructure")
    assert (
        ci_config._ci_config_project(_settings(), "service-infrastructure")
        == "service-infrastructure"
    )
    assert (
        ci_config._ci_secret_id(_settings(), "test", "service-infrastructure")
        == "/service-infrastructure/ci/test"
    )


def test_mismatched_component_override_fails_before_registration_or_invokes(
    monkeypatch,
):
    def forbidden(*args, **kwargs):
        raise AssertionError("invalid identity reached Pulumi or provider")

    monkeypatch.setattr(ci_config.pulumi.ComponentResource, "__init__", forbidden)
    monkeypatch.setattr(ci_config.aws, "get_caller_identity", forbidden)
    monkeypatch.setattr(ci_config.aws, "get_partition", forbidden)
    monkeypatch.setattr(ci_config.aws.iam, "Role", forbidden)
    monkeypatch.setattr(ci_config.aws.secretsmanager, "Secret", forbidden)
    with pytest.raises(ValueError, match="repository-scoped settings"):
        ci_config.CiConfiguration(
            "invalid",
            args=ci_config.CiConfigurationArgs(
                settings=_settings(),
                repo="service-infrastructure",
                oidc_provider_arn=PROVIDER,
            ),
        )


def test_current_loader_workflow_names_are_in_the_fixed_suffix_lists():
    root = Path(__file__).resolve().parents[2]
    checked = 0
    for path in (root / ".github/workflows").glob("*.yml"):
        workflow = yaml.safe_load(path.read_text())
        for job in workflow.get("jobs", {}).values():
            for step in job.get("steps", []):
                if "load-aws-ci-env" not in step.get("uses", ""):
                    continue
                suffix = step["with"]["environment"]
                suffixes = (
                    ["test-pr", "test"]
                    if suffix == "${{ steps.ci_config_target.outputs.environment }}"
                    else [suffix]
                )
                for selected in suffixes:
                    assert (
                        workflow["name"]
                        in conditions(_settings(), selected)[PREFIX + "workflow"]
                    )
                checked += 1
    assert checked > 0


@pytest.mark.parametrize(
    "suffix,expected",
    [
        ("test", ["Service Self Deploy", "Initialize Service Stack"]),
        ("prod-preview", ["Service Self Deploy"]),
        ("prod", ["Service Self Deploy", "Initialize Service Stack"]),
        ("test-pr", WORKFLOWS["test-pr"]),
    ],
)
def test_service_workflows_require_explicit_scope_and_preserve_platform_lists(
    suffix, expected
):
    settings = scoped_settings()
    platform = conditions(settings, suffix)
    service = conditions(settings, suffix, governed_service_workflows=True)
    assert platform[PREFIX + "workflow"] == WORKFLOWS[suffix]
    assert service.pop(PREFIX + "workflow") == expected
    del platform[PREFIX + "workflow"]
    assert service == platform
    assert ci_config.CiConfigurationArgs().governed_service_workflows is False
