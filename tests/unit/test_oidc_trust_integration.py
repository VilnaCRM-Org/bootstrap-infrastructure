"""Security regressions for pinned identities across all OIDC trust builders."""

import json
from types import SimpleNamespace

import pytest
from infra import automation, ci_bootstrap, ci_config
from infra.bootstrap_settings import BootstrapSettings
from infra.iam import github_oidc

ACCOUNT = "123456789012"
PROVIDER = f"arn:aws:iam::{ACCOUNT}:oidc-provider/token.actions.githubusercontent.com"
REPO = "VilnaCRM-Org/bootstrap-infrastructure"
IDS = {"repository_id": "1098568429", "owner_id": "114362548"}


def settings():
    return BootstrapSettings(
        org="VilnaCRM-Org",
        repo="bootstrap-infrastructure",
        environment="test",
        owner="platform",
        cost_center="core",
        data_classification="internal",
        criticality="high",
        retention_class="standard",
        github_branch="main",
        logging_prefix="company",
        replication_region=None,
        github_token=None,
        github_oidc_provider_arn=PROVIDER,
        github_repository_id=IDS["repository_id"],
        github_repository_owner_id=IDS["owner_id"],
    )


def condition(document):
    return json.loads(document)["Statement"][0]["Condition"]["StringEquals"]


def matches(conditions, claims):
    return all(
        claims.get(key) in (value if isinstance(value, list) else [value])
        for key, value in conditions.items()
    )


def documents():
    cfg = settings()
    result = {}
    for purpose in ("preview", "drift", "apply"):
        result[purpose] = ci_bootstrap._deployment_assume_role_policy(
            PROVIDER,
            REPO,
            ci_bootstrap._deployment_role_subjects(cfg, purpose),
            **IDS,
            branch_ref=None if purpose == "preview" else "refs/heads/main",
        )
    for suffix in ("test-pr", "test", "prod-preview", "prod"):
        result["config-" + suffix] = ci_config._ci_config_read_assume_role_policy(
            PROVIDER, cfg, suffix
        )
    result["automation"] = automation._automation_assume_role_policy(
        PROVIDER, cfg.org, cfg.repo, "test", "main", **IDS
    )
    result["triage"] = automation._operations_alert_triage_assume_role_policy(
        PROVIDER, cfg.org, cfg.repo, "main", **IDS
    )
    result["legacy"] = github_oidc._assume_role_policy_for_repo(
        PROVIDER, cfg.org, cfg.repo, "main", environment="test", **IDS
    )
    return result


@pytest.mark.parametrize(
    "name",
    [
        "preview",
        "drift",
        "apply",
        "config-test-pr",
        "config-test",
        "config-prod-preview",
        "config-prod",
        "automation",
        "triage",
        "legacy",
    ],
)
def test_all_role_trusts_pin_ids_and_exact_subject_formats(name):
    conditions = condition(documents()[name])
    assert (
        conditions["token.actions.githubusercontent.com:repository_id"]
        == IDS["repository_id"]
    )
    assert (
        conditions["token.actions.githubusercontent.com:repository_owner_id"]
        == IDS["owner_id"]
    )
    assert conditions["token.actions.githubusercontent.com:repository"] == REPO
    assert (
        "StringLike" not in json.loads(documents()[name])["Statement"][0]["Condition"]
    )
    subjects = conditions["token.actions.githubusercontent.com:sub"]
    assert len(subjects) >= 2
    assert all("*" not in subject and "?" not in subject for subject in subjects)
    claims = {
        key: value[0] if isinstance(value, list) else value
        for key, value in conditions.items()
    }
    for subject in subjects:
        assert matches(
            conditions, {**claims, "token.actions.githubusercontent.com:sub": subject}
        )
    for key in ("repository_id", "repository_owner_id", "repository", "aud", "sub"):
        assert not matches(
            conditions,
            {**claims, f"token.actions.githubusercontent.com:{key}": "attacker"},
        )
    if name in {"preview", "config-test-pr"}:
        assert "token.actions.githubusercontent.com:ref" not in conditions
    else:
        assert (
            conditions["token.actions.githubusercontent.com:ref"] == "refs/heads/main"
        )
        assert not matches(
            conditions,
            {**claims, "token.actions.githubusercontent.com:ref": "refs/pull/1/merge"},
        )


def test_automation_apply_only_accepts_its_account_environment():
    for environment in ("test", "prod"):
        trust = condition(
            automation._automation_assume_role_policy(
                PROVIDER,
                "VilnaCRM-Org",
                "bootstrap-infrastructure",
                environment,
                "main",
                **IDS,
            )
        )
        assert all(
            subject.endswith(f":environment:{environment}")
            for subject in trust["token.actions.githubusercontent.com:sub"]
        )


@pytest.mark.parametrize("environment", ["test", "prod"])
def test_legacy_deploy_requires_protected_environment_and_main(environment):
    trust = condition(
        github_oidc._assume_role_policy_for_repo(
            PROVIDER,
            "VilnaCRM-Org",
            "bootstrap-infrastructure",
            "main",
            environment=environment,
            **IDS,
        )
    )
    claims = {
        key: value[0] if isinstance(value, list) else value
        for key, value in trust.items()
    }
    subject_key = "token.actions.githubusercontent.com:sub"
    assert trust[subject_key] == [
        f"repo:{REPO}:environment:{environment}",
        f"repo:VilnaCRM-Org@{IDS['owner_id']}/bootstrap-infrastructure@{IDS['repository_id']}:environment:{environment}",
    ]
    for subject in trust[subject_key]:
        assert matches(trust, {**claims, subject_key: subject})
    for subject in (
        f"repo:{REPO}:ref:refs/heads/main",
        f"repo:VilnaCRM-Org@{IDS['owner_id']}/bootstrap-infrastructure@{IDS['repository_id']}:ref:refs/heads/main",
        f"repo:{REPO}:environment:{'prod' if environment == 'test' else 'test'}",
        f"repo:attacker/bootstrap-infrastructure:environment:{environment}",
    ):
        assert not matches(trust, {**claims, subject_key: subject})
    assert not matches(
        trust,
        {**claims, "token.actions.githubusercontent.com:ref": "refs/pull/1/merge"},
    )


def test_existing_legacy_role_is_imported_with_catalog_identity(monkeypatch):
    captured = {}
    monkeypatch.setattr(github_oidc, "_role_exists", lambda name: True)
    monkeypatch.setattr(
        github_oidc, "apply_output", lambda value, callback: callback(value)
    )
    monkeypatch.setattr(
        github_oidc.aws.iam,
        "Role",
        lambda resource_name, **kwargs: captured.update(kwargs),
    )
    component = SimpleNamespace(
        provider=SimpleNamespace(arn=PROVIDER),
        _settings=settings(),
        _manage_roles=True,
        _permissions_boundary=None,
    )
    context = github_oidc._DeployRoleContext(
        "component",
        "bootstrap-infrastructure",
        "bootstrap-infrastructure",
        "main",
        "platform-bootstrap",
        {},
        IDS["repository_id"],
        IDS["owner_id"],
    )
    github_oidc.GitHubOidcRoles._deploy_role_resource(component, context)
    assert captured["opts"].import_ == "PulumiDeploy-bootstrap-infrastructure"
    assert (
        condition(captured["assume_role_policy"])[
            "token.actions.githubusercontent.com:repository_id"
        ]
        == IDS["repository_id"]
    )
