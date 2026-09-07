"""Security regressions for pinned identities across all OIDC trust builders."""

import importlib
import json
import runpy
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from infra import automation, ci_bootstrap, ci_config, governance_automation
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
    args = governance_automation.GovernanceAutomationArgs(
        settings=cfg,
        repositories=[],
        account_id=ACCOUNT,
        region="eu-central-1",
        provider_arn=PROVIDER,
        backend_url="s3://backend/governance",
        secrets_provider="awskms://alias/pulumi-platform-bootstrap-test?region=eu-central-1",
    )
    for purpose in ("preview", "drift", "apply"):
        result["governor-" + purpose] = governance_automation.governance_trust_policy(
            args, purpose, PROVIDER
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
        "governor-preview",
        "governor-drift",
        "governor-apply",
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


@pytest.mark.parametrize("project", ["github-ci-bootstrap", "governance"])
@pytest.mark.parametrize("missing", ["githubRepositoryId", "githubRepositoryOwnerId"])
def test_live_entrypoints_require_identity_before_any_resource(
    monkeypatch, project, missing
):
    required = []

    def require(key):
        required.append(key)
        if key == missing:
            raise ValueError("missing pinned identity")
        return "12345"

    cfg = SimpleNamespace(require=require)
    infra = SimpleNamespace(
        BootstrapSettings=BootstrapSettings,
        GitHubCiBootstrap=None,
        GitHubCiBootstrapArgs=None,
        GovernanceStack=None,
        GovernanceStackArgs=None,
        ManagedRepositoryCatalog=None,
    )
    modules = {
        "pulumi": SimpleNamespace(Config=lambda: cfg),
        "infra": infra,
        "pulumi_aws": SimpleNamespace(),
    }
    monkeypatch.setattr(importlib, "import_module", modules.__getitem__)
    with pytest.raises(ValueError, match="missing pinned identity"):
        runpy.run_path(
            str(Path(__file__).parents[2] / "pulumi" / project / "__main__.py")
        )
    assert missing in required


@pytest.mark.parametrize("project", ["github-ci-bootstrap", "governance"])
@pytest.mark.parametrize("missing", ["repository_id", "repository_owner_id"])
def test_live_entrypoints_reject_unpinned_catalog_before_allocating(
    monkeypatch, project, missing
):
    repository = SimpleNamespace(repository_id="123", repository_owner_id="456")
    setattr(repository, missing, None)
    cfg = SimpleNamespace(
        require=lambda key: "123456789012",
        get=lambda key: None,
        get_bool=lambda key: None,
    )
    catalog = SimpleNamespace(repositories=[repository])

    def allocate(*args, **kwargs):
        pytest.fail("No resource may be allocated for an unpinned catalog")

    modules = {
        "pulumi": SimpleNamespace(Config=lambda: cfg),
        "infra": SimpleNamespace(
            BootstrapSettings=SimpleNamespace(
                from_pulumi_config=lambda cfg: settings()
            ),
            GitHubCiBootstrap=allocate,
            GitHubCiBootstrapArgs=lambda **kwargs: kwargs,
            GovernanceStack=allocate,
            GovernanceStackArgs=lambda **kwargs: kwargs,
            ManagedRepositoryCatalog=SimpleNamespace(
                from_settings=lambda *args: catalog,
                load_from_json_file=lambda path: [repository],
            ),
        ),
        "pulumi_aws": SimpleNamespace(
            get_caller_identity=lambda: SimpleNamespace(account_id=ACCOUNT)
        ),
        "infra.governance_automation": governance_automation,
    }
    monkeypatch.setattr(importlib, "import_module", modules.__getitem__)
    with pytest.raises(ValueError, match="require pinned GitHub IDs"):
        runpy.run_path(
            str(Path(__file__).parents[2] / "pulumi" / project / "__main__.py")
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


GOVERNANCE_ACCOUNTS = {"test": "891377212104", "prod": "933245420672"}
GOVERNANCE_PURPOSES = ("preview", "drift", "apply")


def governance_conditions(account, purpose):
    number = GOVERNANCE_ACCOUNTS[account]
    provider = (
        f"arn:aws:iam::{number}:oidc-provider/token.actions.githubusercontent.com"
    )
    config = replace(settings(), environment=account, github_oidc_provider_arn=provider)
    args = governance_automation.GovernanceAutomationArgs(
        settings=config,
        repositories=[],
        account_id=number,
        region="eu-central-1",
        provider_arn=provider,
        backend_url=f"s3://state-{account}/governance",
        secrets_provider=f"awskms://alias/pulumi-platform-bootstrap-{account}?region=eu-central-1",
    )
    document = json.loads(
        governance_automation.governance_trust_policy(args, purpose, provider)
    )
    assert document["Statement"][0]["Principal"] == {"Federated": provider}
    assert len(json.dumps(document, separators=(",", ":"))) <= 2048
    return document["Statement"][0]["Condition"]["StringEquals"]


def governance_token(account, purpose, immutable):
    """Model caller/callee claims from actual installed workflow declarations."""
    root = Path(__file__).resolve().parents[2]
    caller = yaml.safe_load(
        (root / ".github/workflows/pulumi-pr-command-runner.yml").read_text()
    )
    worker_path = ".github/workflows/pulumi-governance-account.yml"
    worker = yaml.safe_load((root / worker_path).read_text())
    job_name = {"preview": "preview", "apply": "apply", "drift": "post_apply_drift"}[
        purpose
    ]
    expression = worker["jobs"][job_name]["environment"]
    prefix, suffix = "${{ format('", "', inputs.account) }}"
    assert expression.startswith(prefix) and expression.endswith(suffix)
    environment = expression[len(prefix) : -len(suffix)].format(account)
    repository_subject = (
        f"VilnaCRM-Org@{IDS['owner_id']}/bootstrap-infrastructure@{IDS['repository_id']}"
        if immutable
        else REPO
    )
    prefix = "token.actions.githubusercontent.com:"
    return {
        prefix + "aud": "sts.amazonaws.com",
        prefix + "sub": f"repo:{repository_subject}:environment:{environment}",
        prefix + "repository": REPO,
        prefix + "repository_id": IDS["repository_id"],
        prefix + "repository_owner_id": IDS["owner_id"],
        prefix + "workflow": caller["name"],
        prefix + "ref": "refs/heads/main",
        prefix + "environment": environment,
        prefix + "job_workflow_ref": f"{REPO}/{worker_path}@refs/heads/main",
    }


@pytest.mark.parametrize("role_account", GOVERNANCE_ACCOUNTS)
@pytest.mark.parametrize("role_purpose", GOVERNANCE_PURPOSES)
@pytest.mark.parametrize("token_account", GOVERNANCE_ACCOUNTS)
@pytest.mark.parametrize("token_purpose", GOVERNANCE_PURPOSES)
@pytest.mark.parametrize("immutable", [False, True])
def test_governance_account_purpose_matrix(
    role_account, role_purpose, token_account, token_purpose, immutable
):
    trust = governance_conditions(role_account, role_purpose)
    claims = governance_token(token_account, token_purpose, immutable)
    assert matches(trust, claims) is (
        (role_account, role_purpose) == (token_account, token_purpose)
    )


@pytest.mark.parametrize("account", GOVERNANCE_ACCOUNTS)
@pytest.mark.parametrize("purpose", GOVERNANCE_PURPOSES)
@pytest.mark.parametrize("immutable", [False, True])
@pytest.mark.parametrize("environment", ["governance", "governance-preview"])
def test_shared_governance_subjects_are_retired(
    account, purpose, immutable, environment
):
    trust = governance_conditions(account, purpose)
    claims = governance_token(account, purpose, immutable)
    prefix = "token.actions.githubusercontent.com:"
    claims[prefix + "sub"] = (
        claims[prefix + "sub"].split(":environment:")[0] + ":environment:" + environment
    )
    # Even retaining the expected separate environment claim cannot rescue a
    # legacy shared subject. There is no compatibility Allow for old tokens.
    assert not matches(trust, claims)


@pytest.mark.parametrize("account", GOVERNANCE_ACCOUNTS)
@pytest.mark.parametrize("purpose", GOVERNANCE_PURPOSES)
@pytest.mark.parametrize(
    "claim,value",
    [
        ("workflow", "Pulumi Governance Runner"),
        ("workflow", "Pulumi Governance Account"),
        ("ref", "refs/pull/1/merge"),
        ("ref", "refs/heads/feature"),
        ("job_workflow_ref", None),
        (
            "job_workflow_ref",
            f"{REPO}/.github/workflows/pulumi-governance-account.yml@refs/heads/feature",
        ),
        ("job_workflow_ref", f"{REPO}/.github/workflows/foreign.yml@refs/heads/main"),
        (
            "job_workflow_ref",
            "foreign/repository/.github/workflows/pulumi-governance-account.yml@refs/heads/main",
        ),
        ("environment", "governance"),
        ("environment", "governance-preview"),
    ],
)
def test_governance_caller_and_callee_are_exact(account, purpose, claim, value):
    trust = governance_conditions(account, purpose)
    claims = governance_token(account, purpose, True)
    key = "token.actions.githubusercontent.com:" + claim
    if value is None:
        del claims[key]
    else:
        claims[key] = value
    assert not matches(trust, claims)
    # AWS's documented reusable key is job_workflow_ref, not workflow_ref.
    assert "token.actions.githubusercontent.com:workflow_ref" not in trust
