"""Delegated governance cannot escape its immutable service boundaries."""

from __future__ import annotations

import dataclasses
import fnmatch
import importlib
import json
import runpy
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from infra.bootstrap_settings import BootstrapSettings
from infra.governance_automation import (
    GovernanceAutomation,
    GovernanceAutomationArgs,
    _document,
    assert_bootstrap_account,
    governance_backend_policy,
    governance_repo_iam_policy,
    governance_repo_storage_policy,
    governance_trust_policy,
    service_boundary_policy,
)
from infra.managed_repository import ManagedRepository
from infra.utils.outputs import future_output
from pulumi.runtime.stack import wait_for_rpcs
from pulumi.runtime.sync_await import _sync_await

ACCOUNT = "123456789012"
PROVIDER = f"arn:aws:iam::{ACCOUNT}:oidc-provider/token.actions.githubusercontent.com"
REPO = ManagedRepository(
    name="user-service-infrastructure",
    default_branch="main",
    project="user-service-infrastructure",
    repository_id="911736693",
    repository_owner_id="114362548",
)


@pytest.mark.parametrize(
    "expected", [None, "", "123", "1234567890123", "１２３４５６７８９０１２"]
)
def test_bootstrap_account_config_is_required_and_ascii(expected):
    with pytest.raises(ValueError, match="12-digit awsAccountId"):
        assert_bootstrap_account(expected, ACCOUNT)


def test_bootstrap_account_mismatch_fails():
    with pytest.raises(ValueError, match="account mismatch"):
        assert_bootstrap_account(ACCOUNT, "999999999999")
    assert_bootstrap_account(ACCOUNT, ACCOUNT)


@pytest.mark.parametrize(
    "expected,actual",
    [
        (None, ACCOUNT),
        (ACCOUNT, "999999999999"),
        (ACCOUNT, ACCOUNT),
    ],
)
@pytest.mark.parametrize("missing_catalog", [None, "governance", "bootstrap"])
def test_entrypoint_asserts_account_before_first_resource(
    monkeypatch, expected, actual, missing_catalog
):
    allocated = []

    def require(key):
        if key in {"githubRepositoryId", "githubRepositoryOwnerId"}:
            return "12345"
        assert key == "awsAccountId"
        if expected is None:
            raise ValueError("missing required awsAccountId")
        return expected

    def allocate(*args, **kwargs):
        allocated.append((args, kwargs))
        raise RuntimeError("reached first resource allocation")

    config = SimpleNamespace(
        require=require, get_bool=lambda key: None, get=lambda key: None
    )
    modules = {
        "pulumi": SimpleNamespace(Config=lambda: config),
        "pulumi_aws": SimpleNamespace(
            get_caller_identity=lambda: SimpleNamespace(account_id=actual),
            get_region=lambda: SimpleNamespace(region="eu-central-1"),
            get_partition=lambda: SimpleNamespace(partition="aws"),
        ),
        "infra": SimpleNamespace(
            BootstrapSettings=SimpleNamespace(
                from_pulumi_config=lambda cfg: dataclasses.replace(
                    inputs().settings,
                    github_repository_id=REPO.repository_id,
                    github_repository_owner_id=REPO.repository_owner_id,
                )
            ),
            GitHubCiBootstrap=allocate,
            GitHubCiBootstrapArgs=lambda **kwargs: kwargs,
            ManagedRepositoryCatalog=SimpleNamespace(
                load_from_json_file=lambda path: [
                    dataclasses.replace(
                        REPO, repository_id=None, repository_owner_id=None
                    )
                    if missing_catalog
                    and f"repositories.{missing_catalog}.json" in path
                    else dataclasses.replace(REPO, name="bootstrap-infrastructure")
                    if "repositories.bootstrap.json" in path
                    else REPO
                ]
            ),
        ),
        "infra.governance_automation": SimpleNamespace(
            assert_bootstrap_account=assert_bootstrap_account
        ),
        "infra.platform_iam": SimpleNamespace(PlatformIamBoundaries=allocate),
        "infra.platform_control_iam": SimpleNamespace(),
    }
    monkeypatch.setattr(importlib, "import_module", modules.__getitem__)
    path = (
        Path(__file__).resolve().parents[2] / "pulumi/github-ci-bootstrap/__main__.py"
    )
    if expected is None or expected != actual or missing_catalog:
        with pytest.raises(ValueError):
            runpy.run_path(str(path))
        assert allocated == []
    else:
        with pytest.raises(RuntimeError, match="first resource"):
            runpy.run_path(str(path))
        assert len(allocated) == 1


@pytest.mark.parametrize("github_branch", [None, "main"])
@pytest.mark.parametrize("overrides", [False, True])
@pytest.mark.parametrize(
    "catalog_change",
    [
        None,
        "name",
        "repository_id",
        "repository_owner_id",
        "default_branch",
        "protection",
    ],
)
def test_entrypoint_wires_complete_bootstrap_and_governance(
    monkeypatch, overrides, catalog_change, github_branch
):
    """The operator entrypoint keeps account, provider, backend and outputs aligned."""
    environment = "prod" if overrides else "test"
    settings = dataclasses.replace(
        inputs(environment).settings,
        github_branch=github_branch,
        github_repository_id="12345",
        github_repository_owner_id="67890",
    )
    values = {
        "awsAccountId": ACCOUNT,
        "githubRepositoryId": "12345",
        "githubRepositoryOwnerId": "67890",
    }
    if overrides:
        values.update(
            pulumiBackendUrl="s3://operator-state/platform",
            pulumiDir="custom-pulumi",
            pulumiSecretsProvider="awskms://alias/custom-platform",
            governanceRepositoryCatalogPath="custom-catalog.json",
            governanceBackendUrl="s3://operator-state/governance",
            governanceSecretsProvider="awskms://alias/custom-governance",
            writeSecretValues=False,
            protectResources=True,
        )
    if catalog_change == "protection":
        values["protectResources"] = False
    config = SimpleNamespace(
        require=values.__getitem__,
        get=values.get,
        get_bool=values.get,
        get_object=values.get,
    )
    catalog = [REPO]
    catalog_paths = []
    allocations = {}
    exported = {}
    bootstrap = SimpleNamespace(
        oidc_provider_arn=PROVIDER,
        ci_configuration=SimpleNamespace(
            secret_ids={"test": "/bootstrap/ci/test"},
            read_role_arns={"test": "config-role"},
        ),
        role_arns={"preview": "preview-role", "apply": "apply-role"},
        operations_alert_triage_role=(
            None if overrides else SimpleNamespace(arn="triage-role")
        ),
        github_variables={"AWS_TEST_REGION": "eu-central-1"},
        secret_payload_keys={"test": ["AWS_ACCOUNT_ID"]},
        secret_versions=(
            {} if overrides else {"test": SimpleNamespace(version_id="version-id")}
        ),
    )
    governance = SimpleNamespace(
        github_variables={"AWS_GOVERNANCE_TEST_ACCOUNT_ID": ACCOUNT}
    )

    def allocate_bootstrap(name, *, args, opts):
        allocations[name] = args
        return bootstrap

    def allocate_governance(name, *, args):
        allocations[name] = args
        return governance

    def load_catalog(path):
        catalog_paths.append(path)
        if "repositories.bootstrap.json" in path:
            repository = dataclasses.replace(
                REPO,
                name=settings.repo,
                repository_id="12345",
                repository_owner_id="67890",
            )
            if catalog_change and catalog_change != "protection":
                repository = dataclasses.replace(
                    repository, **{catalog_change: "99999"}
                )
            return [repository]
        return catalog

    modules = {
        "pulumi": SimpleNamespace(
            Config=lambda: config,
            export=exported.__setitem__,
            ResourceOptions=lambda **kwargs: kwargs,
        ),
        "pulumi_aws": SimpleNamespace(
            get_caller_identity=lambda: SimpleNamespace(account_id=ACCOUNT),
            get_region=lambda: SimpleNamespace(region="eu-central-1"),
            get_partition=lambda: SimpleNamespace(partition="aws"),
        ),
        "infra": SimpleNamespace(
            BootstrapSettings=SimpleNamespace(from_pulumi_config=lambda cfg: settings),
            GitHubCiBootstrap=allocate_bootstrap,
            GitHubCiBootstrapArgs=lambda **kwargs: kwargs,
            ManagedRepositoryCatalog=SimpleNamespace(load_from_json_file=load_catalog),
        ),
        "infra.governance_automation": SimpleNamespace(
            assert_bootstrap_account=assert_bootstrap_account,
            GovernanceAutomation=allocate_governance,
            GovernanceAutomationArgs=lambda **kwargs: kwargs,
        ),
        "infra.platform_iam": SimpleNamespace(
            PlatformIamBoundaries=lambda name, **kw: (
                allocations.setdefault(name, kw)
                and SimpleNamespace(
                    policies={
                        purpose: SimpleNamespace(arn=f"{purpose}-boundary")
                        for purpose in (
                            "control",
                            "backup",
                            "state-replication",
                            "log-replication",
                        )
                    }
                )
            ),
            platform_boundary_arn=lambda *a, **kw: "control-boundary",
        ),
        "infra.platform_control_iam": SimpleNamespace(
            PlatformControlIam=lambda name, **kw: allocations.setdefault(name, kw),
        ),
    }
    root = Path(__file__).resolve().parents[2] / "pulumi"
    if overrides:
        monkeypatch.setattr(sys, "path", [p for p in sys.path if p != str(root)])
    monkeypatch.setattr(importlib, "import_module", modules.__getitem__)
    if catalog_change:
        with pytest.raises(
            ValueError,
            match=(
                "Platform catalog|GitHub IDs differ|"
                "default branches differ|protectResources=true"
            ),
        ):
            runpy.run_path(str(root / "github-ci-bootstrap/__main__.py"))
        assert allocations == {}
        assert exported == {}
        return
    runpy.run_path(str(root / "github-ci-bootstrap/__main__.py"))
    assert str(root) in sys.path
    bootstrap_args = allocations["github-ci-bootstrap"]
    assert bootstrap_args == {
        "settings": settings,
        "pulumi_backend_url": values.get("pulumiBackendUrl"),
        "pulumi_dir": "custom-pulumi" if overrides else "pulumi",
        "pulumi_secrets_provider": values.get("pulumiSecretsProvider"),
        "write_secret_values": not overrides,
        "protect_resources": True,
        "control_permissions_boundary": "control-boundary",
        "manage_oidc_provider": True,
    }
    assert allocations["platform-control-iam"]["provider_arn"] == PROVIDER
    assert (
        allocations["platform-control-iam"]["boundary_arns"]["control"]
        == "control-boundary"
    )
    assert allocations["platform-iam-boundaries"]["account_id"] == ACCOUNT
    assert catalog_paths == [
        "custom-catalog.json"
        if overrides
        else str(root / "repositories.governance.json"),
        str(root / "repositories.bootstrap.json"),
    ]
    assert allocations["governance-automation"] == {
        "settings": settings,
        "repositories": catalog,
        "account_id": ACCOUNT,
        "partition": "aws",
        "region": "eu-central-1",
        "provider_arn": PROVIDER,
        "backend_url": (
            values["governanceBackendUrl"]
            if overrides
            else f"s3://{settings.state_bucket_name()}/governance"
        ),
        "secrets_provider": (
            values["governanceSecretsProvider"]
            if overrides
            else "awskms://alias/pulumi-platform-bootstrap-test?region=eu-central-1"
        ),
        "protect_resources": True,
    }
    assert exported == {
        "governanceGithubVariables": governance.github_variables,
        "environment": environment,
        "oidcProviderArn": PROVIDER,
        "ciConfigurationSecretIds": bootstrap.ci_configuration.secret_ids,
        "githubCiConfigReadRoleArns": bootstrap.ci_configuration.read_role_arns,
        "githubCiDeploymentRoleArns": bootstrap.role_arns,
        "operationsAlertTriageRoleArn": None if overrides else "triage-role",
        "githubVariables": bootstrap.github_variables,
        "ciSecretPayloadKeys": bootstrap.secret_payload_keys,
        "ciSecretVersionIds": {} if overrides else {"test": "version-id"},
    }


def inputs(environment: str = "test", **overrides) -> GovernanceAutomationArgs:
    settings = BootstrapSettings(
        org="test-org",
        repo="bootstrap-infrastructure",
        environment=environment,
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
    )
    values = dict(
        settings=settings,
        repositories=[REPO],
        account_id=ACCOUNT,
        region="eu-central-1",
        provider_arn=PROVIDER,
        backend_url=f"s3://pulumi-bootstrap-infrastructure-{environment}-state/governance",
        secrets_provider=(
            f"awskms://alias/pulumi-platform-bootstrap-{environment}?region=eu-central-1"
        ),
    )
    values.update(overrides)
    return GovernanceAutomationArgs(**values)


def allows(document: str, action: str, resource: str) -> list[dict]:
    """Return matching Allows for inspection; never pretend to evaluate AWS context."""
    return [
        statement
        for statement in json.loads(document)["Statement"]
        if statement["Effect"] == "Allow"
        and any(
            fnmatch.fnmatchcase(action.lower(), pattern.lower())
            for pattern in statement["Action"]
        )
        and any(
            fnmatch.fnmatchcase(resource, pattern) for pattern in statement["Resource"]
        )
    ]


@pytest.mark.parametrize("environment", ["test", "prod"])
def test_backend_and_service_boundary_are_disjoint(environment):
    args = inputs(environment)
    backend = governance_backend_policy(args)
    boundary = service_boundary_policy(args, REPO)
    own_state = (
        f"arn:aws:s3:::pulumi-bootstrap-infrastructure-{environment}-state/"
        "governance/.pulumi/stacks/governance/test.json"
    )
    other_state = own_state.replace("/governance/", "/other/")
    service_state = (
        f"arn:aws:s3:::pulumi-user-service-infrastructure-{environment}-state/"
        ".pulumi/stacks/service/test.json"
    )
    assert allows(backend, "s3:PutObject", own_state)
    assert not allows(backend, "s3:PutObject", other_state)
    assert not allows(backend, "s3:GetObject", service_state)
    assert not allows(boundary, "s3:GetObject", own_state)
    assert allows(boundary, "s3:PutObject", service_state)
    assert not allows(boundary, "iam:CreateRole", f"arn:aws:iam::{ACCOUNT}:role/admin")
    service_key = [
        s for s in json.loads(boundary)["Statement"] if "kms:Decrypt" in s["Action"]
    ][0]
    aliases = service_key["Condition"]["ForAnyValue:StringEquals"][
        "kms:ResourceAliases"
    ]
    assert aliases == [
        f"alias/pulumi-user-service-infrastructure-{environment}-secrets"
    ]


@pytest.mark.parametrize("purpose", ["preview", "drift"])
def test_read_runners_write_only_locks(purpose):
    document = governance_backend_policy(inputs(), purpose=purpose)
    prefix = (
        "arn:aws:s3:::pulumi-bootstrap-infrastructure-test-state/governance/.pulumi"
    )
    assert allows(document, "s3:PutObject", f"{prefix}/locks/project/test/lock.json")
    assert not allows(document, "s3:PutObject", f"{prefix}/stacks/project/test.json")
    assert not allows(document, "s3:DeleteObjectVersion", f"{prefix}/locks/lock.json")
    denies = [s for s in json.loads(document)["Statement"] if s["Effect"] == "Deny"]
    assert denies == [
        {
            "Effect": "Deny",
            "Action": ["s3:PutObject", "s3:DeleteObject"],
            "NotResource": [f"{prefix}/locks/*"],
        },
        {
            "Effect": "Deny",
            "Action": ["s3:DeleteObjectVersion"],
            "Resource": "*",
        },
    ]


@pytest.mark.parametrize("purpose", ["preview", "drift", "apply"])
def test_trust_requires_repository_branch_workflow_and_environment(purpose):
    args = inputs()
    document = json.loads(governance_trust_policy(args, purpose, PROVIDER))
    conditions = document["Statement"][0]["Condition"]["StringEquals"]
    environment = "governance" if purpose == "apply" else "governance-preview"
    assert conditions["token.actions.githubusercontent.com:sub"] == [
        f"repo:test-org/bootstrap-infrastructure:environment:{environment}"
    ]
    assert conditions["token.actions.githubusercontent.com:aud"] == "sts.amazonaws.com"
    assert conditions["token.actions.githubusercontent.com:repository"] == (
        "test-org/bootstrap-infrastructure"
    )
    assert conditions["token.actions.githubusercontent.com:ref"] == "refs/heads/main"
    assert (
        conditions["token.actions.githubusercontent.com:workflow"]
        == "Pulumi Governance Runner"
    )
    assert "token.actions.githubusercontent.com:job_workflow_ref" not in conditions
    fallback = dataclasses.replace(
        args, settings=dataclasses.replace(args.settings, github_branch=None)
    )
    assert governance_trust_policy(
        fallback, purpose, PROVIDER
    ) == governance_trust_policy(args, purpose, PROVIDER)


def test_trust_rejects_unknown_purpose_and_wrong_account():
    with pytest.raises(ValueError, match="purpose"):
        governance_trust_policy(inputs(), "admin", PROVIDER)
    with pytest.raises(ValueError, match="target account"):
        governance_trust_policy(
            inputs(), "apply", PROVIDER.replace(ACCOUNT, "000000000000")
        )


@pytest.mark.parametrize(
    "url",
    [
        "file:///tmp/state",
        "s3:///governance",
        "s3://bucket",
        "s3://bucket/other",
        "s3://bucket/governance?x=1",
        "s3://bucket/governance#fragment",
        "s3://user@bucket/governance",
        "s3://bucket:123/governance",
        "s3://bucket/governance/",
        "s3://BUCKET/governance",
        "s3://ab/governance",
        "s3://" + "a" * 64 + "/governance",
        "s3://bucket_name/governance",
        "s3://bucket/governance%2F",
        "s3://bucket\\other/governance",
        " s3://bucket/governance",
        "s3://bucket/governance\n",
        "s3://[broken/governance",
    ],
)
def test_backend_rejects_ambient_or_shared_state(url):
    with pytest.raises(ValueError, match="governance backend"):
        governance_backend_policy(inputs(backend_url=url))


def test_backend_rejects_wrong_key_and_environment():
    with pytest.raises(ValueError, match="platform KMS"):
        governance_backend_policy(inputs(secrets_provider="awskms://alias/other"))
    with pytest.raises(ValueError, match="test and prod"):
        governance_backend_policy(inputs("dev"))


def test_governor_iam_cannot_edit_itself_boundaries_or_unrelated_roles():
    args = inputs()
    document = governance_repo_iam_policy(args, REPO, apply=True)
    role = f"arn:aws:iam::{ACCOUNT}:role/GitHubCiApply-user-service-infrastructure-test"
    assert allows(document, "iam:PutRolePolicy", role)
    expected_boundary = (
        f"arn:aws:iam::{ACCOUNT}:policy/"
        "GovernanceBoundary-user-service-infrastructure-test"
    )
    for action in (
        "iam:CreateRole",
        "iam:PutRolePolicy",
        "iam:AttachRolePolicy",
        "iam:PutRolePermissionsBoundary",
    ):
        matches = allows(document, action, role)
        assert matches
        assert all(
            s["Condition"]["StringEquals"]["iam:PermissionsBoundary"]
            == expected_boundary
            for s in matches
        )
    for protected_role in (
        "GitHubGovernanceApply-test",
        "GitHubCiApply-bootstrap-infrastructure-test",
        "GitHubCiApply-other-infrastructure-test",
    ):
        assert not allows(
            document,
            "iam:PutRolePolicy",
            f"arn:aws:iam::{ACCOUNT}:role/{protected_role}",
        )
    for action in (
        "iam:CreatePolicyVersion",
        "iam:DeletePolicy",
        "iam:SetDefaultPolicyVersion",
    ):
        assert not allows(document, action, expected_boundary)
    assert not allows(document, "iam:DeleteOpenIDConnectProvider", PROVIDER)
    assert not allows(document, "iam:CreateUser", "*")
    assert not allows(document, "iam:DeleteRolePermissionsBoundary", role)
    denies = [s for s in json.loads(document)["Statement"] if s["Effect"] == "Deny"]
    assert denies[0]["Action"] == ["iam:DeleteRolePermissionsBoundary"]
    replication = (
        f"arn:aws:iam::{ACCOUNT}:role/PulumiStateRepl-user-service-infrastructure-test"
    )
    passed = allows(document, "iam:PassRole", replication)
    assert (
        passed[0]["Condition"]["StringEquals"]["iam:PassedToService"]
        == "s3.amazonaws.com"
    )
    assert not allows(document, "iam:PassRole", role)


def test_read_roles_cannot_mutate_iam_or_storage():
    args = inputs()
    iam = governance_repo_iam_policy(args, REPO, apply=False)
    storage = governance_repo_storage_policy(args, REPO, apply=False)
    assert all(s["Effect"] == "Allow" for s in json.loads(iam)["Statement"])
    assert not allows(
        iam,
        "iam:PutRolePolicy",
        f"arn:aws:iam::{ACCOUNT}:role/GitHubCiApply-user-service-infrastructure-test",
    )
    assert not allows(storage, "kms:CreateKey", "*")
    assert not allows(
        storage,
        "s3:PutBucketPolicy",
        "arn:aws:s3:::pulumi-user-service-infrastructure-test-state",
    )


def test_storage_mutation_is_exact_repo_and_tag_constrained():
    args = inputs()
    document = governance_repo_storage_policy(args, REPO, apply=True)
    own = "arn:aws:s3:::pulumi-user-service-infrastructure-test-state"
    assert allows(document, "s3:CreateBucket", own)
    assert not allows(
        document, "s3:PutBucketPolicy", own.replace("user-service", "other")
    )
    key = f"arn:aws:kms:eu-central-1:{ACCOUNT}:key/example"
    edit = allows(document, "kms:PutKeyPolicy", key)
    assert (
        edit[0]["Condition"]["StringEquals"]["aws:ResourceTag/Repository"] == REPO.name
    )
    create = allows(document, "kms:CreateKey", "*")
    assert create[0]["Condition"] == {
        "StringEquals": {
            "aws:RequestTag/Repository": REPO.name,
            "aws:RequestTag/Environment": "test",
            "aws:RequestTag/Purpose": "pulumi-secrets",
        }
    }
    assert not allows(document, "kms:UntagResource", key)
    assert not allows(document, "kms:Decrypt", key)
    secret = (
        f"arn:aws:secretsmanager:eu-central-1:{ACCOUNT}:secret:"
        "/user-service-infrastructure/ci/test-ABC123"
    )
    assert allows(document, "secretsmanager:PutSecretValue", secret)
    assert not allows(
        document,
        "secretsmanager:GetSecretValue",
        secret.replace("user-service", "other"),
    )
    assert not allows(
        document, "secretsmanager:GetSecretValue", secret.replace("-ABC123", "-ABC1234")
    )


def test_policy_size_limit_fails_closed():
    with pytest.raises(ValueError, match="6144"):
        _document(
            [{"Effect": "Allow", "Action": ["example:Read"], "Resource": ["x" * 6200]}]
        )


@pytest.mark.parametrize("environment", ["test", "prod"])
def test_component_creates_three_roles_and_two_immutable_boundaries(
    pulumi_mocks, environment, monkeypatch
):
    import pulumi_aws as aws

    protected = []

    def capture(constructor):
        def allocate(*args, **kwargs):
            protected.append((constructor.__name__, kwargs["opts"].protect))
            return constructor(*args, **kwargs)

        return allocate

    for kind in ("Role", "Policy", "RolePolicyAttachment"):
        monkeypatch.setattr(aws.iam, kind, capture(getattr(aws.iam, kind)))
    component = GovernanceAutomation("test-governor", args=inputs(environment))
    for role in component.roles.values():
        _sync_await(future_output(role.arn))
    for boundary in component.boundaries.values():
        _sync_await(future_output(boundary.arn))
    _sync_await(wait_for_rpcs())
    assert {kind for kind, _ in protected} == {"Role", "Policy", "RolePolicyAttachment"}
    assert len(protected) == 29
    assert all(protect is True for _, protect in protected)
    assert set(component.roles) == {"preview", "drift", "apply"}
    assert set(component.boundaries) == {
        f"GovernanceBoundary-user-service-infrastructure-{environment}",
        f"GovernanceReplicationBoundary-user-service-infrastructure-{environment}",
    }
    prefix = f"AWS_GOVERNANCE_{environment.upper()}"
    assert set(component.github_variables) == {
        f"{prefix}_{suffix}"
        for suffix in (
            "PREVIEW_ROLE_ARN",
            "DRIFT_ROLE_ARN",
            "APPLY_ROLE_ARN",
            "ACCOUNT_ID",
            "REGION",
            "BACKEND_URL",
            "SECRETS_PROVIDER",
        )
    }
    assert component.github_variables[f"{prefix}_ACCOUNT_ID"] == ACCOUNT
    assert not any(
        t == "aws:iam/openIdConnectProvider:OpenIdConnectProvider"
        for t, _, _ in pulumi_mocks.resources
    )


@pytest.mark.parametrize(
    "repos",
    [
        [],
        [REPO, REPO],
        [
            ManagedRepository(
                name="bootstrap-infrastructure",
                default_branch="main",
                project="bootstrap-infrastructure",
            )
        ],
    ],
)
def test_component_rejects_invalid_catalog(repos):
    with pytest.raises(ValueError, match="catalog"):
        GovernanceAutomation("invalid-governor", args=inputs(repositories=repos))


def test_component_rejects_unreviewed_attachment_quota_growth():
    repos = [
        ManagedRepository(
            name=f"service-{i}-infrastructure",
            default_branch="main",
            project=f"service-{i}-infrastructure",
        )
        for i in range(5)
    ]
    with pytest.raises(ValueError, match="10 policy"):
        GovernanceAutomation("too-large-governor", args=inputs(repositories=repos))


@pytest.mark.parametrize(
    "repos",
    [
        [
            dataclasses.replace(REPO, name="service.one"),
            dataclasses.replace(REPO, name="service-one", project="different"),
        ],
        [REPO, dataclasses.replace(REPO, name="other-service")],
        [dataclasses.replace(REPO, name="BOOTSTRAP-INFRASTRUCTURE")],
        [dataclasses.replace(REPO, project="bootstrap-infrastructure")],
    ],
)
def test_catalog_namespace_collisions_fail_before_allocation(monkeypatch, repos):
    import pulumi

    def forbidden(*args, **kwargs):
        pytest.fail("Invalid catalog reached resource allocation")

    monkeypatch.setattr(pulumi.ComponentResource, "__init__", forbidden)
    with pytest.raises(ValueError, match="catalog"):
        GovernanceAutomation("collision", args=inputs(repositories=repos))


@pytest.mark.parametrize("environment", ["test", "prod"])
@pytest.mark.parametrize("size", ["maximum", "config-over", "deploy-over"])
def test_catalog_role_lengths_checked_before_allocation(monkeypatch, environment, size):
    """Use real naming helpers before any ComponentResource is registered."""
    import pulumi

    suffix = "test-pr" if environment == "test" else "prod-preview"
    length = 64 - len(f"GitHubCiConfigRead--{suffix}")
    if size == "config-over":
        length += 1
    elif size == "deploy-over":
        length = 65 - len(f"GitHubCiPreview--{environment}")
    repo = dataclasses.replace(REPO, name="a" * length)
    allocations = []

    def first_resource(*args, **kwargs):
        allocations.append(True)
        raise RuntimeError("first resource")

    monkeypatch.setattr(pulumi.ComponentResource, "__init__", first_resource)
    args = inputs(environment, repositories=[repo])
    if size == "maximum":
        with pytest.raises(RuntimeError, match="first resource"):
            GovernanceAutomation("maximum-name", args=args)
        assert allocations == [True]
    else:
        with pytest.raises(ValueError, match="longer than 64 characters"):
            GovernanceAutomation("too-long-name", args=args)
        assert allocations == []
