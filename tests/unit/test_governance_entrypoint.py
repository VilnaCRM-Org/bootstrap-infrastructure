"""Execute governance entrypoint wiring without relying on imported global state."""

from __future__ import annotations

import importlib
import runpy
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

PULUMI_ROOT = Path(__file__).resolve().parents[2] / "pulumi"
ENTRYPOINT = PULUMI_ROOT / "governance/__main__.py"


def entry_modules(
    monkeypatch, values, repositories, region="eu-central-1", region_reads=None
):
    """Intercept only the entrypoint's external resource composition boundaries."""
    allocations = []
    exports = {}
    settings = object()
    catalog = SimpleNamespace(repositories=repositories)
    config = SimpleNamespace(
        require=values.__getitem__, get=values.get, get_bool=values.get
    )
    component = SimpleNamespace(
        oidc_provider_arn="provider-arn",
        managed_repositories=["service-infrastructure"],
        per_repo={"service-infrastructure": {"stateBucketName": "state-bucket"}},
    )

    def allocate(name, *, args):
        allocations.append((name, args))
        return component

    def get_region():
        if region_reads is not None:
            region_reads.append(region)
        return SimpleNamespace(region=region)

    modules = {
        "pulumi_aws": SimpleNamespace(get_region=get_region),
        "pulumi": SimpleNamespace(
            Config=lambda: config,
            export=lambda key, value: exports.update({key: value}),
        ),
        "infra": SimpleNamespace(
            BootstrapSettings=SimpleNamespace(from_pulumi_config=lambda cfg: settings),
            ManagedRepositoryCatalog=SimpleNamespace(
                from_settings=lambda actual, cfg: catalog
            ),
            GovernanceStackArgs=lambda **kwargs: kwargs,
            GovernanceStack=allocate,
        ),
    }
    original = importlib.import_module
    monkeypatch.setattr(
        importlib,
        "import_module",
        lambda name, *args: modules[name] if name in modules else original(name, *args),
    )
    return allocations, exports, settings, catalog, component


@pytest.mark.parametrize("overrides", [False, True])
@pytest.mark.parametrize("empty_catalog", [False, True])
def test_governance_entrypoint_executes_complete_contract(
    monkeypatch, overrides, empty_catalog
):
    values = {
        "githubRepositoryId": "1098568429",
        "githubRepositoryOwnerId": "114362548",
        "awsAccountId": "891377212104",
        "githubOidcProviderArn": "pinned-provider",
    }
    if overrides:
        values.update(
            githubOidcProviderArn="pinned-provider",
            region="eu-west-1",
            pulumiDir="service-project",
            pulumiBackendUrl="s3://state/governance",
            pulumiSecretsProvider="awskms://alias/governance",
            writeSecretValues=False,
            protectResources=False,
        )
    repositories = (
        []
        if empty_catalog
        else [
            SimpleNamespace(repository_id="911736693", repository_owner_id="114362548")
        ]
    )
    allocations, exports, settings, catalog, component = entry_modules(
        monkeypatch,
        values,
        repositories,
        region="eu-west-1" if overrides else "eu-central-1",
    )
    path = [item for item in sys.path if item != str(PULUMI_ROOT)]
    if overrides:
        path.insert(0, str(PULUMI_ROOT))
    monkeypatch.setattr(sys, "path", path)
    runpy.run_path(str(ENTRYPOINT))
    assert str(PULUMI_ROOT) in sys.path
    assert allocations == [
        (
            "governance",
            {
                "settings": settings,
                "repository_catalog": catalog,
                "expected_account_id": values["awsAccountId"],
                "oidc_provider_arn": values.get("githubOidcProviderArn"),
                "region": "eu-west-1" if overrides else "eu-central-1",
                "pulumi_dir": "service-project" if overrides else "pulumi",
                "pulumi_backend_url": values.get("pulumiBackendUrl"),
                "pulumi_secrets_provider": values.get("pulumiSecretsProvider"),
                "write_secret_values": not overrides,
                "protect_resources": not overrides,
            },
        )
    ]
    assert exports == {
        "oidcProviderArn": component.oidc_provider_arn,
        "managedRepositories": component.managed_repositories,
        "perRepo": component.per_repo,
    }


@pytest.mark.parametrize(
    "missing",
    [
        "githubRepositoryId",
        "githubRepositoryOwnerId",
        "awsAccountId",
        "githubOidcProviderArn",
    ],
)
def test_governance_entrypoint_missing_required_identity_never_allocates(
    monkeypatch, missing
):
    values = {
        "githubRepositoryId": "1098568429",
        "githubRepositoryOwnerId": "114362548",
        "awsAccountId": "891377212104",
        "githubOidcProviderArn": "pinned-provider",
    }
    del values[missing]
    region_reads = []
    allocations, exports, *_ = entry_modules(
        monkeypatch, values, [], region_reads=region_reads
    )
    with pytest.raises(KeyError, match=missing):
        runpy.run_path(str(ENTRYPOINT))
    assert allocations == []
    assert exports == {}
    assert region_reads == []


@pytest.mark.parametrize("missing", ["repository_id", "repository_owner_id"])
def test_governance_entrypoint_unpinned_catalog_never_allocates(monkeypatch, missing):
    repository = {"repository_id": "911736693", "repository_owner_id": "114362548"}
    repository[missing] = None
    allocations, exports, *_ = entry_modules(
        monkeypatch,
        {"githubRepositoryId": "1098568429", "githubRepositoryOwnerId": "114362548"},
        [SimpleNamespace(**repository)],
    )
    with pytest.raises(ValueError, match="pinned GitHub IDs"):
        runpy.run_path(str(ENTRYPOINT))
    assert allocations == []
    assert exports == {}


def test_governance_defaults_to_actual_provider_region(monkeypatch):
    values = {
        "githubRepositoryId": "1098568429",
        "githubRepositoryOwnerId": "114362548",
        "awsAccountId": "891377212104",
        "githubOidcProviderArn": "pinned-provider",
    }
    allocations, *_ = entry_modules(monkeypatch, values, [], region="ap-south-1")
    runpy.run_path(str(ENTRYPOINT))
    assert allocations[0][1]["region"] == "ap-south-1"


@pytest.mark.parametrize(
    "configured", ["eu-west-1", "", " eu-central-1", "EU-CENTRAL-1"]
)
def test_governance_rejects_region_different_from_provider(monkeypatch, configured):
    values = {
        "githubRepositoryId": "1098568429",
        "githubRepositoryOwnerId": "114362548",
        "awsAccountId": "891377212104",
        "githubOidcProviderArn": "pinned-provider",
        "region": configured,
    }
    allocations, exports, *_ = entry_modules(monkeypatch, values, [])
    with pytest.raises(ValueError, match="match the AWS provider region"):
        runpy.run_path(str(ENTRYPOINT))
    assert allocations == []
    assert exports == {}
