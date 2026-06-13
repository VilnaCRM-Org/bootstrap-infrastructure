"""Entrypoint for the Kravalg-gated multi-repo governance Pulumi project."""

from __future__ import annotations

import sys
from importlib import import_module
from pathlib import Path

PULUMI_ROOT = Path(__file__).resolve().parents[1]
if str(PULUMI_ROOT) not in sys.path:
    sys.path.insert(0, str(PULUMI_ROOT))

pulumi = import_module("pulumi")
infra = import_module("infra")
BootstrapSettings = infra.BootstrapSettings
GovernanceStack = infra.GovernanceStack
GovernanceStackArgs = infra.GovernanceStackArgs
ManagedRepositoryCatalog = infra.ManagedRepositoryCatalog

cfg = pulumi.Config()
settings = BootstrapSettings.from_pulumi_config(cfg)
catalog = ManagedRepositoryCatalog.from_settings(settings, cfg)
write_secret_values = cfg.get_bool("writeSecretValues")
protect_resources = cfg.get_bool("protectResources")
managed_secret_values = True if write_secret_values is None else write_secret_values
protected_resources = True if protect_resources is None else protect_resources

governance = GovernanceStack(
    "governance",
    args=GovernanceStackArgs(
        settings=settings,
        repository_catalog=catalog,
        expected_account_id=cfg.get("awsAccountId"),
        oidc_provider_arn=cfg.get("githubOidcProviderArn"),
        region=cfg.get("region") or "eu-central-1",
        # PULUMI_DIR flows into each managed repo's generated CI-config payload
        # (governance.py -> _governance_payloads -> the per-repo CI secret), and
        # the managed repo's self-deploy resolves its own Pulumi project from
        # this value. A managed *-infrastructure repo hosts its Pulumi project at
        # the repo-root ``pulumi/`` directory (architecture §8.1), NOT at
        # ``pulumi/governance`` (that path only exists in THIS bootstrap repo).
        # The default must therefore be ``pulumi`` so downstream repos point at
        # their own project root.
        pulumi_dir=cfg.get("pulumiDir") or "pulumi",
        pulumi_backend_url=cfg.get("pulumiBackendUrl"),
        pulumi_secrets_provider=cfg.get("pulumiSecretsProvider"),
        write_secret_values=managed_secret_values,
        protect_resources=protected_resources,
    ),
)

pulumi.export("oidcProviderArn", governance.oidc_provider_arn)
pulumi.export("managedRepositories", governance.managed_repositories)
pulumi.export("perRepo", governance.per_repo)
