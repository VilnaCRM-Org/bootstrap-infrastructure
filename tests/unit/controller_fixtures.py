"""Nonsecret inputs shared by installation IAM library tests."""

from types import SimpleNamespace

from infra.bootstrap_settings import BootstrapSettings
from infra.managed_repository import ManagedRepository

ACCOUNT = "123456789012"
PROVIDER = f"arn:aws:iam::{ACCOUNT}:oidc-provider/token.actions.githubusercontent.com"
REPO = ManagedRepository(
    name="user-service-infrastructure",
    default_branch="main",
    project="user-service-infrastructure",
    repository_id="911736693",
    repository_owner_id="114362548",
)


def inputs(environment: str = "test", **overrides) -> SimpleNamespace:
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
    return SimpleNamespace(**values)
