"""Preserve historical dependency injection and canonical platform key aliases."""

import json

import pytest
from infra import ci_bootstrap, platform_iam
from infra.bootstrap_dependencies import BootstrapInfrastructureDependencies
from infra.ci_config import CiConfiguration
from test_platform_iam import ACCOUNT, REPO, settings


def test_historical_positional_dependencies_keep_their_targets():
    """Appending a new dependency cannot move existing positional arguments."""
    names = (
        "logging_buckets_cls",
        "state_buckets_cls",
        "secrets_keys_cls",
        "oidc_roles_cls",
        "automation_cls",
        "backup_plan_cls",
        "monitoring_cls",
        "cost_controls_cls",
        "security_account_controls_cls",
    )
    supplied = [type(name, (), {}) for name in names]
    dependencies = BootstrapInfrastructureDependencies(*supplied)
    assert [getattr(dependencies, name) for name in names] == supplied
    assert dependencies.ci_config_cls is CiConfiguration


@pytest.mark.parametrize("environment", ["test", "prod", "dev.1"])
def test_platform_boundaries_match_actual_provider_alias(environment):
    """A valid dotted environment must decrypt the same alias the provider uses."""
    configured = settings(environment)
    alias = ci_bootstrap._default_secrets_provider(configured, "eu-central-1")
    alias = alias.removeprefix("awskms://").split("?", 1)[0]
    documents = [
        json.loads(
            platform_iam.platform_control_boundary(ACCOUNT, configured, REPO.name)
        ),
        json.loads(
            platform_iam.platform_workload_boundaries(
                ACCOUNT, configured, "eu-central-1", [REPO]
            )["backup"]
        ),
    ]
    for document in documents:
        aliases = []
        for statement in document["Statement"]:
            for conditions in statement.get("Condition", {}).values():
                value = conditions.get("kms:ResourceAliases", [])
                aliases.extend(value if isinstance(value, list) else [value])
        assert alias in aliases
        if environment == "dev.1":
            assert "alias/pulumi-platform-bootstrap-dev.1" not in aliases
