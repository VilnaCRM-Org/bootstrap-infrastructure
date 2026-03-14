"""Cost and governance guardrails for the Pulumi bootstrap stack."""

from __future__ import annotations

import runpy
from pathlib import Path

from infra import config

STACK_PATH = Path(__file__).resolve().parents[2] / "pulumi" / "__main__.py"
DISALLOWED_RESOURCE_PREFIXES = (
    "aws:ec2/",
    "aws:ecs/",
    "aws:eks/",
    "aws:elasticache/",
    "aws:elbv2/",
    "aws:lambda/provisionedConcurrencyConfig:",
    "aws:natgateway/",
    "aws:rds/",
    "aws:redshift/",
)
TAGGABLE_RESOURCE_TYPES = {
    "aws:backup/vault:Vault",
    "aws:iam/role:Role",
    "aws:kms/key:Key",
    "aws:s3/bucket:Bucket",
}


def _run_stack(monkeypatch, pulumi_mocks):
    pulumi_mocks.resources.clear()
    config.managed_repositories.cache_clear()
    monkeypatch.setattr(config.settings, "repo", "repo")
    monkeypatch.setattr(config.settings, "environment", "test")
    monkeypatch.setattr(config.settings, "owner", "platform")
    monkeypatch.setattr(config.settings, "cost_center", "core")
    monkeypatch.setattr(config.settings, "replication_region", "us-west-2")
    monkeypatch.setattr(config.settings, "managed_repo_overrides", None)
    runpy.run_path(STACK_PATH)
    return list(pulumi_mocks.resources)


def test_stack_limits_bootstrap_resources_to_low_cost_families(
    monkeypatch, pulumi_mocks
):
    resource_types = {
        type_
        for type_, _name, _state in _run_stack(monkeypatch, pulumi_mocks)
        if type_.startswith("aws:")
    }

    for prefix in DISALLOWED_RESOURCE_PREFIXES:
        assert not any(
            resource_type.startswith(prefix) for resource_type in resource_types
        )  # nosec B101


def test_taggable_resources_include_finops_tags(monkeypatch, pulumi_mocks):
    resources = _run_stack(monkeypatch, pulumi_mocks)

    for type_, _name, state in resources:
        if type_ not in TAGGABLE_RESOURCE_TYPES:
            continue
        tags = state.get("tags")
        assert isinstance(tags, dict)  # nosec B101
        assert tags["Owner"] == "platform"  # nosec B101
        assert tags["CostCenter"] == "core"  # nosec B101
