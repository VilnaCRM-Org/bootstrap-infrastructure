"""The real platform entrypoint rejects identity drift before AWS allocation."""

from __future__ import annotations

import runpy
from pathlib import Path
from types import SimpleNamespace

import app
import pulumi_aws as aws
import pytest
from infra import BootstrapInfrastructure
from infra import config as bootstrap_config

import pulumi

ENTRYPOINT = Path(__file__).resolve().parents[2] / "pulumi/__main__.py"


def run_entrypoint(monkeypatch, config_values, *, caller="123456789012"):
    monkeypatch.setattr(
        app,
        "EnvironmentSettings",
        lambda _name: SimpleNamespace(
            environment="test",
            service_name="bootstrap-infrastructure",
            stack_tag="bootstrap-infrastructure-test",
            default_tags={},
        ),
    )
    monkeypatch.setattr(pulumi, "export", lambda *_args: None)
    monkeypatch.setattr(bootstrap_config.settings, "repo", "bootstrap-infrastructure")
    values = {
        "environment": "test",
        "serviceName": "bootstrap-infrastructure",
        "repoSlug": "bootstrap-infrastructure",
        **config_values,
    }
    config = SimpleNamespace(
        get=lambda key, default=None: values.get(key, default),
        get_object=lambda key, default=None: default,
        require=values.__getitem__,
    )
    monkeypatch.setattr(pulumi, "Config", lambda: config)
    monkeypatch.setattr(
        aws, "get_caller_identity", lambda: SimpleNamespace(account_id=caller)
    )
    runpy.run_path(str(ENTRYPOINT))


def valid_identity():
    return {
        "awsAccountId": "123456789012",
        "githubRepositoryId": "1098568429",
        "githubRepositoryOwnerId": "114362548",
    }


@pytest.mark.parametrize("missing", list(valid_identity()))
def test_missing_identity_fails_before_platform_resources(monkeypatch, missing):
    values = valid_identity()
    del values[missing]
    allocations = []
    monkeypatch.setattr(
        BootstrapInfrastructure, "__init__", lambda *_a, **kw: allocations.append(kw)
    )
    with pytest.raises(KeyError, match=missing):
        run_entrypoint(monkeypatch, values)
    assert allocations == []


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("awsAccountId", "123456789013"),
        ("awsAccountId", "12345"),
        ("githubRepositoryId", "01"),
        ("githubRepositoryOwnerId", "*"),
    ],
)
def test_invalid_identity_fails_before_platform_resources(monkeypatch, key, value):
    allocations = []
    monkeypatch.setattr(
        BootstrapInfrastructure, "__init__", lambda *_a, **kw: allocations.append(kw)
    )
    with pytest.raises(ValueError):
        run_entrypoint(monkeypatch, {**valid_identity(), key: value})
    assert allocations == []


def test_live_platform_can_only_consume_control_resources(monkeypatch):
    allocations = []

    def allocate(_self, *_args, **kwargs):
        allocations.append(kwargs)
        raise RuntimeError("allocation boundary reached")

    monkeypatch.setattr(BootstrapInfrastructure, "__init__", allocate)
    with pytest.raises(RuntimeError, match="allocation boundary reached"):
        run_entrypoint(monkeypatch, valid_identity())
    assert len(allocations) == 1
    assert allocations[0]["manage_control_resources"] is False
