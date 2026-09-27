"""Actual central Pulumi resource graph, provider scope and fail-closed preflight."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pulumi_aws as aws
import pytest
from infra import poc_runtime_enrollment as enrollment
from infra.utils.outputs import future_output
from pulumi.runtime.sync_await import _sync_await
from seed import poc_runtime as runtime
from seed.policy_registry import RegistryError
from test_poc_runtime import subject


def target(monkeypatch, project):
    """Synthetic provider/account metadata, never a real enrollment receipt."""
    monkeypatch.setattr(enrollment.pulumi, "get_project", lambda: project)
    monkeypatch.setattr(
        aws,
        "get_caller_identity",
        lambda **_: SimpleNamespace(account_id=runtime.ACCOUNT_ID),
    )
    monkeypatch.setattr(
        aws, "get_region", lambda **_: SimpleNamespace(region=runtime.REGION)
    )
    policies, _ = runtime.enrollment_records()
    documents = {record.arn: record.document_json for record in policies}
    calls = []

    def observed(*, arn, opts):
        calls.append((arn, opts.provider))
        return SimpleNamespace(arn=arn, policy=documents[arn])

    monkeypatch.setattr(aws.iam, "get_policy", observed)
    provider = aws.Provider("poc-test-explicit", region=runtime.REGION)
    _sync_await(future_output(provider.urn))
    return provider, calls


def capture(monkeypatch, resource_class):
    """Retain resource options not exposed by the shared mock state helper."""
    original = getattr(aws.iam, resource_class)
    result = []

    def register(resource_name, **kwargs):
        result.append((resource_name, kwargs))
        return original(resource_name, **kwargs)

    monkeypatch.setattr(aws.iam, resource_class, register)
    return result


def expected_trust(activate, purpose):
    """Match the fixed runtime trust selection for each enrollment role."""
    if purpose == "publisher":
        return (
            runtime.publisher_trust(subject()) if activate else runtime.disabled_trust()
        )
    if purpose == "execution":
        return runtime.execution_trust()
    return runtime.disabled_trust()


def test_seed_registers_only_six_protected_fences(pulumi_mocks, monkeypatch):
    provider, _ = target(monkeypatch, "independent-seed")
    registered = capture(monkeypatch, "Policy")
    component = enrollment.PocRuntimeFences(provider=provider)
    for policy in component.policies.values():
        _sync_await(future_output(policy.arn))
    assert len(registered) == 6
    expected = {
        record.arn: record.document_json for record in runtime.enrollment_records()[0]
    }
    for name, inputs in registered:
        arn = f"arn:aws:iam::{runtime.ACCOUNT_ID}:policy{inputs['path']}{name}"
        assert inputs["policy"] == expected[arn]
        assert inputs["opts"].protect is True
        assert inputs["opts"].provider is provider
    assert not any(typ == "aws:iam/role:Role" for typ, _, _ in pulumi_mocks.resources)


@pytest.mark.parametrize("activate", [False, True])
def test_governance_creates_pull_only_execution_and_disabled_task(
    pulumi_mocks, monkeypatch, activate
):
    provider, reads = target(monkeypatch, "governance")
    registered = capture(monkeypatch, "Role")
    component = enrollment.PocRuntimeRoles(
        provider=provider, publisher_subject=subject() if activate else None
    )
    for arn in component.role_arns.values():
        _sync_await(future_output(arn))
    assert len(reads) == 6
    assert all(observed_provider is provider for _, observed_provider in reads)
    assert len(registered) == 3
    assert set(component.role_arns) == {"execution", "task", "publisher"}
    for identity, (name, inputs) in zip(runtime.runtime_identities(), registered):
        assert name == inputs["name"] == identity.name
        assert inputs["permissions_boundary"] == identity.policy_arn("boundary")
        assert inputs["managed_policy_arns"] == [identity.policy_arn("guard")]
        assert inputs["opts"].provider is provider
        assert inputs["opts"].protect is True
        expected = expected_trust(activate, identity.purpose)
        assert inputs["assume_role_policy"] == expected
        if identity.purpose == "publisher":
            assert len(inputs["inline_policies"]) == 1
            assert inputs["inline_policies"][0].policy == runtime.publisher_policy()
        elif identity.purpose == "execution":
            assert len(inputs["inline_policies"]) == 1
            assert inputs["inline_policies"][0].name == "Issue219TestImagePull"
            assert inputs["inline_policies"][0].policy == runtime.execution_policy()
        else:
            assert len(inputs["inline_policies"]) == 1
            assert inputs["inline_policies"][0].name is None
            assert inputs["inline_policies"][0].policy is None
    assert not any(
        typ == "aws:iam/policy:Policy" for typ, _, _ in pulumi_mocks.resources
    )


def test_task_inline_policy_empty_block_survives_serialization(
    pulumi_mocks, monkeypatch
):
    provider, _ = target(monkeypatch, "governance")
    component = enrollment.PocRuntimeRoles(provider=provider)
    _sync_await(future_output(component.roles["task"].urn))
    task = next(
        inputs
        for typ, _, inputs in pulumi_mocks.resources
        if typ == "aws:iam/role:Role" and inputs["tags"]["Purpose"] == "task"
    )
    assert task["inlinePolicies"] == [{}]


@pytest.mark.parametrize("mismatch", ["arn", "policy"])
def test_governance_rejects_changed_seed_documents_before_roles(
    pulumi_mocks, monkeypatch, mismatch
):
    provider, _ = target(monkeypatch, "governance")
    registered = capture(monkeypatch, "Role")
    monkeypatch.setattr(
        aws.iam,
        "get_policy",
        lambda **kwargs: SimpleNamespace(
            arn=kwargs["arn"] if mismatch == "policy" else "wrong",
            policy=json.dumps({"Version": "2012-10-17", "Statement": []}),
        ),
    )
    with pytest.raises(RegistryError, match="fence differs"):
        enrollment.PocRuntimeRoles(provider=provider)
    assert registered == []


@pytest.mark.parametrize("mismatch", ["project", "account", "region", "provider"])
def test_wrong_provider_target_or_project_rejected_before_enrollment(
    pulumi_mocks, monkeypatch, mismatch
):
    provider, _ = target(monkeypatch, "governance")
    if mismatch == "project":
        monkeypatch.setattr(
            enrollment.pulumi, "get_project", lambda: "user-service-infrastructure"
        )
    elif mismatch == "account":
        monkeypatch.setattr(
            aws,
            "get_caller_identity",
            lambda **_: SimpleNamespace(account_id="933245420672"),
        )
    elif mismatch == "region":
        monkeypatch.setattr(
            aws, "get_region", lambda **_: SimpleNamespace(region="us-east-1")
        )
    else:
        provider = None
    registered = capture(monkeypatch, "Role")
    with pytest.raises(RegistryError, match="Runtime enrollment requires"):
        enrollment.PocRuntimeRoles(provider=provider)
    assert registered == []
