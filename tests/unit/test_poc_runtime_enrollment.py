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


def expected_trust(purpose):
    """Match the fixed ECS trust selection for each enrollment role."""
    if purpose == "execution":
        return runtime.execution_trust()
    return runtime.disabled_trust()


def test_governance_proposes_only_ecs_roles_not_independent_publisher(
    pulumi_mocks, monkeypatch
):
    provider, reads = target(monkeypatch, "governance")
    registered = capture(monkeypatch, "Role")
    component = enrollment.PocRuntimeRoles(provider=provider)
    for arn in component.role_arns.values():
        _sync_await(future_output(arn))
    assert len(reads) == 6
    assert all(observed_provider is provider for _, observed_provider in reads)
    assert len(registered) == 2
    assert set(component.role_arns) == {"execution", "task"}
    for identity, (name, inputs) in zip(runtime.runtime_identities()[:2], registered):
        assert name == inputs["name"] == identity.name
        assert inputs["permissions_boundary"] == identity.policy_arn("boundary")
        assert "managed_policy_arns" not in inputs
        assert "inline_policies" not in inputs
        assert inputs["opts"].provider is provider
        assert inputs["opts"].protect is True
        expected = expected_trust(identity.purpose)
        assert inputs["assume_role_policy"] == expected
    for grants in component.grants.values():
        for grant in grants:
            _sync_await(future_output(grant.urn))
    by_type = {}
    for typ, name, inputs in pulumi_mocks.resources:
        by_type.setdefault(typ, {})[name] = inputs
    attach = by_type[
        "aws:iam/rolePolicyAttachmentsExclusive:RolePolicyAttachmentsExclusive"
    ]
    exclusive = by_type["aws:iam/rolePoliciesExclusive:RolePoliciesExclusive"]
    inline = by_type["aws:iam/rolePolicy:RolePolicy"]
    for identity in runtime.runtime_identities()[:2]:
        assert attach[f"{identity.name}-managed-policy-attachments-exclusive"][
            "policyArns"
        ] == [identity.policy_arn("guard")]
        names = exclusive[f"{identity.name}-inline-policies-exclusive"].get(
            "policyNames", []
        )
        assert names == (
            ["Issue219TestImagePull"] if identity.purpose == "execution" else []
        )
    assert len(inline) == 1
    (row,) = inline.values()
    assert row["name"] == "Issue219TestImagePull"
    assert row["policy"] == runtime.execution_policy()
    assert not any(
        typ == "aws:iam/policy:Policy" for typ, _, _ in pulumi_mocks.resources
    )


@pytest.mark.parametrize("mismatch", ["arn", "policy", "missing", "raises"])
def test_governance_rejects_changed_seed_documents_before_roles(
    pulumi_mocks, monkeypatch, mismatch
):
    provider, _ = target(monkeypatch, "governance")
    registered = capture(monkeypatch, "Role")
    policies, _ = runtime.enrollment_records()
    first = policies[0]

    def observed(**kwargs):
        if mismatch == "raises":
            raise RuntimeError("no such policy")
        if mismatch == "missing":
            return None
        if mismatch == "arn":
            # Document equal to the expected fence, ARN different.
            return SimpleNamespace(arn="wrong", policy=first.document_json)
        return SimpleNamespace(
            arn=kwargs["arn"],
            policy=json.dumps({"Version": "2012-10-17", "Statement": []}),
        )

    monkeypatch.setattr(aws.iam, "get_policy", observed)
    with pytest.raises(RegistryError, match="fence (differs|missing)"):
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
