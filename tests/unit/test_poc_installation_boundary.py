"""Runtime source cannot silently enter the installed operator seed protocol."""

import json
from dataclasses import replace

import pytest
from seed import poc_runtime as runtime
from test_operator_seed_installation import installation, packet_for
from test_poc_runtime import decision


@pytest.mark.parametrize("field", ["policies", "principals"])
def test_runtime_append_rejected_by_seed_installer(field):
    packet = packet_for()
    policies, principals = runtime.enrollment_records()
    additions = policies if field == "policies" else principals
    altered = replace(
        packet.registry,
        **{field: (*getattr(packet.registry, field), *additions)},
    )
    with pytest.raises(ValueError, match="differs from pinned registry"):
        installation.validate_installation(replace(packet, registry=altered))
    with pytest.raises(ValueError, match="differs from pinned registry"):
        installation.build_activation(replace(packet, registry=altered))


def test_governor_explicitly_blocks_runtime_installation():
    packet = packet_for()
    governor = next(
        row
        for row in packet.registry.principals
        if row.arn.endswith("/GitHubGovernanceApply-test")
    )
    # Check unconditional denials only; do not pretend to simulate the complete
    # IAM condition dialect or infer an Allow from a missing explicit Deny.
    denials = {
        "Statement": [
            statement
            for row in packet.registry.policies
            if row.arn in governor.guard_arns
            for statement in json.loads(row.document_json)["Statement"]
            if statement["Effect"] == "Deny" and "Condition" not in statement
        ]
    }
    document = json.dumps(denials)
    policies, principals = runtime.enrollment_records()
    for principal in principals:
        for action in (
            "iam:GetRole",
            "iam:CreateRole",
            "iam:PutRolePermissionsBoundary",
            "iam:PutRolePolicy",
            "iam:AttachRolePolicy",
            "iam:UpdateAssumeRolePolicy",
            "iam:PassRole",
        ):
            assert decision(document, action, principal.arn) == "explicit-deny"
    for policy in policies:
        for action in ("iam:GetPolicy", "iam:CreatePolicyVersion"):
            assert decision(document, action, policy.arn) == "explicit-deny"


def test_executor_activation_keeps_runtime_resources_outside_seed_stack():
    packet = packet_for()
    baseline = json.loads(packet.enrollment_template)["Resources"]
    active = json.loads(installation.build_activation(packet).activation_template)[
        "Resources"
    ]
    assert len(packet.registry.policies) == 55
    assert len(packet.registry.principals) == 24
    assert len(baseline) == len(active) == 58
    changed = [key for key in baseline if baseline[key] != active[key]]
    assert len(changed) == 3
    assert {active[key]["Properties"]["RoleName"] for key in changed} == {
        f"GitHubOperator{purpose}-test" for purpose in ("Apply", "Preview", "Drift")
    }
    assert json.loads(packet.stack_policy)["Statement"] == [
        {"Effect": "Deny", "Action": "Update:*", "Principal": "*", "Resource": "*"}
    ]
