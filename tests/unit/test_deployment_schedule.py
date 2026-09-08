"""Account promotion cannot run ahead of an affected TEST dependency."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))

from deployment_schedule import deployment_schedule  # noqa: E402


def test_mixed_prod_apply_finishes_every_test_stack_first():
    steps = deployment_schedule(
        ("operator", "governance", "platform"), command="up", target_environment="prod"
    )
    assert [step.key for step in steps] == [
        "test_operator_plan",
        "test_operator_apply",
        "test_operator_drift",
        "test_governance_plan",
        "test_governance_apply",
        "test_governance_drift",
        "test_platform_plan",
        "test_platform_apply",
        "test_platform_drift",
        "prod_operator_plan",
        "prod_operator_apply",
        "prod_operator_drift",
        "prod_governance_plan",
        "prod_governance_apply",
        "prod_governance_drift",
        "prod_platform_plan",
        "prod_platform_apply",
        "prod_platform_drift",
    ]
    assert [step.predecessor for step in steps] == [None] + [
        step.key for step in steps[:-1]
    ]
    assert steps[9].predecessor == "test_platform_drift"


@pytest.mark.parametrize("scope", ["operator", "governance", "platform"])
def test_single_scope_test_apply_does_not_touch_other_stacks_or_prod(scope):
    steps = deployment_schedule((scope,), command="up", target_environment="test")
    assert [(step.environment, step.scope, step.operation) for step in steps] == [
        ("test", scope, "plan"),
        ("test", scope, "apply"),
        ("test", scope, "drift"),
    ]


@pytest.mark.parametrize("environment", ["test", "prod"])
def test_plan_never_schedules_mutation_or_claims_post_apply_drift(environment):
    steps = deployment_schedule(
        ("operator", "platform"), command="plan", target_environment=environment
    )
    assert all(step.operation == "plan" for step in steps)
    assert [step.scope for step in steps[:2]] == ["operator", "platform"]
    assert len(steps) == (4 if environment == "prod" else 2)


@pytest.mark.parametrize("command", ["plan", "up"])
def test_documentation_selection_has_no_cloud_operations(command):
    assert deployment_schedule((), command=command, target_environment="prod") == ()


@pytest.mark.parametrize(
    "scopes",
    [
        ("platform", "operator"),
        ("operator", "operator"),
        ("service",),
        ("operator", "unknown"),
        ["operator"],
        "operator",
        None,
    ],
)
def test_noncanonical_or_unknown_scope_cannot_get_a_schedule(scopes):
    with pytest.raises(ValueError, match="unique and in dependency order"):
        deployment_schedule(scopes, command="up", target_environment="test")


@pytest.mark.parametrize(
    "command,environment,message",
    [("destroy", "test", "command"), ("up", "staging", "environment")],
)
def test_unsupported_request_cannot_get_a_schedule(command, environment, message):
    with pytest.raises(ValueError, match=message):
        deployment_schedule(
            ("platform",), command=command, target_environment=environment
        )
