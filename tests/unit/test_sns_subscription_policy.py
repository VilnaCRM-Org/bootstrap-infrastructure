"""Generated subscription grants retain topic scope and pass the actual policy gate."""

import json
from dataclasses import replace
from pathlib import Path

import pytest
from iam_statement_matcher import iam_statement_matches
from infra import config
from infra.automation import _automation_policy_documents


@pytest.mark.parametrize(
    "environment,account",
    [("test", "891377212104"), ("prod", "933245420672")],
)
def test_generated_operations_policy_passes_guard_with_parent_topic_scope(
    monkeypatch, environment, account
):
    # AWS SNS SAR lists topic resource authorization for subscription Get/Unsubscribe.
    # This exercises the actual producer and guard together, without digest overrides.
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[2]))
    from policy.guardrails import wildcard_iam_violations

    settings = replace(
        config.settings, environment=environment, repo="bootstrap-infrastructure"
    )
    documents = _automation_policy_documents(account, settings, settings.repo)
    document = next(text for name, text in documents if name == "operations-policy")
    policy = json.loads(document)
    statements = {s["Sid"]: s for s in policy["Statement"]}
    grant = statements["ManageBootstrapSnsSubscriptions"]
    assert grant["Action"] == ["sns:GetSubscriptionAttributes", "sns:Unsubscribe"]
    assert grant["Resource"] == [
        f"arn:aws:sns:*:{account}:bootstrap-{environment}-operations"
    ]
    assert grant["Resource"] == statements["ManageBootstrapSns"]["Resource"]
    topic = f"arn:aws:sns:eu-central-1:{account}:bootstrap-{environment}-operations"
    for action in grant["Action"]:
        assert iam_statement_matches(grant, action, topic)
        for foreign in (
            topic + "-foreign",
            topic.replace(account, "111111111111"),
            topic.replace(f"-{environment}-", "-foreign-"),
        ):
            assert not iam_statement_matches(grant, action, foreign)
    assert wildcard_iam_violations("aws:iam/policy:Policy", {"policy": document}) == []
    # A regression to global subscription scope must be rejected by the same guard.
    grant["Resource"] = "*"
    assert wildcard_iam_violations(
        "aws:iam/policy:Policy", {"policy": json.dumps(policy)}
    )
