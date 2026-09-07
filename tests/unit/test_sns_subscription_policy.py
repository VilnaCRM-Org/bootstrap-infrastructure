"""Generated subscription grants retain topic scope and pass the actual policy gate."""

import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from iam_statement_matcher import iam_statement_matches
from infra import config
from infra.automation import _automation_policy_documents
from infra.platform_iam import platform_control_boundary


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


@pytest.mark.parametrize(
    "environment,account",
    [("test", "891377212104"), ("prod", "933245420672")],
)
def test_actual_control_boundary_matches_reviewed_pin(
    monkeypatch, environment, account
):
    repository = Path(__file__).resolve().parents[2]
    monkeypatch.syspath_prepend(str(repository))
    from policy.config import load_policy_config
    from policy.guardrails import wildcard_iam_violations
    from policy.reviewed_iam import reviewed_iam_document_matches

    path = repository / "pulumi/github-ci-bootstrap" / f"Pulumi.{environment}.yaml"
    values = {
        key.removeprefix("github-ci-bootstrap:"): value
        for key, value in yaml.safe_load(path.read_text())["config"].items()
        if key.startswith("github-ci-bootstrap:")
    }
    settings = config.BootstrapSettings.from_pulumi_config(
        SimpleNamespace(get=values.get, get_secret=lambda _: None)
    )
    document = platform_control_boundary(account, settings, settings.repo)
    props = {"name": f"PlatformBoundary-control-{environment}", "policy": document}
    loaded = load_policy_config(repository / "policy/vilnacrm_guardrails.yaml")
    kind = "aws:iam/policy:Policy"
    assert len(document) <= 6144
    assert reviewed_iam_document_matches(kind, props, loaded.reviewed_iam_documents)
    assert wildcard_iam_violations(kind, props, loaded) == []
    assert wildcard_iam_violations(kind, {**props, "name": "unreviewed"}, loaded)

    # Reintroducing either removed global action must invalidate the whole pin.
    for action in ("sns:GetSubscriptionAttributes", "sns:Unsubscribe"):
        changed = json.loads(document)
        changed["Statement"].append(
            {"Effect": "Allow", "Action": action, "Resource": "*"}
        )
        assert wildcard_iam_violations(kind, {**props, "policy": changed}, loaded)

    changed = json.loads(document)
    changed["Statement"][0]["Condition"]["StringEquals"][
        "aws:RequestTag/Environment"
    ] = "foreign"
    assert wildcard_iam_violations(kind, {**props, "policy": changed}, loaded)
    changed = json.loads(document)
    denies = [s for s in changed["Statement"] if s["Effect"] == "Deny"]
    assert len(denies) == 2
    changed["Statement"].remove(denies[0])
    assert wildcard_iam_violations(kind, {**props, "policy": changed}, loaded)
