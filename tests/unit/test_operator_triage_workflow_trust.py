"""The operator triage trust retains every claim and pins its only workflow."""

import json

import pytest
from infra import ci_bootstrap

PREFIX = "token.actions.githubusercontent.com:"
REPOSITORY = "VilnaCRM-Org/bootstrap-infrastructure"
WORKFLOW = "Operations Alert Issue Triage"
PROVIDER = "arn:aws:iam::891377212104:oidc-provider/token.actions.githubusercontent.com"


def trust(workflow_name=None):
    return json.loads(
        ci_bootstrap._deployment_assume_role_policy(
            PROVIDER,
            REPOSITORY,
            [f"repo:{REPOSITORY}:ref:refs/heads/main"],
            repository_id="1098568429",
            owner_id="114362548",
            branch_ref="refs/heads/main",
            workflow_name=workflow_name,
        )
    )


def test_only_workflow_conjunct_is_added_to_existing_operator_trust():
    original = trust()
    changed = trust(WORKFLOW)
    equals = changed["Statement"][0]["Condition"]["StringEquals"]
    assert equals.pop(PREFIX + "workflow") == WORKFLOW
    assert changed == original
    assert "job_workflow_ref" not in json.dumps(changed)
    assert len(json.dumps(trust(WORKFLOW), separators=(",", ":"))) <= 2048


@pytest.mark.parametrize(
    "claim",
    [
        "workflow",
        "aud",
        "sub",
        "ref",
        "repository",
        "repository_id",
        "repository_owner_id",
    ],
)
@pytest.mark.parametrize("replacement", [None, "wrong-value"])
def test_missing_or_wrong_claim_cannot_match_operator_triage_trust(claim, replacement):
    conditions = trust(WORKFLOW)["Statement"][0]["Condition"]["StringEquals"]
    claims = {
        key: value[0] if isinstance(value, list) else value
        for key, value in conditions.items()
    }
    key = PREFIX + claim
    assert key in conditions
    if replacement is None:
        claims.pop(key)
    else:
        claims[key] = replacement
    assert not all(
        claims.get(name) in (value if isinstance(value, list) else [value])
        for name, value in conditions.items()
    )


def test_only_exact_main_triage_workflow_satisfies_all_claims():
    conditions = trust(WORKFLOW)["Statement"][0]["Condition"]["StringEquals"]
    assert conditions[PREFIX + "workflow"] == WORKFLOW
    assert conditions[PREFIX + "ref"] == "refs/heads/main"
    assert conditions[PREFIX + "repository_id"] == "1098568429"
    assert conditions[PREFIX + "repository_owner_id"] == "114362548"
    assert conditions[PREFIX + "aud"] == "sts.amazonaws.com"
    assert conditions[PREFIX + "repository"] == REPOSITORY
    assert len(conditions[PREFIX + "sub"]) == 2
