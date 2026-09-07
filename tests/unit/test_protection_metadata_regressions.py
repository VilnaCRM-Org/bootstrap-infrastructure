"""Protection metadata retains rules and rejects hidden alternative reviewers."""

from __future__ import annotations

import copy
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import _github_repository_controls as controls


def test_ruleset_update_preserves_all_unreplaced_rule_types():
    extras = [
        {"type": "required_signatures"},
        {"type": "required_linear_history"},
        {
            "type": "workflows",
            "parameters": {"workflows": [{"path": ".github/workflows/required.yml"}]},
        },
        {"type": "future_github_rule", "parameters": {"mustPreserve": True}},
    ]
    before = copy.deepcopy(extras)
    result = controls.ruleset_payload(extras, promotion_app_id=12345)
    assert result["rules"][4:] == extras == before


@pytest.mark.parametrize("strict", [False, None, "true", 1])
def test_required_check_names_do_not_substitute_for_strictness(strict):
    ruleset = controls.ruleset_payload(promotion_app_id=12345)
    rule = next(r for r in ruleset["rules"] if r["type"] == "required_status_checks")
    rule["parameters"]["strict_required_status_checks_policy"] = strict
    assert (
        "Active main branch ruleset must require strict status checks."
        in controls.ruleset_verification_blockers(ruleset, promotion_app_id=12345)
    )


@pytest.mark.parametrize(
    "item",
    [
        None,
        {},
        {"type": "Team", "id": 7},
        {"type": "Team", "reviewer": {"id": 7}},
        {"type": "User", "reviewer": None},
        {"type": "User", "id": True},
        {"type": "User", "id": 0},
        {"type": "User", "id": "7"},
    ],
)
@pytest.mark.parametrize("nested", [False, True])
def test_extra_reviewer_cannot_hide_behind_the_configured_user(item, nested):
    environment = controls.protected_reviewer_environment_payload(7)
    environment["deployment_branch_policies"] = [{"name": "main", "type": "branch"}]
    if nested:
        environment["protection_rules"] = [
            {"type": "required_reviewers", "reviewers": [item]}
        ]
    else:
        environment["reviewers"].append(item)
    assert (
        "Test environment includes a malformed or non-user reviewer."
        in controls.protected_environment_verification_blockers(
            environment, 7, label="Test environment"
        )
    )


@pytest.mark.parametrize(
    "mutation",
    [
        {"reviewers": None},
        {"protection_rules": None},
        {"protection_rules": [None]},
        {"protection_rules": [{"type": "required_reviewers"}]},
    ],
)
def test_malformed_reviewer_containers_fail_closed(mutation):
    environment = controls.protected_reviewer_environment_payload(7)
    environment.update(mutation)
    assert not controls.environment_has_only_user_reviewers(environment)


def test_exact_user_reviewer_survives_both_github_response_shapes():
    for environment in [
        {"reviewers": [{"type": "User", "id": 7}]},
        {
            "protection_rules": [
                {"type": "wait_timer"},
                {
                    "type": "required_reviewers",
                    "reviewers": [{"type": "User", "reviewer": {"id": 7}}],
                },
            ]
        },
        {},
    ]:
        assert controls.environment_has_only_user_reviewers(environment)


def test_status_update_preserves_extra_contexts_and_existing_issuers():
    original = {
        "type": "required_status_checks",
        "parameters": {
            "strict_required_status_checks_policy": False,
            "do_not_enforce_on_create": False,
            "required_status_checks": [
                {"context": "CodeQL (python)", "integration_id": 15368},
                {"context": "Extra reviewed gate", "integration_id": 999},
                {"context": "Another external check", "integration_id": None},
                {"context": "Governance Promotion", "integration_id": 12345},
            ],
        },
    }
    before = copy.deepcopy(original)
    result = controls.ruleset_payload([original], promotion_app_id=12345)
    rule = next(r for r in result["rules"] if r["type"] == "required_status_checks")
    checks = rule["parameters"]["required_status_checks"]
    assert checks[:4] == before["parameters"]["required_status_checks"]
    assert len([c for c in checks if c["context"] == "CodeQL (python)"]) == 1
    assert rule["parameters"]["strict_required_status_checks_policy"] is True
    assert rule["parameters"]["do_not_enforce_on_create"] is False
    assert controls.ruleset_verification_blockers(result, promotion_app_id=12345) == []
    assert original == before


@pytest.mark.parametrize("old_issuer", [None, 12345])
def test_unbound_promotion_can_be_narrowed_without_losing_other_checks(old_issuer):
    existing = {
        "parameters": {
            "required_status_checks": [
                {"context": "Governance Promotion", "integration_id": old_issuer},
                {"context": "External gate", "integration_id": 123},
            ]
        }
    }
    result = controls.harden_required_status_checks_rule(
        existing, promotion_app_id=12345
    )
    assert result["parameters"]["required_status_checks"][:2] == [
        {"context": "Governance Promotion", "integration_id": 12345},
        {"context": "External gate", "integration_id": 123},
    ]


def test_conflicting_existing_promotion_issuer_requires_explicit_reconciliation():
    existing = {
        "parameters": {
            "required_status_checks": [
                {"context": "Governance Promotion", "integration_id": 98765}
            ]
        }
    }
    with pytest.raises(ValueError, match="issuer requires explicit reconciliation"):
        controls.harden_required_status_checks_rule(existing, promotion_app_id=12345)


@pytest.mark.parametrize(
    "existing",
    [
        {"parameters": None},
        {"parameters": {"required_status_checks": None}},
        {"parameters": {"required_status_checks": [None]}},
        {"parameters": {"required_status_checks": [{}]}},
        {"parameters": {"required_status_checks": [{"context": " "}]}},
    ],
)
def test_malformed_existing_checks_fail_without_dropping_them(existing):
    with pytest.raises(ValueError):
        controls.harden_required_status_checks_rule(existing, promotion_app_id=12345)


def test_multiple_status_rules_cannot_silently_discard_the_first():
    rules = [controls.required_status_checks_rule(promotion_app_id=12345)] * 2
    with pytest.raises(ValueError, match="Multiple existing status-check rules"):
        controls.ruleset_payload(rules, promotion_app_id=12345)


@pytest.mark.parametrize("app_id", [0, -1, 15368])
def test_ruleset_update_rejects_invalid_or_shared_promotion_issuer(app_id):
    with pytest.raises(ValueError):
        controls.ruleset_payload(promotion_app_id=app_id)


@pytest.mark.parametrize(
    "direct_id,nested_id", [(7, 8), (8, 7), (True, 7), (None, 7), ("7", 7)]
)
@pytest.mark.parametrize("nested", [False, True])
def test_conflicting_dual_reviewer_identity_fails_before_sole_user_check(
    direct_id, nested_id, nested
):
    environment = controls.protected_reviewer_environment_payload(7)
    environment["deployment_branch_policies"] = [{"name": "main", "type": "branch"}]
    item = {"type": "User", "id": direct_id, "reviewer": {"id": nested_id}}
    environment["reviewers"] = [item]
    if nested:
        environment["reviewers"] = [{"type": "User", "id": 7}]
        environment["protection_rules"] = [
            {"type": "required_reviewers", "reviewers": [item]}
        ]
    assert any(
        "malformed or non-user reviewer" in blocker
        for blocker in controls.protected_environment_verification_blockers(
            environment, 7, label="Test environment"
        )
    )


def test_matching_dual_reviewer_identity_preserves_official_response_shapes():
    environment = controls.protected_reviewer_environment_payload(7)
    environment["deployment_branch_policies"] = [{"name": "main", "type": "branch"}]
    environment["reviewers"] = [{"type": "User", "id": 7, "reviewer": {"id": 7}}]
    assert (
        controls.protected_environment_verification_blockers(
            environment, 7, label="Test environment"
        )
        == []
    )
