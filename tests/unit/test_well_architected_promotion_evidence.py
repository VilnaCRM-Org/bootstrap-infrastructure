"""The central evidence gate cannot accept an obsolete or unbound promotion."""

from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import _github_repository_controls as controls  # noqa: E402
import _well_architected_github_repository_evidence as evidence  # noqa: E402
import collect_well_architected_evidence as collector  # noqa: E402
from test_deployment_promotion_scope import (  # noqa: E402
    PLATFORM_ONLY,
)
from test_deployment_promotion_scope import (
    github as _github,
)
from test_deployment_promotion_scope import (
    graph as _graph,
)
from test_deployment_promotion_scope import (
    prepared as _prepared,
)
from test_deployment_promotion_scope import (
    promotion as _promotion,
)
from test_deployment_promotion_scope import (
    publication as _publication,
)
from test_deployment_promotion_scope import (
    receipt_data as _receipt_data,
)
from test_deployment_promotion_scope import (
    verified_publication as _verified_publication,
)

github, graph, prepared, promotion, publication, receipt_data, verified_publication = (
    _github,
    _graph,
    _prepared,
    _promotion,
    _publication,
    _receipt_data,
    _verified_publication,
)

REPO = controls.CENTRAL_REPOSITORY
CONTEXT = controls.INFRASTRUCTURE_PROMOTION_CONTEXT


def completed(argv, value, *, ok=True):
    return subprocess.CompletedProcess(
        argv, 0 if ok else 1, json.dumps(value), "denied"
    )


@pytest.fixture
def policies():
    return {
        "classic": {
            "required_status_checks": {"contexts": ["Unit"]},
            "required_pull_request_reviews": {"required_approving_review_count": 1},
        },
        "summaries": [{"id": 1}],
        "ruleset": {
            "id": 1,
            "bypass_actors": [],
            "target": "branch",
            "enforcement": "active",
            "conditions": {"ref_name": {"include": ["refs/heads/main"], "exclude": []}},
            "rules": [
                controls.required_status_checks_rule(
                    promotion_app_id=controls.CENTRAL_PROMOTION_APP_ID, repository=REPO
                )
            ],
        },
    }


def collect(policies, *, repo=REPO, expected=None):
    def runner(argv, **_kwargs):
        path = argv[-1]
        if path.endswith("/protection"):
            return completed(
                argv, policies["classic"], ok=policies.get("classic_ok", True)
            )
        if path.endswith(("/rulesets", "/rulesets?per_page=100")):
            return completed(
                argv, policies["summaries"], ok=policies.get("list_ok", True)
            )
        assert path.endswith("/rulesets/1")
        return completed(argv, policies["ruleset"], ok=policies.get("detail_ok", True))

    return evidence.github_branch_protection(repo, "main", expected, runner=runner)


def test_central_defaults_and_bound_gate(policies):
    result = collect(policies)
    assert result["status"] == "passed"
    required = result["evidence"]["expectedRequiredStatusChecks"]
    assert CONTEXT in required
    assert "Governance Promotion" not in required
    assert set(required) == set(controls.required_status_checks_for_repository(REPO))


@pytest.mark.parametrize("issuer", [None, True, "4840884", 15368, 12345])
def test_central_wrong_ruleset_issuer(policies, issuer):
    checks = policies["ruleset"]["rules"][0]["parameters"]["required_status_checks"]
    checks[0]["integration_id"] = issuer
    assert collect(policies)["status"] == "failed"


@pytest.mark.parametrize(
    "change", ["legacy", "duplicate", "exclude", "inactive", "other_branch", "tag"]
)
def test_central_ruleset_scope_rejected(policies, change):
    ruleset = policies["ruleset"]
    checks = ruleset["rules"][0]["parameters"]["required_status_checks"]
    if change == "legacy":
        checks.append({"context": "Governance Promotion", "integration_id": 4840884})
    elif change == "duplicate":
        checks.append(copy.deepcopy(checks[0]))
    elif change == "exclude":
        ruleset["conditions"]["ref_name"]["exclude"] = ["refs/heads/main"]
    elif change == "inactive":
        ruleset["enforcement"] = "evaluate"
    elif change == "other_branch":
        ruleset["conditions"]["ref_name"]["include"] = ["refs/heads/other"]
    else:
        ruleset["target"] = "tag"
    assert collect(policies)["status"] == "failed"


@pytest.mark.parametrize("reference", ["~ALL", "~DEFAULT_BRANCH", "refs/heads/main"])
def test_central_known_branch_policy(policies, reference):
    policies["ruleset"]["conditions"]["ref_name"]["include"] = [reference]
    assert collect(policies)["status"] == "passed"


@pytest.mark.parametrize("strict", [False, None, "true", 1])
def test_nonstrict_promotion_gate_fails(policies, strict):
    policies["ruleset"]["rules"][0]["parameters"][
        "strict_required_status_checks_policy"
    ] = strict
    assert collect(policies)["status"] == "failed"


def test_bypass_actor_blocks_promotion(policies):
    policies["ruleset"]["bypass_actors"] = [
        {"actor_type": "OrganizationAdmin", "actor_id": 1, "bypass_mode": "always"}
    ]
    assert collect(policies)["status"] == "failed"


@pytest.mark.parametrize("actors", [None, 0, False, "", {}])
def test_unknown_bypass_list_blocks(policies, actors):
    policies["ruleset"]["bypass_actors"] = actors
    assert collect(policies)["status"] == "failed"


def test_missing_bypass_list_blocks(policies):
    del policies["ruleset"]["bypass_actors"]
    assert collect(policies)["status"] == "failed"


@pytest.mark.parametrize(
    "conditions",
    [
        None,
        [],
        {},
        {"ref_name": None},
        {"ref_name": []},
        {"ref_name": {"include": "~ALL", "exclude": []}},
        {"ref_name": {"include": [None], "exclude": []}},
        {"ref_name": {"include": ["~ALL"], "exclude": None}},
        {"ref_name": {"include": ["~ALL"], "exclude": [False]}},
    ],
)
def test_malformed_rule_refs_block(policies, conditions):
    policies["ruleset"]["conditions"] = conditions
    assert collect(policies)["status"] == "failed"


@pytest.mark.parametrize("issuer", [4840884, None, True, "4840884", 15368])
def test_classic_requires_concrete_app(policies, issuer):
    policies["summaries"] = []
    policies["classic"]["required_status_checks"] = {
        "contexts": list(controls.required_status_checks_for_repository(REPO)),
        "checks": [{"context": CONTEXT, "app_id": issuer}],
    }
    assert (collect(policies)["status"] == "passed") is (
        type(issuer) is int and issuer == 4840884
    )


@pytest.mark.parametrize(
    "change", ["unbound", "legacy_context", "legacy_check", "duplicate"]
)
def test_weak_classic_rule_still_blocks(policies, change):
    classic = policies["classic"]["required_status_checks"]
    classic["contexts"] = [CONTEXT]
    classic["checks"] = [{"context": CONTEXT, "app_id": 4840884}]
    if change == "unbound":
        classic["checks"] = []
    elif change == "legacy_context":
        classic["contexts"].append("Governance Promotion")
    elif change == "legacy_check":
        classic["checks"].append({"context": "Governance Promotion", "app_id": 4840884})
    else:
        classic["checks"] *= 2
    assert collect(policies)["status"] == "failed"


@pytest.mark.parametrize(
    "summaries",
    [
        [None],
        [{}],
        [{"id": True}],
        [{"id": -1}],
        [{"id": 1}] * 2,
        [{"id": i} for i in range(100)],
    ],
)
def test_incomplete_ruleset_inventory(policies, summaries):
    policies["summaries"] = summaries
    assert collect(policies)["status"] == "failed"


@pytest.mark.parametrize("field", ["list_ok", "detail_ok"])
def test_unreadable_policy_is_blocking(policies, field):
    policies[field] = False
    assert collect(policies)["status"] == "failed"


def test_custom_checks_cannot_waive_app(policies):
    policies["summaries"] = []
    assert collect(policies, expected=["Unit"])["status"] == "failed"


def test_unrelated_gate_cannot_bind_app(policies):
    policies["ruleset"]["rules"][0]["parameters"]["required_status_checks"] = [
        {"context": "Unit", "integration_id": 4840884}
    ]
    assert collect(policies, expected=["Unit"])["status"] == "failed"


def test_service_legacy_defaults_preserved(policies):
    policies["summaries"] = []
    policies["classic"]["required_status_checks"]["contexts"] = list(
        controls.REQUIRED_STATUS_CHECKS
    )
    result = collect(policies, repo="VilnaCRM-Org/user-service-infrastructure")
    assert result["status"] == "passed"
    assert "Governance Promotion" in result["evidence"]["expectedRequiredStatusChecks"]
    assert CONTEXT not in result["evidence"]["expectedRequiredStatusChecks"]


@pytest.fixture
def promotion_stub(monkeypatch):
    calls = []
    snapshot = {
        "head_sha": "a" * 40,
        "state": "success",
        "completion_kind": "apply-drift",
    }

    def verify(pr, *, expected_head_sha):
        calls.append((pr, expected_head_sha))
        return snapshot

    def status(value):
        assert value is snapshot
        calls.append("status")

    module = SimpleNamespace(
        verify_current_promotion=verify, verify_current_promotion_status=status
    )
    monkeypatch.setitem(sys.modules, "deployment_promotion_scope", module)
    return SimpleNamespace(calls=calls, snapshot=snapshot, module=module)


def passing_check():
    return {
        "name": "github_pr_checks",
        "status": "passed",
        "evidence": {
            "headRefOid": "a" * 40,
            "changedFilePaths": ["pulumi/__main__.py"],
        },
        "blockers": [],
    }


def test_central_checks_verify_both_proofs(promotion_stub, monkeypatch):
    original = passing_check()
    monkeypatch.setattr(
        collector._github_pr_checks_evidence,
        "github_pr_checks",
        lambda *a, **kw: original,
    )
    result = collector.github_pr_checks(REPO, 217)
    assert result["status"] == "passed"
    metadata = cast(dict[str, Any], result["evidence"])
    assert metadata["promotion"] == promotion_stub.snapshot
    assert promotion_stub.calls == [(217, "a" * 40), "status"]
    assert metadata["changedFilePaths"] == ["pulumi/__main__.py"]
    assert "promotion" not in original["evidence"]


@pytest.mark.parametrize("repo,pr", [("org/service", 217), (REPO, None)])
def test_service_has_no_central_dependency(promotion_stub, monkeypatch, repo, pr):
    original = passing_check()
    monkeypatch.setattr(
        collector._github_pr_checks_evidence,
        "github_pr_checks",
        lambda *a, **kw: original,
    )
    assert collector.github_pr_checks(repo, pr) is original
    assert not promotion_stub.calls


@pytest.mark.parametrize("phase", ["proof", "status"])
@pytest.mark.parametrize(
    "reason", ["stale base", "stale head", "foreign issuer", "pending selection"]
)
def test_rejected_promotion_blocks(promotion_stub, phase, reason):
    def reject(*args, **kwargs):
        raise ValueError(reason)

    if phase == "proof":
        promotion_stub.module.verify_current_promotion = reject
    else:
        promotion_stub.module.verify_current_promotion_status = reject
    result = evidence.with_current_promotion(passing_check(), 217)
    assert result["status"] == "failed"
    assert reason in cast(list[str], result["blockers"])[0]
    assert "promotion" not in cast(dict[str, Any], result["evidence"])


@pytest.mark.parametrize("head", [None, "", "a" * 39, 123])
def test_missing_head_cannot_delegate(promotion_stub, head):
    original = passing_check()
    original["evidence"]["headRefOid"] = head
    assert evidence.with_current_promotion(original, 217)["status"] == "failed"
    assert not promotion_stub.calls


def test_verified_promotion_keeps_all_gates(promotion_stub):
    original = passing_check()
    original["status"] = "failed"
    original["blockers"] = ["Required review missing", "Owner DR evidence expired"]
    result = evidence.with_current_promotion(original, 217)
    assert result["status"] == "failed"
    assert result["blockers"] == original["blockers"]


def test_missing_check_cannot_be_upgraded(promotion_stub):
    result = evidence.with_current_promotion(
        {"name": "github_pr_checks", "status": "unknown"}, 217
    )
    assert result["status"] == "failed"
    assert not promotion_stub.calls


@pytest.mark.parametrize("receipt_data", [PLATFORM_ONLY], indirect=True)
@pytest.mark.parametrize("change", ["none", "head", "base", "status", "writer"])
def test_real_promotion_consumer(verified_publication, monkeypatch, change):
    """Use original artifact, receipt and App records through the real WA consumer."""
    state = verified_publication
    pr = state.api.overrides[f"repos/{REPO}/pulls/78"]
    if change == "head":
        pr["head"]["sha"] = "f" * 40
    elif change == "base":
        pr["base"]["sha"] = "f" * 40
        state.api.overrides[f"repos/{REPO}/compare/{'f' * 40}...{'a' * 40}"] = {
            "files": state.state.github.evidence["changed_file_records"]
        }
    elif change == "status":
        state.api.statuses[f"repos/{REPO}/commits/{'a' * 40}/statuses"][0]["creator"][
            "id"
        ] = 1
    elif change == "writer":
        state.state.github.evidence["permission"] = "read"
    monkeypatch.setenv("GITHUB_EVENT_NAME", "workflow_dispatch")
    monkeypatch.setenv("GITHUB_RUN_ID", "99999")
    monkeypatch.setattr(
        collector._github_pr_checks_evidence,
        "github_pr_checks",
        lambda *a, **kw: passing_check(),
    )
    result = collector.github_pr_checks(REPO, 78)
    assert (result["status"] == "passed") is (change == "none")
    assert not state.api.writes


def test_transport_failure_is_blocker(promotion_stub):
    def failed(*args, **kwargs):
        raise RuntimeError("GitHub request failed")

    promotion_stub.module.verify_current_promotion = failed
    result = evidence.with_current_promotion(passing_check(), 78)
    assert result["status"] == "failed"
    assert "GitHub request failed" in cast(list[str], result["blockers"])[0]
