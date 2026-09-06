"""Promotion proofs require successful immutable account stages and exact SHA."""

from __future__ import annotations

import hashlib
import importlib
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
promotion = importlib.import_module("governance_promotion")
SHA = "a" * 40


def needs_fixture():
    needs = {name: {"result": "success"} for name in promotion.REQUIRED_STAGES}
    needs["preflight"]["outputs"] = {
        "head_sha": SHA,
        "base_sha": "b" * 40,
        "source_run_id": "99",
        "comment_id": "42",
        "command": "up",
        "target_environment": "prod",
        "pull_request_number": "78",
    }
    return needs


@pytest.fixture
def runtime(monkeypatch, tmp_path):
    monkeypatch.setenv("GITHUB_REPOSITORY", "org/repo")
    monkeypatch.setenv("GITHUB_SERVER_URL", "https://github.com")
    monkeypatch.setenv("GITHUB_RUN_ID", "100")
    monkeypatch.setenv("PROMOTION_APP_SLUG", "promotion-evidence")
    monkeypatch.setenv("PROMOTION_ARTIFACT_ID", "123")
    monkeypatch.setenv("PROMOTION_NEEDS", json.dumps(needs_fixture()))
    event_path = tmp_path / "event.json"
    event_path.write_text('{"number":78}')
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event_path))
    monkeypatch.setattr(promotion, "PROOF_PATH", tmp_path / "artifact" / "proof.json")
    monkeypatch.setattr(promotion, "TRUSTED_SOURCE_ROOT", tmp_path / "trusted")
    inputs = tmp_path / "plans"
    monkeypatch.setattr(promotion, "PLAN_INPUT_PATH", inputs)
    for environment in ("test", "prod"):
        directory = inputs / environment
        directory.mkdir(parents=True)
        plan = environment.encode()
        (directory / "saved.plan").write_bytes(plan)
        (directory / "manifest.json").write_text(
            json.dumps(
                {
                    "commitSha": SHA,
                    "schemaVersion": 1,
                    "backendUrl": f"s3://backend-{environment}",
                    "pulumiDir": "pulumi",
                    "policyPackDir": "policy",
                    "stacks": [
                        {
                            "stack": environment,
                            "planFile": ".artifacts/pulumi-plan/saved.plan",
                            "planSha256": hashlib.sha256(plan).hexdigest(),
                        }
                    ],
                }
            )
        )
    return event_path


def test_api_write_preserves_literal_json(monkeypatch):
    calls = []
    monkeypatch.setattr(
        promotion.subprocess,
        "run",
        lambda args, **kw: (
            calls.append((args, kw)) or SimpleNamespace(stdout='{"id":1}')
        ),
    )
    assert promotion.api_write("endpoint", {"body": "literal\n$(no shell)"}) == {
        "id": 1
    }
    assert calls[0][0] == ["gh", "api", "endpoint", "--method", "POST", "--input", "-"]
    assert json.loads(calls[0][1]["input"]) == {"body": "literal\n$(no shell)"}


def test_prepare_and_publish_project_exact_proof(runtime, monkeypatch):
    writes = []
    monkeypatch.setattr(
        promotion,
        "gh",
        lambda *args: {
            "state": "open",
            "merged": False,
            "head": {"sha": SHA, "repo": {"full_name": "org/repo"}},
            "base": {"sha": "b" * 40, "ref": "main", "repo": {"full_name": "org/repo"}},
        },
    )
    monkeypatch.setattr(
        promotion,
        "api_write",
        lambda path, payload: writes.append((path, payload)) or {"id": 11, "sha": SHA},
    )
    assert promotion.main(["prepare"]) == 0
    proof = json.loads(promotion.PROOF_PATH.read_text())
    assert proof["stages"] == {stage: "success" for stage in promotion.REQUIRED_STAGES}
    assert promotion.main(["publish"]) == 0
    assert len(writes) == 5
    deployments = [payload for path, payload in writes if path.endswith("/deployments")]
    assert [payload["environment"] for payload in deployments] == ["test", "prod"]
    assert all(payload["ref"] == SHA for payload in deployments)
    assert all(payload["payload"]["run_id"] == "100" for payload in deployments)
    assert all(
        payload["payload"]["artifact_url"].endswith("/artifacts/123")
        for payload in deployments
    )
    assert writes[-1][1]["context"] == promotion.CONTEXT
    assert writes[-1][1]["state"] == "success"
    promotion.PROOF_PATH.write_text("{}")
    with pytest.raises(ValueError, match="artifact changed"):
        promotion.main(["publish"])


@pytest.mark.parametrize("stage", promotion.REQUIRED_STAGES)
@pytest.mark.parametrize("result", ["skipped", "failure", "cancelled"])
def test_failed_or_missing_stage_cannot_publish(runtime, stage, result):
    needs = needs_fixture()
    needs[stage]["result"] = result
    with pytest.raises(ValueError, match="did not all succeed"):
        promotion.build_proof(needs)
    del needs[stage]
    with pytest.raises(ValueError):
        promotion.build_proof(needs)


@pytest.mark.parametrize(
    "key,value",
    [
        ("command", "plan"),
        ("target_environment", "test"),
        ("head_sha", "invalid"),
        ("pull_request_number", "0"),
    ],
)
def test_only_exact_prod_up_can_build_proof(runtime, key, value):
    needs = needs_fixture()
    needs["preflight"]["outputs"][key] = value
    with pytest.raises(ValueError):
        promotion.build_proof(needs)


def test_invalid_run_id_rejected(runtime, monkeypatch):
    monkeypatch.setenv("GITHUB_RUN_ID", "invalid")
    with pytest.raises(ValueError):
        promotion.build_proof(needs_fixture())


@pytest.mark.parametrize("sha", ["invalid", "A" * 40, "a" * 39])
def test_matching_plan_sha_cannot_make_malformed_head_valid(runtime, sha):
    """Internally consistent artifacts still need a valid verified commit ID."""
    needs = needs_fixture()
    needs["preflight"]["outputs"]["head_sha"] = sha
    for environment in ("test", "prod"):
        path = promotion.PLAN_INPUT_PATH / environment / "manifest.json"
        manifest = json.loads(path.read_text())
        manifest["commitSha"] = sha
        path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="Invalid verified SHA"):
        promotion.build_proof(needs)


@pytest.mark.parametrize(
    "pr",
    [
        {"state": "closed", "merged": False, "head": {"sha": SHA}},
        {"state": "open", "merged": True, "head": {"sha": SHA}},
        {"state": "open", "merged": False, "head": {"sha": "b" * 40}},
    ],
)
def test_stale_or_closed_pr_never_gets_deployment_projection(runtime, monkeypatch, pr):
    monkeypatch.setattr(promotion, "gh", lambda *args: pr)
    with pytest.raises(ValueError):
        promotion.publish_proof(promotion.build_proof(needs_fixture()))


def test_missing_artifact_or_wrong_deployment_sha_rejected(runtime, monkeypatch):
    monkeypatch.setattr(
        promotion,
        "gh",
        lambda *args: {
            "state": "open",
            "merged": False,
            "head": {"sha": SHA, "repo": {"full_name": "org/repo"}},
            "base": {"sha": "b" * 40, "ref": "main", "repo": {"full_name": "org/repo"}},
        },
    )
    monkeypatch.setenv("PROMOTION_ARTIFACT_ID", "")
    proof = promotion.build_proof(needs_fixture())
    with pytest.raises(ValueError, match="Missing proof artifact"):
        promotion.publish_proof(proof)
    monkeypatch.setenv("PROMOTION_ARTIFACT_ID", "1")
    monkeypatch.setattr(promotion, "api_write", lambda *args: {"sha": "b" * 40})
    with pytest.raises(ValueError, match="Deployment SHA"):
        promotion.publish_proof(proof)


@pytest.mark.parametrize(
    "filename,expected", [("README.md", "success"), ("Makefile", "pending")]
)
@pytest.mark.parametrize("verified", [False, True])
def test_scope_success_for_unrelated_pending_for_governance(
    runtime, monkeypatch, filename, expected, verified
):
    writes = []
    kind = "governance" if filename == "Makefile" else "platform"
    status = {
        "context": promotion.CONTEXT,
        "state": "success",
        "description": promotion.promotion_description(78, "b" * 40, kind),
        "creator": {"login": "promotion-evidence[bot]"},
    }

    def api(path, *args):
        if "/compare/" in path:
            return {"files": [{"filename": filename}]}
        if "/statuses?" in path:
            return [[status] if verified else []]
        return {
            "head": {"sha": SHA},
            "changed_files": 1,
            "base": {"ref": "main", "sha": "b" * 40},
        }

    monkeypatch.setattr(promotion, "gh", api)
    monkeypatch.setattr(
        promotion, "api_write", lambda path, payload: writes.append(payload)
    )
    assert promotion.main(["scope"]) == 0
    if verified:
        assert writes == []
    else:
        assert writes[0]["state"] == expected


@pytest.mark.parametrize(
    "key,value",
    [
        ("context", "Other"),
        ("state", "pending"),
        ("description", "No governance changes"),
        ("creator", {"login": "attacker"}),
    ],
)
def test_untrusted_or_plan_status_is_not_promotion_proof(runtime, key, value):
    status = {
        "context": promotion.CONTEXT,
        "state": "success",
        "description": promotion.promotion_description(78, "b" * 40, "governance"),
        "creator": {"login": "promotion-evidence[bot]"},
    }
    status[key] = value
    assert (
        promotion.verified_promotion_status(status, 78, "b" * 40, "governance") is False
    )


def test_scope_rejects_incomplete_listing(runtime, monkeypatch):
    monkeypatch.setattr(
        promotion,
        "gh",
        lambda path, *args: (
            {"files": []}
            if "/compare/" in path
            else {
                "head": {"sha": SHA},
                "changed_files": 3001,
                "base": {"ref": "main", "sha": "b" * 40},
            }
        ),
    )
    with pytest.raises(ValueError, match="Incomplete"):
        promotion.report_scope()


@pytest.mark.parametrize("stage", promotion.PLATFORM_STAGES)
@pytest.mark.parametrize("result", ["skipped", "failure", "cancelled"])
@pytest.mark.parametrize("kind", ["platform", "service"])
def test_platform_projection_rejects_every_unsuccessful_stage(
    runtime, monkeypatch, stage, result, kind
):
    monkeypatch.setenv("PROMOTION_KIND", kind)
    needs = {name: {"result": "success"} for name in promotion.PLATFORM_STAGES}
    needs["preflight"]["outputs"] = needs_fixture()["preflight"]["outputs"]
    proof = promotion.build_proof(needs)
    assert proof["kind"] == kind
    assert proof["workflow"] == (
        ".github/workflows/self-deploy.yml"
        if kind == "service"
        else ".github/workflows/pulumi-pr-command-runner.yml"
    )
    assert set(proof["saved_plans"]) == {"test", "prod"}
    needs[stage]["result"] = result
    with pytest.raises(ValueError, match="did not all succeed"):
        promotion.build_proof(needs)


@pytest.mark.parametrize(
    "key,value", [("base_sha", "invalid"), ("comment_id", "0"), ("source_run_id", "")]
)
def test_invalid_intake_provenance_cannot_publish(runtime, key, value):
    needs = needs_fixture()
    needs["preflight"]["outputs"][key] = value
    with pytest.raises(ValueError):
        promotion.build_proof(needs)


@pytest.mark.parametrize("change", ["sha", "schema", "empty", "path", "digest"])
def test_saved_plan_proof_rejects_swapped_or_corrupt_artifacts(runtime, change):
    file = promotion.PLAN_INPUT_PATH / "test/manifest.json"
    manifest = json.loads(file.read_text())
    if change == "sha":
        manifest["commitSha"] = "c" * 40
    elif change == "schema":
        manifest["schemaVersion"] = 2
    elif change == "empty":
        manifest["stacks"] = []
    elif change == "path":
        manifest["stacks"][0]["planFile"] = "../../outside"
    else:
        manifest["stacks"][0]["planSha256"] = "0" * 64
    file.write_text(json.dumps(manifest))
    with pytest.raises(ValueError):
        promotion.build_proof(needs_fixture())


def test_moved_base_cannot_publish_valid_saved_plans(runtime, monkeypatch):
    monkeypatch.setattr(
        promotion,
        "gh",
        lambda *args: {
            "state": "open",
            "merged": False,
            "head": {"sha": SHA},
            "base": {"sha": "c" * 40},
        },
    )
    with pytest.raises(ValueError, match="base moved"):
        promotion.publish_proof(promotion.build_proof(needs_fixture()))


def test_unknown_promotion_kind_is_rejected(runtime, monkeypatch):
    monkeypatch.setenv("PROMOTION_KIND", "untrusted")
    with pytest.raises(ValueError, match="Invalid promotion kind"):
        promotion.build_proof(needs_fixture())


@pytest.mark.parametrize("branch", ["main", "*"])
def test_cli_checks_actual_evidence_environment_before_app_auth(
    runtime, monkeypatch, branch
):
    monkeypatch.setattr(
        promotion,
        "gh",
        lambda endpoint: (
            {"branch_policies": [{"name": branch, "type": "branch"}]}
            if endpoint.endswith("/deployment-branch-policies")
            else promotion.evidence_environment.payload()
        ),
    )
    if branch == "main":
        assert promotion.main(["verify-environment"]) == 0
    else:
        with pytest.raises(ValueError, match="only the main branch"):
            promotion.main(["verify-environment"])


@pytest.mark.parametrize("kind", ["platform", "service"])
def test_platform_publishes_current_head_deployments_with_bound_origin(
    runtime, monkeypatch, kind
):
    monkeypatch.setenv("PROMOTION_KIND", kind)
    needs = {name: {"result": "success"} for name in promotion.PLATFORM_STAGES}
    needs["preflight"]["outputs"] = needs_fixture()["preflight"]["outputs"]
    monkeypatch.setattr(
        promotion,
        "gh",
        lambda *_args: {
            "state": "open",
            "merged": False,
            "head": {"sha": SHA, "repo": {"full_name": "org/repo"}},
            "base": {"sha": "b" * 40, "ref": "main", "repo": {"full_name": "org/repo"}},
        },
    )
    writes = []
    monkeypatch.setattr(
        promotion,
        "api_write",
        lambda path, payload: writes.append((path, payload)) or {"id": 11, "sha": SHA},
    )
    promotion.publish_proof(promotion.build_proof(needs))
    deployments = [value for path, value in writes if path.endswith("/deployments")]
    assert {value["environment"] for value in deployments} == {"test", "prod"}
    for value in deployments:
        assert value["ref"] == SHA
        assert value["payload"]["source_run_id"] == "99"
        assert value["payload"]["base_sha"] == "b" * 40
        assert value["payload"]["comment_id"] == "42"
        assert value["required_contexts"] == []


@pytest.mark.parametrize("side", ["base", "head"])
@pytest.mark.parametrize("repository", ["other/repo", "org/fork", None, {}])
def test_foreign_pr_repo_blocks_writes(runtime, monkeypatch, side, repository):
    """Unchanged commit IDs cannot authorize a different repository identity."""
    pr = {
        "state": "open",
        "merged": False,
        "head": {"sha": SHA, "repo": {"full_name": "org/repo"}},
        "base": {
            "sha": "b" * 40,
            "ref": "main",
            "repo": {"full_name": "org/repo"},
        },
    }
    pr[side]["repo"] = (
        {"full_name": repository} if isinstance(repository, str) else repository
    )
    monkeypatch.setattr(promotion, "gh", lambda *_args: pr)
    writes = []
    monkeypatch.setattr(promotion, "api_write", lambda *args: writes.append(args))
    with pytest.raises(ValueError, match="repository identity"):
        promotion.publish_proof(promotion.build_proof(needs_fixture()))
    assert writes == []


def test_same_sha_retarget_blocks_writes(runtime, monkeypatch):
    """A branch retarget remains invalid even when both commits are unchanged."""
    monkeypatch.setattr(
        promotion,
        "gh",
        lambda *_args: {
            "state": "open",
            "merged": False,
            "head": {"sha": SHA, "repo": {"full_name": "org/repo"}},
            "base": {
                "sha": "b" * 40,
                "ref": "release",
                "repo": {"full_name": "org/repo"},
            },
        },
    )
    writes = []
    monkeypatch.setattr(promotion, "api_write", lambda *args: writes.append(args))
    with pytest.raises(ValueError, match="no longer targets main"):
        promotion.publish_proof(promotion.build_proof(needs_fixture()))
    assert writes == []


def test_foreign_proof_stops_before_api(runtime, monkeypatch):
    """A proof cannot select its own external API repository."""
    proof = promotion.build_proof(needs_fixture())
    proof["repository"] = "foreign/repository"
    calls = []
    monkeypatch.setattr(promotion, "gh", lambda *args: calls.append(args))
    monkeypatch.setattr(promotion, "api_write", lambda *args: calls.append(args))
    with pytest.raises(ValueError, match="another repository"):
        promotion.publish_proof(proof)
    assert calls == []


@pytest.mark.parametrize("filename", ["README.md", "Makefile"])
@pytest.mark.parametrize("mismatch", [None, "kind", "creator", "base", "pr"])
def test_service_preserves_exact_proof(runtime, monkeypatch, filename, mismatch):
    """Trusted service controllers preserve only their own current App proof."""
    marker = promotion.TRUSTED_SOURCE_ROOT / promotion.PROMOTION_WORKFLOWS["service"]
    marker.parent.mkdir(parents=True)
    marker.write_text("name: Self Deploy\n")
    status = {
        "context": promotion.CONTEXT,
        "state": "success",
        "description": promotion.promotion_description(78, "b" * 40, "service"),
        "creator": {"login": "promotion-evidence[bot]"},
    }
    if mismatch == "kind":
        status["description"] = promotion.promotion_description(
            78, "b" * 40, "platform"
        )
    elif mismatch == "creator":
        status["creator"]["login"] = "foreign-evidence[bot]"
    elif mismatch == "base":
        status["description"] = promotion.promotion_description(78, "c" * 40, "service")
    elif mismatch == "pr":
        status["description"] = promotion.promotion_description(79, "b" * 40, "service")

    def api(path, *args):
        if "/compare/" in path:
            return {"files": [{"filename": filename}]}
        if "/statuses?" in path:
            assert path == f"repos/org/repo/commits/{SHA}/statuses?per_page=100"
            return [[status]]
        return {
            "head": {"sha": SHA},
            "changed_files": 1,
            "base": {"ref": "main", "sha": "b" * 40},
        }

    writes = []
    monkeypatch.setattr(promotion, "gh", api)
    monkeypatch.setattr(promotion, "api_write", lambda *args: writes.append(args))
    promotion.report_scope()
    if mismatch is None:
        assert writes == []
    else:
        assert len(writes) == 1
        assert writes[0][1]["state"] == "pending"
        assert writes[0][1]["description"].startswith("Service requires")


def test_pr_marker_cannot_select_service(runtime, monkeypatch, tmp_path):
    """Ambient PR/artifact files cannot influence trusted repository scope."""
    untrusted = tmp_path / "pr-checkout"
    marker = untrusted / promotion.PROMOTION_WORKFLOWS["service"]
    marker.parent.mkdir(parents=True)
    marker.write_text("name: Attacker supplied marker\n")
    monkeypatch.chdir(untrusted)
    assert promotion.scope_promotion_kind(False) == "platform"
    assert promotion.scope_promotion_kind(True) == "governance"
