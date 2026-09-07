"""Verify actual original-publication composition over fake GitHub, without writes."""

from __future__ import annotations

import hashlib
import io
import json
import struct
import sys
import zipfile
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import deployment_promotion_scope as scope  # noqa: E402
from test_deployment_promotion_emitter import (  # noqa: E402
    PLATFORM_ONLY,
    FakeAPI,
    emitter,
)
from test_deployment_promotion_emitter import (
    github as _github,
)
from test_deployment_promotion_emitter import (
    graph as _graph,
)
from test_deployment_promotion_emitter import (
    prepared as _prepared,
)
from test_deployment_promotion_emitter import (
    promotion as _promotion,
)
from test_deployment_promotion_emitter import (
    publication as _publication,
)
from test_deployment_promotion_emitter import (
    receipt_data as _receipt_data,
)
from test_deployment_promotion_proof import publish_jobs  # noqa: E402
from test_deployment_worker_runtime import make_zip  # noqa: E402

github, graph, prepared, promotion, publication, receipt_data = (
    _github,
    _graph,
    _prepared,
    _promotion,
    _publication,
    _receipt_data,
)


def repository():
    return {
        "id": scope.REPOSITORY_ID,
        "full_name": scope.REPOSITORY,
        "owner": {"id": scope.OWNER_ID},
    }


def pull_request():
    return {
        "number": 78,
        "state": "open",
        "merged": False,
        "changed_files": 1,
        "base": {"ref": "main", "sha": "b" * 40, "repo": repository()},
        "head": {
            "ref": "codex/issue215-affected-stacks",
            "sha": "a" * 40,
            "repo": repository(),
        },
    }


@pytest.fixture
def snapshot_api(monkeypatch):
    api = FakeAPI()
    api.overrides[f"{scope.BASE}/pulls/78"] = pull_request()
    api.overrides[f"{scope.BASE}/compare/{'b' * 40}...{'a' * 40}"] = {
        "files": [{"filename": "README.md", "status": "modified"}]
    }
    monkeypatch.setattr(emitter, "_api", api)
    return api


@pytest.fixture
def verified_publication(publication, monkeypatch):
    emitter.publish(**publication.emitter_args)
    api = publication.api
    pr = deepcopy(publication.state.github.evidence["pr"])
    pr.update(number=78, merged=False)
    pr["head"]["repo"] = repository()
    api.overrides[f"{scope.BASE}/pulls/78"] = pr
    api.overrides[f"{scope.BASE}/compare/{'b' * 40}...{'a' * 40}"] = {
        "files": publication.state.github.evidence["changed_file_records"]
    }
    metadata = publication.state.github.overrides[f"{scope.BASE}/actions/artifacts/301"]
    api.overrides[f"{scope.BASE}/actions/runs/100/artifacts?per_page=100&page=1"] = {
        "total_count": 1,
        "artifacts": [metadata],
    }
    run = publication.state.github.overrides[f"{scope.BASE}/actions/runs/100"]
    run.update(status="completed", conclusion="success")
    api.overrides[f"{scope.BASE}/actions/runs/100"] = run
    admission_id = publication.args["artifact_id"]
    admission_raw = make_zip(
        [("contract.json", publication.state.github.contract.read_bytes())]
    )
    # Original graph fixture owns the exact original archive; its digest must match.
    raw = publication.archives.get(admission_id, admission_raw)
    if hashlib.sha256(raw).hexdigest() != publication.args["artifact_sha256"]:
        raw = publication.state.raw
    assert hashlib.sha256(raw).hexdigest() == publication.args["artifact_sha256"]
    monkeypatch.setattr(
        scope,
        "_download_zip",
        lambda identifier: publication.raw if identifier == "301" else raw,
    )
    api.calls.clear()
    return publication


def test_docs_are_truthful_no_deployment_and_readonly(snapshot_api):
    result = scope.verify_current_promotion(78, expected_head_sha="a" * 40)
    assert result["state"] == "success"
    assert result["completion_kind"] == "no-deployment" and result["scopes"] == []
    assert result["status_payload"]["context"] == "Infrastructure Promotion"
    assert len(result["status_payload"]["description"]) <= 140
    assert not snapshot_api.writes
    assert not any("deployments" in path for path, _ in snapshot_api.calls)


@pytest.mark.parametrize("filename", ["pulumi/__main__.py"])
def test_runtime_without_evidence_pending(snapshot_api, filename):
    snapshot_api.overrides[f"{scope.BASE}/compare/{'b' * 40}...{'a' * 40}"]["files"][0][
        "filename"
    ] = filename
    result = scope.verify_current_promotion(78)
    assert result["state"] == result["completion_kind"] == "pending"
    assert result["scopes"]
    assert not snapshot_api.writes


@pytest.mark.parametrize("receipt_data", [PLATFORM_ONLY], indirect=True)
def test_real_original_proof_and_app_deployments(verified_publication, monkeypatch):
    # No emulation of the original root's execution environment is needed.
    monkeypatch.setenv("GITHUB_EVENT_NAME", "unrelated-consumer")
    monkeypatch.setenv("GITHUB_RUN_ID", "99999")
    result = scope.verify_current_promotion(78, expected_head_sha="a" * 40)
    assert result["state"] == "success", result
    assert result["completion_kind"] == "apply-drift"
    assert result["scopes"] == ["platform"]
    status = scope.verify_current_promotion_status(result)
    assert status["creator"]["id"] == emitter.APP_BOT_ID
    assert not verified_publication.api.writes


@pytest.mark.parametrize("receipt_data", [PLATFORM_ONLY], indirect=True)
@pytest.mark.parametrize(
    "corruption",
    [
        "issuer",
        "head",
        "base",
        "selection",
        "expired",
        "run",
        "job",
        "status",
        "proof",
        "metadata",
        "rights",
    ],
)
def test_incomplete_or_forged_publication_stays_pending(
    verified_publication, corruption
):
    state = verified_publication
    prod = next(
        row for row in state.api.deployments.values() if row["environment"] == "prod"
    )
    if corruption == "issuer":
        prod["performed_via_github_app"]["id"] = 1
    elif corruption in ("head", "base"):
        prod["payload"]["identity"][corruption + "_sha"] = "f" * 40
    elif corruption == "selection":
        prod["payload"]["selection_digest"] = "f" * 64
    elif corruption == "expired":
        state.state.github.overrides[f"{scope.BASE}/actions/artifacts/301"][
            "expired"
        ] = True
    elif corruption == "run":
        state.api.overrides[f"{scope.BASE}/actions/runs/100"]["conclusion"] = "failure"
    elif corruption == "job":
        state.state.jobs[0]["conclusion"] = "failure"
        publish_jobs(state.state)
    elif corruption == "status":
        next(iter(state.api.statuses.values()))[0]["state"] = "failure"
    elif corruption == "proof":
        prod["payload"]["proof_digest"] = "f" * 64
    elif corruption == "metadata":
        state.state.github.overrides[f"{scope.BASE}/actions/artifacts/301"][
            "workflow_run"
        ]["head_sha"] = "f" * 40
    else:
        state.state.github.evidence["permission"] = "read"
    assert scope.verify_current_promotion(78)["state"] == "pending"
    assert not state.api.writes


@pytest.mark.parametrize(
    "path,value",
    [
        (("base", "ref"), "other"),
        (("base", "repo", "id"), 1),
        (("head", "repo", "id"), 1),
        (("base", "repo", "owner", "id"), True),
        (("state",), "closed"),
        (("merged",), True),
        (("number",), True),
        (("changed_files",), 301),
        (("changed_files",), 0),
        (("changed_files",), True),
        (("head", "sha"), "bad"),
    ],
)
def test_bad_pr_rejected(snapshot_api, path, value):
    row = snapshot_api.overrides[f"{scope.BASE}/pulls/78"]
    for key in path[:-1]:
        row = row[key]
    row[path[-1]] = value
    with pytest.raises(ValueError):
        scope.verify_current_promotion(78)
    assert not snapshot_api.writes


@pytest.mark.parametrize(
    "number,head", [(True, None), (0, None), ("78", None), (78, "bad"), (78, "f" * 40)]
)
def test_closed_arguments(snapshot_api, number, head):
    with pytest.raises(ValueError):
        scope.verify_current_promotion(number, expected_head_sha=head)


@pytest.mark.parametrize(
    "files",
    [
        None,
        [],
        [{"filename": "../bad", "status": "modified"}],
        [{"filename": "README.md", "status": "renamed"}],
    ],
)
def test_incomplete_diff_never_docs_success(snapshot_api, files):
    snapshot_api.overrides[f"{scope.BASE}/compare/{'b' * 40}...{'a' * 40}"]["files"] = (
        files
    )
    with pytest.raises(ValueError):
        scope.verify_current_promotion(78)


def test_rename_from_runtime_is_selected(snapshot_api):
    snapshot_api.overrides[f"{scope.BASE}/compare/{'b' * 40}...{'a' * 40}"]["files"] = [
        {
            "filename": "README.md",
            "previous_filename": "pulumi/__main__.py",
            "status": "renamed",
        }
    ]
    assert scope.verify_current_promotion(78)["state"] == "pending"


def test_pr_move_during_compare_rejected(snapshot_api):
    def hook(path, payload):
        if "/compare/" in path:
            snapshot_api.overrides[f"{scope.BASE}/pulls/78"]["base"]["sha"] = "c" * 40

    snapshot_api.hook = hook
    with pytest.raises(ValueError, match="moved"):
        scope.verify_current_promotion(78)


def test_docs_status_requires_latest_exact_bot(snapshot_api):
    result = scope.verify_current_promotion(78)
    with pytest.raises(ValueError):
        scope.verify_current_promotion_status(result)
    path = f"{scope.BASE}/statuses/{'a' * 40}"
    snapshot_api.write(path, result["status_payload"])
    assert scope.verify_current_promotion_status(result)["state"] == "success"
    snapshot_api.statuses[f"{scope.BASE}/commits/{'a' * 40}/statuses"][0]["creator"][
        "id"
    ] = 1
    with pytest.raises(ValueError):
        scope.verify_current_promotion_status(result)


def test_copied_success_snapshot_is_not_proof(snapshot_api):
    result = scope.verify_current_promotion(78)
    result["selection_digest"] = "f" * 64
    with pytest.raises(ValueError, match="not verified"):
        scope.verify_current_promotion_status(result)


@pytest.fixture
def scope_context(snapshot_api, monkeypatch, tmp_path):
    sha = "b" * 40
    event = {"repository": repository(), "number": 78, "pull_request": pull_request()}
    path = tmp_path / "event.json"
    path.write_text(json.dumps(event))
    env = {
        "GITHUB_REPOSITORY": scope.REPOSITORY,
        "GITHUB_REPOSITORY_ID": str(scope.REPOSITORY_ID),
        "GITHUB_REPOSITORY_OWNER_ID": str(scope.OWNER_ID),
        "GITHUB_EVENT_NAME": "pull_request_target",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_WORKFLOW_REF": (
            f"{scope.REPOSITORY}/{scope.SCOPE_WORKFLOW}@refs/heads/main"
        ),
        "GITHUB_SHA": sha,
        "GITHUB_WORKFLOW_SHA": sha,
        "GITHUB_RUN_ID": "900",
        "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_EVENT_PATH": str(path),
    }
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    run = {
        "id": 900,
        "run_attempt": 1,
        "event": "pull_request_target",
        "path": scope.SCOPE_WORKFLOW,
        "head_branch": "codex/issue215-affected-stacks",
        "head_sha": "a" * 40,
        "repository": repository(),
        "head_repository": repository(),
    }
    snapshot_api.overrides[f"{scope.BASE}/actions/runs/900"] = run
    return SimpleNamespace(api=snapshot_api, event=event, path=path, env=env, run=run)


def test_protected_report_posts_only_new_context_idempotently(scope_context):
    result = scope.report()
    assert result["state"] == "success"
    assert scope.report() == result
    assert len(scope_context.api.writes) == 1
    assert scope_context.api.writes[0][1]["context"] == "Infrastructure Promotion"
    assert not any("deployments" in path for path, _ in scope_context.api.writes)


@pytest.mark.parametrize(
    "key,value",
    [
        ("GITHUB_EVENT_NAME", "pull_request"),
        ("GITHUB_REF", "refs/pull/78/merge"),
        ("GITHUB_WORKFLOW_SHA", "f" * 40),
        ("GITHUB_RUN_ID", "../bad"),
        ("GITHUB_RUN_ATTEMPT", "0"),
    ],
)
def test_wrong_context_no_write(scope_context, monkeypatch, key, value):
    monkeypatch.setenv(key, value)
    with pytest.raises(ValueError):
        scope.report()
    assert not scope_context.api.writes


def test_stale_scope_event_base_no_write(scope_context):
    scope_context.event["pull_request"]["base"]["sha"] = "f" * 40
    scope_context.path.write_text(json.dumps(scope_context.event))
    with pytest.raises(ValueError, match="event base"):
        scope.report()
    assert not scope_context.api.writes


def test_cli_and_environment(scope_context, capsys):
    assert scope.main(["verify-environment"]) == 0
    assert not scope_context.api.writes
    assert scope.main(["scope"]) == 0
    assert json.loads(capsys.readouterr().out)["completion_kind"] == "no-deployment"
    scope_context.api.environment["can_admins_bypass"] = True
    assert scope.main(["verify-environment"]) == 1
    assert "failed" in capsys.readouterr().err


@pytest.mark.parametrize(
    "receipt_data",
    [("operator", "test", "up", ("operator", "governance", "platform"))],
    indirect=True,
)
def test_full_three_scope_original_publication(verified_publication):
    result = scope.verify_current_promotion(78)
    assert result["state"] == "success"
    assert result["scopes"] == ["operator", "governance", "platform"]
    scope.verify_current_promotion_status(result)
    assert not verified_publication.api.writes


def test_unknown_path_is_not_no_deployment(snapshot_api):
    snapshot_api.overrides[f"{scope.BASE}/compare/{'b' * 40}...{'a' * 40}"]["files"][0][
        "filename"
    ] = "unknown.bin"
    with pytest.raises(ValueError, match="Unclassified"):
        scope.verify_current_promotion(78)


@pytest.fixture
def artifact_pages(monkeypatch):
    controller = scope.ControllerMetadata(
        "c" * 40, "100", 1, f"{scope.REPOSITORY}/{scope.WORKFLOW}@refs/heads/main"
    )
    pages = {}

    def read(path):
        return deepcopy(pages[int(path.rsplit("=", 1)[1])])

    monkeypatch.setattr(emitter, "_read", read)
    return controller, pages


def test_complete_artifact_pagination(artifact_pages):
    controller, pages = artifact_pages
    pages[1] = {
        "total_count": 101,
        "artifacts": [{"id": n, "name": "other"} for n in range(1, 101)],
    }
    expected = {"id": 101, "name": "deployment-promotion-100-1"}
    pages[2] = {"total_count": 101, "artifacts": [expected]}
    assert scope._proof_artifact(controller) == expected


@pytest.mark.parametrize(
    "kind",
    [
        "repeated",
        "changed_count",
        "truncated",
        "missing",
        "ambiguous",
        "bad_count",
        "bad_page",
        "limit",
    ],
)
def test_artifact_inventory_failclosed(artifact_pages, kind):
    controller, pages = artifact_pages
    pages[1] = {
        "total_count": 101,
        "artifacts": [{"id": n, "name": "other"} for n in range(1, 101)],
    }
    pages[2] = {
        "total_count": 101,
        "artifacts": [{"id": 101, "name": "deployment-promotion-100-1"}],
    }
    if kind == "repeated":
        pages[2]["artifacts"][0]["id"] = 1
    elif kind == "changed_count":
        pages[2]["total_count"] = 102
    elif kind == "truncated":
        pages[2]["artifacts"] = []
    elif kind == "missing":
        pages[2]["artifacts"][0]["name"] = "other"
    elif kind == "ambiguous":
        pages[1]["artifacts"][0]["name"] = "deployment-promotion-100-1"
    elif kind == "bad_count":
        pages[1]["total_count"] = True
    elif kind == "bad_page":
        pages[1]["artifacts"] = {}
    else:
        for page in range(1, 6):
            pages[page] = {
                "total_count": 500,
                "artifacts": [
                    {"id": (page - 1) * 100 + n, "name": "other"} for n in range(1, 101)
                ],
            }
    with pytest.raises(ValueError):
        scope._proof_artifact(controller)


@pytest.mark.parametrize(
    "field,value",
    [
        ("run_id", "../../bad"),
        ("run_attempt", 2),
        ("workflow_ref", "foreign"),
        ("sha", "bad"),
    ],
)
def test_original_controller_closes_inputs_before_api(snapshot_api, field, value):
    controller = {
        "sha": "c" * 40,
        "run_id": "100",
        "run_attempt": 1,
        "workflow_ref": f"{scope.REPOSITORY}/{scope.WORKFLOW}@refs/heads/main",
    }
    controller[field] = value
    with pytest.raises(ValueError):
        scope._original_controller({"identity": {"controller": controller}})
    assert not snapshot_api.calls


def test_event_duplicate_fields_and_bad_number(scope_context):
    scope_context.path.write_text('{"number":78,"number":79}')
    assert scope.main(["scope"]) == 1
    scope_context.event["number"] = True
    scope_context.path.write_text(json.dumps(scope_context.event))
    assert scope.main(["scope"]) == 1
    assert not scope_context.api.writes


def test_scope_authority_fails_before_write(scope_context):
    scope_context.api.overrides["graphql"] = {
        "data": {"viewer": {"login": "other", "databaseId": 1}}
    }
    with pytest.raises(ValueError, match="Foreign publisher"):
        scope.report()
    assert not scope_context.api.writes


def test_recheck_before_write_observes_changed_promotion(scope_context, monkeypatch):
    real = scope.verify_current_promotion
    calls = 0

    def changed(number, **kwargs):
        nonlocal calls
        calls += 1
        result = real(number, **kwargs)
        if calls > 1:
            result["state"] = "pending"
        return result

    monkeypatch.setattr(scope, "verify_current_promotion", changed)
    with pytest.raises(ValueError, match="changed before publication"):
        scope.report()
    assert not scope_context.api.writes


@pytest.mark.parametrize("receipt_data", [PLATFORM_ONLY], indirect=True)
def test_no_candidate_success_if_transport_fails(verified_publication, monkeypatch):
    monkeypatch.setattr(
        scope,
        "_verified_candidate",
        lambda *args: (_ for _ in ()).throw(emitter.GitHubError("redacted")),
    )
    assert scope.verify_current_promotion(78)["state"] == "pending"


def test_observed_pull_request_target_run_head_is_pr_source(scope_context):
    # Observed run 34164835233 reports these PR source fields, not main/base.
    # The base SHA below is synthetic; this fixture is not live QA evidence.
    observed_head = "c4713d3ed1b3d0f4633d47afabbe399efd0bdc3b"
    scope_context.event["pull_request"]["head"].update(
        sha=observed_head, ref="codex/issue215-affected-stacks"
    )
    scope_context.path.write_text(json.dumps(scope_context.event))
    scope_context.run.update(
        head_sha=observed_head, head_branch="codex/issue215-affected-stacks"
    )
    assert scope._context()["head_sha"] == observed_head
    assert scope._context()["base_sha"] == scope_context.env["GITHUB_SHA"]
    scope_context.run.update(
        head_sha=scope_context.env["GITHUB_SHA"], head_branch="main"
    )
    with pytest.raises(ValueError, match="readback differs"):
        scope._context()


@pytest.mark.parametrize("head_ref", [None, "", "bad\nref", 42])
def test_scope_context_rejects_invalid_event_ref(scope_context, head_ref):
    scope_context.event["pull_request"]["head"]["ref"] = head_ref
    scope_context.path.write_text(json.dumps(scope_context.event))
    with pytest.raises(ValueError, match="head ref"):
        scope._context()


@pytest.mark.parametrize("receipt_data", [PLATFORM_ONLY], indirect=True)
@pytest.mark.parametrize("corruption", ["invalid", "truncated", "bzip2"])
def test_corrupt_archive_stays_pending(verified_publication, corruption):
    state = verified_publication
    if corruption == "bzip2":
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_BZIP2) as archive:
            archive.writestr("proof.json", b"{}")
        raw = bytearray(buffer.getvalue())
        start = 30 + len("proof.json")
        raw[start : start + 3] = b"BAD"
        state.raw = bytes(raw)
        with pytest.raises(OSError, match="Invalid data stream"):
            scope._contract_bytes(state.raw, member_name="proof.json")
    else:
        state.raw = b"invalid archive" if corruption == "invalid" else state.raw[:-16]
    metadata = state.state.github.overrides[f"{scope.BASE}/actions/artifacts/301"]
    metadata["digest"] = "sha256:" + hashlib.sha256(state.raw).hexdigest()
    metadata["size_in_bytes"] = len(state.raw)
    assert scope.verify_current_promotion(78)["state"] == "pending"
    assert not state.api.writes


@pytest.mark.parametrize("receipt_data", [PLATFORM_ONLY], indirect=True)
def test_struct_error_stays_pending(verified_publication, monkeypatch):
    def reject_archive(*args, **kwargs):
        raise struct.error("Invalid archive structure")

    monkeypatch.setattr(scope, "_contract_bytes", reject_archive)
    assert scope.verify_current_promotion(78)["state"] == "pending"
    assert not verified_publication.api.writes
