"""Protected inputs, complete collection and exact publisher identity."""

from __future__ import annotations

import argparse
import datetime as dt
import io
import json
import os
import subprocess
import sys
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import _well_architected_publisher as host  # noqa: E402
import _well_architected_publisher_app as app  # noqa: E402
import _well_architected_publisher_artifacts as artifact  # noqa: E402
import _well_architected_scoring as scoring  # noqa: E402
import publish_well_architected as cli  # noqa: E402
from _well_architected_trusted_evidence import REQUIRED_CHECKS  # noqa: E402


@pytest.fixture
def approved():
    return {
        "schema": "wa-publisher-approval-v1",
        "issued_at": (
            dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=1)
        ).isoformat(),
        "expires_at": (
            dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=1)
        ).isoformat(),
        "repository": host.REPOSITORY,
        "repository_id": 123,
        "pr": 204,
        "artifact_id": 456,
        "transport": "github-artifact",
        "source_sha": "a" * 40,
        "head_sha": "b" * 40,
        "runtime_sha256": "c" * 64,
        "manifest_sha256": "d" * 64,
        "account": host.ACCOUNT,
        "region": host.REGION,
        "app_id": host.APP_ID,
        "app_slug": host.APP_SLUG,
        "read_role_arn": (
            f"arn:aws:iam::{host.ACCOUNT}:role/"
            "GitHubCiPreview-bootstrap-infrastructure-test"
        ),
        "topic_arn": f"arn:aws:sns:{host.REGION}:{host.ACCOUNT}:operations",
        "trail": "operations-trail",
    }


def report(approved):
    return {
        "repo": host.REPOSITORY,
        "pr": approved["pr"],
        "blockers": [],
        "checks": [
            {"name": name, "status": "passed", "blockers": []}
            for name in sorted(REQUIRED_CHECKS)
        ],
    }


def test_protected_approval_is_exact_and_target_bound(approved):
    assert host.approval(json.dumps(approved).encode()) == approved
    assert host.target(approved).head_sha == approved["head_sha"]


@pytest.mark.parametrize(
    "field,value",
    [
        ("source_sha", "main"),
        ("head_sha", "x" * 40),
        ("runtime_sha256", ""),
        ("pr", True),
        ("artifact_id", -1),
        ("repository_id", "123"),
        ("repository", "foreign/repo"),
        ("account", "933245420672"),
        ("region", "eu-west-1"),
        ("app_id", 15368),
        ("app_slug", "other"),
        ("read_role_arn", "arn:aws:iam::891377212104:role/Admin"),
        ("topic_arn", "arn:aws:sns:eu-west-1:891377212104:other"),
        ("trail", "x\ny"),
    ],
)
def test_protected_identity_mutations_fail(approved, field, value):
    approved[field] = value
    with pytest.raises(ValueError):
        host.approval(json.dumps(approved).encode())


def test_runtime_hash_includes_all_tracked_files_and_rejects_untracked_imports(
    tmp_path, monkeypatch, approved
):
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts/x.py").write_text("safe")
    approved["runtime_sha256"] = host.sha(
        json.dumps(
            {"scripts/x.py": host.sha(b"safe")}, sort_keys=True, separators=(",", ":")
        ).encode()
    )

    def run(argv, **kwargs):
        if "rev-parse" in argv:
            return approved["source_sha"]
        return "scripts/x.py\0" if "ls-files" in argv else ""

    monkeypatch.setattr(host, "command", run)
    host.runtime(tmp_path, approved, approved["source_sha"])
    (tmp_path / "scripts/injected.py").write_text("do not import")
    with pytest.raises(ValueError, match="Untracked"):
        host.runtime(tmp_path, approved, approved["source_sha"])
    with pytest.raises(ValueError, match="source pin"):
        host.runtime(tmp_path, approved, "f" * 40)
    (tmp_path / "scripts/x.py").write_text("changed")
    with pytest.raises(ValueError, match="closure"):
        host.runtime(tmp_path, approved, approved["source_sha"])


def pr_payload(approved):
    repo = {"id": approved["repository_id"], "full_name": host.REPOSITORY}
    return {
        "state": "open",
        "draft": False,
        "head": {"sha": approved["head_sha"], "repo": repo.copy()},
        "base": {"ref": "main", "repo": repo.copy()},
    }


@pytest.mark.parametrize(
    "kind", ["valid", "fork", "closed", "draft", "head", "base", "repo"]
)
def test_pr_context_requires_current_same_repository_open_head(
    monkeypatch, approved, kind
):
    pr = pr_payload(approved)
    repo = {"id": approved["repository_id"], "default_branch": "main"}
    if kind == "fork":
        pr["head"]["repo"]["id"] = 999
    if kind == "closed":
        pr["state"] = "closed"
    if kind == "draft":
        pr["draft"] = True
    if kind == "head":
        pr["head"]["sha"] = "f" * 40
    if kind == "base":
        pr["base"]["ref"] = "other"
    if kind == "repo":
        repo["id"] = 999
    monkeypatch.setattr(host, "gh", lambda path: pr if "/pulls/" in path else repo)
    if kind == "valid":
        assert host.pr_context(approved) == pr
    else:
        with pytest.raises(ValueError):
            host.pr_context(approved)


@pytest.mark.parametrize(
    "field,value",
    [
        ("GITHUB_REF", "refs/heads/evil"),
        ("GITHUB_EVENT_NAME", "pull_request"),
        ("GITHUB_RUN_ATTEMPT", "2"),
        ("GITHUB_REPOSITORY", "foreign/repo"),
        ("GITHUB_RUN_ID", "x"),
    ],
)
def test_workflow_ref_and_reruns_fail_before_publication(
    monkeypatch, approved, field, value
):
    for name, content in {
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_REPOSITORY": host.REPOSITORY,
        "GITHUB_RUN_ID": "77",
    }.items():
        monkeypatch.setenv(name, content)
    monkeypatch.setenv(field, value)
    monkeypatch.setattr(
        host, "gh", lambda path: pytest.fail("No API after invalid workflow context")
    )
    with pytest.raises(ValueError):
        host.workflow_context(approved)


def test_workflow_checks_server_provenance(monkeypatch, approved):
    for name, content in {
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_REPOSITORY": host.REPOSITORY,
        "GITHUB_RUN_ID": "77",
    }.items():
        monkeypatch.setenv(name, content)
    run = {
        "head_sha": approved["source_sha"],
        "head_branch": "main",
        "event": "workflow_dispatch",
        "run_attempt": 1,
        "path": host.WORKFLOW,
    }
    monkeypatch.setattr(host, "gh", lambda path: run)
    assert host.workflow_context(approved) == run
    run["head_sha"] = "e" * 40
    with pytest.raises(ValueError, match="provenance"):
        host.workflow_context(approved)


def test_report_binding_expiry_and_complete_failures(approved):
    value = report(approved)
    record = host.result(approved, value, "77")
    assert host.verify_result(approved, record, "77") == value
    for field, changed in [
        ("run_id", "78"),
        ("approval_sha256", "e" * 64),
        ("collected_at", "2026-01-01T00:00:00+00:00"),
    ]:
        with pytest.raises(ValueError):
            host.verify_result(approved, {**record, field: changed}, "77")
    record["report"] = {**value, "checks": []}
    with pytest.raises(ValueError):
        host.verify_result(approved, record, "77")


def zip_bytes(names):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as output:
        for name, data in names:
            output.writestr(name, data)
    return stream.getvalue()


@pytest.mark.parametrize(
    "name",
    [
        "../escape",
        "/escape",
        "folder\\escape",
        "folder//escape",
        "folder/",
        "C:/escape",
        "C:escape",
        "//server/share/escape",
    ],
)
def test_artifact_path_traversal_and_aliases_rejected(tmp_path, name):
    with pytest.raises(ValueError):
        artifact.extract(zip_bytes([(name, b"data")]), tmp_path / "stage")
    assert not (tmp_path / "stage").exists()


def test_finite_artifact_extract_and_duplicate_or_special_rejection(tmp_path):
    artifact.extract(
        zip_bytes([("manifest.json", b"{}"), ("a/b.json", b"{}")]), tmp_path / "stage"
    )
    assert (tmp_path / "stage/a/b.json").read_bytes() == b"{}"
    assert (tmp_path / "stage/a/b.json").stat().st_mode & 0o077 == 0
    with pytest.raises(ValueError):
        artifact.extract(zip_bytes([("x", b"x")]), tmp_path / "stage")
    with pytest.warns(UserWarning):
        raw = zip_bytes([("x", b"1"), ("x", b"2")])
    with pytest.raises(ValueError):
        artifact.extract(raw, tmp_path / "duplicates")
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        item = zipfile.ZipInfo("link")
        item.external_attr = 0o120777 << 16
        archive.writestr(item, "/secret")
    with pytest.raises(ValueError):
        artifact.extract(stream.getvalue(), tmp_path / "link")


def test_data_catalogs_are_exact_independently_approved_bytes(
    tmp_path, monkeypatch, approved
):
    (tmp_path / "pulumi").mkdir()
    path = tmp_path / "pulumi/repositories.schema.json"
    path.write_text("{}")
    manifest = {"pr_data": {"pulumi/repositories.schema.json": host.sha(b"{}")}}
    monkeypatch.setattr(
        host,
        "command",
        lambda argv, **kw: approved["head_sha"] if "rev-parse" in argv else "",
    )
    host.data_checkout(tmp_path, approved, manifest)
    path.write_text('{"forged":true}')
    with pytest.raises(ValueError, match="independently approved"):
        host.data_checkout(tmp_path, approved, manifest)
    path.unlink()
    path.symlink_to(tmp_path / "secret")
    with pytest.raises((ValueError, OSError)):
        host.data_checkout(tmp_path, approved, manifest)


def test_issuer_must_be_required_exact_app(monkeypatch):
    rules = {
        "enforcement": "active",
        "target": "branch",
        "conditions": {"ref_name": {"include": ["refs/heads/main"], "exclude": []}},
        "rules": [
            {
                "type": "required_status_checks",
                "parameters": {
                    "required_status_checks": [
                        {
                            "context": "Test Account Evidence",
                            "integration_id": host.APP_ID,
                        }
                    ]
                },
            }
        ],
    }
    monkeypatch.setattr(host, "command", lambda argv: '[{"id":1}]')
    monkeypatch.setattr(host, "gh", lambda path: rules)
    host.verify_issuer()
    rules["rules"][0]["parameters"]["required_status_checks"][0]["integration_id"] = (
        None
    )
    with pytest.raises(ValueError, match="issuer"):
        host.verify_issuer()
    rules["rules"] = []
    with pytest.raises(ValueError, match="not installed"):
        host.verify_issuer()


def test_self_migration_rechecks_requirements_and_keeps_other_ci_failures(
    monkeypatch, approved
):
    monkeypatch.setattr(host, "verify_issuer", lambda: None)
    url = f"https://github.com/{host.REPOSITORY}/actions/runs/10/job/11"
    monkeypatch.setattr(
        host,
        "legacy_evidence_checks",
        lambda value: {url: {"conclusion": "failure", "node_id": "CR_legacy"}},
    )
    own = {
        "id": 53644588964,
        "node_id": "SC_kwDOQXrS7c8AAAAMfYgN_w",
        "context": "Test Account Evidence",
        "state": "failure",
        "target_url": "old",
        "creator": {
            "login": host.APP_SLUG + "[bot]",
            "id": host.APP_BOT_ID,
            "type": "Bot",
        },
    }
    monkeypatch.setattr(
        host,
        "gh",
        lambda path: (
            [own]
            if "/statuses?" in path
            else {
                "total_count": 1,
                "statuses": [
                    {key: value for key, value in own.items() if key != "creator"}
                ],
            }
        ),
    )
    monkeypatch.setattr(
        host,
        "command",
        lambda argv: json.dumps(
            _rollup_response(approved, entries) if argv[2] == "graphql" else [own]
        ),
    )
    entries = [
        {
            "__typename": "StatusContext",
            "id": "SC_kwDOQXrS7c8AAAAMfYgN_w",
            "context": "Test Account Evidence",
            "state": "FAILURE",
            "targetUrl": "old",
        },
        {
            "__typename": "CheckRun",
            "id": "CR_legacy",
            "name": "Test Account Evidence",
            "detailsUrl": url,
            "conclusion": "FAILURE",
        },
        {
            "__typename": "CheckRun",
            "id": "CR_unit",
            "name": "Unit",
            "conclusion": "FAILURE",
        },
        {
            "__typename": "StatusContext",
            "id": "SC_promotion",
            "context": "Governance Promotion",
            "state": "FAILURE",
        },
    ]

    def base(argv, **kwargs):
        return subprocess.CompletedProcess(
            argv, 0, json.dumps({"statusCheckRollup": entries}), ""
        )

    adapted, receipts = host.self_status_runner(base, approved)
    remaining = json.loads(adapted(["gh", "pr", "view"]).stdout)["statusCheckRollup"]
    assert remaining == entries[2:]
    assert receipts["previousAppStatus"] == [own]
    own["creator"]["login"] = "untrusted"
    with pytest.raises(ValueError, match="issuer"):
        host.self_status_runner(base, approved)


def test_live_legacy_identity_is_exact_path_head_app_and_event(monkeypatch, approved):
    url = f"https://github.com/{host.REPOSITORY}/actions/runs/10/job/11"
    check = {
        "id": 11,
        "node_id": "CR_legacy",
        "name": "Test Account Evidence",
        "app": {"id": 15368},
        "details_url": url,
        "conclusion": "failure",
    }
    run = {
        "id": 10,
        "head_sha": approved["head_sha"],
        "path": ".github/workflows/well-architected-evidence.yml",
        "event": "pull_request",
    }
    monkeypatch.setattr(
        host,
        "gh",
        lambda path: (
            {"total_count": 1, "check_runs": [check]} if "check-runs" in path else run
        ),
    )
    assert host.legacy_evidence_checks(approved)[url]["node_id"] == "CR_legacy"
    run["path"] = ".github/workflows/other.yml"
    assert host.legacy_evidence_checks(approved) == {}
    check["app"]["id"] = 99
    assert host.legacy_evidence_checks(approved) == {}


def test_publisher_cannot_promote_collector_or_fresh_check_failure(
    monkeypatch, approved
):
    calls = []
    monkeypatch.setattr(host, "verify_environment", lambda: calls.append("environment"))
    monkeypatch.setattr(host, "pr_context", lambda value: calls.append("head"))
    monkeypatch.setattr(
        host,
        "fresh_github",
        lambda report, value: {**report, "blockers": ["real CI failure"]},
    )

    def write(argv, **kwargs):
        payload = json.loads(kwargs["input"])
        calls.append(payload)
        return subprocess.CompletedProcess(
            argv,
            0,
            json.dumps({**payload, "creator": {"login": host.APP_SLUG + "[bot]"}}),
            "",
        )

    monkeypatch.setattr(host.subprocess, "run", write)
    result = host.post(approved, report(approved), "https://github.com/example")
    assert result["state"] == "failure"
    assert calls[:2] == ["environment", "head"]
    assert calls[-1]["context"] == "Test Account Evidence"


def test_app_identity_scoped_token_and_revoke_without_exposure(tmp_path, monkeypatch):
    key = tmp_path / "key.pem"
    key.write_text("synthetic")
    key.chmod(0o600)
    calls = []
    monkeypatch.setenv("GH_TOKEN", "previous")
    monkeypatch.setattr(
        app.subprocess,
        "run",
        lambda *a, **kw: subprocess.CompletedProcess(a, 0, b"signature", b""),
    )

    def api(token, path, **kwargs):
        calls.append((path, kwargs))
        if path == "app":
            return {"id": host.APP_ID, "slug": host.APP_SLUG}
        if path.endswith("access_tokens"):
            return {"token": "synthetic-installation-token"}
        if path == "installation/token":
            return {}
        return {"app_id": host.APP_ID, "account": {"login": "VilnaCRM-Org"}}

    monkeypatch.setattr(app, "api", api)
    with pytest.raises(ValueError), app.installation_token(key, 12):
        assert os.environ["GH_TOKEN"] == "synthetic-installation-token"
        raise ValueError("simulate failure")
    assert os.environ["GH_TOKEN"] == "previous"
    assert calls[-1] == ("installation/token", {"method": "DELETE"})
    permission_request = calls[-2][1]["payload"]
    assert permission_request["repositories"] == ["bootstrap-infrastructure"]
    assert permission_request["permissions"]["statuses"] == "write"
    assert "deployments" not in permission_request["permissions"]
    key.chmod(0o644)
    with pytest.raises(ValueError, match="private"):
        with app.installation_token(key, 12):
            pytest.fail("must reject key")


def test_workflow_never_executes_pr_checkout_and_keeps_separate_context():
    root = Path(__file__).resolve().parents[2]
    workflow = yaml.safe_load((root / host.WORKFLOW).read_text())
    assert set(workflow[True]) == {"workflow_dispatch"}
    jobs = workflow["jobs"]
    assert (
        jobs["prepare"]["environment"]
        == jobs["publish"]["environment"]
        == "governance-evidence"
    )
    assert "environment" not in jobs["collect"]
    for job in jobs.values():
        assert "refs/heads/main" in job["if"] and "run_attempt == 1" in job["if"]
        for step in job["steps"]:
            assert step.get("working-directory") != "pr-data"
            assert "pr-data/scripts" not in step.get("run", "")
            if "uses" in step:
                assert len(step["uses"].split("@")[-1]) == 40
    collect_steps = jobs["collect"]["steps"]
    verify = next(
        i
        for i, step in enumerate(collect_steps)
        if "before AWS" in step.get("name", "")
    )
    creds = next(
        i
        for i, step in enumerate(collect_steps)
        if "configure-aws-credentials" in step.get("uses", "")
    )
    assert verify < creds
    assert all("load-aws-ci-env" not in step.get("uses", "") for step in collect_steps)
    app_step = next(
        step
        for step in jobs["publish"]["steps"]
        if "create-github-app-token" in step.get("uses", "")
    )
    assert app_step["with"]["app-id"] == str(host.APP_ID)
    assert "permission-deployments" not in app_step["with"]
    assert (root / ".github/workflows/well-architected-evidence.yml").exists()


def test_cli_collect_failure_is_retained_and_bootstrap_does_not_claim_installed(
    monkeypatch, tmp_path, approved
):
    args = argparse.Namespace(
        mode="collect", bundle=tmp_path, output=tmp_path / "result.json"
    )
    monkeypatch.setattr(cli, "context", lambda args: approved)
    monkeypatch.setattr(host, "bundle", lambda *a: {})
    failed = report(approved)
    failed["blockers"] = ["Restore pending"]
    monkeypatch.setattr(cli, "collect", lambda *a: host.result(approved, failed, "77"))
    assert cli.execute(args) == 0
    assert host.read_json(args.output)["report"]["blockers"] == ["Restore pending"]
    with pytest.raises(ValueError, match="new"):
        cli.save(args.output, {})


def test_cli_bootstrap_requires_explicit_source_and_handles_failure_safely(
    monkeypatch, capsys
):
    monkeypatch.setattr(
        cli,
        "execute",
        lambda args: (_ for _ in ()).throw(
            ValueError("private diagnostic must not print")
        ),
    )
    assert (
        cli.main(
            [
                "bootstrap",
                "--approval",
                "a",
                "--approval-sha256",
                "b",
                "--source-sha",
                "c",
                "--bundle",
                "d",
            ]
        )
        == 1
    )
    assert "private diagnostic" not in capsys.readouterr().err


def test_fixed_metadata_command_errors_and_bound(monkeypatch):
    monkeypatch.setattr(
        host.subprocess,
        "run",
        lambda *a, **k: subprocess.CompletedProcess(a, 0, '{"ok":true}', ""),
    )
    assert host.gh("fixed/path") == {"ok": True}
    monkeypatch.setattr(
        host.subprocess,
        "run",
        lambda *a, **k: subprocess.CompletedProcess(a, 1, "private", "private"),
    )
    with pytest.raises(ValueError, match="metadata command failed"):
        host.command(["gh", "api", "fixed"])


def test_environment_and_bundle_validate_real_boundaries(
    monkeypatch, tmp_path, approved
):
    valid = {
        **host.boundary.payload(),
        "deployment_branch_policies": [{"name": "main", "type": "branch"}],
    }
    monkeypatch.setattr(
        host,
        "gh",
        lambda path: (
            {"total_count": 1, "branch_policies": valid["deployment_branch_policies"]}
            if path.endswith("deployment-branch-policies")
            else valid
        ),
    )
    host.verify_environment()
    valid["can_admins_bypass"] = True
    with pytest.raises(ValueError):
        host.verify_environment()
    (tmp_path / "manifest.json").write_text("{}")

    def verify(raw, **kwargs):
        assert kwargs["approved_sha256"] == approved["manifest_sha256"]
        assert kwargs["target"].head_sha == approved["head_sha"]
        return {
            "source_sha": approved["source_sha"],
            "files": {},
            "issued_at": approved["issued_at"],
            "expires_at": approved["expires_at"],
        }

    monkeypatch.setattr(host, "verify_bundle", verify)
    assert host.bundle(approved, tmp_path)["source_sha"] == approved["source_sha"]


def test_collector_uses_only_explicit_approved_paths_and_full_parser(
    monkeypatch, tmp_path, approved
):
    import collect_well_architected_evidence as actual

    captured = []

    def collect(args, **kwargs):
        captured.append(args)
        assert kwargs["runner"] == "safe-runner"
        return report(approved)

    mock = SimpleNamespace(
        build_parser=actual.build_parser, collect_evidence=collect, run="original"
    )
    monkeypatch.setattr(host.importlib, "import_module", lambda name: mock)
    monkeypatch.setattr(
        host,
        "self_status_runner",
        lambda *args: ("safe-runner", {"historical": "failure"}),
    )
    monkeypatch.setenv("QUESTION_MATRIX_EVIDENCE", "/untrusted/replacement")
    selected = {key: f"{key}.json" for key in host.SELECTORS}
    result = host.collector(
        approved, {"evidence": selected}, tmp_path, tmp_path / "data"
    )
    assert captured[0].question_matrix_evidence == tmp_path / "question_matrix.json"
    assert captured[0].root_dir == tmp_path / "data"
    assert captured[0].dependabot_exception_evidence is None
    assert result["reevaluatedEvidenceProducers"] == {"historical": "failure"}


def test_app_refresh_retains_aws_owner_extra_and_actual_github_failures(approved):
    module = SimpleNamespace(
        _all_blockers=lambda checks: [b for item in checks for b in item["blockers"]],
        score_blockers=scoring.score_blockers,
        pillar_scores=scoring.pillar_scores,
        well_architected_scores=scoring.well_architected_scores,
    )
    initial = report(approved)
    initial["checks"][0]["status"] = "failed"
    initial["checks"][0]["blockers"] = ["AWS identity failure"]
    dep = next(
        row for row in initial["checks"] if row["name"] == "github_dependabot_alerts"
    )
    dep.update(status="unknown", blockers=["GITHUB_TOKEN cannot read Dependabot"])
    initial["blockers"] = [
        "AWS identity failure",
        "GITHUB_TOKEN cannot read Dependabot",
        "extra requirement",
    ]
    fresh = [
        {"name": "github_dependabot_alerts", "status": "passed", "blockers": []},
        {
            "name": "github_pr_checks",
            "status": "failed",
            "blockers": ["Actual Unit failure"],
        },
    ]
    result = host.refresh_github_rows(module, initial, fresh)
    assert set(result["blockers"]) == {
        "AWS identity failure",
        "extra requirement",
        "Actual Unit failure",
    }
    assert any(row["status"] == "unknown" for row in result["previousGitHubChecks"])
    assert result["proxyPillarScores"] == scoring.pillar_scores(result["checks"])
    assert result["pillarScores"] == scoring.well_architected_scores(
        result["proxyPillarScores"], result["checks"]
    )
    assert result["scoreBlockers"] == scoring.score_blockers(result["checks"])


def test_artifact_stream_bounded_actual_subprocess_and_reaped(monkeypatch):
    original = subprocess.Popen
    children = []

    def process(_argv, **kwargs):
        child = original(
            [
                sys.executable,
                "-I",
                "-c",
                "import sys; sys.stdout.buffer.write(b'x'*32)",
            ],
            **kwargs,
        )
        children.append(child)
        return child

    monkeypatch.setattr(artifact.subprocess, "Popen", process)
    assert artifact.download(host.REPOSITORY, 1) == b"x" * 32
    monkeypatch.setattr(artifact, "MAX_BUNDLE_BYTES", 4)
    with pytest.raises(ValueError, match="exceeds"):
        artifact.download(host.REPOSITORY, 1)
    assert all(child.poll() is not None for child in children)


def test_app_api_fixed_host_no_redirect_and_empty_delete(monkeypatch):
    seen = []

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def read(self, count):
            assert count == 2_000_001
            return b"{}"

    class Opener:
        def open(self, request, timeout):
            seen.append(request)
            assert timeout == 30
            return Response()

    monkeypatch.setattr(app.urllib.request, "build_opener", lambda *a: Opener())
    assert app.api("synthetic", "app") == {}
    assert seen[0].full_url == "https://api.github.com/app"
    payload = {
        "repositories": ["bootstrap-infrastructure"],
        "permissions": {"statuses": "write"},
    }
    assert (
        app.api(
            "synthetic",
            "app/installations/1/access_tokens",
            method="POST",
            payload=payload,
        )
        == {}
    )
    assert seen[1].get_method() == "POST"
    assert seen[1].get_header("Content-type") == "application/json"
    assert json.loads(seen[1].data) == payload
    assert (
        app.NoRedirect().redirect_request(
            None, None, 302, None, None, "https://foreign"
        )
        is None
    )


def test_cli_context_checks_independent_pin_before_runtime(
    monkeypatch, tmp_path, approved
):
    path = tmp_path / "approval.json"
    raw = json.dumps(approved).encode()
    path.write_bytes(raw)
    args = argparse.Namespace(
        approval=path,
        approval_sha256=host.sha(raw),
        source_sha=approved["source_sha"],
        mode="bootstrap",
    )
    calls = []
    monkeypatch.setattr(host, "runtime", lambda *a: calls.append("runtime"))
    monkeypatch.setattr(host, "pr_context", lambda *a: calls.append("PR"))
    monkeypatch.setattr(host, "workflow_context", lambda *a: calls.append("workflow"))
    assert cli.context(args) == approved
    assert calls == ["runtime", "PR"]
    args.mode = "collect"
    cli.context(args)
    assert calls[-1] == "workflow"
    args.approval_sha256 = "a" * 64
    with pytest.raises(ValueError, match="digest"):
        cli.context(args)


def test_cli_fetch_verifies_metadata_and_bundle_before_use(
    monkeypatch, tmp_path, approved
):
    info = {"id": approved["artifact_id"], "expired": False, "size_in_bytes": 100}
    monkeypatch.setattr(host, "gh", lambda path: info)
    monkeypatch.setattr(artifact, "download", lambda *args: b"zip")
    calls = []
    monkeypatch.setattr(artifact, "extract", lambda raw, dest: calls.append("extract"))
    monkeypatch.setattr(host, "bundle", lambda *args: calls.append("verify"))
    cli.fetch(approved, tmp_path / "bundle")
    assert calls == ["extract", "verify"]
    info["expired"] = True
    with pytest.raises(ValueError):
        cli.fetch(approved, tmp_path / "bad")


def test_cli_collect_checks_caller_before_trusted_collector(
    monkeypatch, tmp_path, approved
):
    args = argparse.Namespace(data_root=tmp_path, bundle=tmp_path)
    monkeypatch.setattr(host, "data_checkout", lambda *a: None)
    monkeypatch.setattr(
        host, "command", lambda *a: json.dumps({"Account": host.ACCOUNT})
    )
    monkeypatch.setattr(host, "collector", lambda *a: report(approved))
    monkeypatch.delenv("GITHUB_RUN_ID", raising=False)
    assert cli.collect(args, approved, {})["run_id"] == "local-bootstrap"
    monkeypatch.setattr(host, "command", lambda *a: '{"Account":"foreign"}')
    with pytest.raises(ValueError, match="foreign"):
        cli.collect(args, approved, {})


@pytest.mark.parametrize("conclusion", ["success", "failure", "cancelled"])
def test_publication_demands_actual_trusted_collector_job(
    monkeypatch, approved, conclusion
):
    monkeypatch.setenv("GITHUB_RUN_ID", "77")
    record = host.result(approved, report(approved), "77")
    monkeypatch.setattr(
        host, "workflow_context", lambda *a: {"html_url": "https://github.com/run"}
    )
    monkeypatch.setattr(
        host,
        "gh",
        lambda *a: {
            "total_count": 1,
            "jobs": [
                {
                    "name": host.COLLECT_JOB,
                    "status": "completed",
                    "conclusion": conclusion,
                }
            ],
        },
    )
    calls = []
    monkeypatch.setattr(host, "verify_issuer", lambda: calls.append("issuer"))
    monkeypatch.setattr(
        host, "post", lambda *a: calls.append("publish") or {"state": "success"}
    )
    if conclusion == "success":
        assert cli.publication(approved, record, bootstrap=False)["state"] == "success"
        assert calls == ["issuer", "publish"]
    else:
        with pytest.raises(ValueError, match="did not succeed"):
            cli.publication(approved, record, bootstrap=False)
        assert calls == []


def test_cli_prepare_verify_publish_and_local_bootstrap_modes(
    monkeypatch, tmp_path, approved
):
    import contextlib

    args = argparse.Namespace(
        mode="prepare",
        bundle=tmp_path / "bundle",
        output=tmp_path / "prepared.json",
        approval_sha256="a" * 64,
        data_root=tmp_path / "data",
        result=tmp_path / "input.json",
        receipt=tmp_path / "receipt.json",
        app_key=tmp_path / "key",
        installation_id=1,
    )
    monkeypatch.setattr(cli, "context", lambda *a: approved)
    monkeypatch.setattr(host, "verify_environment", lambda: None)
    monkeypatch.setattr(host, "verify_issuer", lambda: None)
    monkeypatch.setattr(host, "data_checkout", lambda *a: None)
    monkeypatch.setattr(cli, "fetch", lambda *a: None)
    monkeypatch.setattr(host, "bundle", lambda *a: {})
    monkeypatch.setenv("GITHUB_OUTPUT", str(tmp_path / "gh-output"))
    assert cli.execute(args) == 0
    assert "head_sha=" + approved["head_sha"] in (tmp_path / "gh-output").read_text()
    args.mode = "verify"
    assert cli.execute(args) == 0
    args.data_root = None
    assert cli.execute(args) == 0
    args.mode = "publish"
    monkeypatch.setattr(host, "read_json", lambda *a: {})
    monkeypatch.setattr(cli, "publication", lambda *a, **k: {"state": "failure"})
    assert cli.execute(args) == 1
    assert json.loads(args.receipt.read_text())["state"] == "failure"
    args.mode = "bootstrap"
    args.output = tmp_path / "bootstrap.json"
    args.receipt = tmp_path / "bootstrap-receipt.json"
    monkeypatch.setattr(cli, "collect", lambda *a: {})
    monkeypatch.setattr(app, "installation_token", lambda *a: contextlib.nullcontext())
    monkeypatch.setattr(cli, "publication", lambda *a, **k: {"state": "success"})
    assert cli.execute(args) == 0
    args.app_key = None
    with pytest.raises(ValueError, match="issuance inputs"):
        cli.execute(args)


def test_observed_source_commit_is_verified_not_only_self_hashed(monkeypatch, tmp_path):
    source = b"reviewed source\r\nnon-UTF8: \xff\r\n"
    receipt = {
        "sourceCommit": "a" * 40,
        "sourceBindings": {"scripts/x.py": host.sha(source)},
    }
    for name in ("first.json", "second.json"):
        (tmp_path / name).write_text(json.dumps(receipt))
    manifest = {
        "files": {
            "first.json": "unused",
            "second.json": "unused",
            "notes.txt": "unused",
        }
    }
    calls = []

    def run(argv, **kwargs):
        calls.append(argv)
        assert "text" not in kwargs
        assert "?ref=" + "a" * 40 in argv[2]
        return subprocess.CompletedProcess(argv, 0, source, b"")

    monkeypatch.setattr(host.subprocess, "run", run)
    host.verify_observed_sources(manifest, tmp_path)
    assert len(calls) == 1
    monkeypatch.setattr(host, "command_bytes", lambda argv: b"replacement")
    with pytest.raises(ValueError, match="GitHub commit"):
        host.verify_observed_sources(manifest, tmp_path)


def test_issuer_ignores_nonapplicable_rules_and_rejects_exclusions(monkeypatch):
    checks = [
        {"context": "Other", "integration_id": 1},
        {"context": "Test Account Evidence", "integration_id": host.APP_ID},
    ]
    active = {
        "enforcement": "active",
        "target": "branch",
        "conditions": {"ref_name": {"include": ["refs/heads/main"], "exclude": []}},
        "rules": [
            {"type": "pull_request"},
            {
                "type": "required_status_checks",
                "parameters": {"required_status_checks": checks},
            },
        ],
    }
    inventory = {
        1: {"enforcement": "disabled"},
        2: {
            "enforcement": "active",
            "target": "branch",
            "conditions": {"ref_name": {"include": ["refs/heads/other"]}},
        },
        3: active,
    }
    monkeypatch.setattr(host, "command", lambda argv: '[{"id":1},{"id":2},{"id":3}]')
    monkeypatch.setattr(host, "gh", lambda path: inventory[int(path.rsplit("/", 1)[1])])
    host.verify_issuer()
    active["conditions"]["ref_name"]["exclude"] = ["refs/heads/main"]
    with pytest.raises(ValueError, match="exclusions"):
        host.verify_issuer()


def test_self_adapter_with_no_prior_app_status_preserves_nonrollup_and_foreign_commands(
    monkeypatch, approved
):
    monkeypatch.setattr(host, "verify_issuer", lambda: None)
    monkeypatch.setattr(host, "gh", lambda path: {"total_count": 0, "statuses": []})
    monkeypatch.setattr(host, "legacy_evidence_checks", lambda value: {})
    original = subprocess.CompletedProcess([], 0, "{}", "")
    adapted, receipts = host.self_status_runner(lambda *a, **kw: original, approved)
    assert adapted(["gh", "pr", "view"]) is original
    assert receipts["previousAppStatus"] == []
    monkeypatch.setattr(host, "legacy_evidence_checks", lambda value: {"legacy": {}})
    adapted, _ = host.self_status_runner(lambda *a, **kw: original, approved)
    assert adapted(["gh", "pr", "view"]) is original
    assert adapted(["aws", "sts", "get-caller-identity"]) is original


def test_local_publication_uses_same_verified_result_contract(monkeypatch, approved):
    record = host.result(approved, report(approved), "local-bootstrap")
    monkeypatch.setattr(host, "verify_issuer", lambda: None)
    monkeypatch.setattr(
        host, "post", lambda value, report, url: {"state": "failure", "url": url}
    )
    result = cli.publication(approved, record, bootstrap=True)
    assert result == {
        "state": "failure",
        "url": f"https://github.com/{host.REPOSITORY}/pull/204",
    }


def test_prepare_without_github_outputs_is_local_file_only(
    monkeypatch, tmp_path, approved
):
    monkeypatch.delenv("GITHUB_OUTPUT", raising=False)
    monkeypatch.setattr(cli, "fetch", lambda *a: None)
    args = argparse.Namespace(
        bundle=tmp_path / "bundle",
        approval_sha256="a" * 64,
        output=tmp_path / "approval.json",
    )
    assert cli.prepare(args, approved) == 0
    assert json.loads(args.output.read_text()) == approved


def test_app_token_removed_without_previous_environment_value(tmp_path, monkeypatch):
    key = tmp_path / "key"
    key.write_text("synthetic")
    key.chmod(0o600)
    monkeypatch.delenv("GH_TOKEN", raising=False)
    monkeypatch.setattr(
        app.subprocess,
        "run",
        lambda *a, **kw: subprocess.CompletedProcess(a, 0, b"signature", b""),
    )

    def api(token, path, **kwargs):
        if path == "app":
            return {"id": host.APP_ID, "slug": host.APP_SLUG}
        if path.endswith("access_tokens"):
            return {"token": "synthetic"}
        return {"app_id": host.APP_ID, "account": {"login": "VilnaCRM-Org"}}

    monkeypatch.setattr(app, "api", api)
    with app.installation_token(key, 1):
        assert os.environ["GH_TOKEN"] == "synthetic"
    assert "GH_TOKEN" not in os.environ


def test_artifact_waits_for_stream_readiness_without_unbounded_output(monkeypatch):
    original_process = subprocess.Popen
    original_selector = artifact.selectors.DefaultSelector

    class SlowSelector:
        def __init__(self):
            self.real = original_selector()
            self.first = True

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.real.close()

        def register(self, *args):
            return self.real.register(*args)

        def select(self, *args, **kwargs):
            if self.first:
                self.first = False
                return []
            return self.real.select(*args, **kwargs)

    monkeypatch.setattr(artifact.selectors, "DefaultSelector", SlowSelector)
    monkeypatch.setattr(
        artifact.subprocess,
        "Popen",
        lambda argv, **kwargs: original_process(
            [sys.executable, "-I", "-c", "print('ready')"], **kwargs
        ),
    )
    assert artifact.download(host.REPOSITORY, 1) == b"ready\n"


@pytest.mark.parametrize(
    "field,value",
    [
        ("issued_at", "2030-01-01T00:00:00+00:00"),
        ("expires_at", "2020-01-01T00:00:00+00:00"),
        ("expires_at", "2030-01-01T00:00:00+00:00"),
    ],
)
def test_protected_approval_time_rechecked_before_publication(approved, field, value):
    approved[field] = value
    with pytest.raises(ValueError, match="stale or excessive"):
        host.approval(json.dumps(approved).encode())


@pytest.mark.parametrize("case", ["clean", "foreign_pending", "promotion_failure"])
def test_fresh_publication_calls_actual_pr_helper_with_callable_adapter(
    monkeypatch, approved, case
):
    import _well_architected_github_pr_checks as actual

    monkeypatch.setenv("WELL_ARCHITECTED_CURRENT_CHECK_NAME", "Test Account Evidence")
    entries = []
    if case == "foreign_pending":
        entries = [
            {
                "__typename": "CheckRun",
                "name": "Test Account Evidence",
                "status": "IN_PROGRESS",
                "detailsUrl": "https://github.com/foreign/producer",
            }
        ]
    elif case == "promotion_failure":
        entries = [
            {
                "__typename": "StatusContext",
                "context": "Governance Promotion",
                "state": "FAILURE",
            }
        ]

    def runner(argv, **kwargs):
        if argv[:3] == ["gh", "pr", "diff"]:
            return subprocess.CompletedProcess(argv, 0, "README.md\n", "")
        payload = (
            {"statusCheckRollup": entries}
            if argv[-1] == "statusCheckRollup"
            else {
                "mergeStateStatus": "CLEAN",
                "mergeable": "MERGEABLE",
                "reviewDecision": "APPROVED",
                "headRefOid": approved["head_sha"],
            }
        )
        return subprocess.CompletedProcess(argv, 0, json.dumps(payload), "")

    module = SimpleNamespace(
        run=runner,
        score_blockers=scoring.score_blockers,
        pillar_scores=scoring.pillar_scores,
        well_architected_scores=scoring.well_architected_scores,
        DependabotAlertRequest=SimpleNamespace,
        DEFAULT_DEPENDABOT_DEPENDENCY="*",
        DEFAULT_DEPENDABOT_MANIFEST="uv.lock",
        github_dependabot_alerts=lambda *a: {
            "name": "github_dependabot_alerts",
            "status": "passed",
            "blockers": [],
        },
        github_pr_checks=actual.github_pr_checks,
        github_review_threads=lambda *a: {
            "name": "github_review_threads",
            "status": "passed",
            "blockers": [],
        },
        github_branch_protection=lambda *a: {
            "name": "github_branch_protection",
            "status": "passed",
            "blockers": [],
        },
        github_production_environment=lambda *a: {
            "name": "github_production_environment",
            "status": "passed",
            "blockers": [],
        },
        _all_blockers=lambda checks: [b for item in checks for b in item["blockers"]],
    )
    monkeypatch.setattr(host.importlib, "import_module", lambda name: module)
    monkeypatch.setattr(host, "self_status_runner", lambda *args: (runner, {}))
    blockers = host.fresh_github(report(approved), approved)["blockers"]
    assert bool(blockers) is (case != "clean")
    assert os.environ["WELL_ARCHITECTED_CURRENT_CHECK_NAME"] == ""


def test_local_bootstrap_needs_no_fabricated_remote_artifact(
    monkeypatch, tmp_path, approved
):
    approved.update(transport="local-reviewed-bundle", artifact_id=None)
    raw = json.dumps(approved).encode()
    assert host.approval(raw)["artifact_id"] is None
    path = tmp_path / "approval.json"
    path.write_bytes(raw)
    args = argparse.Namespace(
        approval=path,
        approval_sha256=host.sha(raw),
        source_sha=approved["source_sha"],
        mode="bootstrap",
    )
    monkeypatch.setattr(host, "runtime", lambda *a: None)
    monkeypatch.setattr(host, "pr_context", lambda *a: None)
    assert cli.context(args)["transport"] == "local-reviewed-bundle"
    args.mode = "collect"
    with pytest.raises(ValueError, match="Local approval"):
        cli.context(args)
    approved["artifact_id"] = 123
    with pytest.raises(ValueError, match="artifact identity"):
        host.approval(json.dumps(approved).encode())


def test_approval_and_result_accept_utc_z_with_python310_parser(approved, monkeypatch):
    class Python310DateTime(dt.datetime):
        @classmethod
        def fromisoformat(cls, value):
            assert not value.endswith("Z"), "Python 3.10 does not accept UTC Z"
            return super().fromisoformat(value)

    monkeypatch.setattr(host.dt, "datetime", Python310DateTime)
    for field in ("issued_at", "expires_at"):
        approved[field] = approved[field].replace("+00:00", "Z")
    assert host.approval(json.dumps(approved).encode()) == approved
    expected = report(approved)
    record = host.result(approved, expected, "77")
    record["collected_at"] = record["collected_at"].replace("+00:00", "Z")
    assert host.verify_result(approved, record, "77") == expected


@pytest.fixture
def prior_app_status():
    """Shape observed from the creator-bearing REST status list."""
    return {
        "id": 53644588964,
        "node_id": "SC_kwDOQXrS7c8AAAAMfYgN_w",
        "context": "Test Account Evidence",
        "state": "failure",
        "target_url": f"https://github.com/{host.REPOSITORY}/pull/204",
        "creator": {
            "id": 325299966,
            "login": "vilnacrm-infrastructure-evidence[bot]",
            "type": "Bot",
        },
    }


def test_creator_lookup_matches_exact_current_id_with_prior_publication_history(
    monkeypatch, approved, prior_app_status
):
    """Real combined status omits creator; older same-context statuses are normal."""
    monkeypatch.setattr(host, "verify_issuer", lambda: None)
    monkeypatch.setattr(host, "legacy_evidence_checks", lambda value: {})
    current = {
        key: value for key, value in prior_app_status.items() if key != "creator"
    }
    history = [
        prior_app_status,
        {**prior_app_status, "id": 53644588000, "state": "pending"},
    ]
    calls = []

    def api(argv, **kwargs):
        assert argv[:2] == ["gh", "api"]
        assert kwargs["text"] is True
        path = argv[2]
        calls.append(path)
        if path == "graphql":
            assert "head=" + approved["head_sha"] in argv
            payload = _rollup_response(approved, entries)
        elif path.endswith("/statuses?per_page=100"):
            payload = history
        else:
            assert path.endswith("/status?per_page=100")
            payload = {"statuses": [current], "total_count": 1}
        return subprocess.CompletedProcess(argv, 0, json.dumps(payload), "")

    monkeypatch.setattr(host.subprocess, "run", api)
    entries = [
        {
            "__typename": "StatusContext",
            "id": "SC_kwDOQXrS7c8AAAAMfYgN_w",
            "context": "Test Account Evidence",
            "state": "FAILURE",
            "targetUrl": current["target_url"],
        },
        {
            "__typename": "CheckRun",
            "id": "CR_unit",
            "name": "Unit",
            "conclusion": "FAILURE",
        },
    ]

    def runner(argv, **kw):
        return subprocess.CompletedProcess(
            argv, 0, json.dumps({"statusCheckRollup": entries}), ""
        )

    for _ in range(2):
        adapter, receipt = host.self_status_runner(runner, approved)
        assert (
            json.loads(adapter(["gh", "pr", "view"]).stdout)["statusCheckRollup"]
            == entries[1:]
        )
        assert receipt["previousAppStatus"] == [prior_app_status]
    assert (
        calls
        == [
            *[
                f"repos/{host.REPOSITORY}/commits/{approved['head_sha']}/{suffix}?per_page=100"
                for suffix in ("status", "statuses")
            ],
            "graphql",
        ]
        * 2
    )


@pytest.mark.parametrize(
    "change",
    [
        {"id": True},
        {"id": "53644588964"},
        {"id": 0},
        {"node_id": None},
        {"node_id": ""},
        {"node_id": "bad id"},
        {"node_id": 123},
        {"state": "SUCCESS"},
        {"state": []},
        {"target_url": None},
        {"target_url": ""},
    ],
)
def test_invalid_current_status_cannot_be_authenticated(
    monkeypatch, approved, prior_app_status, change
):
    def no_lookup(path):
        raise AssertionError("Malformed current identity must fail before lookup")

    monkeypatch.setattr(host, "gh", no_lookup)
    with pytest.raises(ValueError, match="Malformed current"):
        host._authenticated_current_status({**prior_app_status, **change}, approved)


@pytest.mark.parametrize(
    "change",
    [
        {"context": "another check"},
        {"node_id": "SC_different"},
        {"state": "success"},
        {"target_url": "https://example.invalid/other"},
        {"creator": None},
        {"creator": {}},
        {"creator": {"id": 325299966, "login": "foreign[bot]", "type": "Bot"}},
        {"creator": {"id": 1, "login": host.APP_SLUG + "[bot]", "type": "Bot"}},
        {
            "creator": {
                "id": "325299966",
                "login": host.APP_SLUG + "[bot]",
                "type": "Bot",
            }
        },
        {
            "creator": {
                "id": 325299966,
                "login": host.APP_SLUG + "[bot]",
                "type": "User",
            }
        },
    ],
)
def test_creator_metadata_mismatch_is_never_excluded(
    monkeypatch, approved, prior_app_status, change
):
    monkeypatch.setattr(
        host, "command", lambda argv: json.dumps([{**prior_app_status, **change}])
    )
    with pytest.raises(ValueError):
        host._authenticated_current_status(prior_app_status, approved)


@pytest.mark.parametrize(
    "case",
    ["object", "full_page", "missing", "duplicate", "nonobject", "bad_id", "other_id"],
)
def test_incomplete_or_ambiguous_creator_inventory_is_rejected(
    monkeypatch, approved, prior_app_status, case
):
    histories = {
        "object": {},
        "full_page": [{**prior_app_status, "id": i + 1} for i in range(100)],
        "missing": [],
        "duplicate": [prior_app_status, prior_app_status],
        "nonobject": [None],
        "bad_id": [{**prior_app_status, "id": False}],
        "other_id": [{**prior_app_status, "id": 123}],
    }
    monkeypatch.setattr(host, "command", lambda argv: json.dumps(histories[case]))
    with pytest.raises(ValueError):
        host._authenticated_current_status(prior_app_status, approved)


@pytest.mark.parametrize(
    "response",
    [
        None,
        {"statuses": None},
        {"statuses": [None]},
        {"statuses": [], "total_count": False},
        {"statuses": [], "total_count": 1},
    ],
)
def test_malformed_combined_inventory_is_rejected(monkeypatch, approved, response):
    monkeypatch.setattr(host, "verify_issuer", lambda: None)
    monkeypatch.setattr(host, "gh", lambda path: response)
    with pytest.raises(ValueError):
        host.self_status_runner(lambda *a: None, approved)


@pytest.mark.parametrize("returncode,raw", [(1, b"private"), (0, b"x" * 16_000_001)])
def test_raw_source_transport_rejects_failure_and_excess(monkeypatch, returncode, raw):
    monkeypatch.setattr(
        host.subprocess,
        "run",
        lambda *a, **kw: subprocess.CompletedProcess(a, returncode, raw, b""),
    )
    with pytest.raises(ValueError):
        host.command_bytes(["gh", "api", "fixed"])


def test_status_list_transport_rejects_invalid_json(monkeypatch, approved):
    monkeypatch.setattr(
        host.subprocess,
        "run",
        lambda *a, **kw: subprocess.CompletedProcess(a, 0, "not-json", ""),
    )
    with pytest.raises(ValueError):
        host._status_history(approved)


def _rollup_response(approved, rows):
    return {
        "data": {
            "repository": {
                "object": {
                    "oid": approved["head_sha"],
                    "statusCheckRollup": {
                        "contexts": {
                            "nodes": rows,
                            "totalCount": len(rows),
                            "pageInfo": {"hasNextPage": False},
                        }
                    },
                }
            }
        }
    }


def test_identity_rollup_preserves_foreign_same_metadata_and_all_other_checks(
    monkeypatch, approved, prior_app_status
):
    """Foreign immutable identity cannot inherit the authenticated App exemption."""
    monkeypatch.setattr(host, "verify_issuer", lambda: None)
    monkeypatch.setattr(host, "legacy_evidence_checks", lambda value: {})
    monkeypatch.setattr(
        host,
        "gh",
        lambda path: {
            "total_count": 1,
            "statuses": [prior_app_status],
        },
    )
    own = {
        "__typename": "StatusContext",
        "id": prior_app_status["node_id"],
        "context": prior_app_status["context"],
        "state": "FAILURE",
        "targetUrl": prior_app_status["target_url"],
    }
    foreign = {**own, "id": "SC_foreign"}
    other = {
        "__typename": "CheckRun",
        "id": "CR_unrelated",
        "name": "Unit",
        "conclusion": "FAILURE",
    }
    rows = [own, foreign, other]
    monkeypatch.setattr(
        host,
        "command",
        lambda argv: json.dumps(
            _rollup_response(approved, rows)
            if argv[2] == "graphql"
            else [prior_app_status]
        ),
    )
    adapter, _ = host.self_status_runner(
        lambda argv: subprocess.CompletedProcess(
            argv, 0, json.dumps({"statusCheckRollup": [own]}), ""
        ),
        approved,
    )
    actual = json.loads(adapter(["gh", "pr", "view"]).stdout)
    assert actual["statusCheckRollup"] == [foreign, other]
    # A concurrent foreign replacement with identical display fields is rejected.
    rows.remove(own)
    with pytest.raises(ValueError, match="Authenticated evidence status changed"):
        adapter(["gh", "pr", "view"])


@pytest.mark.parametrize(
    "change",
    [
        {"__typename": "CheckRun"},
        {"context": "foreign"},
        {"state": "SUCCESS"},
        {"targetUrl": "changed"},
    ],
)
def test_authenticated_node_with_changed_metadata_is_rejected(
    monkeypatch, approved, prior_app_status, change
):
    monkeypatch.setattr(host, "verify_issuer", lambda: None)
    monkeypatch.setattr(host, "legacy_evidence_checks", lambda value: {})
    monkeypatch.setattr(
        host, "gh", lambda path: {"total_count": 1, "statuses": [prior_app_status]}
    )
    monkeypatch.setattr(host, "command", lambda argv: json.dumps([prior_app_status]))
    monkeypatch.setattr(
        host,
        "_identity_rollup",
        lambda value: [
            {
                "__typename": "StatusContext",
                "id": prior_app_status["node_id"],
                "context": prior_app_status["context"],
                "state": "FAILURE",
                "targetUrl": prior_app_status["target_url"],
                **change,
            }
        ],
    )
    adapter, _ = host.self_status_runner(
        lambda argv: subprocess.CompletedProcess(
            argv, 0, '{"statusCheckRollup": []}', ""
        ),
        approved,
    )
    with pytest.raises(ValueError, match="Authenticated evidence status changed"):
        adapter(["gh", "pr", "view"])


@pytest.mark.parametrize(
    "path,replacement",
    [
        (("errors",), [{"message": "partial result"}]),
        (("data",), None),
        (("data", "repository"), None),
        (("data", "repository", "object"), None),
        (("data", "repository", "object", "oid"), "f" * 40),
        (("data", "repository", "object", "statusCheckRollup"), None),
        (("data", "repository", "object", "statusCheckRollup", "contexts"), None),
    ],
)
def test_identity_rollup_rejects_bad_envelope(monkeypatch, approved, path, replacement):
    payload = _rollup_response(approved, [])
    node = payload
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = replacement
    monkeypatch.setattr(host, "command", lambda argv: json.dumps(payload))
    with pytest.raises(ValueError):
        host._identity_rollup(approved)


@pytest.mark.parametrize(
    "change",
    [
        {"nodes": None},
        {"totalCount": True},
        {"totalCount": 2},
        {"pageInfo": {}},
        {"pageInfo": None},
        {"pageInfo": {"hasNextPage": True}},
        {
            "nodes": [{"__typename": "CheckRun", "id": f"CR_{i}"} for i in range(100)],
            "totalCount": 100,
        },
        {"nodes": [None]},
        {"nodes": [{"__typename": "Unknown", "id": "X_one"}]},
        {"nodes": [{"__typename": "CheckRun"}]},
        {"nodes": [{"__typename": "CheckRun", "id": "bad id"}]},
        {"nodes": [{"__typename": "CheckRun", "id": "CR_one"}] * 2, "totalCount": 2},
    ],
)
def test_identity_rollup_rejects_bad_inventory(monkeypatch, approved, change):
    payload = _rollup_response(approved, [{"__typename": "CheckRun", "id": "CR_one"}])
    payload["data"]["repository"]["object"]["statusCheckRollup"]["contexts"].update(
        change
    )
    monkeypatch.setattr(host, "command", lambda argv: json.dumps(payload))
    with pytest.raises(ValueError):
        host._identity_rollup(approved)


def test_legacy_only_adapter_keeps_all_unrelated_typed_nodes(monkeypatch, approved):
    monkeypatch.setattr(host, "verify_issuer", lambda: None)
    monkeypatch.setattr(host, "gh", lambda path: {"total_count": 0, "statuses": []})
    monkeypatch.setattr(
        host,
        "legacy_evidence_checks",
        lambda value: {"exact-legacy": {"node_id": "CR_old"}},
    )
    rows = [
        {
            "__typename": "CheckRun",
            "id": "CR_old",
            "name": "Test Account Evidence",
            "detailsUrl": "exact-legacy",
        },
        {
            "__typename": "CheckRun",
            "id": "CR_foreign",
            "name": "Test Account Evidence",
            "detailsUrl": "exact-legacy",
            "status": "IN_PROGRESS",
        },
    ]
    monkeypatch.setattr(
        host, "command", lambda argv: json.dumps(_rollup_response(approved, rows))
    )
    adapter, _ = host.self_status_runner(
        lambda argv: subprocess.CompletedProcess(
            argv, 0, '{"statusCheckRollup": []}', ""
        ),
        approved,
    )
    assert (
        json.loads(adapter(["gh", "pr", "view"]).stdout)["statusCheckRollup"]
        == rows[1:]
    )


@pytest.mark.parametrize("identity", [None, "", 123, "bad id"])
def test_legacy_exemption_requires_real_node_identity(monkeypatch, approved, identity):
    check = {
        "id": 11,
        "node_id": identity,
        "name": "Test Account Evidence",
        "app": {"id": 15368},
        "details_url": f"https://github.com/{host.REPOSITORY}/actions/runs/10/job/11",
    }
    run = {
        "id": 10,
        "head_sha": approved["head_sha"],
        "path": ".github/workflows/well-architected-evidence.yml",
        "event": "pull_request",
    }
    monkeypatch.setattr(
        host,
        "gh",
        lambda path: (
            {"total_count": 1, "check_runs": [check]} if "check-runs" in path else run
        ),
    )
    with pytest.raises(ValueError, match="Malformed legacy check node ID"):
        host.legacy_evidence_checks(approved)
