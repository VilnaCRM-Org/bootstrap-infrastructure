"""Exercise executable publication against fake GitHub and real proof composition."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import deployment_promotion_emitter as emitter  # noqa: E402
from test_deployment_promotion_publication import (  # noqa: E402
    PLATFORM_ONLY,
)
from test_deployment_promotion_publication import (
    github as _github,
)
from test_deployment_promotion_publication import (
    graph as _graph,
)
from test_deployment_promotion_publication import (
    prepared as _prepared,
)
from test_deployment_promotion_publication import (
    promotion as _promotion,
)
from test_deployment_promotion_publication import (
    receipt_data as _receipt_data,
)
from test_deployment_receipt_runtime import ARTIFACT_PATH  # noqa: E402
from test_deployment_worker_runtime import make_zip  # noqa: E402

github, graph, prepared, promotion, receipt_data = (
    _github,
    _graph,
    _prepared,
    _promotion,
    _receipt_data,
)
PROCESS = subprocess.Popen
RUN = subprocess.run


def issuer():
    return {
        "id": emitter.APP_BOT_ID,
        "login": emitter.APP_SLUG + "[bot]",
        "type": "Bot",
    }


class FakeAPI:
    def __init__(self):
        self.calls = []
        self.deployments = {}
        self.statuses = {}
        self.overrides = {
            f"apps/{emitter.APP_SLUG}": {"id": emitter.APP_ID, "slug": emitter.APP_SLUG}
        }
        self.counter = 500
        self.deployment_app = {"id": emitter.APP_ID, "slug": emitter.APP_SLUG}
        self.fail_after = None
        self.hook = lambda path, payload: None
        self.environment = emitter.boundary.payload()
        self.policies = {
            "total_count": 1,
            "branch_policies": [{"name": "main", "type": "branch"}],
        }

    def __call__(self, path, payload=None):
        self.calls.append((path, deepcopy(payload)))
        self.hook(path, payload)
        if path in self.overrides:
            value = self.overrides[path]
            if isinstance(value, Exception):
                raise value
            return deepcopy(value)
        if path == "graphql":
            return {
                "data": {
                    "viewer": {
                        "login": emitter.APP_SLUG + "[bot]",
                        "databaseId": emitter.APP_BOT_ID,
                    }
                }
            }
        if path == "installation/repositories?per_page=100":
            return {
                "total_count": 1,
                "repositories": [
                    {"id": emitter.REPOSITORY_ID, "full_name": emitter.REPOSITORY}
                ],
            }
        if "/environments/" in path:
            return deepcopy(
                self.policies
                if "/deployment-branch-policies" in path
                else self.environment
            )
        if payload is not None:
            value = self.write(path, payload)
            if self.fail_after == path:
                raise emitter.GitHubError("uncertain POST")
            return deepcopy(value)
        if path in self.deployments:
            return deepcopy(self.deployments[path])
        if "/deployments?" in path:
            account = path.split("environment=")[1].split("&")[0]
            return [
                deepcopy(value)
                for value in self.deployments.values()
                if value["environment"] == account
            ]
        key = path.split("?")[0]
        return deepcopy(self.statuses.get(key, []))

    def write(self, path, payload):
        self.counter += 1
        value = {"id": self.counter, "creator": issuer()}
        if path.endswith("/deployments"):
            value.update(payload)
            value.update(
                sha=payload["ref"],
                repository_url="https://api.github.com/" + emitter.BASE,
                performed_via_github_app=deepcopy(self.deployment_app),
            )
            self.deployments[f"{path}/{self.counter}"] = value
        else:
            value.update(
                {key: val for key, val in payload.items() if key != "auto_inactive"}
            )
            value["url"] = "https://api.github.com/" + path
            if "context" in payload:
                sha = path.rsplit("/", 1)[1]
                key = f"{emitter.BASE}/commits/{sha}/statuses"
            else:
                value["url"] += f"/{self.counter}"
                key = path
            self.statuses.setdefault(key, []).insert(0, value)
        return value

    @property
    def writes(self):
        return [
            (path, payload)
            for path, payload in self.calls
            if payload is not None and path != "graphql"
        ]


@pytest.fixture
def publication(prepared, monkeypatch):
    payload = prepared.publication_args["proof_payload"]
    raw = make_zip([("proof.json", payload)])
    metadata = deepcopy(prepared.state.github.overrides[ARTIFACT_PATH])
    metadata.update(
        id=301,
        name="deployment-promotion-100-1",
        digest="sha256:" + hashlib.sha256(raw).hexdigest(),
        size_in_bytes=len(raw),
    )
    prepared.state.github.overrides[ARTIFACT_PATH.replace("/123", "/301")] = metadata
    prepared.emitter_args = {
        **prepared.args,
        "proof_artifact_id": "301",
        "proof_artifact_sha256": hashlib.sha256(raw).hexdigest(),
        "proof_file_sha256": hashlib.sha256(payload).hexdigest(),
        "needs_payload": json.dumps(prepared.dependencies),
    }
    prepared.api = FakeAPI()
    prepared.raw = raw
    monkeypatch.setattr(emitter, "_download_zip", lambda identifier: prepared.raw)
    monkeypatch.setattr(emitter, "_api", prepared.api)
    return prepared


@pytest.mark.parametrize("receipt_data", [PLATFORM_ONLY], indirect=True)
class TestPublication:
    def test_real_graph_publishes_idempotently(self, publication, capsys):
        first = emitter.publish(**publication.emitter_args)
        assert first["published"] == "true"
        assert len(publication.api.writes) == 5
        assert [
            payload.get("environment")
            for _, payload in publication.api.writes
            if "ref" in payload
        ] == ["test", "prod"]
        assert publication.api.writes[-1][1]["context"] == "Infrastructure Promotion"
        assert emitter.publish(**publication.emitter_args) == first
        assert len(publication.api.writes) == 5
        assert capsys.readouterr().out == ""

    @pytest.mark.parametrize(
        "field,value",
        [
            ("proof_artifact_id", "bad"),
            ("proof_artifact_sha256", "a" * 64),
            ("proof_file_sha256", "b" * 64),
        ],
    )
    def test_bad_proof_refs_never_write(self, publication, field, value):
        publication.emitter_args[field] = value
        with pytest.raises(ValueError):
            emitter.publish(**publication.emitter_args)
        assert not publication.api.writes

    @pytest.mark.parametrize(
        "field,value", [("name", "foreign"), ("expired", True), ("workflow_run", {})]
    )
    def test_foreign_proof_metadata(self, publication, field, value):
        metadata = publication.state.github.overrides[
            ARTIFACT_PATH.replace("/123", "/301")
        ]
        metadata[field] = value
        with pytest.raises(ValueError):
            emitter.publish(**publication.emitter_args)
        assert not publication.api.writes

    def test_modified_zip_never_writes(self, publication):
        publication.raw += b"tampered"
        with pytest.raises(ValueError, match="ZIP SHA"):
            emitter.publish(**publication.emitter_args)
        assert not publication.api.writes

    @pytest.mark.parametrize("index", (1, 2, 3, 4, 5))
    def test_revoked_writer_stops_next_write(self, publication, monkeypatch, index):
        original = emitter.revalidate_publication

        def revalidate(**kwargs):
            if len(publication.api.writes) >= index - 1:
                raise ValueError("Requester no longer has write permission")
            return original(**kwargs)

        monkeypatch.setattr(emitter, "revalidate_publication", revalidate)
        with pytest.raises(ValueError, match="write permission"):
            emitter.publish(**publication.emitter_args)
        assert len(publication.api.writes) == index - 1
        assert not any(
            payload.get("context") == emitter.CONTEXT
            for _, payload in publication.api.writes
        )

    def test_mismatched_fresh_proof_stops(self, publication, monkeypatch):
        original = emitter.revalidate_publication
        count = 0

        def revalidate(**kwargs):
            nonlocal count
            count += 1
            result = original(**kwargs)
            if count > 1:
                result["head_sha"] = "f" * 40
            return result

        monkeypatch.setattr(emitter, "revalidate_publication", revalidate)
        with pytest.raises(ValueError, match="evidence changed"):
            emitter.publish(**publication.emitter_args)
        assert not publication.api.writes

    @pytest.mark.parametrize(
        "kind", ("deployment", "deployment-status", "commit-status")
    )
    def test_uncertain_post_recovers_once(self, publication, kind):
        def hook(path, payload):
            matches = (
                (kind == "deployment" and path.endswith("/deployments"))
                or (
                    kind == "deployment-status"
                    and "/deployments/" in path
                    and path.endswith("/statuses")
                )
                or (kind == "commit-status" and payload and "context" in payload)
            )
            if payload is not None and matches:
                publication.api.fail_after = path

        publication.api.hook = hook
        assert emitter.publish(**publication.emitter_args)["published"] == "true"
        assert len(publication.api.writes) == 5

    def test_failed_prod_has_no_aggregate(self, publication):
        def hook(path, payload):
            if payload and payload.get("environment") == "prod":
                raise emitter.GitHubError("no deployment created")

        publication.api.hook = hook
        with pytest.raises(ValueError):
            emitter.publish(**publication.emitter_args)
        assert not any(payload.get("context") for _, payload in publication.api.writes)

    def test_cli_emits_only_verified_outputs(self, publication, monkeypatch, tmp_path):
        output = tmp_path / "output"
        arguments = dict(publication.emitter_args)
        monkeypatch.setenv("PROMOTION_NEEDS", arguments.pop("needs_payload"))
        args = [
            item
            for key, value in {**arguments, "output": str(output)}.items()
            for item in ("--" + key.replace("_", "-"), value)
        ]
        assert emitter.main(args) == 0
        assert "published=true" in output.read_text()
        assert "receipt" not in output.read_text()
        assert "token" not in output.read_text()

    @pytest.mark.parametrize("truncate", [False, True])
    def test_corrupt_zip_is_redacted(
        self, publication, monkeypatch, tmp_path, capsys, truncate
    ):
        publication.raw = publication.raw[:20] if truncate else b"invalid ZIP"
        digest = hashlib.sha256(publication.raw).hexdigest()
        publication.emitter_args["proof_artifact_sha256"] = digest
        metadata = publication.state.github.overrides[
            ARTIFACT_PATH.replace("/123", "/301")
        ]
        metadata.update(digest="sha256:" + digest, size_in_bytes=len(publication.raw))
        output = tmp_path / "output"
        arguments = dict(publication.emitter_args)
        monkeypatch.setenv("PROMOTION_NEEDS", arguments.pop("needs_payload"))
        args = [
            item
            for key, value in {**arguments, "output": str(output)}.items()
            for item in ("--" + key.replace("_", "-"), value)
        ]
        assert emitter.main(args) == 1
        assert not output.exists()
        assert not publication.api.writes
        assert capsys.readouterr().err == (
            "Promotion publication failed; no verified aggregate result.\n"
        )


def test_authority_boundary_rejects_foreign(monkeypatch):
    api = FakeAPI()
    monkeypatch.setattr(emitter, "_api", api)
    emitter._verify_authority()
    api.environment["can_admins_bypass"] = True
    with pytest.raises(ValueError, match="boundary"):
        emitter._verify_authority()


@pytest.mark.parametrize(
    "path,value",
    [
        ("graphql", {"errors": [{"message": "secret"}]}),
        (
            "graphql",
            {
                "data": {
                    "viewer": {"login": "foreign", "databaseId": emitter.APP_BOT_ID}
                }
            },
        ),
        (
            "graphql",
            {
                "data": {
                    "viewer": {"login": emitter.APP_SLUG + "[bot]", "databaseId": True}
                }
            },
        ),
        (
            "installation/repositories?per_page=100",
            {"total_count": 2, "repositories": []},
        ),
        (
            "installation/repositories?per_page=100",
            {
                "total_count": 1,
                "repositories": [{"id": True, "full_name": emitter.REPOSITORY}],
            },
        ),
    ],
)
def test_wrong_token_or_repo_rejected(monkeypatch, path, value):
    api = FakeAPI()
    api.overrides[path] = value
    monkeypatch.setattr(emitter, "_api", api)
    with pytest.raises(ValueError):
        emitter._verify_authority()
    assert not api.writes


@pytest.mark.parametrize(
    "field,value",
    [
        ("id", True),
        ("id", 0),
        ("sha", "foreign"),
        ("environment", "prod"),
        ("payload", {}),
        ("creator", {}),
        ("performed_via_github_app", {"id": 1, "slug": emitter.APP_SLUG}),
    ],
)
def test_deployment_readback_is_exact(field, value):
    request = {
        "environment": "test",
        "create_payload": {
            "ref": "a" * 40,
            "environment": "test",
            "production_environment": False,
            "description": "verified",
            "payload": {"proof": "bound"},
        },
    }
    api = FakeAPI()
    result = api.write(emitter.BASE + "/deployments", request["create_payload"])
    result[field] = value
    with pytest.raises(ValueError):
        emitter._deployment(result, request)


def test_pagination_and_read_retries(monkeypatch):
    responses = iter([emitter.GitHubError("failed"), [{"id": 1}]])

    def api(*args):
        value = next(responses)
        if isinstance(value, Exception):
            raise value
        return value

    monkeypatch.setattr(emitter, "_api", api)
    assert emitter._pages("path") == [{"id": 1}]
    monkeypatch.setattr(emitter, "_api", lambda *args: [{}] * 100)
    with pytest.raises(ValueError, match="incomplete"):
        emitter._pages("path")
    monkeypatch.setattr(emitter, "_api", lambda *args: {})
    with pytest.raises(ValueError, match="page"):
        emitter._pages("path")


def test_read_retry_exhaustion(monkeypatch):
    def fail(*args):
        raise emitter.GitHubError("unavailable")

    monkeypatch.setattr(emitter, "_api", fail)
    with pytest.raises(emitter.GitHubError):
        emitter._read("path")


def test_cli_failure_redacts_everything(monkeypatch, tmp_path, capsys):
    def fail(**kwargs):
        raise emitter.GitHubError("TOKEN secret BODY")

    monkeypatch.setattr(emitter, "publish", fail)
    output = tmp_path / "output"
    args = [
        item
        for name in (
            "artifact-id",
            "artifact-sha256",
            "contract-sha256",
            "proof-artifact-id",
            "proof-artifact-sha256",
            "proof-file-sha256",
        )
        for item in ("--" + name, "value")
    ]
    assert emitter.main([*args, "--output", str(output)]) == 1
    assert not output.exists()
    assert "secret" not in capsys.readouterr().err


def test_isolated_cli_ignores_hostile_imports(tmp_path):
    (tmp_path / "deployment_promotion_publication.py").write_text(
        "raise RuntimeError('HOSTILE')"
    )
    result = RUN(
        [sys.executable, "-I", str(Path(emitter.__file__).resolve()), "--help"],
        cwd=tmp_path,
        env={"PATH": os.environ["PATH"], "PYTHONPATH": str(tmp_path)},
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0
    assert "HOSTILE" not in result.stderr
    assert "--proof-artifact-id" in result.stdout


@pytest.mark.parametrize("payload", (None, {"literal": "$(do-not-execute)"}))
def test_transport_uses_fixed_argv(monkeypatch, payload):
    seen = []

    def popen(arguments, **kwargs):
        seen.append(arguments)
        if payload is not None:
            assert json.loads(Path(arguments[-1]).read_bytes()) == payload
        return PROCESS([sys.executable, "-I", "-c", "print('{\"ok\":true}')"], **kwargs)

    monkeypatch.setattr(emitter.subprocess, "Popen", popen)
    assert emitter._api("fixed", payload) == {"ok": True}
    assert seen[0][:5] == [
        "gh",
        "api",
        "fixed",
        "--method",
        "GET" if payload is None else "POST",
    ]


@pytest.mark.parametrize("code", ("print('bad')", "raise SystemExit(1)"))
def test_transport_errors_hide_response(monkeypatch, code):
    monkeypatch.setattr(
        emitter.subprocess,
        "Popen",
        lambda *args, **kwargs: PROCESS([sys.executable, "-I", "-c", code], **kwargs),
    )
    with pytest.raises(emitter.GitHubError):
        emitter._api("fixed")


def test_response_size_and_deadline(monkeypatch):
    monkeypatch.setattr(emitter, "MAX_RESPONSE", 10)
    process = PROCESS(
        [sys.executable, "-I", "-c", "print('x' * 20)"], stdout=subprocess.PIPE
    )
    with pytest.raises(emitter.GitHubError, match="bound"):
        emitter._response(process)
    clock = iter([0, 121])
    monkeypatch.setattr(emitter.time, "monotonic", lambda: next(clock))
    process = PROCESS(
        [sys.executable, "-I", "-c", "import time; time.sleep(20)"],
        stdout=subprocess.PIPE,
    )
    with pytest.raises(emitter.GitHubError, match="timed out"):
        emitter._response(process)


def test_missing_response_stream():
    process = SimpleNamespace(stdout=None, poll=lambda: 0, wait=lambda: 0)
    with pytest.raises(emitter.GitHubError, match="stream"):
        emitter._response(process)


def test_request_size_rejected(monkeypatch):
    monkeypatch.setattr(emitter, "MAX_RESPONSE", 1)
    with pytest.raises(ValueError, match="request exceeds"):
        emitter._api("fixed", {"too": "large"})


@pytest.mark.parametrize("receipt_data", [PLATFORM_ONLY], indirect=True)
@pytest.mark.parametrize("change", ("writer", "head", "base", "comment", "run"))
def test_identity_revoked_after_test(publication, change):
    def hook(path, payload):
        if payload and payload.get("state") == "success" and "context" not in payload:
            facts = publication.state.github.evidence
            if change == "writer":
                facts["permission"] = "read"
            elif change in ("head", "base"):
                facts["pr"][change]["sha"] = "f" * 40
                if change == "base":
                    endpoint = f"{emitter.BASE}/compare/{'f' * 40}...{'a' * 40}"
                    publication.state.github.overrides[endpoint] = {
                        "files": facts["changed_file_records"]
                    }
            elif change == "comment":
                facts["comment"]["updated_at"] = "2026-09-08T00:00:00Z"
            else:
                endpoint = f"{emitter.BASE}/actions/runs/100"
                publication.state.github.overrides[endpoint]["run_attempt"] = 2

    publication.api.hook = hook
    with pytest.raises(ValueError):
        emitter.publish(**publication.emitter_args)
    assert len(publication.api.writes) == 2
    assert not any(value.get("context") for _, value in publication.api.writes)


def test_pending_status_requires_real_write(monkeypatch):
    api = FakeAPI()
    path = emitter.BASE + "/deployments/1/statuses"
    pending = api.write(path, {"state": "pending"})
    monkeypatch.setattr(emitter, "_api", api)
    authorized = []
    identifier = emitter._ensure_status(
        path, {"state": "success"}, lambda: authorized.append(True)
    )
    assert identifier != pending["id"]
    assert authorized == [True]


@pytest.mark.parametrize("ambiguous", (False, True))
def test_missing_status_readback_fails(monkeypatch, ambiguous):
    def api(path, payload=None):
        if payload is None:
            return []
        if ambiguous:
            raise emitter.GitHubError("uncertain")
        return {
            "id": 4,
            "creator": issuer(),
            "state": "success",
            "url": "https://api.github.com/path/4",
        }

    monkeypatch.setattr(emitter, "_api", api)
    with pytest.raises(ValueError, match="not persisted"):
        emitter._ensure_status("path", {"state": "success"}, lambda: None)


def test_superseded_status_rejected(monkeypatch):
    api = FakeAPI()
    path = emitter.BASE + "/deployments/1/statuses"
    count = 0

    def transport(endpoint, payload=None):
        nonlocal count
        result = api(endpoint, payload)
        if payload is None:
            count += 1
            if count > 1:
                return [api.write(path, {"state": "success"})]
        return result

    monkeypatch.setattr(emitter, "_api", transport)
    with pytest.raises(ValueError, match="superseded"):
        emitter._ensure_status(path, {"state": "success"}, lambda: None)


def test_duplicate_deployments_fail(monkeypatch):
    request = {
        "environment": "test",
        "create_payload": {"ref": "a" * 40, "payload": {"bound": True}},
    }
    monkeypatch.setattr(
        emitter, "_api", lambda *args: [{"payload": {"bound": True}}] * 2
    )
    with pytest.raises(ValueError, match="Ambiguous"):
        emitter._find_deployment(request)


def test_response_waits_for_readiness(monkeypatch):
    original = emitter.selectors.DefaultSelector

    class DelayedSelector:
        def __init__(self):
            self.real = original()
            self.first = True

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.real.close()

        def register(self, *args):
            self.real.register(*args)

        def select(self, **kwargs):
            if self.first:
                self.first = False
                return []
            return self.real.select(**kwargs)

    monkeypatch.setattr(emitter.selectors, "DefaultSelector", DelayedSelector)
    process = PROCESS(
        [sys.executable, "-I", "-c", "print('ok')"], stdout=subprocess.PIPE
    )
    assert emitter._response(process) == b"ok\n"


@pytest.mark.parametrize(
    "field,value",
    [
        ("creator", {"id": 1, "login": emitter.APP_SLUG + "[bot]", "type": "Bot"}),
        ("creator", {"id": emitter.APP_BOT_ID, "login": "foreign", "type": "Bot"}),
        (
            "creator",
            {
                "id": emitter.APP_BOT_ID,
                "login": emitter.APP_SLUG + "[bot]",
                "type": "User",
            },
        ),
        ("url", "https://attacker.invalid/statuses/123"),
        ("state", "pending"),
        ("context", "Governance Promotion"),
        ("target_url", "https://attacker.invalid/run"),
    ],
)
def test_final_status_readback_rejects(field, value):
    path = emitter.BASE + "/statuses/" + "a" * 40
    payload = {
        "context": emitter.CONTEXT,
        "state": "success",
        "target_url": "https://github.com/run",
    }
    result = FakeAPI().write(path, payload)
    result[field] = value
    with pytest.raises(ValueError):
        emitter._status(result, payload, path=path)


@pytest.mark.parametrize("annotation", [None, "omitted"])
def test_actual_nullable_app_metadata_keeps_creator_binding(annotation):
    # Recorded PR221 deployments6318073083/6318073168 have this exact public issuer
    # shape; these are synthetic structural tests, not copied acceptance claims.
    value = {"creator": issuer(), "performed_via_github_app": annotation}
    if annotation == "omitted":
        del value["performed_via_github_app"]
    emitter._issuer(value, app=True)
    value["creator"]["id"] = 1
    with pytest.raises(ValueError, match="Foreign publication creator"):
        emitter._issuer(value, app=True)


@pytest.mark.parametrize(
    "integration",
    [
        {},
        [],
        "foreign",
        {"id": True, "slug": emitter.APP_SLUG},
        {"id": emitter.APP_ID, "slug": "foreign"},
    ],
)
def test_present_foreign_app_still_fails(integration):
    with pytest.raises(ValueError):
        emitter._issuer(
            {"creator": issuer(), "performed_via_github_app": integration}, app=True
        )


@pytest.mark.parametrize(
    "value",
    [
        None,
        {},
        {"id": True, "slug": emitter.APP_SLUG},
        {"id": 1, "slug": emitter.APP_SLUG},
        {"id": emitter.APP_ID, "slug": "foreign"},
    ],
)
def test_configured_app_binding_fails_before_write(monkeypatch, value):
    api = FakeAPI()
    api.overrides[f"apps/{emitter.APP_SLUG}"] = value
    monkeypatch.setattr(emitter, "_api", api)
    with pytest.raises(ValueError):
        emitter._verify_authority()
    assert not api.writes


def test_full_publication_accepts_null_deployment_app(publication):
    publication.api.deployment_app = None
    result = emitter.publish(**publication.emitter_args)
    assert result["published"] == "true"
    assert len(publication.api.writes) == 5
    assert all(
        value["performed_via_github_app"] is None
        for value in publication.api.deployments.values()
    )
    assert any(path == f"apps/{emitter.APP_SLUG}" for path, _ in publication.api.calls)
    # Existing-deployment recovery also requires the original exact proof/fields.
    assert emitter.publish(**publication.emitter_args) == result
    assert len(publication.api.writes) == 5
