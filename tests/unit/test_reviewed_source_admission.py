"""Exercise trusted-source admission with hostile and changing API evidence."""

import sys
from copy import deepcopy
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import reviewed_source_admission as gate

HEAD = "a" * 40
MAIN = "b" * 40
BASE = f"repos/{gate.REPOSITORY}"


@pytest.fixture
def evidence(monkeypatch):
    repo = {"full_name": gate.REPOSITORY, "id": gate.REPOSITORY_ID}
    pr = {
        "number": 1,
        "state": "open",
        "merged": False,
        "user": {"id": 7},
        "head": {"sha": HEAD, "repo": repo},
        "base": {"ref": "main", "repo": repo},
    }
    review = {
        "id": 11,
        "state": "APPROVED",
        "commit_id": HEAD,
        "user": {"id": 8, "login": "reviewer", "type": "User"},
    }
    values = {
        f"{BASE}/commits/main": {"sha": MAIN},
        f"{BASE}/pulls/1": pr,
        f"{BASE}/pulls/1/reviews?per_page=100": [[review]],
        f"{BASE}/collaborators/reviewer/permission": {
            "permission": "write",
            "user": {"id": 8},
        },
    }
    for sha in (HEAD, MAIN):
        values[f"{BASE}/git/trees/{sha}"] = {"truncated": False, "tree": []}
    monkeypatch.setattr(gate, "gh", lambda path, *args: deepcopy(values[path]))
    return values


def test_current_independent_human_approved_head_is_admitted(evidence):
    assert gate.admit("1", HEAD, MAIN)["reviewer_id"] == "8"


def test_current_authorized_automated_reviewer_is_admitted(evidence):
    review = evidence[f"{BASE}/pulls/1/reviews?per_page=100"][0][0]
    review["user"] = dict(zip(("id", "login", "type"), gate.AUTOMATED_REVIEWER))
    assert gate.admit("1", HEAD, MAIN)["reviewer_id"] == str(gate.AUTOMATED_REVIEWER[0])


@pytest.mark.parametrize(
    "field,value",
    [
        ("state", "DISMISSED"),
        ("state", "CHANGES_REQUESTED"),
        ("state", "COMMENTED"),
        ("commit_id", "c" * 40),
    ],
)
def test_unapproved_or_stale_review_denied(evidence, field, value):
    evidence[f"{BASE}/pulls/1/reviews?per_page=100"][0][0][field] = value
    with pytest.raises(ValueError):
        gate.admit("1", HEAD, MAIN)


@pytest.mark.parametrize(
    "kind", ["none", "self", "rights", "impostor", "fork", "closed", "head", "main"]
)
def test_fail_closed_identity_and_authorization(evidence, kind):
    reviews = evidence[f"{BASE}/pulls/1/reviews?per_page=100"]
    pr = evidence[f"{BASE}/pulls/1"]
    if kind == "none":
        reviews[0].clear()
    if kind == "self":
        reviews[0][0]["user"]["id"] = 7
    if kind == "rights":
        evidence[f"{BASE}/collaborators/reviewer/permission"]["permission"] = "read"
    if kind == "impostor":
        reviews[0][0]["user"] = {"id": 1, "login": "coderabbitai[bot]", "type": "Bot"}
    if kind == "fork":
        pr["head"]["repo"] = {"full_name": "attacker/repo", "id": 1}
    if kind == "closed":
        pr["state"] = "closed"
    if kind == "head":
        pr["head"]["sha"] = "c" * 40
    if kind == "main":
        evidence[f"{BASE}/commits/main"]["sha"] = "c" * 40
    with pytest.raises(ValueError):
        gate.admit("1", HEAD, MAIN)


def test_comment_does_not_cancel_approval_but_later_decisive_review_does(evidence):
    reviews = evidence[f"{BASE}/pulls/1/reviews?per_page=100"][0]
    reviews.append({**deepcopy(reviews[0]), "id": 12, "state": "COMMENTED"})
    assert gate.admit("1", HEAD, MAIN)
    reviews.append({**deepcopy(reviews[0]), "id": 13, "state": "DISMISSED"})
    with pytest.raises(ValueError):
        gate.admit("1", HEAD, MAIN)


@pytest.mark.parametrize(
    "endpoint",
    [f"{BASE}/pulls/1", f"{BASE}/commits/main", f"{BASE}/pulls/1/reviews?per_page=100"],
)
def test_change_during_admission_denied(evidence, monkeypatch, endpoint):
    calls = 0

    def fetch(path, *args):
        nonlocal calls
        data = deepcopy(evidence[path])
        if path == endpoint:
            calls += 1
            if calls == 2:
                if path.endswith("/pulls/1"):
                    data["head"]["sha"] = "c" * 40
                elif path.endswith("/main"):
                    data["sha"] = "c" * 40
                else:
                    data[0][0]["state"] = "DISMISSED"
        return data

    monkeypatch.setattr(gate, "gh", fetch)
    with pytest.raises(ValueError):
        gate.admit("1", HEAD, MAIN)


def test_signal_resolves_server_observed_head(evidence):
    evidence[f"{BASE}/actions/runs/10"] = {
        "path": ".github/workflows/reviewed-source-signal.yml",
        "event": "pull_request_review",
        "status": "completed",
        "conclusion": "success",
        "head_repository": {"id": gate.REPOSITORY_ID},
        "head_sha": HEAD,
    }
    evidence[f"{BASE}/commits/{HEAD}/pulls?per_page=100"] = [
        [evidence[f"{BASE}/pulls/1"]]
    ]
    assert gate.signal_request({"workflow_run": {"id": 10}}) == ("1", HEAD)
    evidence[f"{BASE}/actions/runs/10"]["event"] = "push"
    with pytest.raises(ValueError):
        gate.signal_request({"workflow_run": {"id": 10}})


def test_automated_approval_cannot_authorize_its_own_configuration_change(evidence):
    review = evidence[f"{BASE}/pulls/1/reviews?per_page=100"][0][0]
    review["user"] = dict(zip(("id", "login", "type"), gate.AUTOMATED_REVIEWER))
    evidence[f"{BASE}/git/trees/{HEAD}"]["tree"] = [
        {"path": ".coderabbit.yaml", "mode": "100644", "type": "blob", "sha": "c" * 40}
    ]
    with pytest.raises(ValueError, match="No independent"):
        gate.admit("1", HEAD, MAIN)


def test_github_transport_uses_argument_vector_and_fails_closed(monkeypatch):
    from types import SimpleNamespace

    def run(args, **kwargs):
        assert args == ["gh", "api", "repos/example", "--paginate", "--slurp"]
        assert kwargs == {"check": True, "capture_output": True, "text": True}
        return SimpleNamespace(stdout='{"ok": true}')

    monkeypatch.setattr(gate.subprocess, "run", run)
    assert gate.gh("repos/example", "--paginate", "--slurp") == {"ok": True}


@pytest.mark.parametrize("signal", [False, True])
@pytest.mark.parametrize("publication", [False, True])
def test_cli_uses_trusted_context_and_closed_output_values(
    evidence, monkeypatch, tmp_path, signal, publication
):
    import json

    output = tmp_path / "output"
    event = tmp_path / "event"
    event.write_text(json.dumps({"workflow_run": {"id": 10}}))
    evidence[f"{BASE}/actions/runs/10"] = {
        "path": ".github/workflows/reviewed-source-signal.yml",
        "event": "pull_request_review",
        "status": "completed",
        "conclusion": "success",
        "head_repository": {"id": gate.REPOSITORY_ID},
        "head_sha": HEAD,
    }
    evidence[f"{BASE}/commits/{HEAD}/pulls?per_page=100"] = [
        [evidence[f"{BASE}/pulls/1"]]
    ]
    for key, value in {
        "GITHUB_REPOSITORY": gate.REPOSITORY,
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_EVENT_NAME": "workflow_run" if signal else "repository_dispatch",
        "GITHUB_SHA": MAIN,
        "GITHUB_OUTPUT": str(output),
        "GITHUB_EVENT_PATH": str(event),
    }.items():
        monkeypatch.setenv(key, value)
    published = []
    monkeypatch.setattr(
        gate, "publish_statuses", lambda head, state: published.append((head, state))
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["admission"]
        + ([] if signal else ["--number", "1", "--head-sha", HEAD])
        + (
            (["--publish-pending"] if signal else ["--publish-result", "success"])
            if publication
            else []
        ),
    )
    gate.main()
    assert published == (
        [(HEAD, "pending" if signal else "success")] if publication else []
    )
    assert (
        output.read_text()
        == f"pull_request_number=1\nhead_sha={HEAD}\nreview_id=11\nreviewer_id=8\n"
    )
    monkeypatch.setenv("GITHUB_REF", "refs/pull/1/merge")
    with pytest.raises(ValueError, match="Untrusted workflow ref"):
        gate.main()


@pytest.mark.parametrize("state", ["pending", "success", "failure"])
def test_status_writer_binds_each_context_to_exact_head_and_run(monkeypatch, state):
    monkeypatch.setenv("GITHUB_RUN_ID", "123")
    calls = []

    def api(path, *args):
        assert path == f"{BASE}/statuses/{HEAD}"
        assert args[:2] == ("--method", "POST")
        fields = dict(arg.split("=", 1) for arg in args if "=" in arg)
        assert fields["state"] == state
        assert (
            fields["target_url"]
            == f"https://github.com/{gate.REPOSITORY}/actions/runs/123"
        )
        calls.append(fields["context"])
        return fields

    monkeypatch.setattr(gate, "gh", api)
    gate.publish_statuses(HEAD, state)
    assert calls == list(gate.REQUIRED_CONTEXTS)
