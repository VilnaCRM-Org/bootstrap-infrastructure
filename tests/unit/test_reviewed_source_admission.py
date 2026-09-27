"""Exercise trusted-source admission with hostile and changing API evidence."""

import os
import subprocess
import sys
from copy import deepcopy
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import _github_repository_controls as controls
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
    assert gate.signal_request({"workflow_run": {"id": 10}}) == ("1", HEAD, "success")
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
        assert args == ["gh", "api", "repos/example", "--paginate"]
        assert kwargs == {"check": True, "capture_output": True, "text": True}
        return SimpleNamespace(stdout='[{"id": 1}]\n[{"id": 2}]\n')

    monkeypatch.setattr(gate.subprocess, "run", run)
    assert gate.gh("repos/example", "--paginate", "--slurp") == [
        [{"id": 1}],
        [{"id": 2}],
    ]
    with pytest.raises(ValueError, match="Invalid page request"):
        gate.gh("repos/example", "--slurp")


@pytest.mark.parametrize("response", ['{"id": 1}', '[1]\n{"id": 2}', "[1]garbage"])
def test_paginated_github_transport_rejects_non_array_or_malformed_pages(
    monkeypatch, response
):
    from types import SimpleNamespace

    monkeypatch.setattr(
        gate.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(stdout=response),
    )
    with pytest.raises(ValueError):
        gate.gh("repos/example", "--paginate", "--slurp")


def test_isolated_cli_loads_only_installed_pagination_helper(tmp_path):
    (tmp_path / "github_api_pages.py").write_text("raise RuntimeError('untrusted cwd')")
    script = Path(gate.__file__).resolve()
    command = [sys.executable, "-I", str(script)]
    env = {"PATH": os.environ["PATH"]}
    help_result = subprocess.run(  # nosec B603
        [*command, "--help"],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert help_result.returncode == 0
    assert "usage: reviewed_source_admission.py" in help_result.stdout
    assert "untrusted cwd" not in help_result.stderr
    missing_context = subprocess.run(  # nosec B603
        command,
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert missing_context.returncode != 0
    assert missing_context.stdout == ""


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
    creator = {"id": 99, "login": "reviewed-test[bot]", "type": "Bot"}
    monkeypatch.setattr(gate, "publisher_identity", lambda: creator)

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
        return {**fields, "creator": creator}

    monkeypatch.setattr(gate, "gh", api)
    gate.publish_statuses(HEAD, state)
    assert calls == list(gate.REQUIRED_CONTEXTS)


def test_reviewed_statuses_are_distinct_from_legacy_required_checks():
    assert gate.REQUIRED_CONTEXTS == (
        "Reviewed Preview",
        "Reviewed Destructive Diff Gate",
        "Reviewed IAM Validation",
    )


def test_ruleset_reconciliation_preserves_additive_reviewed_contexts():
    original = controls.required_status_checks_rule(
        promotion_app_id=controls.CENTRAL_PROMOTION_APP_ID,
        repository=gate.REPOSITORY,
    )
    original["parameters"]["required_status_checks"].extend(
        {"context": context, "integration_id": 777001}
        for context in gate.REQUIRED_CONTEXTS
    )
    reconciled = controls.harden_required_status_checks_rule(
        original,
        promotion_app_id=controls.CENTRAL_PROMOTION_APP_ID,
        repository=gate.REPOSITORY,
    )
    contexts = {
        check["context"] for check in reconciled["parameters"]["required_status_checks"]
    }
    assert contexts == set(
        controls.required_status_checks_for_repository(gate.REPOSITORY)
    ) | set(gate.REQUIRED_CONTEXTS)
    assert all(
        check["integration_id"] == 777001
        for check in reconciled["parameters"]["required_status_checks"]
        if check["context"] in gate.REQUIRED_CONTEXTS
    )


@pytest.fixture
def publisher_evidence(monkeypatch, evidence):
    monkeypatch.setenv("REVIEWED_SOURCE_APP_ID", "777001")
    monkeypatch.setenv("REVIEWED_SOURCE_APP_SLUG", "reviewed-test")
    monkeypatch.setenv("REVIEWED_SOURCE_RULESET_ID", "123")
    monkeypatch.setenv("REVIEWED_SOURCE_PREVIEW_ACTIVE", "false")
    evidence["apps/reviewed-test"] = {
        "id": 777001,
        "slug": "reviewed-test",
        "owner": {"id": gate.OWNER_ID},
    }
    evidence["users/reviewed-test[bot]"] = {
        "id": 99,
        "login": "reviewed-test[bot]",
        "type": "Bot",
    }
    env_path = f"{BASE}/environments/{gate.PUBLISHER_ENVIRONMENT}"
    evidence[env_path] = {
        "can_admins_bypass": False,
        "deployment_branch_policy": {
            "protected_branches": False,
            "custom_branch_policies": True,
        },
    }
    evidence[f"{env_path}/deployment-branch-policies?per_page=100"] = {
        "total_count": 1,
        "branch_policies": [{"name": "main", "type": "branch"}],
    }
    evidence[f"{BASE}/rulesets/123"] = {
        "enforcement": "active",
        "target": "branch",
        "bypass_actors": [],
        "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
        "rules": [
            {
                "type": "required_status_checks",
                "parameters": {
                    "strict_required_status_checks_policy": True,
                    "required_status_checks": [
                        {"context": c, "integration_id": 777001}
                        for c in gate.REQUIRED_CONTEXTS
                    ],
                },
            }
        ],
    }
    return evidence


def test_dedicated_publisher_identity_and_activated_ruleset(
    publisher_evidence, monkeypatch
):
    gate.verify_publisher_boundary()
    assert gate.publisher_identity()["id"] == 99
    monkeypatch.setenv("REVIEWED_SOURCE_PREVIEW_ACTIVE", "true")
    assert gate.publisher_identity()["id"] == 99


@pytest.mark.parametrize("value", ["", "15368", "4840884", "-1", "abc"])
def test_missing_or_shared_publisher_is_rejected(monkeypatch, value):
    monkeypatch.setenv("REVIEWED_SOURCE_APP_ID", value)
    with pytest.raises(ValueError):
        gate.publisher_app_id()


@pytest.mark.parametrize("issuer", [None, 15368, 4840884, 777002, "777001", True])
def test_ruleset_rejects_unbound_or_alternate_issuer(publisher_evidence, issuer):
    rule = publisher_evidence[f"{BASE}/rulesets/123"]
    rule["rules"][0]["parameters"]["required_status_checks"][0]["integration_id"] = (
        issuer
    )
    with pytest.raises(ValueError, match="dedicated App issuer"):
        gate.verify_reviewed_ruleset(rule, 777001)


@pytest.mark.parametrize(
    "mutation",
    ["missing", "duplicate", "nonstrict", "disabled", "bypass", "foreign_branch"],
)
def test_ruleset_rejects_incomplete_or_weak_activation(publisher_evidence, mutation):
    rule = publisher_evidence[f"{BASE}/rulesets/123"]
    params = rule["rules"][0]["parameters"]
    if mutation == "missing":
        params["required_status_checks"].pop()
    elif mutation == "duplicate":
        params["required_status_checks"].append(params["required_status_checks"][0])
    elif mutation == "nonstrict":
        params["strict_required_status_checks_policy"] = False
    elif mutation == "disabled":
        rule["enforcement"] = "disabled"
    elif mutation == "bypass":
        rule["bypass_actors"] = [{"actor_type": "RepositoryRole", "actor_id": 5}]
    else:
        rule["conditions"]["ref_name"]["include"] = ["refs/heads/other"]
    with pytest.raises(ValueError):
        gate.verify_reviewed_ruleset(rule, 777001)


@pytest.mark.parametrize(
    "mutation", ["bypass", "protected", "wildcard", "tag", "extra"]
)
def test_publisher_key_environment_rejects_pr_access(publisher_evidence, mutation):
    path = f"{BASE}/environments/{gate.PUBLISHER_ENVIRONMENT}"
    environment = publisher_evidence[path]
    policies = publisher_evidence[f"{path}/deployment-branch-policies?per_page=100"]
    if mutation == "bypass":
        environment["can_admins_bypass"] = True
    elif mutation == "protected":
        environment["deployment_branch_policy"]["protected_branches"] = True
    elif mutation == "wildcard":
        policies["branch_policies"][0]["name"] = "*"
    elif mutation == "tag":
        policies["branch_policies"][0]["type"] = "tag"
    else:
        policies["total_count"] = 2
    with pytest.raises(ValueError):
        gate.verify_publisher_boundary()


def test_status_writer_rejects_github_token_creator(monkeypatch):
    monkeypatch.setenv("GITHUB_RUN_ID", "123")
    monkeypatch.setattr(
        gate,
        "publisher_identity",
        lambda: {"id": 99, "login": "reviewed-test[bot]", "type": "Bot"},
    )

    def api(path, *args):
        fields = dict(arg.split("=", 1) for arg in args if "=" in arg)
        return {
            **fields,
            "creator": {"id": 41898282, "login": "github-actions[bot]", "type": "Bot"},
        }

    monkeypatch.setattr(gate, "gh", api)
    with pytest.raises(ValueError, match="dedicated issuer differs"):
        gate.publish_statuses(HEAD, "success")


@pytest.fixture
def publication_cli(evidence, monkeypatch, tmp_path):
    import json

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
        "GITHUB_EVENT_NAME": "workflow_run",
        "GITHUB_SHA": MAIN,
        "GITHUB_OUTPUT": str(tmp_path / "output"),
        "GITHUB_EVENT_PATH": str(event),
    }.items():
        monkeypatch.setenv(key, value)
    published = []
    monkeypatch.setattr(
        gate, "publish_statuses", lambda head, state: published.append((head, state))
    )
    monkeypatch.setattr(sys, "argv", ["admission", "--publish-pending"])
    return published


@pytest.mark.parametrize("conclusion", ["failure", "cancelled", "timed_out"])
def test_failed_review_signal_invalidates_prior_success_without_admission(
    evidence, publication_cli, monkeypatch, conclusion
):
    evidence[f"{BASE}/actions/runs/10"]["conclusion"] = conclusion
    evidence[f"{BASE}/pulls/1/reviews?per_page=100"][0][0]["state"] = "DISMISSED"
    called = []
    monkeypatch.setattr(gate, "admit", lambda *args: called.append(args))
    with pytest.raises(ValueError, match="signal did not succeed"):
        gate.main()
    assert publication_cli == [(HEAD, "pending"), (HEAD, "failure")]
    assert called == []


def test_dismissed_review_invalidates_success_on_successful_signal(
    evidence, publication_cli
):
    evidence[f"{BASE}/pulls/1/reviews?per_page=100"][0][0]["state"] = "DISMISSED"
    with pytest.raises(ValueError, match="No independent"):
        gate.main()
    assert publication_cli == [(HEAD, "pending"), (HEAD, "failure")]


def test_final_publication_invalidates_success_after_review_revocation(
    evidence, publication_cli, monkeypatch
):
    evidence[f"{BASE}/pulls/1/reviews?per_page=100"][0][0]["state"] = "DISMISSED"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "admission",
            "--number",
            "1",
            "--head-sha",
            HEAD,
            "--publish-result",
            "success",
        ],
    )
    with pytest.raises(ValueError, match="No independent"):
        gate.main()
    assert publication_cli == [(HEAD, "failure")]


def test_failed_execution_publishes_failure_after_valid_recheck(
    publication_cli, monkeypatch
):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "admission",
            "--number",
            "1",
            "--head-sha",
            HEAD,
            "--publish-result",
            "failure",
        ],
    )
    gate.main()
    assert publication_cli == [(HEAD, "failure")]


def test_boundary_cli_precedes_app_token_minting(
    publication_cli, publisher_evidence, monkeypatch
):
    monkeypatch.setattr(sys, "argv", ["admission", "--verify-publisher-boundary"])
    gate.main()
    assert publication_cli == []


def test_credential_job_rejection_has_no_status_writing_fallback(
    evidence, publication_cli, monkeypatch
):
    evidence[f"{BASE}/pulls/1/reviews?per_page=100"][0][0]["state"] = "DISMISSED"
    monkeypatch.setattr(sys, "argv", ["admission", "--number", "1", "--head-sha", HEAD])
    with pytest.raises(ValueError, match="No independent"):
        gate.main()
    assert publication_cli == []
