"""Negative authentication cases for the trusted comment-dispatch boundary."""

from __future__ import annotations

import importlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
preflight = importlib.import_module("pulumi_command_preflight")
UTC = timezone.utc


def fixture_data(*, governance=True, action="up", target="test"):
    request = {
        "pull_request_number": "78",
        "head_sha": "a" * 40,
        "comment_id": "9",
        "source_run_id": "12",
        "command": action,
        "target_environment": target,
    }
    created = "2026-09-05T12:00:00Z"
    evidence = {
        "scope_base_sha": "b" * 40,
        "repository": "org/repo",
        "api_url": "https://api.github.com",
        "artifact": dict(request),
        "permission": "write",
        "now": datetime(2026, 9, 5, 12, 1, tzinfo=UTC),
        "files": ["Makefile"] if governance else ["README.md"],
        "pr": {
            "state": "open",
            "changed_files": 2,
            "base": {"ref": "main", "sha": "b" * 40, "repo": {"full_name": "org/repo"}},
            "merged": False,
            "head": {"sha": "a" * 40, "repo": {"full_name": "org/repo"}},
        },
        "comment": {
            "id": 9,
            "issue_url": "https://api.github.com/repos/org/repo/issues/78",
            "created_at": created,
            "updated_at": created,
            "user": {"id": 10, "login": "dmytrocraft"},
            "body": f"/pulumi {target} {action}",
        },
        "run": {
            "id": 12,
            "event": "issue_comment",
            "path": preflight.INTAKE_PATH,
            "head_repository": {"full_name": "org/repo"},
            "run_attempt": 1,
            "actor": {"id": 10},
            "created_at": created,
        },
    }
    return request, evidence


@pytest.mark.parametrize("governance", [False, True])
@pytest.mark.parametrize("action", ["plan", "up"])
@pytest.mark.parametrize("target", ["test", "prod"])
def test_authentic_commands(governance, action, target):
    request, evidence = fixture_data(
        governance=governance, action=action, target=target
    )
    if action == "plan":
        evidence["comment"]["user"]["login"] = "dmytrocraft"
    result = preflight.validate_request(request, evidence, governance=governance)
    assert result["display_command"] == f"/pulumi {target} {action}"


def test_service_scope_preserves_authentication_for_control_file_changes():
    request, evidence = fixture_data(governance=True, action="plan")
    evidence["comment"]["user"]["login"] = "dmytrocraft"
    assert (
        preflight.validate_request(request, evidence, governance=False, service=True)[
            "head_sha"
        ]
        == request["head_sha"]
    )
    evidence["comment"]["issue_url"] = "https://api.github.com/repos/org/repo/issues/99"
    with pytest.raises(ValueError, match="another PR"):
        preflight.validate_request(request, evidence, governance=False, service=True)


@pytest.mark.parametrize(
    "path,value",
    [
        (("run", "event"), "workflow_dispatch"),
        (("run", "path"), ".github/workflows/attacker.yml"),
        (("run", "head_repository", "full_name"), "fork/repo"),
        (("run", "run_attempt"), 2),
        (("run", "id"), 13),
        (("artifact", "command"), "plan"),
        (("pr", "state"), "closed"),
        (("pr", "base", "ref"), "attacker"),
        (("pr", "base", "sha"), "c" * 40),
        (("pr", "base", "repo", "full_name"), "fork/repo"),
        (("pr", "merged"), True),
        (("pr", "head", "repo", "full_name"), "fork/repo"),
        (("pr", "head", "sha"), "b" * 40),
        (("comment", "issue_url"), "https://api.github.com/repos/org/repo/issues/79"),
        (("comment", "id"), 11),
        (("comment", "updated_at"), "2026-09-05T12:00:01Z"),
        (("run", "created_at"), "2026-09-05T12:06:00Z"),
        (("run", "created_at"), "2026-09-05T11:59:59Z"),
        (("now",), datetime(2026, 9, 5, 12, 16, tzinfo=UTC)),
        (("now",), datetime(2026, 9, 5, 11, 59, tzinfo=UTC)),
        (("run", "actor", "id"), 11),
        (("comment", "body"), "Approved"),
        (("comment", "body"), "/pulumi test plan"),
        (("comment", "body"), "/pulumi prod up"),
        (("permission",), "read"),
        (("comment", "user", "login"), "Kravalg"),
        (("files",), ["README.md"]),
    ],
)
def test_rejects_forged_stale_cross_pr_and_unauthorized_requests(path, value):
    request, evidence = fixture_data()
    node = evidence
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = value
    with pytest.raises(ValueError):
        preflight.validate_request(request, evidence, governance=True)


def test_generic_runner_rejects_governance_bypass():
    request, evidence = fixture_data()
    with pytest.raises(ValueError, match="scope"):
        preflight.validate_request(request, evidence, governance=False)


def set_request_env(monkeypatch, request):
    for key, value in request.items():
        monkeypatch.setenv(f"REQUEST_{key.upper()}", value)


def test_read_request_accepts_closed_format(monkeypatch):
    request, _ = fixture_data()
    set_request_env(monkeypatch, request)
    assert preflight.read_request() == request


@pytest.mark.parametrize("key", list(fixture_data()[0]))
def test_read_request_rejects_missing_and_injected_fields(monkeypatch, key):
    request, _ = fixture_data()
    set_request_env(monkeypatch, request)
    monkeypatch.delenv(f"REQUEST_{key.upper()}")
    with pytest.raises(ValueError, match=f"Invalid {key}"):
        preflight.read_request()
    monkeypatch.setenv(f"REQUEST_{key.upper()}", "bad\noutput=up")
    with pytest.raises(ValueError):
        preflight.read_request()


def test_gh_uses_argument_array_and_parses_json(monkeypatch):
    calls = []
    monkeypatch.setattr(
        preflight.subprocess,
        "run",
        lambda args, **kw: (
            calls.append((args, kw)) or SimpleNamespace(stdout='{"permission":"write"}')
        ),
    )
    assert preflight.gh("repos/org/repo") == {"permission": "write"}
    assert calls[0][0] == ["gh", "api", "repos/org/repo"]
    assert calls[0][1]["check"] is True


def test_collect_evidence_paginates_and_protects_renamed_paths(monkeypatch):
    request, evidence = fixture_data()
    monkeypatch.setenv("GITHUB_REPOSITORY", "org/repo")

    def api(path, *args):
        if "/actions/runs/" in path:
            return evidence["run"]
        if "/issues/comments/" in path:
            return evidence["comment"]
        if "/compare/" in path:
            assert path.endswith(f"{'b' * 40}...{'a' * 40}")
            assert args == ()
            return {
                "files": [
                    {"filename": "README.md", "previous_filename": "Makefile"},
                    {"filename": "docs/example.md"},
                ]
            }
        if "/collaborators/" in path:
            return {"permission": "write"}
        return evidence["pr"]

    def download(args, **kwargs):
        (Path(args[-1]) / "request.json").write_text(json.dumps(request))

    monkeypatch.setattr(preflight, "gh", api)
    monkeypatch.setattr(preflight.subprocess, "run", download)
    result = preflight.collect_evidence(request)
    assert result["artifact"] == request
    assert result["files"] == ["README.md", "Makefile", "docs/example.md", ""]
    assert result["pr"] == evidence["pr"]


def test_collect_rejects_untrusted_source_before_download(monkeypatch):
    request, evidence = fixture_data()
    monkeypatch.setenv("GITHUB_REPOSITORY", "org/repo")
    evidence["run"]["path"] = "attacker.yml"
    monkeypatch.setattr(preflight, "gh", lambda *args: evidence["run"])
    with pytest.raises(ValueError, match="Untrusted"):
        preflight.collect_evidence(request)


def test_claim_is_single_use_including_older_status_pages(monkeypatch):
    request, _ = fixture_data()
    monkeypatch.setenv("GITHUB_REPOSITORY", "org/repo")
    calls = []
    monkeypatch.setattr(preflight, "gh", lambda *args: calls.append(args) or [[]])
    preflight.claim_request(request)
    assert len(calls) == 2
    assert "context=Pulumi command claim/9" in calls[1]
    monkeypatch.setattr(
        preflight, "gh", lambda *args: [[], [{"context": "Pulumi command claim/9"}]]
    )
    with pytest.raises(ValueError, match="already consumed"):
        preflight.claim_request(request)


def test_main_exposes_outputs_only_after_claim(monkeypatch, tmp_path):
    request, evidence = fixture_data()
    set_request_env(monkeypatch, request)
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "1")
    monkeypatch.setenv("GITHUB_EVENT_NAME", "repository_dispatch")
    monkeypatch.setenv("GITHUB_REF", "refs/heads/main")
    monkeypatch.setenv("GITHUB_OUTPUT", str(tmp_path / "output"))
    monkeypatch.setattr(preflight, "collect_intake_evidence", lambda request: evidence)
    monkeypatch.setattr(
        preflight, "collect_evidence", lambda request, **kwargs: evidence
    )
    monkeypatch.setattr(preflight, "verify_environments", lambda *args, **kwargs: None)
    claimed = []
    monkeypatch.setattr(
        preflight, "claim_request", lambda request: claimed.append(request)
    )
    assert preflight.main(["--governance"]) == 0
    assert claimed == [request]
    assert "command=up" in (tmp_path / "output").read_text()
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "2")
    with pytest.raises(ValueError, match="Re-run"):
        preflight.main([])


@pytest.mark.parametrize(
    "governance,action,target,names",
    [
        (True, "plan", "test", ["governance-preview"]),
        (True, "up", "prod", ["governance-preview", "governance"]),
        (False, "plan", "test", ["test-preview"]),
        (False, "plan", "prod", ["test-preview", "prod-preview"]),
        (False, "up", "test", ["test-preview", "test"]),
        (False, "up", "prod", ["test-preview", "prod-preview", "test", "prod"]),
    ],
)
def test_verify_environments_requires_current_protections(
    monkeypatch, governance, action, target, names
):
    request, _ = fixture_data(action=action, target=target)
    monkeypatch.setenv("GITHUB_REPOSITORY", "org/repo")
    calls = []
    environment = {
        "prevent_self_review": True,
        "reviewers": [{"type": "User", "id": 10}],
        "can_admins_bypass": False,
        "deployment_branch_policy": {
            "protected_branches": False,
            "custom_branch_policies": True,
        },
    }

    def api(path):
        calls.append(path)
        if path.endswith("/deployment-branch-policies"):
            return {
                "total_count": 1,
                "branch_policies": [{"name": "main", "type": "branch"}],
            }
        return {"id": 10} if path == "users/Kravalg" else environment

    monkeypatch.setattr(preflight, "gh", api)
    preflight.verify_environments(request, governance=governance)
    assert calls[1:] == [
        f"repos/org/repo/environments/{name}{suffix}"
        for name in names
        for suffix in ("", "/deployment-branch-policies")
    ]
    environment["prevent_self_review"] = False
    with pytest.raises(ValueError, match="self-review"):
        preflight.verify_environments(request, governance=governance)
    environment["prevent_self_review"] = True
    environment["reviewers"].append({"type": "User", "id": 11})
    with pytest.raises(ValueError, match="only the configured reviewer"):
        preflight.verify_environments(request, governance=governance)


@pytest.mark.parametrize(
    "event,ref",
    [
        ("workflow_dispatch", "refs/heads/main"),
        ("repository_dispatch", "refs/heads/attacker"),
    ],
)
def test_main_rejects_wrong_event_or_untrusted_ref(monkeypatch, event, ref):
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "1")
    monkeypatch.setenv("GITHUB_EVENT_NAME", event)
    monkeypatch.setenv("GITHUB_REF", ref)
    with pytest.raises(ValueError, match="Only"):
        preflight.main([])


@pytest.mark.parametrize("governance", [False, True])
@pytest.mark.parametrize("login", ["Kravalg", "kRaVaLg"])
def test_up_rejects_same_human_requester_and_sole_approver(governance, login):
    request, evidence = fixture_data(governance=governance)
    evidence["comment"]["user"]["login"] = login
    with pytest.raises(ValueError, match="requester must differ"):
        preflight.validate_request(request, evidence, governance=governance)


def _feedback_runtime(monkeypatch, tmp_path, evidence, request):
    """Configure an offline preflight with observable output and claim boundaries."""
    set_request_env(monkeypatch, request)
    monkeypatch.setenv("GITHUB_REPOSITORY", "org/repo")
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "1")
    monkeypatch.setenv("GITHUB_EVENT_NAME", "repository_dispatch")
    monkeypatch.setenv("GITHUB_REF", "refs/heads/main")
    output = tmp_path / "output"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    monkeypatch.setattr(preflight, "collect_intake_evidence", lambda _: evidence)
    monkeypatch.setattr(preflight, "collect_evidence", lambda *args, **kw: evidence)
    monkeypatch.setattr(preflight, "verify_environments", lambda *args, **kw: None)
    monkeypatch.setattr(preflight, "claim_request", lambda _: None)
    return output


def _feedback_values(output):
    """Read the exact Actions output keys, avoiding substring-based assertions."""
    return dict(line.split("=", 1) for line in output.read_text().splitlines())


@pytest.mark.parametrize(
    "path,value",
    [
        (("permission",), "read"),
        (("pr", "head", "sha"), "c" * 40),
        (("pr", "base", "ref"), "release"),
        (("pr", "state"), "closed"),
        (("now",), datetime(2026, 9, 5, 12, 16, tzinfo=UTC)),
        (("files",), ["README.md"]),
        (("comment", "user", "login"), "Kravalg"),
    ],
)
def test_rejection_keeps_feedback_only(monkeypatch, tmp_path, path, value):
    """Mutable authorization failure cannot turn feedback into execution outputs."""
    request, evidence = fixture_data()
    node = evidence
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = value
    output = _feedback_runtime(monkeypatch, tmp_path, evidence, request)
    claims = []
    monkeypatch.setattr(preflight, "claim_request", lambda args: claims.append(args))
    with pytest.raises(ValueError):
        preflight.main(["--governance"])
    assert _feedback_values(output) == {
        "feedback_head_sha": request["head_sha"],
        "feedback_pull_request_number": "78",
        "feedback_command": "up",
        "feedback_target_environment": "test",
        "feedback_display_command": "/pulumi test up",
    }
    assert claims == []


@pytest.mark.parametrize(
    "path,value",
    [
        (("run", "event"), "workflow_dispatch"),
        (("run", "path"), "attacker.yml"),
        (("run", "head_repository", "full_name"), "foreign/repo"),
        (("run", "run_attempt"), 2),
        (("run", "id"), 13),
        (("artifact", "head_sha"), "c" * 40),
        (("pr", "head", "repo", "full_name"), "foreign/repo"),
        (("pr", "base", "repo", "full_name"), "foreign/repo"),
        (("comment", "issue_url"), "https://api.github.com/repos/org/repo/issues/99"),
        (("comment", "id"), 99),
        (("comment", "updated_at"), "2026-09-05T12:00:01Z"),
        (("run", "actor", "id"), 99),
        (("comment", "body"), "/pulumi prod up"),
    ],
)
def test_untrusted_origin_has_no_target(monkeypatch, tmp_path, path, value):
    """Forged source, artifact, repository or comment cannot select a victim SHA."""
    request, evidence = fixture_data()
    node = evidence
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = value
    output = _feedback_runtime(monkeypatch, tmp_path, evidence, request)
    current_reads = []
    monkeypatch.setattr(
        preflight,
        "collect_evidence",
        lambda *args, **kw: current_reads.append(args) or evidence,
    )
    with pytest.raises(ValueError):
        preflight.main(["--governance"])
    assert not output.exists()
    assert current_reads == []


@pytest.mark.parametrize("missing", ["artifact", "run", "comment", "pr"])
def test_missing_origin_has_no_feedback(monkeypatch, tmp_path, missing):
    """Incomplete intake evidence never yields a feedback commit or PR number."""
    request, evidence = fixture_data()
    del evidence[missing]
    output = _feedback_runtime(monkeypatch, tmp_path, evidence, request)
    with pytest.raises(KeyError):
        preflight.main(["--governance"])
    assert not output.exists()


@pytest.mark.parametrize("failure", ["duplicate", "claim-api", "environment"])
def test_claim_failure_has_no_exec_keys(monkeypatch, tmp_path, failure):
    """Known origin remains visible when actual claim/protection checks fail."""
    request, evidence = fixture_data()
    claim = preflight.claim_request
    output = _feedback_runtime(monkeypatch, tmp_path, evidence, request)

    def reject(*args, **kwargs):
        values = _feedback_values(output)
        assert values and all(key.startswith("feedback_") for key in values)
        raise ValueError("environment")

    def api(*args):
        assert all(key.startswith("feedback_") for key in _feedback_values(output))
        if "--method" in args:
            raise preflight.subprocess.CalledProcessError(1, ["gh", "api"])
        if failure == "duplicate":
            return [[], [{"context": "Pulumi command claim/9"}]]
        return [[]]

    if failure == "environment":
        monkeypatch.setattr(preflight, "verify_environments", reject)
    else:
        monkeypatch.setattr(preflight, "claim_request", claim)
        monkeypatch.setattr(preflight, "gh", api)
    exception = (
        preflight.subprocess.CalledProcessError
        if failure == "claim-api"
        else ValueError
    )
    with pytest.raises(exception):
        preflight.main(["--governance"])
    assert all(key.startswith("feedback_") for key in _feedback_values(output))


def test_success_emits_exec_after_claim(monkeypatch, tmp_path):
    """Only a successful final claim exposes the original execution contract."""
    request, evidence = fixture_data()
    output = _feedback_runtime(monkeypatch, tmp_path, evidence, request)
    observed = []
    monkeypatch.setattr(
        preflight, "claim_request", lambda _: observed.append(_feedback_values(output))
    )
    assert preflight.main(["--governance"]) == 0
    assert all(key.startswith("feedback_") for key in observed[0])
    result = _feedback_values(output)
    assert result["head_sha"] == request["head_sha"]
    assert result["command"] == "up"
    assert result["base_sha"] == "b" * 40


def test_early_stale_head_keeps_feedback(monkeypatch, tmp_path):
    """Real current-evidence collection can reject before scope and still report."""
    request, evidence = fixture_data()
    collector = preflight.collect_evidence
    output = _feedback_runtime(monkeypatch, tmp_path, evidence, request)
    monkeypatch.setattr(preflight, "collect_evidence", collector)
    changed_pr = {**evidence["pr"], "head": {"sha": "c" * 40}}
    calls = []
    monkeypatch.setattr(preflight, "gh", lambda *args: calls.append(args) or changed_pr)
    with pytest.raises(ValueError, match="head moved before scope scan"):
        preflight.main(["--governance"])
    assert _feedback_values(output)["feedback_head_sha"] == request["head_sha"]
    assert len(calls) == 1
    assert "head_sha" not in _feedback_values(output)


@pytest.mark.parametrize("malformed_field", ["environment", "policies"])
def test_environment_envelope_shape_rejected_before_policy_validation(
    monkeypatch, malformed_field
):
    """Dict-coercible API arrays are not authenticated object responses."""
    request, _ = fixture_data(action="plan", target="test")
    monkeypatch.setenv("GITHUB_REPOSITORY", "org/repo")
    environment = {
        "prevent_self_review": True,
        "reviewers": [{"type": "User", "id": 10}],
        "can_admins_bypass": False,
        "deployment_branch_policy": {
            "protected_branches": False,
            "custom_branch_policies": True,
        },
    }
    policies = {
        "total_count": 1,
        "branch_policies": [{"name": "main", "type": "branch"}],
    }
    responses = {
        "users/Kravalg": {"id": 10},
        "repos/org/repo/environments/test-preview": list(environment.items())
        if malformed_field == "environment"
        else environment,
        "repos/org/repo/environments/test-preview/deployment-branch-policies": list(
            policies.items()
        )
        if malformed_field == "policies"
        else policies,
    }
    monkeypatch.setattr(preflight, "gh", responses.__getitem__)
    reached_validation = []
    original = preflight.protected_environment_verification_blockers

    def observe(*args, **kwargs):
        reached_validation.append(True)
        return original(*args, **kwargs)

    monkeypatch.setattr(
        preflight, "protected_environment_verification_blockers", observe
    )
    with pytest.raises(
        ValueError, match="environment and branch policies must be objects"
    ):
        preflight.verify_environments(request, governance=False)
    assert reached_validation == []
