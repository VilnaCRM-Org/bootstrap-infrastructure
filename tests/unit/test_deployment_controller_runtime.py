"""Admission exercises real shared collectors through fake GitHub APIs only."""

from __future__ import annotations

import hashlib
import json
import sys
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))

import deployment_controller_runtime as runtime  # noqa: E402
from test_deployment_controller import input_facts  # noqa: E402


def output_values(path):
    """Read the actual GitHub output file written by admission."""
    return (
        dict(line.split("=", 1) for line in path.read_text().splitlines())
        if path.exists()
        else {}
    )


def fake_api(state, path, *args):
    """Serve modeled reads and permit only the one expected claim mutation."""
    base = f"repos/{runtime.REPOSITORY}"
    state.calls.append((path, args))
    if path in state.overrides:
        response = state.overrides[path]
        if isinstance(response, Exception):
            raise response
        return deepcopy(response)
    responses = {
        f"{base}/actions/runs/12": state.evidence["run"],
        f"{base}/issues/comments/9": state.evidence["comment"],
        f"{base}/collaborators/dmytrocraft/permission": {
            "permission": state.evidence["permission"]
        },
        f"{base}/compare/{'b' * 40}...{'a' * 40}": {
            "files": state.evidence["changed_file_records"]
        },
        "users/Kravalg": {"id": 44, "login": "Kravalg"},
    }
    if path in responses:
        return deepcopy(responses[path])
    if path == f"{base}/pulls/78":
        return deepcopy(
            state.pr_observations.pop(0)
            if state.pr_observations
            else state.evidence["pr"]
        )
    if path.startswith(f"{base}/environments/"):
        return deepcopy(
            state.policies
            if path.endswith("/deployment-branch-policies")
            else state.protected
        )
    if path == f"{base}/commits/{'a' * 40}/statuses?per_page=100":
        assert args == ("--paginate", "--slurp")
        return deepcopy(state.statuses)
    assert path == f"{base}/statuses/{'a' * 40}"
    assert args == (
        "--method",
        "POST",
        "-f",
        "state=success",
        "-f",
        "context=Pulumi command claim/9",
        "-f",
        "description=Comment command consumed",
    )
    state.events.append(("claim", output_values(state.output), state.contract.exists()))
    state.writes.append((path, args))
    state.statuses[-1].append({"context": "Pulumi command claim/9"})
    return {"id": 123}


@pytest.fixture
def github(monkeypatch, tmp_path):
    """Replace API and artifact transport while retaining real validation/claim code."""
    request, evidence, metadata = input_facts()
    created = (datetime.now(timezone.utc) - timedelta(seconds=60)).isoformat()
    evidence["comment"].update(created_at=created, updated_at=created)
    evidence["run"]["created_at"] = created
    output_path = tmp_path / "github-output"
    contract_path = tmp_path / runtime.CONTRACT_RELATIVE_PATH
    monkeypatch.setattr(runtime, "CONTRACT_PATH", contract_path)
    settings = {
        "DEPLOYMENT_COORDINATOR_MODE": "active",
        "GITHUB_EVENT_NAME": "repository_dispatch",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_REPOSITORY": runtime.REPOSITORY,
        "GITHUB_REPOSITORY_ID": str(runtime.REPOSITORY_ID),
        "GITHUB_REPOSITORY_OWNER_ID": str(runtime.OWNER_ID),
        "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_SHA": metadata.sha,
        "GITHUB_RUN_ID": metadata.run_id,
        "GITHUB_WORKFLOW_REF": metadata.workflow_ref,
        "GITHUB_OUTPUT": str(output_path),
        "GITHUB_API_URL": "https://api.github.com",
    }
    for key, value in settings.items():
        monkeypatch.setenv(key, value)
    for key, value in request.items():
        monkeypatch.setenv(f"REQUEST_{key.upper()}", value)
    state = SimpleNamespace(
        request=request,
        evidence=evidence,
        output=output_path,
        contract=contract_path,
        calls=[],
        events=[],
        writes=[],
        overrides={},
        pr_observations=[],
        statuses=[[]],
        artifact=dict(request),
        settings=settings,
    )
    state.protected = {
        "prevent_self_review": True,
        "reviewers": [{"type": "User", "id": 44}],
        "can_admins_bypass": False,
        "deployment_branch_policy": {
            "protected_branches": False,
            "custom_branch_policies": True,
        },
    }
    state.policies = {
        "total_count": 1,
        "branch_policies": [{"name": "main", "type": "branch"}],
    }

    def download(args, **kwargs):
        assert args[:3] == ["gh", "run", "download"]
        assert args[3:8] == [
            "12",
            "--repo",
            runtime.REPOSITORY,
            "--name",
            "pulumi-command-request",
        ]
        directory = Path(args[args.index("--dir") + 1])
        (directory / "request.json").write_text(json.dumps(state.artifact))
        state.events.append(("download",))
        return SimpleNamespace(returncode=0)

    original_write = runtime.preflight.write_outputs

    def write(outputs, output_path):
        state.events.append(
            ("execution" if "execution_ready" in outputs else "feedback",)
        )
        original_write(outputs, output_path)

    monkeypatch.setattr(
        runtime.preflight, "gh", lambda path, *args: fake_api(state, path, *args)
    )
    monkeypatch.setattr(runtime.preflight.subprocess, "run", download)
    monkeypatch.setattr(runtime.preflight, "write_outputs", write)
    return state


def set_request(github, monkeypatch, *, scopes=None, command="up", target="prod"):
    """Change all copies of the original request consistently in the fake backend."""
    github.request.update(command=command, target_environment=target)
    github.artifact = dict(github.request)
    github.evidence["comment"]["body"] = f"/pulumi {target} {command}"
    for key, value in github.request.items():
        monkeypatch.setenv(f"REQUEST_{key.upper()}", value)
    if scopes is not None:
        _, selected, _ = input_facts(scopes)
        github.evidence["changed_file_records"] = selected["changed_file_records"]
        github.evidence["pr"]["changed_files"] = selected["pr"]["changed_files"]


def assert_feedback_only(github):
    """A rejected request cannot provide any execution guard output or artifact."""
    values = output_values(github.output)
    assert set(values) == {
        "feedback_head_sha",
        "feedback_pull_request_number",
        "feedback_command",
        "feedback_target_environment",
        "feedback_display_command",
    }
    assert values["feedback_head_sha"] == "a" * 40
    assert not github.writes
    assert not github.contract.exists()


def test_accept_claims_once_after_checks_then_persists_canonical_contract(
    github, capsys
):
    github.evidence["changed_file_records"][0]["patch"] = "RAW PATCH MUST NOT ESCAPE"
    assert runtime.main(["accept"]) == 0
    values = output_values(github.output)
    raw = github.contract.read_bytes()
    contract = json.loads(raw)
    assert len(github.writes) == 1
    assert [event[0] for event in github.events] == [
        "download",
        "feedback",
        "claim",
        "execution",
    ]
    assert all(key.startswith("feedback_") for key in github.events[2][1])
    assert github.events[2][2] is False
    assert (
        raw
        == (
            json.dumps(
                contract, sort_keys=True, separators=(",", ":"), ensure_ascii=True
            )
            + "\n"
        ).encode()
    )
    assert values["execution_ready"] == "true"
    assert values["scopes"] == '["operator","governance","platform"]'
    assert values["contract_path"] == runtime.CONTRACT_RELATIVE_PATH
    assert values["contract_file_sha256"] == hashlib.sha256(raw).hexdigest()
    assert values["contract_digest"] == contract["contract_digest"]
    assert values["selection_digest"] == contract["selection_digest"]
    assert (
        values["selector_sha256"]
        == hashlib.sha256(
            Path(runtime.deployment_scopes.__file__).read_bytes()
        ).hexdigest()
    )
    assert (
        values["controller_sha"]
        == contract["identity"]["controller"]["sha"]
        == "c" * 40
    )
    assert values["controller_run_id"] == "100"
    assert values["controller_run_attempt"] == "1"
    assert values["controller_workflow_ref"] == github.settings["GITHUB_WORKFLOW_REF"]
    assert values["repository_id"] == str(runtime.REPOSITORY_ID)
    assert values["repository_owner_id"] == str(runtime.OWNER_ID)
    assert values["base_sha"] == "b" * 40
    assert all(values[key] == value for key, value in github.request.items())
    assert all(
        values[f"{scope}_selected"] == "true"
        for scope in runtime.deployment_scopes.STACK_ORDER
    )
    assert (
        values["scaffold_validation"]
        == values["catalog_validation"]
        == values["execution_validation"]
        == "false"
    )
    assert "RAW PATCH MUST NOT ESCAPE" not in raw.decode() + capsys.readouterr().out
    assert "changed_file_records" not in contract
    environment_reads = [
        path.split("/environments/")[1]
        for path, _ in github.calls
        if "/environments/" in path and not path.endswith("/deployment-branch-policies")
    ]
    assert environment_reads == [
        "operator-preview",
        "operator",
        "governance-preview",
        "governance",
        "test-preview",
        "test",
        "prod-preview",
        "prod",
    ]
    claim_index = next(
        index for index, (_, args) in enumerate(github.calls) if "POST" in args
    )
    assert all(
        index < claim_index
        for index, (path, _) in enumerate(github.calls)
        if "/environments/" in path
    )


@pytest.mark.parametrize(
    "mode",
    [None, "", "inactive", "installed", "unknown", "ACTIVE", " active", "active\n"],
)
def test_uninstalled_or_inactive_controller_has_no_io_or_outputs(
    github, monkeypatch, mode
):
    if mode is None:
        monkeypatch.delenv("DEPLOYMENT_COORDINATOR_MODE")
    else:
        monkeypatch.setenv("DEPLOYMENT_COORDINATOR_MODE", mode)
    with pytest.raises(ValueError, match="not active"):
        runtime.main(["accept"])
    assert not github.calls
    assert not github.events
    assert not github.output.exists()
    assert not github.contract.exists()


@pytest.mark.parametrize(
    "name",
    [
        "GITHUB_EVENT_NAME",
        "GITHUB_REF",
        "GITHUB_REPOSITORY",
        "GITHUB_REPOSITORY_ID",
        "GITHUB_REPOSITORY_OWNER_ID",
        "GITHUB_RUN_ATTEMPT",
        "GITHUB_WORKFLOW_REF",
        "GITHUB_SHA",
        "GITHUB_RUN_ID",
    ],
)
@pytest.mark.parametrize("value", [None, "wrong", ""])
def test_untrusted_or_missing_context_stops_before_api(
    github, monkeypatch, name, value
):
    if value is None:
        monkeypatch.delenv(name)
    else:
        monkeypatch.setenv(name, value)
    with pytest.raises(ValueError, match="Invalid trusted context"):
        runtime.main(["accept"])
    assert not github.calls
    assert not github.output.exists()
    assert not github.contract.exists()


@pytest.mark.parametrize(
    "name,value",
    [
        ("GITHUB_EVENT_NAME", "workflow_dispatch"),
        ("GITHUB_REF", "refs/pull/78/head"),
        ("GITHUB_RUN_ATTEMPT", "2"),
        ("GITHUB_RUN_ATTEMPT", "01"),
        ("GITHUB_RUN_ID", "0"),
        ("GITHUB_SHA", "A" * 40),
        (
            "GITHUB_WORKFLOW_REF",
            f"{runtime.REPOSITORY}/{runtime.WORKFLOW}@refs/pull/78/head",
        ),
        ("GITHUB_WORKFLOW_REF", f"foreign/repo/{runtime.WORKFLOW}@refs/heads/main"),
    ],
)
def test_rerun_or_forged_ref_cannot_admit(github, monkeypatch, name, value):
    monkeypatch.setenv(name, value)
    with pytest.raises(ValueError):
        runtime.accept()
    assert not github.calls
    assert not github.output.exists()


def test_context_identifiers_are_not_coerced_from_nonstring_values(github, monkeypatch):
    actual = dict(runtime.os.environ)
    actual["GITHUB_SHA"] = 123
    monkeypatch.setattr(runtime.os, "environ", actual)
    with pytest.raises(ValueError, match="GITHUB_SHA"):
        runtime.accept()
    assert not github.calls


@pytest.mark.parametrize("key", tuple(runtime.REQUEST_PATTERNS))
def test_invalid_dispatch_field_has_no_api_or_feedback(github, monkeypatch, key):
    monkeypatch.setenv(f"REQUEST_{key.upper()}", "bad\ninput")
    with pytest.raises(ValueError):
        runtime.accept()
    assert not github.calls
    assert not github.output.exists()


@pytest.mark.parametrize(
    "change",
    ["source_workflow", "source_event", "rerun", "edited", "actor", "artifact"],
)
def test_untrusted_intake_never_identifies_feedback_target(github, change):
    if change == "source_workflow":
        github.evidence["run"]["path"] = ".github/workflows/other.yml"
    elif change == "source_event":
        github.evidence["run"]["event"] = "workflow_dispatch"
    elif change == "rerun":
        github.evidence["run"]["run_attempt"] = 2
    elif change == "edited":
        github.evidence["comment"]["updated_at"] = datetime.now(
            timezone.utc
        ).isoformat()
    elif change == "actor":
        github.evidence["run"]["actor"]["id"] = 99
    else:
        github.artifact["head_sha"] = "e" * 40
    with pytest.raises(ValueError):
        runtime.accept()
    assert not github.output.exists()
    assert not github.contract.exists()
    assert not github.writes


@pytest.mark.parametrize(
    "change",
    ["unauthorized", "expired", "closed", "foreign_id", "incomplete", "unknown_path"],
)
def test_authenticated_request_rejection_exposes_feedback_only(github, change):
    if change == "unauthorized":
        github.evidence["permission"] = "read"
    elif change == "expired":
        created = (datetime.now(timezone.utc) - timedelta(minutes=16)).isoformat()
        github.evidence["comment"].update(created_at=created, updated_at=created)
        github.evidence["run"]["created_at"] = created
    elif change == "closed":
        github.evidence["pr"]["state"] = "closed"
    elif change == "foreign_id":
        github.evidence["pr"]["head"]["repo"]["id"] = 1
    elif change == "incomplete":
        github.evidence["changed_file_records"].pop()
    else:
        github.evidence["changed_file_records"][0]["filename"] = "unclassified.bin"
    with pytest.raises(ValueError):
        runtime.accept()
    assert_feedback_only(github)


@pytest.mark.parametrize("observation", [1, 2])
@pytest.mark.parametrize("field", ["head", "base", "count"])
def test_changed_file_collection_races_do_not_claim(github, observation, field):
    github.pr_observations = [deepcopy(github.evidence["pr"]) for _ in range(3)]
    changed = github.pr_observations[observation]
    if field == "count":
        changed["changed_files"] += 1
    else:
        changed[field]["sha"] = "e" * 40
    if field == "base" and observation == 1:
        github.overrides[
            f"repos/{runtime.REPOSITORY}/compare/{'e' * 40}...{'a' * 40}"
        ] = {"files": github.evidence["changed_file_records"]}
    with pytest.raises(ValueError):
        runtime.accept()
    assert_feedback_only(github)


@pytest.mark.parametrize(
    "scopes,command,target,expected",
    [
        (("operator",), "plan", "prod", ["operator-preview"]),
        (("operator",), "up", "test", ["operator-preview", "operator"]),
        (("governance",), "up", "prod", ["governance-preview", "governance"]),
        (("governance",), "plan", "test", ["governance-preview"]),
        (("platform",), "plan", "test", ["test-preview"]),
        (("platform",), "plan", "prod", ["test-preview", "prod-preview"]),
        (("platform",), "up", "test", ["test-preview", "test"]),
        ((), "up", "prod", []),
    ],
)
def test_only_selected_protected_environments_are_read(
    github, monkeypatch, scopes, command, target, expected
):
    set_request(github, monkeypatch, scopes=scopes, command=command, target=target)
    contract = runtime.accept()
    assert list(runtime.required_environments(contract)) == expected
    reads = [
        path.rsplit("/", 1)[-1]
        for path, _ in github.calls
        if "/environments/" in path and not path.endswith("/deployment-branch-policies")
    ]
    assert reads == expected
    values = output_values(github.output)
    assert json.loads(values["scopes"]) == list(scopes)
    assert values["has_deployment_scopes"] == str(bool(scopes)).lower()
    assert len(github.writes) == 1
    if not scopes:
        assert "users/Kravalg" not in [path for path, _ in github.calls]
        assert contract.schedule == ()


@pytest.mark.parametrize(
    "response", [None, [], {"id": True}, {"id": "44"}, {"id": 0}, {}]
)
def test_unreadable_reviewer_identity_blocks_claim(github, response):
    github.overrides["users/Kravalg"] = response
    with pytest.raises(ValueError):
        runtime.accept()
    assert_feedback_only(github)


@pytest.mark.parametrize(
    "target",
    [
        "operator-preview",
        "operator",
        "governance-preview",
        "governance",
        "test-preview",
        "test",
        "prod-preview",
        "prod",
    ],
)
def test_each_missing_selected_environment_blocks_claim(github, target):
    github.overrides[f"repos/{runtime.REPOSITORY}/environments/{target}"] = (
        RuntimeError("environment unavailable")
    )
    with pytest.raises(RuntimeError, match="unavailable"):
        runtime.accept()
    assert_feedback_only(github)


@pytest.mark.parametrize(
    "change",
    [
        "missing",
        "wrong_type",
        "self_review",
        "admin_bypass",
        "wrong_reviewer",
        "missing_policy",
        "partial_policy",
        "wildcard",
        "tag",
        "policy_type",
    ],
)
def test_environment_requires_current_complete_main_only_protection(github, change):
    endpoint = f"repos/{runtime.REPOSITORY}/environments/operator-preview"
    environment = {
        "prevent_self_review": True,
        "reviewers": [{"type": "User", "id": 44}],
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
    if change == "missing":
        environment = None
    elif change == "wrong_type":
        environment = []
    elif change == "self_review":
        environment["prevent_self_review"] = False
    elif change == "admin_bypass":
        environment["can_admins_bypass"] = True
    elif change == "wrong_reviewer":
        environment["reviewers"][0]["id"] = 99
    elif change == "missing_policy":
        policies = {}
    elif change == "partial_policy":
        policies["total_count"] = 2
    elif change == "wildcard":
        policies["branch_policies"][0]["name"] = "*"
    elif change == "tag":
        policies["branch_policies"][0]["type"] = "tag"
    else:
        policies = []
    github.overrides[endpoint] = environment
    github.overrides[f"{endpoint}/deployment-branch-policies"] = policies
    with pytest.raises(ValueError):
        runtime.accept()
    assert_feedback_only(github)


@pytest.mark.parametrize("failure", ["existing", "read_error", "write_error"])
def test_failed_claim_never_persists_or_exposes_execution(github, failure):
    base = f"repos/{runtime.REPOSITORY}"
    if failure == "existing":
        github.statuses = [[], [{"context": "Pulumi command claim/9"}]]
    elif failure == "read_error":
        github.overrides[f"{base}/commits/{'a' * 40}/statuses?per_page=100"] = (
            RuntimeError("claim failed")
        )
    else:
        github.overrides[f"{base}/statuses/{'a' * 40}"] = RuntimeError("claim failed")
    with pytest.raises((ValueError, RuntimeError)):
        runtime.accept()
    assert_feedback_only(github)


def test_missing_installed_selector_source_cannot_claim(github, monkeypatch, tmp_path):
    monkeypatch.setattr(
        runtime.deployment_scopes, "__file__", str(tmp_path / "missing-selector.py")
    )
    with pytest.raises(FileNotFoundError):
        runtime.accept()
    assert_feedback_only(github)


def test_existing_contract_is_never_overwritten_or_exposed_as_new_admission(github):
    github.contract.parent.mkdir(parents=True)
    github.contract.write_text("previous contract")
    with pytest.raises(FileExistsError):
        runtime.accept()
    assert len(github.writes) == 1
    assert github.contract.read_text() == "previous contract"
    assert all(key.startswith("feedback_") for key in output_values(github.output))
    assert [event[0] for event in github.events] == ["download", "feedback", "claim"]


def test_claimed_request_with_persistence_failure_has_no_execution_outputs(
    github, monkeypatch
):
    def fail(contract):
        raise OSError("artifact unavailable")

    monkeypatch.setattr(runtime, "_persist_contract", fail)
    with pytest.raises(OSError, match="artifact unavailable"):
        runtime.accept()
    assert len(github.writes) == 1
    assert not github.contract.exists()
    assert all(key.startswith("feedback_") for key in output_values(github.output))


@pytest.mark.parametrize(
    "args", [[], ["recheck"], ["apply"], ["accept", "--skip-claim"]]
)
def test_cli_has_no_bypass_or_unimplemented_commands(github, args):
    with pytest.raises(SystemExit) as exc:
        runtime.main(args)
    assert exc.value.code == 2
    assert not github.calls
    assert not github.output.exists()
