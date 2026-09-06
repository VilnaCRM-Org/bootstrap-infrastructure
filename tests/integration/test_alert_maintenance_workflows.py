"""Execute protected alert maintenance shells against a stateful GitHub double."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
REPO = "example/infra"
GH_DOUBLE = r"""
import json, os, sys
from pathlib import Path
args = sys.argv[1:]
path = Path(os.environ["FAKE_GH_STATE"])
data = json.loads(path.read_text())
def save():
    path.write_text(json.dumps(data))
def option(flag):
    return args[args.index(flag) + 1]
data.setdefault("calls", []).append(args)
save()
if args[:2] == ["issue", "view"]:
    field = option("--json")
    assert field in {"state", "title", "body"}
    assert option("--jq") == "." + field
    print(data["issues"][args[2]][field])
elif args[:2] == ["api", "graphql"]:
    query = next(a[6:] for a in args if a.startswith("query="))
    assert "".join(query.split()) == (
        "query($owner:String!,$name:String!,$number:Int!){"
        "repository(owner:$owner,name:$name){issue(number:$number){"
        "statestateReasonduplicateOf{numberrepository{nameWithOwner}}}}}"
    )
    assert "owner=example" in args and "name=infra" in args
    issue = next(a[7:] for a in args if a.startswith("number="))
    record = data["issues"][issue]
    data.setdefault("verified", []).append(issue)
    save()
    print(json.dumps({"data": {"repository": {"issue": {
        "state": record["state"],
        "stateReason": record.get("stateReason"),
        "duplicateOf": record.get("duplicateOf"),
    }}}}))
elif args[:2] == ["issue", "close"]:
    issue = args[2]
    if issue == data.get("fail_once"):
        data.pop("fail_once")
        save()
        sys.exit(1)
    record = data["issues"][issue]
    record.update(state="CLOSED", stateReason="DUPLICATE", duplicateOf={
        "number": int(option("--duplicate-of")),
        "repository": {"nameWithOwner": option("--repo")},
    })
    data.setdefault("closed", []).append(issue)
    data.setdefault("closure_comments", []).append(option("--comment"))
    save()
elif args[:2] == ["issue", "list"]:
    assert option("--limit") == "2"
    assert option("--json") == "number,body"
    search = option("--search")
    fingerprint = search.split('"')[1]
    assert search == f'"{fingerprint}" in:body'
    marker = f"<!-- operations-alert:fingerprint={fingerprint} -->"
    print(json.dumps([{
        "number": n, "body": data.get("match_body", marker),
    } for n in data.get("matches", [])][:2]))
elif args[:2] == ["issue", "comment"]:
    data.setdefault("comments", []).append({
        "number": args[2], "body": Path(option("--body-file")).read_text(),
    })
    save()
elif args[:2] == ["issue", "create"]:
    data["created_body"] = Path(option("--body-file")).read_text()
    save()
    print("https://github.com/example/infra/issues/99")
elif args[:2] == ["variable", "list"]:
    environment = option("--env")
    data.setdefault("listed", []).append(environment)
    save()
    if environment == data.get("unreadable"):
        sys.exit(1)
    print("\n".join(data["variables"][environment]))
elif args[:2] == ["variable", "delete"]:
    environment = option("--env")
    assert set(data["variables"]) <= set(data.get("listed", []))
    data["variables"][environment].remove(args[2])
    data.setdefault("deleted", []).append([environment, args[2]])
    save()
else:
    raise AssertionError(args)
"""


def workflow_job(filename, job_name):
    """Load executable workflow source rather than duplicating its shell logic."""
    workflow = yaml.safe_load((ROOT / ".github/workflows" / filename).read_text())
    return workflow["jobs"][job_name]


def run_workflow(tmp_path, filename, job_name, step_name, state, **inputs):
    """Run the named actual workflow step with no live GitHub credentials."""
    job = workflow_job(filename, job_name)
    script = next(s["run"] for s in job["steps"] if s.get("name") == step_name)
    binary_dir = tmp_path / "bin"
    binary_dir.mkdir(exist_ok=True)
    gh = binary_dir / "gh"
    gh.write_text(f"#!{sys.executable}\n" + GH_DOUBLE)
    gh.chmod(0o755)
    state_path = tmp_path / "github.json"
    state_path.write_text(json.dumps(state))
    result = subprocess.run(
        ["bash", "-euo", "pipefail", "-c", script],
        cwd=ROOT,
        env={
            "PATH": str(binary_dir) + os.pathsep + os.environ["PATH"],
            "TMPDIR": str(tmp_path),
            "FAKE_GH_STATE": str(state_path),
            "GH_REPO": REPO,
            **inputs,
        },
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    return result, json.loads(state_path.read_text())


def issue_state():
    """Two open legacy issues plus an open canonical fingerprinted issue."""
    issues = {
        str(number): {
            "state": "OPEN",
            "title": "Operations alerts queued: 1",
            "body": "legacy",
        }
        for number in (10, 11, 12)
    }
    issues["10"]["body"] = "<!-- operations-alert:fingerprint=reviewed -->"
    return {"issues": issues}


def reconcile(tmp_path, state, legacy="11,12", reference="https://example.invalid/sre"):
    """Run the closure step with an explicit SRE attestation reference."""
    return run_workflow(
        tmp_path,
        "operations-alert-reconcile.yml",
        "reconcile",
        "Reconcile legacy operations alerts",
        state,
        CANONICAL_ISSUE="10",
        LEGACY_ISSUES=legacy,
        CONFIRMATION=(
            "I confirm these legacy issues match the canonical operations alert stream"
        ),
        SRE_CONFIRMATION_REFERENCE=reference,
    )


@pytest.mark.parametrize("legacy", ["11,10", "11,invalid", "", "11,010", "11,0"])
def test_invalid_reconcile_input_has_zero_closure_effects(tmp_path, legacy):
    result, state = reconcile(tmp_path, issue_state(), legacy)
    assert result.returncode != 0
    assert not state.get("closed")
    assert all(i["state"] == "OPEN" for i in state["issues"].values())


@pytest.mark.parametrize(
    "field,value",
    [("title", "Unrelated"), ("body", "operations-alert:fingerprint=other")],
)
def test_invalid_later_issue_is_rejected_before_any_closure(tmp_path, field, value):
    state = issue_state()
    state["issues"]["12"][field] = value
    result, updated = reconcile(tmp_path, state)
    assert result.returncode != 0
    assert not updated.get("closed")


def test_partial_closure_retry_skips_only_verified_success(tmp_path):
    state = issue_state()
    state["fail_once"] = "12"
    result, state = reconcile(tmp_path, state)
    assert result.returncode != 0
    assert state["closed"] == ["11"]
    result, state = reconcile(tmp_path, state)
    assert result.returncode == 0, result.stderr
    assert state["closed"] == ["11", "12"]
    assert state["verified"] == ["11"]
    result, state = reconcile(tmp_path, state)
    assert result.returncode == 0, result.stderr
    assert state["closed"] == ["11", "12"]


@pytest.mark.parametrize(
    "fault", ["missing", "wrong_issue", "wrong_repo", "wrong_reason"]
)
def test_closed_duplicate_requires_exact_current_canonical_evidence(tmp_path, fault):
    state = issue_state()
    closed = state["issues"]["12"]
    closed.update(
        state="CLOSED",
        stateReason="DUPLICATE",
        duplicateOf={
            "number": 10,
            "repository": {"nameWithOwner": REPO},
        },
    )
    if fault == "missing":
        closed["duplicateOf"] = None
    elif fault == "wrong_issue":
        closed["duplicateOf"]["number"] = 99
    elif fault == "wrong_repo":
        closed["duplicateOf"]["repository"]["nameWithOwner"] = "other/infra"
    else:
        closed["stateReason"] = "COMPLETED"
    result, updated = reconcile(tmp_path, state)
    assert result.returncode != 0
    assert not updated.get("closed")
    assert updated["issues"]["11"]["state"] == "OPEN"


def test_reconcile_requires_main_branch():
    assert workflow_job("operations-alert-reconcile.yml", "reconcile")["if"] == (
        "github.ref == 'refs/heads/main'"
    )


def backfill(tmp_path, state, reference="https://example.invalid/sre"):
    """Execute the complete backfill shell against the stateful GitHub double."""
    event = '{"source":"aws.health","detail-type":"AWS Health Event","detail":{}}'
    return run_workflow(
        tmp_path,
        "operations-alert-backfill.yml",
        "backfill",
        "Create or update canonical operations alert issue",
        state,
        STABLE_EVENT_JSON=event,
        MESSAGE_COUNT="37",
        OPERATIONS_ALERT_QUEUE_NAME="reviewed-queue",
        AWS_ACCOUNT_ID="123456789012",
        AWS_REGION="eu-central-1",
        CONFIRMATION=(
            "I confirm these stable fields represent the canonical "
            "operations alert stream"
        ),
        SRE_CONFIRMATION_REFERENCE=reference,
    )


def test_backfill_body_distinguishes_representative_from_legacy_count(tmp_path):
    result, state = backfill(tmp_path, {})
    assert result.returncode == 0, result.stderr
    body = state["created_body"]
    assert "one synthetic representative event" in body
    assert "37 legacy message(s)" in body
    assert "queue contains 1 message(s)" not in body
    assert "operations-alert:fingerprint=" in body


@pytest.mark.parametrize("workflow", [backfill, reconcile])
@pytest.mark.parametrize(
    "reference",
    [
        "https://?",
        "https://%host.invalid",
        "https://-bad.invalid",
        "https://bad..invalid",
        "https://[gg::]/reference",
        "https://[bad",
        "https://:443/path",
        "http://example.invalid",
        "https://user:password@example.invalid",
        "https://example.invalid:70000",
        "https://example.invalid:bad",
        " https://example.invalid",
        "https://example.invalid/\nreference",
        "https://example.invalid/\x01reference",
        "https://example.invalid/\x7freference",
        "https://example.invalid/\u0085reference",
        "https://example.invalid/\u202ereference",
        "https://example.invalid/\u200breference",
        "https://example.invalid/?token=synthetic",
        "https://example.invalid/#fragment",
        "https://example.invalid/a)[click](https://attacker.invalid)",
        "https://example.invalid/<script>",
        "https://example.invalid/`code`",
        "https://example.invalid/\\reference",
    ],
)
def test_invalid_confirmation_url_fails_before_any_github_call(
    tmp_path, workflow, reference
):
    result, state = workflow(tmp_path, issue_state(), reference=reference)
    assert result.returncode != 0
    assert "sre_confirmation_reference must be an HTTPS URL" in result.stderr
    assert not state.get("calls")


@pytest.mark.parametrize("workflow", [backfill, reconcile])
def test_confirmation_url_is_rendered_as_one_safe_autolink(tmp_path, workflow):
    reference = "https://example.invalid/review/%5B123%5D"
    result, state = workflow(tmp_path, issue_state(), reference=reference)
    assert result.returncode == 0, result.stderr
    bodies = (
        [state["created_body"]] if workflow is backfill else state["closure_comments"]
    )
    assert all(f"SRE confirmation reference: <{reference}>" in body for body in bodies)


@pytest.mark.parametrize("matches", [[], [11], [11, 12, 13]])
def test_backfill_requires_unambiguous_canonical_search(tmp_path, matches):
    result, state = backfill(tmp_path, {"matches": matches})
    if len(matches) > 1:
        assert result.returncode != 0
        assert "multiple open canonical issues" in result.stderr
        assert all(call[:2] == ["issue", "list"] for call in state["calls"])
    elif matches:
        assert result.returncode == 0, result.stderr
        assert state["comments"][0]["number"] == "11"
        assert "created_body" not in state
    else:
        assert result.returncode == 0, result.stderr
        assert "created_body" in state
        assert "comments" not in state


def test_backfill_rejects_search_hit_without_exact_body_marker(tmp_path):
    result, state = backfill(tmp_path, {"matches": [11], "match_body": "unrelated"})
    assert result.returncode == 1
    assert "without the exact fingerprint marker" in result.stderr
    assert all(call[:2] == ["issue", "list"] for call in state["calls"])


@pytest.mark.parametrize("dry_run", ["true", "false"])
def test_cleanup_visits_test_preview_and_preserves_unlisted_variables(
    tmp_path, dry_run
):
    environments = ("test-preview", "test", "prod-preview", "prod")
    variables = [
        "PULUMI_PR_BACKEND_URL",
        "PULUMI_PR_PREVIEW_STACKS",
        "AWS_TEST_ACCOUNT_ID",
        "OTHER",
    ]
    result, state = run_workflow(
        tmp_path,
        "github-environment-legacy-cleanup.yml",
        "cleanup",
        "Remove legacy GitHub Environment variables",
        {"variables": {name: list(variables) for name in environments}},
        GH_ENVIRONMENT_ADMIN_TOKEN="test-placeholder",
        DRY_RUN=dry_run,
        CONFIRMATION=(
            "I confirm AWS Secrets Manager-backed privileged CI is green and "
            "legacy GitHub Environment variables can be removed"
        ),
    )
    assert result.returncode == 0, result.stderr
    for name in environments:
        assert state["variables"][name] == (
            variables if dry_run == "true" else ["AWS_TEST_ACCOUNT_ID", "OTHER"]
        )


@pytest.mark.parametrize("dry_run", ["true", "false"])
@pytest.mark.parametrize("unreadable", ["test-preview", "test", "prod-preview", "prod"])
def test_cleanup_unreadable_inventory_fails_before_any_deletion(
    tmp_path, dry_run, unreadable
):
    variables = {
        name: ["AWS_REGION"]
        for name in ("test-preview", "test", "prod-preview", "prod")
    }
    result, state = run_workflow(
        tmp_path,
        "github-environment-legacy-cleanup.yml",
        "cleanup",
        "Remove legacy GitHub Environment variables",
        {"variables": variables, "unreadable": unreadable},
        GH_ENVIRONMENT_ADMIN_TOKEN="test-placeholder",
        DRY_RUN=dry_run,
        CONFIRMATION=(
            "I confirm AWS Secrets Manager-backed privileged CI is green and "
            "legacy GitHub Environment variables can be removed"
        ),
    )
    assert result.returncode != 0
    assert "::error::" in result.stderr
    assert "inventory is incomplete" in result.stderr
    assert state["variables"] == variables
    assert not state.get("deleted")
    assert "Would delete" not in result.stdout


@pytest.mark.parametrize("dry_run", ["", "TRUE", "invalid"])
def test_cleanup_shell_boundary_rejects_invalid_boolean_before_inventory(
    tmp_path, dry_run
):
    result, state = run_workflow(
        tmp_path,
        "github-environment-legacy-cleanup.yml",
        "cleanup",
        "Remove legacy GitHub Environment variables",
        {},
        GH_ENVIRONMENT_ADMIN_TOKEN="test-placeholder",
        DRY_RUN=dry_run,
        CONFIRMATION=(
            "I confirm AWS Secrets Manager-backed privileged CI is green and "
            "legacy GitHub Environment variables can be removed"
        ),
    )
    assert result.returncode != 0
    assert "::error:: dry_run must be true or false" in result.stderr
    assert state == {}


def test_alert_writers_share_installed_triage_concurrency():
    live = yaml.safe_load(
        (ROOT / ".github/workflows/operations-alert-triage.yml").read_text()
    )
    assert live["concurrency"]["group"] == "${{ github.workflow }}"
    for path in (
        ".github/workflows/operations-alert-backfill.yml",
        "docs/examples/operations-alert-triage-v2.yml",
    ):
        workflow = yaml.safe_load((ROOT / path).read_text())
        assert workflow["concurrency"]["group"] == live["name"]
        assert workflow["concurrency"]["cancel-in-progress"] is False
