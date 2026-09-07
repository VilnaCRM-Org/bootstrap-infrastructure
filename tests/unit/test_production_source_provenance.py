"""Run the production workflow's actual pre-checkout source guard offline."""

import json
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
TRUSTED = "a" * 40
REQUESTED = "b" * 40


def workflow():
    """Read the actual production workflow including its executable guard."""
    return yaml.safe_load((ROOT / ".github/workflows/pulumi-prod.yml").read_text())


def comparison(**changes):
    """Build the documented requested-base versus trusted-head response."""
    return {
        "base_commit": {"sha": REQUESTED},
        "merge_base_commit": {"sha": REQUESTED},
        "behind_by": 0,
        "ahead_by": 1,
        "status": "ahead",
        **changes,
    }


def run_guard(tmp_path, payload, *, changes=None, api_exit=0):
    """Invoke Bash and jq with only the GitHub read API replaced by a double."""
    source = workflow()["jobs"]["preview"]["steps"][0]["run"]
    script = (
        'gh() { printf "%s\\n" "$*" >> "$CALLS"; '
        'printf "%s" "$RESPONSE"; return "$API_EXIT"; };\n' + source
    )
    calls = tmp_path / "calls"
    result = subprocess.run(
        ["bash", "-eo", "pipefail", "-c", script],
        env={
            "PATH": "/usr/bin:/bin",
            "GH_TOKEN": "offline-placeholder",
            "GITHUB_REPOSITORY": "org/repo",
            "WORKFLOW_REF": "refs/heads/main",
            "TRUSTED_MAIN_SHA": TRUSTED,
            "REQUESTED_SHA": REQUESTED,
            "RESPONSE": payload,
            "API_EXIT": str(api_exit),
            "CALLS": str(calls),
            **(changes or {}),
        },
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )
    return result, calls.read_text().splitlines() if calls.exists() else []


@pytest.mark.parametrize("status", ["ahead", "identical"])
def test_known_main_history_passes(tmp_path, status):
    """Both an older main commit and the exact main commit are valid sources."""
    changes = {} if status == "ahead" else {"TRUSTED_MAIN_SHA": REQUESTED}
    result, calls = run_guard(
        tmp_path, json.dumps(comparison(status=status)), changes=changes
    )
    assert result.returncode == 0, result.stderr
    head = changes.get("TRUSTED_MAIN_SHA", TRUSTED)
    assert calls == [f"api repos/org/repo/compare/{REQUESTED}...{head}"]


@pytest.mark.parametrize(
    "changes",
    [
        {"WORKFLOW_REF": "refs/tags/main"},
        {"WORKFLOW_REF": "refs/heads/feature"},
        {"WORKFLOW_REF": "refs/pull/74/merge"},
        {"WORKFLOW_REF": ""},
        {"REQUESTED_SHA": "main"},
        {"REQUESTED_SHA": "b" * 39},
        {"REQUESTED_SHA": "b" * 40 + "\n"},
        {"REQUESTED_SHA": "$(touch injected)"},
        {"TRUSTED_MAIN_SHA": "not-a-sha"},
    ],
)
def test_untrusted_ref_or_input_rejected_before_api(tmp_path, changes):
    """A tag called main and malformed targets cannot reach even the API read."""
    result, calls = run_guard(tmp_path, json.dumps(comparison()), changes=changes)
    assert result.returncode != 0
    assert "requires the main workflow" in result.stderr
    assert calls == []
    assert not (tmp_path / "injected").exists()


@pytest.mark.parametrize(
    "payload",
    [
        comparison(status="behind", behind_by=1),
        comparison(status="diverged", behind_by=1),
        comparison(status="ahead", behind_by=1),
        comparison(base_commit={"sha": "c" * 40}),
        comparison(merge_base_commit={"sha": "c" * 40}),
        comparison(base_commit={}),
        comparison(merge_base_commit=None),
        comparison(behind_by="0"),
        comparison(status="unknown"),
        {},
        [],
        None,
    ],
)
def test_unproven_comparison_rejected(tmp_path, payload):
    """A successful API status alone never supplies trusted ancestry."""
    result, calls = run_guard(tmp_path, json.dumps(payload))
    assert result.returncode != 0
    assert "not in the trusted main history" in result.stderr
    assert len(calls) == 1


@pytest.mark.parametrize("payload", ["", "{", "{}\n" + json.dumps(comparison())])
def test_incomplete_or_multiple_responses_rejected(tmp_path, payload):
    """Parsing must not accept a trailing successful object after invalid data."""
    result, _ = run_guard(tmp_path, payload)
    assert result.returncode != 0


def test_api_error_cannot_be_masked_by_valid_stdout(tmp_path):
    """A failed API read stops even when a partial body resembles valid proof."""
    result, _ = run_guard(tmp_path, json.dumps(comparison()), api_exit=1)
    assert result.returncode != 0


def test_guard_precedes_checkout_and_existing_test_gate_remains():
    """Preserve source, successful TEST, dependency and approval boundaries."""
    data = workflow()
    jobs = data["jobs"]
    preview = jobs["preview"]
    steps = preview["steps"]
    guard = steps[0]
    assert guard["name"] == "Verify production source belongs to trusted main"
    assert guard["env"]["WORKFLOW_REF"] == "${{ github.ref }}"
    assert guard["env"]["TRUSTED_MAIN_SHA"] == "${{ github.sha }}"
    assert guard["env"]["REQUESTED_SHA"] == "${{ inputs.commit_sha }}"
    assert steps[1]["uses"].startswith("actions/checkout@")
    assert steps[1]["with"]["persist-credentials"] is False
    assert "if" not in guard and "continue-on-error" not in guard
    assert (
        preview["outputs"]["preview_sha"]
        == "${{ steps.resolve_sha.outputs.preview_sha }}"
    )
    test_gate = next(
        s for s in steps if s.get("name") == "Verify test deployment succeeded for SHA"
    )
    assert '.conclusion == "success" and .head_branch == "main"' in test_gate["run"]
    assert "head_sha=${TARGET_SHA}" in test_gate["run"]
    assert "exit 1" in test_gate["run"]
    loader_index = next(
        i
        for i, s in enumerate(steps)
        if s.get("uses") == "./.github/actions/load-aws-ci-env"
    )
    assert steps.index(test_gate) < loader_index
    assert jobs["destructive_diff"]["needs"] == ["preview"]
    assert "if" not in jobs["destructive_diff"]
    assert jobs["apply"]["environment"] == "prod"
    assert set(jobs["apply"]["needs"]) == {
        "preview",
        "destructive_diff",
        "iam_validation",
    }
    assert data["permissions"] == {"actions": "read", "contents": "read"}
