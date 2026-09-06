"""Execute the backfill workflow jq and compare its event with direct v2 intake."""

from __future__ import annotations

import importlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS_DIR = ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))
triage = importlib.import_module("operations_alert_triage")


def run_backfill(tmp_path: Path, event: object, *, serialized: bool = False):
    """Run the actual preparation shell, stopping before renderer or GitHub calls."""
    workflow = yaml.safe_load(
        (ROOT / ".github/workflows/operations-alert-backfill.yml").read_text()
    )
    steps = workflow["jobs"]["backfill"]["steps"]
    run = next(step["run"] for step in steps if "run" in step)
    preparation, boundary, _ = run.partition(
        "python3 scripts/operations_alert_triage.py"
    )
    assert boundary
    return subprocess.run(
        ["bash", "-euo", "pipefail", "-c", preparation + '\ncat "${alerts_json}"'],
        env={
            "PATH": os.environ["PATH"],
            "TMPDIR": str(tmp_path),
            "STABLE_EVENT_JSON": event if serialized else json.dumps(event),
            "MESSAGE_COUNT": "1",
            "AWS_ACCOUNT_ID": "123456789012",
            "AWS_REGION": "eu-central-1",
            "CONFIRMATION": (
                "I confirm these stable fields represent the canonical "
                "operations alert stream"
            ),
            "SRE_CONFIRMATION_REFERENCE": "https://example.invalid/sre-confirmation",
        },
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )


def confirmed_event(state_key: str = "state"):
    """Represent the original EventBridge shape, including empty stable values."""
    return {
        "source": "aws.backup",
        "detail-type": "Backup Job State Change",
        "detail": {
            state_key: "FAILED",
            "resourceArn": "arn:aws:dynamodb:eu-central-1:123456789012:table/example",
            "backupVaultName": "reviewed-vault",
            "backupPlanId": "reviewed-plan",
            "backupRuleId": "reviewed-rule",
            "statusMessage": "",
            "nested": {"empty": "", "nullable": None, "enabled": False},
        },
    }


@pytest.mark.parametrize("state_key", ["state", "status"])
@pytest.mark.parametrize(
    "resources", ["absent", None, [], ["resource-a", "resource-b"]]
)
def test_actual_backfill_jq_preserves_direct_v2_fingerprint(
    tmp_path, state_key, resources
):
    event = confirmed_event(state_key)
    if resources != "absent":
        event["resources"] = resources
    result = run_backfill(tmp_path, event)
    assert result.returncode == 0, result.stderr
    backfill = json.loads(result.stdout)["Messages"][0]
    _, reconstructed = triage.event_from_message(backfill)
    assert reconstructed == event
    direct = {"Body": json.dumps({"Message": json.dumps(event)})}
    assert triage.message_fingerprint(backfill) == triage.message_fingerprint(direct)
    assert triage.alerts_fingerprint({"Messages": [backfill]}) == (
        triage.alerts_fingerprint({"Messages": [direct]})
    )


@pytest.mark.parametrize(
    "duplicate",
    [
        "detailType",
        "detail_type",
        "state",
        "resourceArn",
        "resource_arn",
        "backupVaultName",
        "backup_vault_name",
        "backupPlanId",
        "backup_plan_id",
        "backupRuleId",
        "backup_rule_id",
    ],
)
@pytest.mark.parametrize("conflicting", [False, True])
def test_actual_backfill_rejects_flattened_duplicates(tmp_path, duplicate, conflicting):
    event = confirmed_event()
    value = event["detail"].get(duplicate, event["detail-type"])
    event[duplicate] = "conflicting-value" if conflicting else value
    result = run_backfill(tmp_path, event)
    assert result.returncode != 0
    assert "only source, detail-type, detail and resources" in result.stderr
    assert not result.stdout


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("source", ""),
        ("source", None),
        ("detail-type", ""),
        ("detail-type", 1),
        ("detail", None),
        ("detail", []),
        ("resources", {}),
        ("resources", "resource"),
    ],
)
def test_actual_backfill_rejects_invalid_event_shape(tmp_path, field, value):
    event = confirmed_event()
    event[field] = value
    result = run_backfill(tmp_path, event)
    assert result.returncode != 0
    assert not result.stdout


def test_actual_backfill_accepts_empty_detail_without_synthetic_state(tmp_path):
    event = {"source": "aws.health", "detail-type": "AWS Health Event", "detail": {}}
    result = run_backfill(tmp_path, event)
    assert result.returncode == 0, result.stderr
    _, reconstructed = triage.event_from_message(
        json.loads(result.stdout)["Messages"][0]
    )
    assert reconstructed == event


@pytest.mark.parametrize(
    "raw_json",
    [
        "null",
        "[]",
        "true",
        "{}\n{}",
        "",
        "{invalid}",
        json.dumps({"source": "aws.backup"}),
    ],
)
def test_actual_backfill_rejects_incomplete_or_multiple_documents(tmp_path, raw_json):
    result = run_backfill(tmp_path, raw_json, serialized=True)
    assert result.returncode != 0
    assert not result.stdout


def test_actual_backfill_rejects_unknown_envelope_keys(tmp_path):
    event = confirmed_event()
    event["id"] = "occurrence-metadata-is-not-the-confirmed-projection"
    result = run_backfill(tmp_path, event)
    assert result.returncode != 0
    assert "only source, detail-type, detail and resources" in result.stderr
    assert not result.stdout
