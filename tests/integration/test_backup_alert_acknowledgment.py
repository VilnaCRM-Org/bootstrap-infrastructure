"""Run the real acknowledgment shell with a local AWS stub, never live SQS."""

from __future__ import annotations

import importlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

SCRIPTS_DIR = Path(__file__).resolve().parents[2] / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

triage = importlib.import_module("operations_alert_triage")
ROOT = Path(__file__).resolve().parents[2]
TOPIC = "arn:aws:sns:eu-central-1:123456789012:operations"
CONTEXT = triage.IssueContext("queue", "123456789012", "eu-central-1", "")


def backup_message(receipt: str, state: str, status_message: object):
    event = {
        "source": "aws.backup",
        "detail-type": "Backup Job State Change",
        "account": CONTEXT.account_id,
        "region": CONTEXT.region,
        "id": f"event-{receipt}",
        "time": "2026-09-06T00:00:00Z",
        "detail": {
            "backupJobId": "job",
            "state": state,
            "statusMessage": status_message,
        },
    }
    return {
        "MessageId": f"message-{receipt}",
        "ReceiptHandle": receipt,
        "Body": json.dumps(
            {
                "Type": "Notification",
                "TopicArn": TOPIC,
                "MessageId": f"sns-{receipt}",
                "Message": json.dumps(event),
            }
        ),
    }


@pytest.mark.parametrize("include_quarantine", [False, True])
def test_exact_consumer_allowlist_controls_real_workflow_ack_step(
    tmp_path, include_quarantine
):
    alerts = {
        "Messages": [
            backup_message("benign", "COMPLETED", None),
            backup_message("actionable", "FAILED", "Failed"),
        ]
    }
    if include_quarantine:
        alerts["Messages"].append(
            backup_message("quarantined", "COMPLETED", ["warning"])
        )
    actionable, allowlist, audit = triage.classified_alerts(alerts, CONTEXT, TOPIC)
    assert [item["ReceiptHandle"] for item in actionable["Messages"]] == ["actionable"]
    (tmp_path / "operations-acknowledgments.json").write_text(json.dumps(allowlist))
    (tmp_path / "operations-classification.json").write_text(json.dumps(audit))
    (tmp_path / "operations-queue-url").write_text("https://sqs.invalid/queue")
    executable = tmp_path / "aws"
    executable.write_text(
        f"#!{sys.executable}\nimport json,os,sys\n"
        "assert sys.argv[1:3] == ['sqs','delete-message']\n"
        "with open(os.environ['ACK_LOG'], 'a') as output:\n"
        "    output.write(json.dumps(sys.argv[3:]) + '\\n')\n"
    )
    executable.chmod(0o700)
    workflow = yaml.safe_load(
        (ROOT / ".github/workflows/operations-alert-triage.yml").read_text()
    )
    steps = workflow["jobs"]["triage_operations_alerts"]["steps"]
    step = next(
        item for item in steps if item.get("name", "").startswith("Acknowledge only")
    )
    result = subprocess.run(
        ["bash", "-euo", "pipefail", "-c", step["run"]],
        env={
            **os.environ,
            "PATH": f"{tmp_path}:{os.environ['PATH']}",
            "RUNNER_TEMP": str(tmp_path),
            "ACK_LOG": str(tmp_path / "ack-log"),
        },
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == int(include_quarantine)
    calls = [
        json.loads(line) for line in (tmp_path / "ack-log").read_text().splitlines()
    ]
    assert [call[call.index("--receipt-handle") + 1] for call in calls] == [
        "benign",
        "actionable",
    ]
    assert "quarantined" not in json.dumps(calls)
    if include_quarantine:
        assert "remain unacknowledged" in result.stderr
