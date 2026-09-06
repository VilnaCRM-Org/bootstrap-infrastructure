"""Run the staged v2 acknowledgment shell with a local AWS stub, never live SQS."""

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
def test_exact_consumer_allowlist_controls_staged_workflow_ack_step(
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
        (ROOT / "docs/examples/operations-alert-triage-v2.yml").read_text()
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


@pytest.mark.parametrize("available", [0, 10, 25])
def test_staged_receive_leaves_backlog_after_one_visibility_protected_batch(
    tmp_path, available
):
    workflow = yaml.safe_load(
        (ROOT / "docs/examples/operations-alert-triage-v2.yml").read_text()
    )
    job = workflow["jobs"]["triage_operations_alerts"]
    step = next(item for item in job["steps"] if item.get("id") == "triage")
    preparation, boundary, _ = step["run"].partition("aggregate_body_file=")
    assert boundary, "Update the staged receive extraction after renderer changes."
    state_path = tmp_path / "queue.json"
    state_path.write_text(json.dumps({"available": available, "receives": 0}))
    executable = tmp_path / "aws"
    executable.write_text(
        f"#!{sys.executable}\n"
        "import json, os, sys\nfrom pathlib import Path\n"
        "path = Path(os.environ['QUEUE_STATE'])\n"
        "state = json.loads(path.read_text())\n"
        "args = sys.argv[1:]\n"
        "if args[:2] == ['sqs', 'get-queue-url']:\n"
        "    print('https://sqs.invalid/queue')\n"
        "else:\n"
        "    assert args[:2] == ['sqs', 'receive-message']\n"
        "    assert int(args[args.index('--max-number-of-messages')+1]) == 10\n"
        "    assert int(args[args.index('--visibility-timeout')+1]) > "
        f"{job['timeout-minutes'] * 60}\n"
        "    state['receives'] += 1\n"
        "    assert state['receives'] == 1, 'Second receive would exceed batch bound'\n"
        "    count = min(state['available'], 10)\n"
        "    state['available'] -= count\n"
        "    path.write_text(json.dumps(state))\n"
        "    print(json.dumps({'Messages':"
        "[{'MessageId':str(i)} for i in range(count)]}))\n"
    )
    executable.chmod(0o700)
    result = subprocess.run(
        ["bash", "-euo", "pipefail", "-c", preparation + '\ncat "${alerts_json}"'],
        env={
            "PATH": f"{tmp_path}:{os.environ['PATH']}",
            "RUNNER_TEMP": str(tmp_path),
            "TMPDIR": str(tmp_path),
            "QUEUE_STATE": str(state_path),
            "OPERATIONS_ALERT_QUEUE_NAME": "queue",
        },
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    state = json.loads(state_path.read_text())
    assert state == {"available": max(available - 10, 0), "receives": 1}
    if available:
        assert len(json.loads(result.stdout)["Messages"]) == min(available, 10)
    else:
        assert "No operations alert messages" in result.stdout
