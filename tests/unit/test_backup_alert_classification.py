"""Typed backup classification protects the queue acknowledgment boundary."""

from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

import pytest

SCRIPTS_DIR = Path(__file__).resolve().parents[2] / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

triage = importlib.import_module("operations_alert_triage")
CONTEXT = triage.IssueContext("queue", "123456789012", "eu-central-1", "")
TOPIC = "arn:aws:sns:eu-central-1:123456789012:operations"


def message(job="Backup", field="state", state="COMPLETED", status_message=None):
    detail = {field: state, f"{job.lower()}JobId": "job-1"}
    if status_message is not ...:
        detail["statusMessage"] = status_message
    event = {
        "id": "event-1",
        "time": "2026-09-06T00:00:00Z",
        "account": CONTEXT.account_id,
        "region": CONTEXT.region,
        "source": "aws.backup",
        "detail-type": f"{job} Job State Change",
        "detail": detail,
    }
    sns = {
        "Type": "Notification",
        "TopicArn": TOPIC,
        "MessageId": "sns-1",
        "Message": json.dumps(event),
    }
    return {
        "MessageId": "sqs-1",
        "ReceiptHandle": "private-receipt",
        "Body": json.dumps(sns),
    }


def replace_event(item, update):
    sns = json.loads(item["Body"])
    event = json.loads(sns["Message"])
    update(event)
    sns["Message"] = json.dumps(event)
    item["Body"] = json.dumps(sns)
    return item


@pytest.mark.parametrize("job", ["Backup", "Copy", "Restore"])
@pytest.mark.parametrize("field", ["state", "status"])
@pytest.mark.parametrize("value", [None, "", ...])
def test_exact_completed_without_warning_is_benign(job, field, value):
    assert triage.message_disposition(
        message(job, field, status_message=value), CONTEXT, TOPIC
    ) == ("benign", "backup_completed_without_warning")


@pytest.mark.parametrize("value", ["Warning", " "])
@pytest.mark.parametrize("state", ["COMPLETED", "FAILED", "ABORTED", "EXPIRED"])
def test_real_warning_or_failure_remains_actionable(value, state):
    assert (
        triage.message_disposition(
            message(state=state, status_message=value), CONTEXT, TOPIC
        )[0]
        == "actionable"
    )


@pytest.mark.parametrize("value", [0, False, {}, [], ["warning"]])
@pytest.mark.parametrize("state", ["COMPLETED", "FAILED"])
def test_nonstring_status_message_is_never_acknowledgeable(value, state):
    item = message(state=state, status_message=value)
    alerts, acknowledgments, audit = triage.classified_alerts(
        {"Messages": [item]}, CONTEXT, TOPIC
    )
    assert alerts == acknowledgments == {"Messages": []}
    assert audit["records"][0]["reason"] == "invalid_backup_status_message"
    assert "private-receipt" not in json.dumps(audit)


@pytest.mark.parametrize(
    "detail,reason",
    [
        ({"backupJobId": "job"}, "invalid_backup_state"),
        ({"backupJobId": "job", "state": []}, "invalid_backup_state"),
        (
            {"backupJobId": "job", "state": "COMPLETED", "status": "FAILED"},
            "conflicting_backup_state",
        ),
        ({"backupJobId": "job", "state": "RUNNING"}, "unexpected_backup_state"),
        (
            {"backupJobId": "job", "state": "COMPLETED", "StatusMessage": "warning"},
            "invalid_backup_status_message",
        ),
        ({"state": "COMPLETED"}, "invalid_backup_job"),
        (None, "invalid_backup_job"),
    ],
)
def test_malformed_backup_detail_is_quarantined(detail, reason):
    item = replace_event(message(), lambda event: event.update(detail=detail))
    assert triage.message_disposition(item, CONTEXT, TOPIC) == ("quarantine", reason)


@pytest.mark.parametrize(
    "key,value",
    [
        ("account", "000000000000"),
        ("region", "us-east-1"),
        ("id", ""),
        ("time", None),
        ("time", "not-a-time"),
        ("time", "2026-09-06T00:00:00"),
        ("detail-type", []),
    ],
)
def test_backup_envelope_context_cannot_be_forged(key, value):
    item = replace_event(message(), lambda event: event.update({key: value}))
    assert triage.message_disposition(item, CONTEXT, TOPIC)[0] == "quarantine"


@pytest.mark.parametrize(
    "key,value",
    [
        ("TopicArn", TOPIC + "-other"),
        ("Type", "SubscriptionConfirmation"),
        ("MessageId", None),
    ],
)
def test_exact_sns_notification_is_required(key, value):
    item = message()
    sns = json.loads(item["Body"])
    sns[key] = value
    item["Body"] = json.dumps(sns)
    assert triage.message_disposition(item, CONTEXT, TOPIC)[0] == "quarantine"


def test_duplicate_json_fields_cannot_hide_warning():
    item = message()
    sns = json.loads(item["Body"])
    sns["Message"] = sns["Message"].replace(
        '"state": "COMPLETED"', '"state": "FAILED", "state": "COMPLETED"'
    )
    item["Body"] = json.dumps(sns)
    assert triage.message_disposition(item, CONTEXT, TOPIC) == (
        "quarantine",
        "invalid_backup_envelope",
    )


@pytest.mark.parametrize(
    "source,kind",
    [
        ("aws.kms", "AWS API Call via CloudTrail"),
        ("aws.backup", "Unknown Backup Alert"),
    ],
)
def test_valid_other_alerts_keep_existing_dedup(source, kind):
    item = replace_event(
        message(), lambda event: event.update(source=source, **{"detail-type": kind})
    )
    alerts, acknowledgments, audit = triage.classified_alerts(
        {"Messages": [item]}, CONTEXT, TOPIC
    )
    assert alerts == {"Messages": [item]}
    assert acknowledgments == {"Messages": [{"ReceiptHandle": "private-receipt"}]}
    assert triage.alerts_fingerprint(alerts) == triage.message_fingerprint(item)
    assert audit["records"][0]["reason"] == "existing_alert"


@pytest.mark.parametrize("receipt", [None, "", "line\nbreak"])
def test_invalid_receipts_are_never_deleted(receipt):
    item = message()
    item["ReceiptHandle"] = receipt
    _, acknowledgments, audit = triage.classified_alerts(
        {"Messages": [item]}, CONTEXT, TOPIC
    )
    assert acknowledgments == {"Messages": []}
    assert audit["records"][0]["reason"] == "invalid_receipt"


def test_duplicate_receipt_cannot_cross_quarantine_boundary():
    benign = message()
    malformed = message(status_message=[])
    alerts, acknowledgments, audit = triage.classified_alerts(
        {"Messages": [benign, malformed]}, CONTEXT, TOPIC
    )
    assert alerts == acknowledgments == {"Messages": []}
    assert {entry["reason"] for entry in audit["records"]} == {"duplicate_receipt"}


@pytest.mark.parametrize(
    "topic",
    ["", TOPIC.replace("123456789012", "000000000000"), TOPIC.rsplit(":", 1)[0] + ":"],
)
def test_expected_topic_must_be_independently_account_bound(topic):
    with pytest.raises(ValueError, match="trusted account"):
        triage.classified_alerts({}, CONTEXT, topic)


def test_both_state_fields_may_agree():
    item = replace_event(
        message(), lambda event: event["detail"].update(status="COMPLETED")
    )
    assert triage.message_disposition(item, CONTEXT, TOPIC)[0] == "benign"


def test_classification_cli_writes_private_ack_and_sanitized_audit(tmp_path):
    source = tmp_path / "input.json"
    source.write_text(json.dumps({"Messages": [message()]}))
    args = [
        "--alerts-json",
        str(source),
        "--queue-name",
        "queue",
        "--account-id",
        CONTEXT.account_id,
        "--region",
        CONTEXT.region,
        "--body-file",
        str(tmp_path / "body"),
        "--fingerprint-file",
        str(tmp_path / "fingerprint"),
        "--groups-file",
        str(tmp_path / "groups"),
    ]
    assert triage.main([*args, "--audit-file", str(tmp_path / "audit")]) == 1
    assert (
        triage.main(
            [
                *args,
                "--audit-file",
                str(tmp_path / "audit"),
                "--acknowledgments-file",
                str(tmp_path / "acks"),
                "--topic-arn",
                TOPIC,
            ]
        )
        == 0
    )
    assert (tmp_path / "acks").stat().st_mode & 0o777 == 0o600
    assert "private-receipt" not in (tmp_path / "audit").read_text()
    assert json.loads((tmp_path / "groups").read_text())["groups"] == []
    assert (tmp_path / "fingerprint").read_text().strip() == "empty"
