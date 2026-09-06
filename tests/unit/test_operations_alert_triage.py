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


def _message(
    *,
    backup_job_id: str,
    message_id: str = "sqs-1",
    resource_arn: str = "arn:aws:s3:::example",
) -> dict[str, object]:
    event = {
        "source": "aws.backup",
        "detail-type": "Backup Job State Change",
        "time": "2026-05-24T06:08:57Z",
        "detail": {
            "state": "FAILED",
            "backupVaultName": "bootstrap-test",
            "backupPlanId": "plan-1",
            "backupRuleId": "rule-1",
            "resourceArn": resource_arn,
            "backupJobId": backup_job_id,
        },
    }
    sns = {
        "MessageId": "sns-1",
        "Timestamp": "2026-05-24T06:08:58Z",
        "Message": json.dumps(event),
    }
    return {
        "MessageId": message_id,
        "Body": json.dumps(sns),
        "Attributes": {"SentTimestamp": "1779602937768"},
    }


def _event_message(
    *,
    source: str,
    detail_type: str,
    detail: dict[str, object],
    message_id: str,
) -> dict[str, object]:
    event = {
        "id": f"event-{message_id}",
        "source": source,
        "detail-type": detail_type,
        "time": "2026-05-24T06:08:57Z",
        "detail": detail,
    }
    sns = {
        "MessageId": f"sns-{message_id}",
        "Timestamp": "2026-05-24T06:08:58Z",
        "Message": json.dumps(event),
    }
    return {
        "MessageId": message_id,
        "Body": json.dumps(sns),
        "Attributes": {"SentTimestamp": "1779602937768"},
    }


def test_alerts_fingerprint_ignores_per_occurrence_ids() -> None:
    first = {"Messages": [_message(backup_job_id="job-1", message_id="sqs-1")]}
    second = {"Messages": [_message(backup_job_id="job-2", message_id="sqs-2")]}

    assert triage.alerts_fingerprint(first) == triage.alerts_fingerprint(second)


def test_alerts_keep_streams_separate() -> None:
    alerts = {
        "Messages": [
            _message(backup_job_id="job-1", resource_arn="arn:aws:s3:::one"),
            _message(backup_job_id="job-2", resource_arn="arn:aws:s3:::one"),
            _message(backup_job_id="job-3", resource_arn="arn:aws:s3:::two"),
        ]
    }

    groups = triage.grouped_alerts_payload(alerts)["groups"]

    assert sorted(group["messageCount"] for group in groups) == [1, 2]  # nosec B101
    assert groups[0]["fingerprint"] != groups[1]["fingerprint"]  # nosec B101


def test_non_backup_fingerprint_uses_stable_detail_without_occurrence_ids() -> None:
    first = {
        "Messages": [
            _event_message(
                source="aws.kms",
                detail_type="AWS API Call via CloudTrail",
                detail={
                    "eventSource": "kms.amazonaws.com",
                    "eventName": "DisableKey",
                    "requestID": "request-1",
                    "requestParameters": {"keyId": "arn:aws:kms:::key/one"},
                },
                message_id="sqs-1",
            )
        ]
    }
    same_stream = {
        "Messages": [
            _event_message(
                source="aws.kms",
                detail_type="AWS API Call via CloudTrail",
                detail={
                    "eventSource": "kms.amazonaws.com",
                    "eventName": "DisableKey",
                    "requestID": "request-2",
                    "requestParameters": {"keyId": "arn:aws:kms:::key/one"},
                },
                message_id="sqs-2",
            )
        ]
    }
    distinct_stream = {
        "Messages": [
            _event_message(
                source="aws.kms",
                detail_type="AWS API Call via CloudTrail",
                detail={
                    "eventSource": "kms.amazonaws.com",
                    "eventName": "ScheduleKeyDeletion",
                    "requestID": "request-3",
                    "requestParameters": {"keyId": "arn:aws:kms:::key/one"},
                },
                message_id="sqs-3",
            )
        ]
    }

    assert triage.alerts_fingerprint(first) == triage.alerts_fingerprint(same_stream)
    assert triage.alerts_fingerprint(first) != triage.alerts_fingerprint(  # nosec B101
        distinct_stream
    )


def test_stable_detail_handles_lists_and_unknown_objects() -> None:
    class CustomValue:
        def __str__(self) -> str:
            return "custom-value"

    detail = {
        "items": [{"id": "volatile", "name": "kept"}, CustomValue()],
        "requestID": "volatile",
    }

    assert triage.stable_detail(detail) == {  # nosec B101
        "items": [{"name": "kept"}, "unknown"]
    }


def test_aggregate_fingerprint_combines_multiple_streams() -> None:
    alerts = {
        "Messages": [
            _message(backup_job_id="job-1", resource_arn="arn:aws:s3:::one"),
            _message(backup_job_id="job-2", resource_arn="arn:aws:s3:::two"),
        ]
    }

    fingerprint = triage.alerts_fingerprint(alerts)
    group_fingerprints = [
        group["fingerprint"]
        for group in triage.grouped_alerts_payload(alerts)["groups"]
    ]

    assert fingerprint not in group_fingerprints  # nosec B101
    assert fingerprint != "empty"  # nosec B101


def test_load_json_handles_invalid_and_non_object_values() -> None:
    assert triage.load_json({"answer": 42}) == {"answer": 42}
    assert triage.load_json("") == {}
    assert triage.load_json("{not-json") == {}
    assert triage.load_json("[1, 2, 3]") == {}


def test_safe_value_and_empty_fingerprint_defaults() -> None:
    assert triage.safe_value(None) == "unknown"
    assert triage.alerts_fingerprint({}) == "empty"
    assert triage.alerts_fingerprint({"Messages": "not-a-list"}) == "empty"


def test_malformed_messages_are_skipped_safely() -> None:
    alerts = {
        "Messages": [
            "not-a-message",
            None,
            {
                "MessageId": "sqs-safe",
                "Body": "{not-json",
                "Attributes": "not-a-dict",
            },
        ]
    }
    fingerprint = triage.alerts_fingerprint(alerts)

    body = triage.render_issue_body(
        alerts,
        triage.IssueContext(
            queue_name="queue",
            account_id="123456789012",
            region="eu-central-1",
            fingerprint=fingerprint,
        ),
    )

    assert fingerprint != "empty"
    assert "contains 1 message(s)" in body
    assert "sqsMessageId: `sqs-safe`" in body
    assert "snsMessageId: `unknown`" in body
    assert "sentTimestamp: `unknown`" in body


def test_render_issue_body_includes_only_sanitized_metadata() -> None:
    alerts = {"Messages": [_message(backup_job_id="job-1")]}
    fingerprint = triage.alerts_fingerprint(alerts)

    body = triage.render_issue_body(
        alerts,
        triage.IssueContext(
            queue_name="bootstrap-test-operations-alerts",
            account_id="123456789012",
            region="eu-central-1",
            fingerprint=fingerprint,
        ),
    )

    assert f"operations-alert:fingerprint={fingerprint}" in body
    assert "sqsMessageId: `sqs-1`" in body
    assert "eventSource: `aws.backup`" in body
    assert "Backup Job State Change" in body
    assert "backupJobId" not in body
    assert "resourceArn" not in body


def test_main_writes_body_and_fingerprint_files(tmp_path: Path) -> None:
    alerts_path = tmp_path / "alerts.json"
    body_path = tmp_path / "body.md"
    fingerprint_path = tmp_path / "fingerprint"
    groups_path = tmp_path / "groups.json"
    alerts_path.write_text(
        json.dumps({"Messages": [_message(backup_job_id="job-1")]}),
        encoding="utf-8",
    )

    assert (
        triage.main(
            [
                "--alerts-json",
                str(alerts_path),
                "--queue-name",
                "queue",
                "--account-id",
                "123456789012",
                "--region",
                "eu-central-1",
                "--body-file",
                str(body_path),
                "--fingerprint-file",
                str(fingerprint_path),
                "--groups-file",
                str(groups_path),
            ]
        )
        == 0
    )

    assert "operations-alert:fingerprint=" in body_path.read_text(encoding="utf-8")
    grouped = json.loads(groups_path.read_text(encoding="utf-8"))
    assert (
        fingerprint_path.read_text(encoding="utf-8").strip()
        == grouped[  # nosec B101
            "groups"
        ][0]["fingerprint"]
    )
    assert grouped["groups"][0]["messageCount"] == 1  # nosec B101


def test_main_writes_without_group_manifest(tmp_path: Path) -> None:
    alerts_path = tmp_path / "alerts.json"
    body_path = tmp_path / "body.md"
    fingerprint_path = tmp_path / "fingerprint"
    alerts_path.write_text(
        json.dumps({"Messages": [_message(backup_job_id="job-1")]}),
        encoding="utf-8",
    )

    assert (
        triage.main(
            [
                "--alerts-json",
                str(alerts_path),
                "--queue-name",
                "queue",
                "--account-id",
                "123456789012",
                "--region",
                "eu-central-1",
                "--body-file",
                str(body_path),
                "--fingerprint-file",
                str(fingerprint_path),
            ]
        )
        == 0
    )
    assert body_path.exists()  # nosec B101
    assert fingerprint_path.read_text(encoding="utf-8").strip()  # nosec B101


def test_main_rejects_invalid_alerts_json(tmp_path: Path, capsys) -> None:
    alerts_path = tmp_path / "alerts.json"
    body_path = tmp_path / "body.md"
    fingerprint_path = tmp_path / "fingerprint"
    alerts_path.write_text("[1, 2, 3]", encoding="utf-8")

    assert (
        triage.main(
            [
                "--alerts-json",
                str(alerts_path),
                "--queue-name",
                "queue",
                "--account-id",
                "123456789012",
                "--region",
                "eu-central-1",
                "--body-file",
                str(body_path),
                "--fingerprint-file",
                str(fingerprint_path),
            ]
        )
        == 1
    )

    assert str(alerts_path) in capsys.readouterr().err
    assert not body_path.exists()
    assert not fingerprint_path.exists()


def test_main_rejects_malformed_alerts_json(tmp_path: Path, capsys) -> None:
    alerts_path = tmp_path / "alerts.json"
    body_path = tmp_path / "body.md"
    fingerprint_path = tmp_path / "fingerprint"
    alerts_path.write_text("{not-json", encoding="utf-8")

    assert (
        triage.main(
            [
                "--alerts-json",
                str(alerts_path),
                "--queue-name",
                "queue",
                "--account-id",
                "123456789012",
                "--region",
                "eu-central-1",
                "--body-file",
                str(body_path),
                "--fingerprint-file",
                str(fingerprint_path),
            ]
        )
        == 1
    )

    error = capsys.readouterr().err
    assert str(alerts_path) in error
    assert "JSON object" in error
    assert not body_path.exists()
    assert not fingerprint_path.exists()


@pytest.mark.parametrize(
    "value",
    [
        {"private": "nested-payload"},
        ["nested-payload"],
        ("nested-payload",),
        {"nested-payload"},
    ],
)
def test_safe_value_does_not_serialize_containers(value):
    assert triage.safe_value(value) == "unknown"


@pytest.mark.parametrize(
    "value,expected",
    [
        (False, "False"),
        (12, "12"),
        (1.5, "1.5"),
        ("ok`\nnext", "ok' next"),
        ("a\x00\t\r\x1b\x7f\x85\u202eb", "ab"),
    ],
)
def test_safe_scalar_metadata_has_no_control_characters(value, expected):
    assert triage.safe_value(value) == expected
    assert len(triage.safe_value("x" * 201)) == 200


def test_rendered_metadata_type_mismatches_do_not_leak_nested_payload():
    nested = {"private": ["nested-payload-do-not-publish"]}
    item = {
        "MessageId": nested,
        "Attributes": {"SentTimestamp": nested},
        "Body": json.dumps(
            {
                "MessageId": nested,
                "Message": json.dumps(
                    {"source": nested, "detail-type": nested, "time": nested}
                ),
            }
        ),
    }
    body = triage.render_issue_body(
        {"Messages": [item]},
        triage.IssueContext("queue", "123456789012", "eu-central-1", "fingerprint"),
    )
    assert "nested-payload" not in body
    assert "private" not in body.split("Messages:\n", 1)[1]
    for field in (
        "sqsMessageId",
        "snsMessageId",
        "sentTimestamp",
        "eventSource",
        "detailType",
        "eventTime",
    ):
        assert field + ": `unknown`" in body


def test_duplicate_outer_batch_fields_fail_before_outputs(tmp_path):
    source = tmp_path / "input.json"
    source.write_text('{"Messages": [], "Messages": []}')
    body, fingerprint = tmp_path / "body", tmp_path / "fingerprint"
    assert (
        triage.main(
            [
                "--alerts-json",
                str(source),
                "--queue-name",
                "queue",
                "--account-id",
                "123456789012",
                "--region",
                "eu-central-1",
                "--body-file",
                str(body),
                "--fingerprint-file",
                str(fingerprint),
            ]
        )
        == 1
    )
    assert not body.exists()
    assert not fingerprint.exists()
