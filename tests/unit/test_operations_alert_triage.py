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
        "items": [{"id": "stable-resource", "name": "kept"}, CustomValue()],
        "requestID": "volatile",
    }

    assert triage.stable_detail(detail) == {  # nosec B101
        "items": [{"id": "stable-resource", "name": "kept"}, "unknown"]
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
    with pytest.raises(ValueError, match="Messages must be a list"):
        triage.alerts_fingerprint({"Messages": "not-a-list"})


def test_malformed_body_metadata_renders_unknown_safely() -> None:
    alerts = {
        "Messages": [
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


def test_resources_presence_and_full_value_have_distinct_fingerprints():
    fingerprints = []
    for resources in (..., None, [], ["arn:aws:s3:::one"], ["arn:aws:s3:::two"]):
        event: dict[str, object] = {
            "source": "aws.health",
            "detail-type": "AWS Health Event",
            "detail": {"state": "FAILED"},
        }
        if resources is not ...:
            event["resources"] = resources
        item = {"Body": json.dumps({"Message": json.dumps(event)})}
        fingerprints.append(triage.message_fingerprint(item))
        assert triage.fingerprint_parts(item)[-2] == (
            "false" if resources is ... else "true"
        )
    assert len(set(fingerprints)) == len(fingerprints)


@pytest.mark.parametrize("value", ["\x00", "\t\r\x1b", "\u200b", "   ", "\n"])
def test_safe_value_filtered_empty_metadata_is_unknown(value):
    assert triage.safe_value(value) == "unknown"


def _runtime_cli(tmp_path):
    paths = {
        name: tmp_path / name
        for name in ("input", "body", "fingerprint", "groups", "ack", "audit")
    }
    args = [
        "--alerts-json",
        str(paths["input"]),
        "--queue-name",
        "queue",
        "--account-id",
        "123456789012",
        "--region",
        "eu-central-1",
        "--body-file",
        str(paths["body"]),
        "--fingerprint-file",
        str(paths["fingerprint"]),
        "--groups-file",
        str(paths["groups"]),
        "--acknowledgments-file",
        str(paths["ack"]),
        "--audit-file",
        str(paths["audit"]),
        "--topic-arn",
        "arn:aws:sns:eu-central-1:123456789012:alerts",
    ]
    return args, paths


@pytest.mark.parametrize("invalid", [None, False, 7, "message", []])
@pytest.mark.parametrize("classification", [False, True])
def test_nonobject_batch_entry_fails_before_any_artifact(
    tmp_path, invalid, classification, monkeypatch, capsys
):
    args, paths = _runtime_cli(tmp_path)
    if not classification:
        args = args[: args.index("--acknowledgments-file")]
    valid = {
        "Body": json.dumps({"Message": '{"source":"aws.health"}'}),
        "ReceiptHandle": "valid-receipt",
    }
    paths["input"].write_text(json.dumps({"Messages": [valid, invalid]}))

    def must_not_classify(*_):
        pytest.fail("A malformed batch reached classification")

    monkeypatch.setattr(triage, "_prepare_classification", must_not_classify)
    assert triage.main(args) == 1
    assert all(not path.exists() for name, path in paths.items() if name != "input")
    assert "Traceback" not in capsys.readouterr().err


@pytest.mark.parametrize("messages", [None, {}, "invalid", 1])
def test_nonlist_messages_fail_before_artifacts(tmp_path, messages):
    args, paths = _runtime_cli(tmp_path)
    paths["input"].write_text(json.dumps({"Messages": messages}))
    assert triage.main(args) == 1
    assert all(not path.exists() for name, path in paths.items() if name != "input")


@pytest.mark.parametrize("layer", ["sns", "event", "stable"])
def test_nested_message_quarantines_without_acknowledgment(layer):
    depth = sys.getrecursionlimit() + 100
    if layer == "stable":
        depth = sys.getrecursionlimit() // 2 + 30
    nested = "[" * depth + "0" + "]" * depth
    event = '{"source":"aws.health","detail":{"nested":' + nested + "}}"
    if layer == "stable":
        # Parsing succeeds; recursive stable-field processing must still quarantine.
        json.loads(event)
        with pytest.raises(RecursionError):
            triage.stable_detail(json.loads(event))
    body = event if layer == "sns" else json.dumps({"Message": event})
    item = {"Body": body, "ReceiptHandle": "receipt"}
    context = triage.IssueContext("queue", "123456789012", "eu-central-1", "")
    actionable, ack, audit = triage.classified_alerts(
        {"Messages": [item]}, context, "arn:aws:sns:eu-central-1:123456789012:alerts"
    )
    assert actionable == {"Messages": []}
    assert ack == {"Messages": []}
    assert audit["records"][0]["reason"] == "invalid_alert_envelope"
    assert audit["records"][0]["disposition"] == "quarantine"


def test_deep_outer_json_returns_clean_failure_without_artifacts(tmp_path, capsys):
    args, paths = _runtime_cli(tmp_path)
    depth = sys.getrecursionlimit() + 100
    paths["input"].write_text('{"Messages":' + "[" * depth + "0" + "]" * depth + "}")
    assert triage.main(args) == 1
    assert all(not path.exists() for name, path in paths.items() if name != "input")
    assert "Traceback" not in capsys.readouterr().err


def test_load_json_rejects_excessive_nesting():
    depth = sys.getrecursionlimit() + 100
    assert triage.load_json("[" * depth + "0" + "]" * depth) == {}


@pytest.mark.parametrize(
    "failure", ["open", "fchmod", "dump", "audit", "groups", "body", "fingerprint"]
)
def test_artifact_oserror_returns_clean_failure(tmp_path, monkeypatch, capsys, failure):
    args, paths = _runtime_cli(tmp_path)
    paths["input"].write_text('{"Messages": []}')

    def denied(*_, **__):
        raise OSError("private-error-payload")

    if failure in {"open", "fchmod"}:
        monkeypatch.setattr(triage.os, failure, denied)
    elif failure == "dump":
        monkeypatch.setattr(triage.json, "dump", denied)
    else:
        original = Path.write_text

        def write(path, *args, **kwargs):
            if path == paths[failure]:
                denied()
            return original(path, *args, **kwargs)

        monkeypatch.setattr(Path, "write_text", write)
    assert triage.main(args) == 1
    error = capsys.readouterr().err
    assert "artifact write failed" in error
    assert "private-error-payload" not in error
    assert "Traceback" not in error
    assert not paths["fingerprint"].exists()


@pytest.mark.parametrize("location", ["detail", "nested", "list"])
def test_generic_resource_ids_remain_distinct_stable_streams(location):
    def event(resource_id, occurrence_id):
        details = {
            "detail": {"id": resource_id},
            "nested": {"resource": {"id": resource_id}},
            "list": {"resources": [{"id": resource_id}]},
        }
        detail = {**details[location], "backupJobId": occurrence_id}
        return _event_message(
            source="aws.backup",
            detail_type="Backup Job State Change",
            detail=detail,
            message_id=occurrence_id,
        )

    first = event("resource-1", "occurrence-1")
    redelivery = event("resource-1", "occurrence-2")
    distinct = event("resource-2", "occurrence-1")
    assert triage.message_fingerprint(first) == triage.message_fingerprint(redelivery)
    assert triage.message_fingerprint(first) != triage.message_fingerprint(distinct)
    groups = triage.alert_groups({"Messages": [first, redelivery, distinct]})
    assert sorted(len(group["Messages"]) for _, group in groups) == [1, 2]


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
@pytest.mark.parametrize("layer", ["sns", "event"])
def test_nonfinite_envelope_constants_quarantine_without_ack(constant, layer):
    event = '{"source":"aws.health","detail":{"value":' + constant + "}}"
    body = event if layer == "sns" else json.dumps({"Message": event})
    context = triage.IssueContext("queue", "123456789012", "eu-central-1", "")
    actionable, ack, audit = triage.classified_alerts(
        {"Messages": [{"Body": body, "ReceiptHandle": "receipt"}]},
        context,
        "arn:aws:sns:eu-central-1:123456789012:alerts",
    )
    assert actionable == ack == {"Messages": []}
    assert audit["records"][0]["disposition"] == "quarantine"
    assert audit["records"][0]["reason"] == "invalid_alert_envelope"
    assert triage.load_json(event) == {}


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
def test_nonfinite_outer_constants_fail_before_artifacts(tmp_path, constant):
    args, paths = _runtime_cli(tmp_path)
    paths["input"].write_text('{"Messages": [], "other":' + constant + "}")
    assert triage.main(args) == 1
    assert all(not path.exists() for name, path in paths.items() if name != "input")


def test_rendered_body_keeps_marker_and_visible_canonical_fingerprint():
    fingerprint = "0123456789abcdef01234567"
    body = triage.render_issue_body(
        {"Messages": []},
        triage.IssueContext("queue", "123456789012", "eu-central-1", fingerprint),
    )
    assert (
        body.splitlines()[0] == f"<!-- operations-alert:fingerprint={fingerprint} -->"
    )
    assert f"Canonical fingerprint: <code>{fingerprint}</code>" in body.splitlines()
    sanitized = triage.render_issue_body(
        {"Messages": []},
        triage.IssueContext("queue", "123456789012", "eu-central-1", "\x00"),
    )
    assert "Canonical fingerprint: <code>unknown</code>" in sanitized.splitlines()
