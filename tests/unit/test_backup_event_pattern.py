"""Keep the conservative Backup event filter paired with typed triage validation."""

import pytest
from infra.operations_monitoring import _event_patterns


def test_backup_rule_keeps_exact_service_and_job_types():
    """The warning extension must not admit unrelated event services or job types."""
    pattern = _event_patterns()["backup-failed"]
    assert pattern["source"] == ["aws.backup"]
    assert pattern["detail-type"] == [
        "Backup Job State Change",
        "Copy Job State Change",
        "Restore Job State Change",
    ]


@pytest.mark.parametrize("field", ["state", "status"])
def test_backup_rule_routes_failures_and_completed_with_issues(field):
    """Both AWS field spellings need failure and completed-warning routing."""
    detail = _event_patterns()["backup-failed"]["detail"]
    assert detail == {
        "$or": [
            {"state": ["FAILED", "ABORTED", "EXPIRED"]},
            {"status": ["FAILED", "ABORTED", "EXPIRED"]},
            {"state": ["COMPLETED"], "statusMessage": [{"anything-but": ""}]},
            {"status": ["COMPLETED"], "statusMessage": [{"anything-but": ""}]},
        ]
    }
    branches = detail["$or"]
    assert {field: ["FAILED", "ABORTED", "EXPIRED"]} in branches
    assert {field: ["COMPLETED"]} not in branches
    # EventBridge can still match null/array values. The typed consumer owns
    # that rejection; this test intentionally makes no string-type claim.
    assert {field: ["COMPLETED"], "statusMessage": [{"anything-but": ""}]} in branches
