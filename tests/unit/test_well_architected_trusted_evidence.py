"""A PR's internally consistent claims do not supply independent approval."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import _well_architected_trusted_evidence as trusted  # noqa: E402


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


@pytest.fixture
def bundle(tmp_path):
    target = trusted.Target(
        "VilnaCRM-Org/bootstrap-infrastructure", 12, 204, "a" * 40, "b" * 64
    )
    now = dt.datetime(2026, 9, 6, tzinfo=dt.timezone.utc)
    files = {}
    selected = {}
    for kind in [
        "question_matrix",
        "external_controls",
        "security_account",
        "alert_route",
        "restore_drill",
        "production_dr",
    ]:
        name = f"evidence/{kind}.json"
        path = tmp_path / name
        path.parent.mkdir(exist_ok=True)
        path.write_bytes(b"{}")
        files[name] = digest(b"{}")
        selected[kind] = name
    manifest = {
        "schema": "well-architected-approved-evidence-v1",
        **vars(target),
        "issued_at": (now - dt.timedelta(minutes=1)).isoformat(),
        "expires_at": (now + dt.timedelta(hours=1)).isoformat(),
        "files": files,
        "evidence": selected,
    }
    return tmp_path, manifest, target, now


def verify(bundle, manifest=None, approval=None):
    root, original, target, now = bundle
    raw = json.dumps(original if manifest is None else manifest).encode()
    return trusted.verify_bundle(
        raw,
        approved_sha256=approval or digest(raw),
        target=target,
        bundle_root=root,
        now=now,
    )


def test_independently_bound_finite_bundle_passes(bundle):
    assert verify(bundle) == bundle[1]


def test_rehashed_forged_all_pass_matrix_still_requires_external_approval(bundle):
    root, manifest, *_ = bundle
    approved = digest(json.dumps(manifest).encode())
    raw = b'{"unresolvedQuestionCount":0,"questionCount":57,"allPassed":true}'
    (root / "evidence/question_matrix.json").write_bytes(raw)
    manifest["files"]["evidence/question_matrix.json"] = digest(raw)
    with pytest.raises(ValueError, match="independently approved"):
        verify(bundle, approval=approved)


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema", "other"),
        ("repository", "foreign/repository"),
        ("repository_id", 13),
        ("pr", True),
        ("head_sha", "c" * 40),
        ("runtime_sha256", "c" * 64),
        ("issued_at", "invalid"),
        ("issued_at", "2026-09-07T00:00:00+00:00"),
        ("expires_at", "2026-09-05T00:00:00+00:00"),
        ("expires_at", "2026-09-08T00:00:00+00:00"),
        ("expires_at", "2026-09-06T01:00:00"),
        ("files", {}),
        ("files", None),
        ("evidence", {}),
    ],
)
def test_target_time_and_inventory_tampering_rejected(bundle, field, value):
    bundle[1][field] = value
    with pytest.raises(ValueError):
        verify(bundle)


@pytest.mark.parametrize(
    "kind", ["changed", "missing", "symlink", "directory_symlink", "oversized"]
)
def test_bad_file_never_becomes_authenticated(bundle, kind, monkeypatch):
    root, *_ = bundle
    path = root / "evidence/question_matrix.json"
    if kind == "changed":
        path.write_bytes(b'{"forged":true}')
    elif kind == "missing":
        path.unlink()
    elif kind == "symlink":
        path.unlink()
        path.symlink_to(root / "evidence/restore_drill.json")
    elif kind == "directory_symlink":
        (root / "evidence").rename(root / "other")
        (root / "evidence").symlink_to(root / "other", target_is_directory=True)
    else:
        monkeypatch.setattr(trusted, "MAX_FILE_BYTES", 1)
    with pytest.raises(ValueError):
        verify(bundle)


@pytest.mark.parametrize("name", ["../x", "/x", "evidence//x", "evidence\\x", ""])
def test_unsafe_paths_rejected(bundle, name):
    bundle[1]["files"][name] = "c" * 64
    with pytest.raises(ValueError):
        verify(bundle)


@pytest.mark.parametrize(
    "raw",
    [
        b'{"a":1,"a":2}',
        b'{"x":NaN}',
        b"[]",
        b"\xff",
        b'{"x":' + b"[" * 2000 + b"0" + b"]" * 2000 + b"}",
    ],
)
def test_ambiguous_or_nonstandard_json_rejected(raw):
    with pytest.raises(ValueError):
        trusted._json(raw)


def test_declared_receipts_and_historical_sources_are_verified(bundle):
    root, manifest, *_ = bundle
    historical = "d" * 40
    source = f"sources/{historical}/script.py"
    (root / source).parent.mkdir(parents=True)
    (root / source).write_bytes(b"historical source")
    manifest["files"][source] = digest(b"historical source")
    document = {
        "sourceCommit": historical,
        "sourceBindings": {"script.py": manifest["files"][source]},
        "receiptBindings": {
            "evidence/restore_drill.json": manifest["files"][
                "evidence/restore_drill.json"
            ]
        },
    }
    raw = json.dumps(document).encode()
    (root / "evidence/question_matrix.json").write_bytes(raw)
    manifest["files"]["evidence/question_matrix.json"] = digest(raw)
    assert verify(bundle)
    (root / source).write_bytes(b"replacement")
    with pytest.raises(ValueError, match="content differs"):
        verify(bundle)


@pytest.mark.parametrize(
    "payload",
    [
        {"receiptBindings": None},
        {"receiptBindings": {"absent": "a" * 64}},
        {"sourceCommit": "bad"},
        {"sourceBindings": None},
        {"sourceBindings": {"file": "a" * 64}},
        {"sourceCommit": "a" * 40, "sourceBindings": {"file": "b" * 64}},
    ],
)
def test_unverified_references_fail(payload):
    with pytest.raises(ValueError):
        trusted._references(payload, {})


def test_empty_or_failed_collector_cannot_publish_success(bundle):
    target = bundle[2]
    report = {
        "repo": target.repository,
        "pr": target.pr,
        "checks": [
            {"name": name, "status": "passed", "blockers": []}
            for name in sorted(trusted.REQUIRED_CHECKS)
        ],
        "blockers": [],
    }
    assert (
        trusted.status_payload(report, target=target, current_head=target.head_sha)[
            "context"
        ]
        == "Test Account Evidence"
    )
    report["blockers"] = ["Restore has not succeeded"]
    assert (
        trusted.status_payload(report, target=target, current_head=target.head_sha)[
            "state"
        ]
        == "failure"
    )
    report["blockers"] = []
    report["checks"][0]["status"] = "failed"
    assert (
        trusted.status_payload(report, target=target, current_head=target.head_sha)[
            "state"
        ]
        == "failure"
    )
    with pytest.raises(ValueError, match="head moved"):
        trusted.status_payload(report, target=target, current_head="c" * 40)
    report["checks"] = []
    with pytest.raises(ValueError, match="checks missing"):
        trusted.status_payload(report, target=target, current_head=target.head_sha)


@pytest.mark.parametrize(
    "value", [[], "evidence/absent.json", "evidence/question_matrix.json"]
)
def test_invalid_or_aliased_selector_is_rejected(bundle, value):
    bundle[1]["evidence"]["restore_drill"] = value
    with pytest.raises(ValueError, match="selector"):
        verify(bundle)


def test_non_json_and_source_json_are_bound_without_execution(bundle):
    root, manifest, *_ = bundle
    for name in ("receipt.txt", "sources/old/script.json"):
        path = root / name
        path.parent.mkdir(exist_ok=True, parents=True)
        path.write_bytes(b"not executable JSON")
        manifest["files"][name] = digest(path.read_bytes())
    assert verify(bundle)


def test_total_bundle_bound(bundle, monkeypatch):
    monkeypatch.setattr(trusted, "MAX_BUNDLE_BYTES", 1)
    with pytest.raises(ValueError, match="bundle exceeds"):
        verify(bundle)


@pytest.mark.parametrize(
    "checks",
    [
        [None],
        [{"name": "x", "status": "passed", "blockers": None}],
        [{"name": "x", "status": "passed", "blockers": []}],
        [{"name": "x", "status": None, "blockers": []}],
        [{"name": None, "status": "passed", "blockers": []}],
    ],
)
def test_partial_or_malformed_reports_never_publish_success(bundle, checks):
    target = bundle[2]
    with pytest.raises(ValueError):
        trusted.status_payload(
            {
                "repo": target.repository,
                "pr": target.pr,
                "blockers": [],
                "checks": checks,
            },
            target=target,
            current_head=target.head_sha,
        )


def test_duplicate_report_rows_cannot_cover_missing_controls(bundle):
    target = bundle[2]
    rows = [
        {"name": name, "status": "passed", "blockers": []}
        for name in sorted(trusted.REQUIRED_CHECKS)
    ]
    rows[-1] = rows[0]
    with pytest.raises(ValueError, match="duplicate"):
        trusted.status_payload(
            {
                "repo": target.repository,
                "pr": target.pr,
                "blockers": [],
                "checks": rows,
            },
            target=target,
            current_head=target.head_sha,
        )


def test_symlink_bundle_root_is_not_an_authenticated_evidence_directory(bundle):
    root, manifest, target, now = bundle
    link = root / "linked-root"
    link.symlink_to(root, target_is_directory=True)
    with pytest.raises(ValueError, match="symlinks"):
        verify((link, manifest, target, now))


@pytest.mark.parametrize("value", [None, 0, "invalid", "2026-09-06T00:00:00"])
def test_timestamp_requires_text_and_timezone(value):
    with pytest.raises(ValueError):
        trusted.parse_timestamp(value)


def test_utc_z_bundle_works_with_python310_parser_semantics(bundle, monkeypatch):
    class Python310DateTime(dt.datetime):
        @classmethod
        def fromisoformat(cls, value):
            assert not value.endswith("Z"), "Python 3.10 does not accept UTC Z"
            return super().fromisoformat(value)

    monkeypatch.setattr(trusted.dt, "datetime", Python310DateTime)
    for field in ("issued_at", "expires_at"):
        bundle[1][field] = bundle[1][field].replace("+00:00", "Z")
    assert verify(bundle) == bundle[1]
