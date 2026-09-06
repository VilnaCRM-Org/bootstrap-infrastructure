"""Verify operator-approved evidence bytes inside an independently trusted host.

The approved digest and Target must come from protected metadata and fresh GitHub
readback, never the PR or its manifest. This pure slice does not establish its
own authority, execute PR code, collect AWS evidence, or publish a GitHub status.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, cast

CONTEXT = "Test Account Evidence"
MAX_FILE_BYTES = 2_000_000
MAX_BUNDLE_BYTES = 16_000_000
MAX_FILES = 128
REQUIRED_CHECKS = frozenset(
    {
        "github_pr_checks",
        "github_pr_local_state",
        "github_review_threads",
        "github_branch_protection",
        "github_dependabot_alerts",
        "github_production_environment",
        "aws_identity",
        "aws_iam_account_access",
        "aws_cost_controls",
        "aws_sns_alert_route",
        "aws_cloudtrail_management_events",
        "aws_restore_jobs",
        "restore_drill_evidence",
        "repository_fanout",
        "question_matrix_evidence",
        "external_control_evidence",
    }
)


@dataclass(frozen=True)
class Target:
    """Fresh server identity and independently pinned trusted collector runtime."""

    repository: str
    repository_id: int
    pr: int
    head_sha: str
    runtime_sha256: str


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        _require(key not in result, "Duplicate evidence JSON key")
        result[key] = value
    return result


def _constant(_value: str) -> None:
    raise ValueError("Non-finite evidence JSON number")


def _json(raw: bytes) -> dict[str, Any]:
    _require(len(raw) <= MAX_FILE_BYTES, "Evidence file exceeds size bound")
    try:
        value = json.loads(raw, object_pairs_hook=_unique, parse_constant=_constant)
    except (UnicodeError, RecursionError) as error:
        raise ValueError("Invalid evidence JSON encoding or depth") from error
    _require(isinstance(value, dict), "Evidence JSON must be an object")
    return value


def _digest(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _path(root: Path, name: str) -> Path:
    part = PurePosixPath(name)
    _require(
        bool(name)
        and not part.is_absolute()
        and ".." not in part.parts
        and str(part) == name
        and "\\" not in name,
        "Invalid evidence relative path",
    )
    path = root
    for component in part.parts:
        path = path / component
        _require(not path.is_symlink(), "Evidence symlinks are forbidden")
    _require(path.is_file(), "Required evidence file is missing")
    _require(path.stat().st_size <= MAX_FILE_BYTES, "Evidence file exceeds size bound")
    return path


def _target(manifest: dict[str, Any], expected: Target, now: dt.datetime) -> None:
    _require(
        manifest.get("schema") == "well-architected-approved-evidence-v1",
        "Unknown evidence schema",
    )
    for field in ("repository", "repository_id", "pr", "head_sha", "runtime_sha256"):
        actual = manifest.get(field)
        wanted = getattr(expected, field)
        _require(
            type(actual) is type(wanted) and actual == wanted, "Evidence target differs"
        )
    _require(
        re.fullmatch(r"[0-9a-f]{40}", expected.head_sha) is not None, "Invalid head SHA"
    )
    _require(_digest(expected.runtime_sha256), "Invalid runtime digest")
    _require(expected.pr > 0 and expected.repository_id > 0, "Invalid server identity")
    try:
        issued = dt.datetime.fromisoformat(manifest["issued_at"])
        expires = dt.datetime.fromisoformat(manifest["expires_at"])
        valid = issued <= now < expires and expires - issued <= dt.timedelta(hours=24)
    except (KeyError, ValueError, TypeError) as error:
        raise ValueError("Invalid evidence approval time bounds") from error
    _require(valid, "Evidence approval expired, future or excessive")


def _references(payload: dict[str, Any], files: dict[str, str]) -> None:
    """Validate top-level declared receipts and historical source hashes as bytes."""
    receipts = payload.get("receiptBindings", {})
    _require(isinstance(receipts, dict), "Invalid receipt bindings")
    for name, digest in receipts.items():
        _require(
            _digest(digest) and files.get(name) == digest,
            "Receipt binding is missing or differs",
        )
    source = payload.get("sourceCommit")
    if source is not None:
        _require(
            isinstance(source, str)
            and re.fullmatch(r"[0-9a-f]{40}", source) is not None,
            "Invalid historical source commit",
        )
    bindings = payload.get("sourceBindings", {})
    _require(isinstance(bindings, dict), "Invalid historical source bindings")
    for name, digest in bindings.items():
        snapshot = f"sources/{source}/{name}"
        _require(
            source is not None and _digest(digest) and files.get(snapshot) == digest,
            "Historical source binding is missing or differs",
        )


def verify_bundle(
    raw_manifest: bytes,
    *,
    approved_sha256: str,
    target: Target,
    bundle_root: Path,
    now: dt.datetime,
) -> dict[str, Any]:
    """Return authenticated finite inputs; never infer approval from self-hashes."""
    _require(_digest(approved_sha256), "Protected manifest digest is missing")
    _require(
        hashlib.sha256(raw_manifest).hexdigest() == approved_sha256,
        "Manifest was not independently approved",
    )
    manifest = _json(raw_manifest)
    _target(manifest, target, now)
    files = manifest.get("files")
    _require(
        isinstance(files, dict) and 0 < len(files) <= MAX_FILES,
        "Invalid bundle file inventory",
    )
    files = cast(dict[str, str], files)
    total = 0
    documents = {}
    for name, digest in files.items():
        _require(_digest(digest), "Invalid evidence content digest")
        with _path(bundle_root, name).open("rb") as stream:
            data = stream.read(MAX_FILE_BYTES + 1)
        _require(len(data) <= MAX_FILE_BYTES, "Evidence file exceeds size bound")
        total += len(data)
        _require(total <= MAX_BUNDLE_BYTES, "Evidence bundle exceeds size bound")
        _require(hashlib.sha256(data).hexdigest() == digest, "Evidence content differs")
        if name.endswith(".json") and not name.startswith("sources/"):
            documents[name] = _json(data)
    selected = manifest.get("evidence")
    _require(
        isinstance(selected, dict)
        and set(selected)
        == {
            "question_matrix",
            "external_controls",
            "security_account",
            "alert_route",
            "restore_drill",
            "production_dr",
        },
        "Incomplete evidence selectors",
    )
    selected = cast(dict[str, str], selected)
    for name in selected.values():
        _require(
            isinstance(name, str) and name in documents,
            "Evidence selector is not authenticated JSON",
        )
    _require(len(set(selected.values())) == len(selected), "Evidence selectors alias")
    for payload in documents.values():
        _references(payload, files)
    return manifest


def status_payload(
    report: dict[str, Any], *, target: Target, current_head: str
) -> dict[str, str]:
    """Construct the fixed context from trusted collector output, without writes.

    Only the trusted host may provide report (the captured collector result).
    This function is not an attestation API for arbitrary PR-provided JSON.
    """
    _require(current_head == target.head_sha, "PR head moved before publication")
    _require(
        report.get("repo") == target.repository and report.get("pr") == target.pr,
        "Collector target differs",
    )
    blockers = report.get("blockers")
    _require(isinstance(blockers, list), "Collector blockers missing")
    checks = _complete_checks(report.get("checks"))
    failed = bool(blockers) or any(
        check["status"] != "passed" or check["blockers"] for check in checks
    )
    return {
        "context": CONTEXT,
        "state": "failure" if failed else "success",
        "description": "Trusted Well-Architected evidence has blockers"
        if failed
        else "Trusted Well-Architected evidence passed",
    }


def _complete_checks(checks: object) -> list[dict[str, Any]]:
    """Refuse truncated or malformed output from the pinned collector contract."""
    _require(isinstance(checks, list) and bool(checks), "Collector checks missing")
    checks = cast(list[dict[str, Any]], checks)
    _require(
        all(
            isinstance(check, dict)
            and isinstance(check.get("blockers"), list)
            and isinstance(check.get("status"), str)
            and isinstance(check.get("name"), str)
            for check in checks
        ),
        "Malformed collector check",
    )
    _require(
        len(checks) == len(REQUIRED_CHECKS)
        and {check["name"] for check in checks} == REQUIRED_CHECKS,
        "Incomplete or duplicate collector checks",
    )
    return checks
