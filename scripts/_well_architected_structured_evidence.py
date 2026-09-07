from __future__ import annotations

import argparse
import datetime as dt
import json
from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from decimal import ROUND_HALF_UP, Decimal
from pathlib import Path
from typing import Any, cast

import _well_architected_recording as _recording
import _well_architected_scoring as _scoring

AWS_WELL_ARCHITECTED_TOC_URL = (
    "https://docs.aws.amazon.com/wellarchitected/latest/framework/toc-contents.json"
)
STRUCTURED_EVIDENCE_ALLOWED_STATUSES = frozenset({"passed", "unresolved"})
QUESTION_MATRIX_REQUIRED_FIELDS = (
    "workload",
    "owner",
    "reviewedAt",
    "questionCount",
    "unresolvedQuestionCount",
    "evidenceLocation",
)
EXTERNAL_CONTROL_REQUIRED_FIELDS = (
    "workload",
    "owner",
    "reviewedAt",
    "controlCount",
    "unresolvedControlCount",
    "controls",
    "evidenceLocation",
    "fallbackPlan",
)
REQUIRED_EXTERNAL_CONTROL_IDS = (
    "branch_protection",
    "alert_route",
    "backup_restore",
    "finops",
    "quota_headroom",
    "security_account_controls",
    "sustainability_governance",
    "production_approval",
)
OPERATIONAL_EXCELLENCE_PILLAR = _scoring.OPERATIONAL_EXCELLENCE_PILLAR
PERFORMANCE_EFFICIENCY_PILLAR = _scoring.PERFORMANCE_EFFICIENCY_PILLAR
COST_OPTIMIZATION_PILLAR = _scoring.COST_OPTIMIZATION_PILLAR
MISSING_QUESTION_ID = "<missing>"
EXPECTED_WELL_ARCHITECTED_QUESTION_PREFIX_PILLARS = (
    ("OPS", OPERATIONAL_EXCELLENCE_PILLAR, 11),
    ("SEC", "Security", 11),
    ("REL", "Reliability", 13),
    ("PERF", PERFORMANCE_EFFICIENCY_PILLAR, 5),
    ("COST", COST_OPTIMIZATION_PILLAR, 11),
    ("SUS", "Sustainability", 6),
)
EXPECTED_WELL_ARCHITECTED_QUESTION_PREFIX_COUNTS = tuple(
    (prefix, count)
    for prefix, _pillar, count in EXPECTED_WELL_ARCHITECTED_QUESTION_PREFIX_PILLARS
)
EXPECTED_WELL_ARCHITECTED_QUESTION_IDS = tuple(
    f"{prefix}{number}"
    for prefix, count in EXPECTED_WELL_ARCHITECTED_QUESTION_PREFIX_COUNTS
    for number in range(1, count + 1)
)
EXPECTED_WELL_ARCHITECTED_QUESTION_PILLAR_BY_ID = {
    f"{prefix}{number}": pillar
    for prefix, pillar, count in EXPECTED_WELL_ARCHITECTED_QUESTION_PREFIX_PILLARS
    for number in range(1, count + 1)
}
EXPECTED_WELL_ARCHITECTED_QUESTION_COUNT = len(EXPECTED_WELL_ARCHITECTED_QUESTION_IDS)
EXPECTED_WELL_ARCHITECTED_QUESTION_COUNTS = {
    OPERATIONAL_EXCELLENCE_PILLAR: 11,
    "Security": 11,
    "Reliability": 13,
    PERFORMANCE_EFFICIENCY_PILLAR: 5,
    COST_OPTIMIZATION_PILLAR: 11,
    "Sustainability": 6,
}
STRUCTURED_EVIDENCE_MAX_AGE_DAYS = _recording.STRUCTURED_EVIDENCE_MAX_AGE_DAYS


@dataclass(frozen=True)
class StructuredEvidenceSpec:
    """Validation contract for one structured evidence artifact."""

    name: str
    label: str
    required_fields: Sequence[str]
    count_field: str
    unresolved_field: str
    minimum_count: int
    required_control_ids: Sequence[str] = ()


def _check(
    name: str,
    *,
    status: str,
    evidence: dict[str, object] | None = None,
    blockers: Sequence[str] = (),
) -> dict[str, object]:
    """Return one normalized non-secret evidence check."""
    return {
        "name": name,
        "status": status,
        "evidence": evidence or {},
        "blockers": list(blockers),
    }


def question_matrix_evidence(args: argparse.Namespace) -> dict[str, object]:
    """Validate structured evidence for all Well-Architected questions."""
    return _structured_evidence_check(
        StructuredEvidenceSpec(
            name="question_matrix_evidence",
            label="Question-matrix evidence",
            required_fields=QUESTION_MATRIX_REQUIRED_FIELDS,
            count_field="questionCount",
            unresolved_field="unresolvedQuestionCount",
            minimum_count=EXPECTED_WELL_ARCHITECTED_QUESTION_COUNT,
        ),
        evidence_path=args.question_matrix_evidence,
        legacy_confirmed=args.question_matrix_evidence_confirmed,
    )


def external_control_evidence(args: argparse.Namespace) -> dict[str, object]:
    """Validate structured evidence for external control ownership and freshness."""
    return _structured_evidence_check(
        StructuredEvidenceSpec(
            name="external_control_evidence",
            label="External-control evidence",
            required_fields=EXTERNAL_CONTROL_REQUIRED_FIELDS,
            count_field="controlCount",
            unresolved_field="unresolvedControlCount",
            minimum_count=len(REQUIRED_EXTERNAL_CONTROL_IDS),
            required_control_ids=REQUIRED_EXTERNAL_CONTROL_IDS,
        ),
        evidence_path=args.external_control_evidence,
        legacy_confirmed=args.external_control_evidence_confirmed,
    )


def _structured_evidence_check(
    spec: StructuredEvidenceSpec,
    *,
    evidence_path: Path | None,
    legacy_confirmed: bool,
) -> dict[str, object]:
    """Validate a non-secret, owner-backed evidence record."""
    if evidence_path is None:
        blockers = [
            f"{spec.label} JSON path is required for final Well-Architected scoring."
        ]
        if legacy_confirmed:
            blockers.append(
                f"{spec.label} cannot be satisfied by a boolean confirmation flag."
            )
        return _check(spec.name, status="missing", blockers=blockers)

    payload, blockers = _read_structured_evidence_payload(evidence_path, spec.label)
    blockers.extend(
        _structured_evidence_payload_blockers(payload, spec.required_fields)
    )
    blockers.extend(_structured_evidence_freshness_blockers(payload, spec.label))
    blockers.extend(_structured_evidence_count_blockers(payload, spec))
    blockers.extend(
        _structured_evidence_control_blockers(payload, spec.required_control_ids)
    )
    if spec.name == "question_matrix_evidence":
        blockers.extend(_question_matrix_source_verification_blockers(payload))
        blockers.extend(_question_matrix_score_blockers(payload))
    return _check(
        spec.name,
        status="passed" if not blockers else "failed",
        evidence=_structured_evidence_payload(
            payload,
            spec.count_field,
            spec.unresolved_field,
        ),
        blockers=blockers,
    )


def _read_required_structured_evidence(
    evidence_path: Path,
    label: str,
    required_fields: Sequence[str],
    *,
    max_review_age_days: int | None = STRUCTURED_EVIDENCE_MAX_AGE_DAYS,
) -> tuple[dict[str, Any], list[str]]:
    """Read structured evidence and apply shared required-field checks."""
    payload, blockers = _read_structured_evidence_payload(evidence_path, label)
    blockers.extend(_structured_evidence_payload_blockers(payload, required_fields))
    blockers.extend(
        _structured_evidence_freshness_blockers(
            payload, label, max_review_age_days=max_review_age_days
        )
    )
    return payload, blockers


def _read_structured_evidence_payload(
    evidence_path: Path,
    label: str,
) -> tuple[dict[str, Any], list[str]]:
    """Read one structured evidence JSON object."""
    try:
        payload = json.loads(evidence_path.read_text(encoding="utf-8"))
    except OSError as exc:
        return {}, [f"Unable to read {label}: {exc}"]
    except json.JSONDecodeError as exc:
        return {}, [f"{label} is not valid JSON: {exc.msg}"]
    if not isinstance(payload, dict):
        return {}, [f"{label} must be a JSON object."]
    return payload, []


def _structured_evidence_payload_blockers(
    payload: dict[str, Any],
    required_fields: Sequence[str],
) -> list[str]:
    """Return blockers for common structured evidence fields."""
    blockers = [
        f"Structured evidence is missing required field: {field}"
        for field in required_fields
        if not _structured_evidence_field_present(payload, field)
    ]
    if payload.get("workload") != "bootstrap-infrastructure":
        blockers.append(
            "Structured evidence must be scoped to the bootstrap-infrastructure "
            "workload."
        )
    return blockers


def _structured_evidence_field_present(payload: dict[str, Any], field: str) -> bool:
    """Return whether a required structured evidence field is populated."""
    if field not in payload or payload[field] is None:
        return False
    value = payload[field]
    return not (isinstance(value, str) and not value.strip())


def _structured_evidence_mismatch_blockers(
    candidate: object,
    expected: dict[str, object],
    fields: Sequence[str],
    *,
    object_error: str,
    mismatch_message: str,
) -> list[str]:
    """Return blockers when an embedded evidence object differs from live evidence."""
    if not isinstance(candidate, dict):
        return [object_error]

    mismatched_fields = [
        field for field in fields if candidate.get(field) != expected.get(field)
    ]
    if not mismatched_fields:
        return []
    return [f"{mismatch_message}: {', '.join(mismatched_fields)}."]


def _structured_evidence_freshness_blockers(
    payload: dict[str, Any],
    label: str,
    *,
    timestamp_field: str = "reviewedAt",
    max_review_age_days: int | None = STRUCTURED_EVIDENCE_MAX_AGE_DAYS,
) -> list[str]:
    """Return blockers for stale or invalid structured evidence timestamps."""
    reviewed_at = payload.get(timestamp_field)
    if not reviewed_at:
        return []
    parsed_at = _parse_reviewed_at(reviewed_at)
    if parsed_at is None:
        return [f"{label} {timestamp_field} must be an ISO-8601 date or timestamp."]
    now = dt.datetime.now(dt.timezone.utc)
    if parsed_at > now + dt.timedelta(minutes=5):
        return [f"{label} {timestamp_field} is in the future."]
    if max_review_age_days is not None and now - parsed_at > dt.timedelta(
        days=max_review_age_days
    ):
        return [f"{label} is older than {max_review_age_days} days."]
    return []


def _parse_reviewed_at(value: object) -> dt.datetime | None:
    """Parse an ISO date or timestamp into an aware UTC datetime."""
    if not isinstance(value, str):
        return None
    try:
        if "T" not in value:
            parsed_date = dt.date.fromisoformat(value)
            return dt.datetime.combine(
                parsed_date,
                dt.time.min,
                tzinfo=dt.timezone.utc,
            )
        parsed_datetime = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed_datetime.tzinfo is None:
        parsed_datetime = parsed_datetime.replace(tzinfo=dt.timezone.utc)
    return parsed_datetime.astimezone(dt.timezone.utc)


def _structured_evidence_count_blockers(
    payload: dict[str, Any],
    spec: StructuredEvidenceSpec,
) -> list[str]:
    """Return blockers for coverage and unresolved counts."""
    blockers = []
    count = payload.get(spec.count_field)
    unresolved = payload.get(spec.unresolved_field)
    if isinstance(count, bool) or not isinstance(count, int):
        blockers.append(f"{spec.label} {spec.count_field} must be an integer.")
    elif count < spec.minimum_count:
        blockers.append(
            f"{spec.label} {spec.count_field} must be at least {spec.minimum_count}."
        )
    if isinstance(unresolved, bool) or not isinstance(unresolved, int):
        blockers.append(f"{spec.label} {spec.unresolved_field} must be an integer.")
    elif unresolved != 0:
        blockers.append(f"{spec.label} has {unresolved} unresolved item(s).")
    return blockers


def _structured_evidence_control_blockers(
    payload: dict[str, Any],
    required_control_ids: Sequence[str],
) -> list[str]:
    """Return blockers for external-control evidence coverage and proof shape."""
    if not required_control_ids:
        return []
    controls = payload.get("controls")
    if not isinstance(controls, list):
        return ["External-control evidence controls must be a list."]
    control_items = [control for control in controls if isinstance(control, dict)]
    return [
        *_missing_external_control_blockers(control_items, required_control_ids),
        *_external_control_id_blockers(control_items, required_control_ids),
        *_external_control_status_blockers(control_items),
        *_external_control_count_blockers(payload, control_items),
        *_external_control_unresolved_count_blockers(payload, control_items),
        *_external_control_unresolved_id_blockers(payload, control_items),
        *_external_control_proof_blockers(control_items),
    ]


def _question_matrix_source_verification_blockers(
    payload: dict[str, Any],
) -> list[str]:
    """Return blockers when AWS framework source coverage is not auditable."""
    verification = payload.get("frameworkSourceVerification")
    if not isinstance(verification, dict):
        return [
            "Question-matrix evidence frameworkSourceVerification must be an object."
        ]

    blockers = _structured_evidence_freshness_blockers(
        verification,
        "Question-matrix framework source verification",
        timestamp_field="checkedAt",
    )
    source = verification.get("source")
    if not isinstance(source, str) or not source.strip():
        blockers.append(
            "Question-matrix framework source verification source is required."
        )
    question_counts = verification.get("questionCounts")
    if question_counts != EXPECTED_WELL_ARCHITECTED_QUESTION_COUNTS:
        blockers.append(
            "Question-matrix framework source verification questionCounts must "
            "match the expected AWS Well-Architected pillar counts."
        )
    source_urls = verification.get("sourceUrls")
    if not _non_empty_string_list(source_urls):
        blockers.append(
            "Question-matrix framework source verification sourceUrls must include "
            "non-empty documentation URLs."
        )
    elif AWS_WELL_ARCHITECTED_TOC_URL not in source_urls:
        blockers.append(
            "Question-matrix framework source verification sourceUrls must include "
            f"{AWS_WELL_ARCHITECTED_TOC_URL}."
        )
    return blockers


def _question_matrix_score_blockers(payload: dict[str, Any]) -> list[str]:
    """Return blockers when question score entries are not auditable."""
    scores = payload.get("questionScores")
    if not isinstance(scores, list):
        return ["Question-matrix evidence questionScores must be a list."]
    score_items = [score for score in scores if isinstance(score, dict)]
    blockers: list[str] = []
    if len(score_items) != len(scores):
        blockers.append(
            "Question-matrix evidence questionScores entries must be objects."
        )
    blockers.extend(_question_matrix_score_id_blockers(score_items))
    blockers.extend(_question_matrix_pillar_blockers(score_items))
    blockers.extend(_question_matrix_score_count_blockers(payload, score_items))
    blockers.extend(_question_matrix_invalid_score_blockers(score_items))
    blockers.extend(_question_matrix_status_blockers(score_items))
    blockers.extend(_question_matrix_score_status_blockers(score_items))
    blockers.extend(_question_matrix_evidence_ref_blockers(score_items))
    blockers.extend(_question_matrix_summary_blockers(payload, score_items))
    return blockers


def _question_matrix_score_id_blockers(
    scores: Sequence[dict[str, Any]],
) -> list[str]:
    """Return blockers for missing, duplicate, or unknown question IDs."""
    observed_ids = _question_matrix_observed_ids(scores)
    id_counts = Counter(observed_ids)
    duplicate_ids = _sort_question_ids(
        question_id for question_id, count in id_counts.items() if count > 1
    )
    expected_ids = set(EXPECTED_WELL_ARCHITECTED_QUESTION_IDS)
    observed_id_set = set(observed_ids)
    missing_ids = _expected_question_id_order(expected_ids - observed_id_set)
    unknown_ids = _sort_question_ids(observed_id_set - expected_ids)
    blockers = []
    if duplicate_ids:
        blockers.append(
            "Question-matrix evidence includes duplicate question IDs: "
            f"{', '.join(duplicate_ids)}."
        )
    if missing_ids:
        blockers.append(
            "Question-matrix evidence is missing question IDs: "
            f"{', '.join(missing_ids)}."
        )
    if unknown_ids:
        blockers.append(
            "Question-matrix evidence includes unknown question IDs: "
            f"{', '.join(unknown_ids)}."
        )
    return blockers


def _question_matrix_observed_ids(scores: Sequence[dict[str, Any]]) -> list[str]:
    """Return populated string question IDs from evidence score entries."""
    return [
        question_id.strip()
        for score in scores
        if isinstance(question_id := score.get("id"), str) and question_id.strip()
    ]


def _question_matrix_pillar_blockers(
    scores: Sequence[dict[str, Any]],
) -> list[str]:
    """Return blockers when row pillar labels disagree with question IDs."""
    invalid_ids = []
    for score in scores:
        question_id = score.get("id")
        expected_pillar = (
            EXPECTED_WELL_ARCHITECTED_QUESTION_PILLAR_BY_ID.get(question_id)
            if isinstance(question_id, str)
            else None
        )
        if expected_pillar is not None and score.get("pillar") != expected_pillar:
            invalid_ids.append(question_id)
    return (
        [
            "Question-matrix evidence pillar values must match AWS question IDs "
            f"for: {', '.join(_sort_question_ids(invalid_ids))}."
        ]
        if invalid_ids
        else []
    )


def _expected_question_id_order(question_ids: set[str]) -> list[str]:
    """Return expected question IDs in AWS framework order."""
    return [
        question_id
        for question_id in EXPECTED_WELL_ARCHITECTED_QUESTION_IDS
        if question_id in question_ids
    ]


def _sort_question_ids(question_ids: Iterable[object]) -> list[str]:
    """Sort question IDs by pillar prefix and numeric suffix."""
    return sorted(
        (str(question_id) for question_id in question_ids),
        key=_question_id_sort_key,
    )


def _question_id_sort_key(question_id: str) -> tuple[int, int, str]:
    """Return a stable natural-sort key for Well-Architected question IDs."""
    prefix_order = {
        prefix: index
        for index, (prefix, _count) in enumerate(
            EXPECTED_WELL_ARCHITECTED_QUESTION_PREFIX_COUNTS
        )
    }
    for prefix, order in prefix_order.items():
        if not question_id.startswith(prefix):
            continue
        suffix = question_id[len(prefix) :]
        number = int(suffix) if suffix.isdigit() else 0
        return order, number, question_id
    return len(prefix_order), 0, question_id


def _question_matrix_score_count_blockers(
    payload: dict[str, Any],
    scores: Sequence[dict[str, Any]],
) -> list[str]:
    """Return blockers when declared question counts disagree with score entries."""
    blockers: list[str] = []
    question_count = payload.get("questionCount")
    if isinstance(question_count, int) and not isinstance(question_count, bool):
        if question_count != len(scores):
            blockers.append(
                "Question-matrix evidence questionCount must match "
                "valid questionScores entries."
            )
    unresolved_count = payload.get("unresolvedQuestionCount")
    if isinstance(unresolved_count, int) and not isinstance(unresolved_count, bool):
        non_passed_count = sum(1 for score in scores if score.get("status") != "passed")
        if unresolved_count != non_passed_count:
            blockers.append(
                "Question-matrix evidence unresolvedQuestionCount must match "
                "the number of non-passed questionScores entries."
            )
    return blockers


def _question_matrix_invalid_score_blockers(
    scores: Sequence[dict[str, Any]],
) -> list[str]:
    """Return blockers for question scores outside the accepted 1-5 range."""
    invalid_ids = [
        str(score.get("id", MISSING_QUESTION_ID))
        for score in scores
        if _invalid_question_score(score.get("score"))
    ]
    return (
        [
            "Question-matrix evidence scores must be integers from 1 to 5 for: "
            f"{', '.join(invalid_ids)}."
        ]
        if invalid_ids
        else []
    )


def _invalid_question_score(score: object) -> bool:
    """Return whether a score is not an integer in the 1-5 range."""
    return isinstance(score, bool) or not isinstance(score, int) or not 1 <= score <= 5


def _question_matrix_status_blockers(
    scores: Sequence[dict[str, Any]],
) -> list[str]:
    """Return blockers for unsupported question score statuses."""
    invalid_ids = [
        str(score.get("id", MISSING_QUESTION_ID))
        for score in scores
        if not _valid_structured_status(score.get("status"))
    ]
    return (
        [
            "Question-matrix evidence statuses must be one of "
            f"{_allowed_status_text()} for: {', '.join(invalid_ids)}."
        ]
        if invalid_ids
        else []
    )


def _question_matrix_score_status_blockers(
    scores: Sequence[dict[str, Any]],
) -> list[str]:
    """Return blockers when scores and pass/fail status disagree."""
    invalid_ids = [
        str(score.get("id", MISSING_QUESTION_ID))
        for score in scores
        if _valid_question_score(score.get("score"))
        and (
            (score.get("status") == "passed" and score.get("score") != 5)
            or (score.get("status") != "passed" and score.get("score") == 5)
        )
    ]
    return (
        [
            "Question-matrix passed entries must score 5 and non-passed entries "
            f"must score below 5 for: {', '.join(invalid_ids)}."
        ]
        if invalid_ids
        else []
    )


def _valid_question_score(score: object) -> bool:
    """Return whether a score is an integer in the accepted 1-5 range."""
    return not _invalid_question_score(score)


def _question_matrix_evidence_ref_blockers(
    scores: Sequence[dict[str, Any]],
) -> list[str]:
    """Return blockers when unresolved question entries lack evidenceRefs."""
    missing_ids = [
        str(score.get("id", MISSING_QUESTION_ID))
        for score in scores
        if score.get("status") != "passed"
        and not _non_empty_string_list(score.get("evidenceRefs"))
    ]
    return (
        [
            "Question-matrix non-passed entries must include evidenceRefs for: "
            f"{', '.join(missing_ids)}."
        ]
        if missing_ids
        else []
    )


def _question_matrix_summary_blockers(
    payload: dict[str, Any],
    scores: Sequence[dict[str, Any]],
) -> list[str]:
    """Return blockers when summary fields disagree with question score rows."""
    return [
        *_question_matrix_unresolved_id_blockers(payload, scores),
        *_question_matrix_pillar_unresolved_blockers(payload, scores),
        *_question_matrix_average_blockers(payload, scores),
    ]


def _question_matrix_unresolved_id_blockers(
    payload: dict[str, Any],
    scores: Sequence[dict[str, Any]],
) -> list[str]:
    """Return blockers for stale or inconsistent unresolved question IDs."""
    if "unresolvedQuestionIds" not in payload:
        return []
    declared_ids = _string_list(payload.get("unresolvedQuestionIds"))
    if declared_ids is None:
        return [
            "Question-matrix evidence unresolvedQuestionIds must be a list of strings."
        ]
    expected_ids = _expected_question_id_order(set(_non_passed_question_ids(scores)))
    if declared_ids == expected_ids:
        return []
    return [
        "Question-matrix evidence unresolvedQuestionIds must match non-passed "
        f"questionScores entries: {_question_id_list_text(expected_ids)}."
    ]


def _question_matrix_pillar_unresolved_blockers(
    payload: dict[str, Any],
    scores: Sequence[dict[str, Any]],
) -> list[str]:
    """Return blockers for stale or inconsistent per-pillar unresolved counts."""
    if "pillarUnresolvedQuestionCounts" not in payload:
        return []
    declared_counts = _string_key_int_map(payload.get("pillarUnresolvedQuestionCounts"))
    if declared_counts is None:
        return [
            "Question-matrix evidence pillarUnresolvedQuestionCounts must be a "
            "string-keyed integer map."
        ]
    expected_counts = _expected_pillar_unresolved_question_counts(scores)
    if declared_counts == expected_counts:
        return []
    return [
        "Question-matrix evidence pillarUnresolvedQuestionCounts must match "
        "non-passed questionScores entries by pillar."
    ]


def _question_matrix_average_blockers(
    payload: dict[str, Any],
    scores: Sequence[dict[str, Any]],
) -> list[str]:
    """Return blockers for stale or inconsistent per-pillar score averages."""
    if "questionScoreAverages" not in payload:
        return []
    declared_averages = _string_key_number_map(payload.get("questionScoreAverages"))
    if declared_averages is None:
        return [
            "Question-matrix evidence questionScoreAverages must be a "
            "string-keyed numeric map."
        ]
    expected_averages = _expected_pillar_question_score_averages(scores)
    if not expected_averages or declared_averages == expected_averages:
        return []
    return [
        "Question-matrix evidence questionScoreAverages must match score averages "
        "computed from questionScores entries."
    ]


def _non_passed_question_ids(scores: Sequence[dict[str, Any]]) -> list[str]:
    """Return populated question IDs for non-passed score rows."""
    return [
        question_id.strip()
        for score in scores
        if score.get("status") != "passed"
        and isinstance(question_id := score.get("id"), str)
        and question_id.strip()
    ]


def _expected_pillar_unresolved_question_counts(
    scores: Sequence[dict[str, Any]],
) -> dict[str, int]:
    """Return unresolved question counts by expected AWS pillar."""
    counts = {pillar: 0 for pillar in EXPECTED_WELL_ARCHITECTED_QUESTION_COUNTS}
    for question_id in _non_passed_question_ids(scores):
        pillar = EXPECTED_WELL_ARCHITECTED_QUESTION_PILLAR_BY_ID.get(question_id)
        if pillar is not None:
            counts[pillar] += 1
    return counts


def _expected_pillar_question_score_averages(
    scores: Sequence[dict[str, Any]],
) -> dict[str, float]:
    """Return rounded score averages by expected AWS pillar."""
    scores_by_pillar: dict[str, list[int]] = {
        pillar: [] for pillar in EXPECTED_WELL_ARCHITECTED_QUESTION_COUNTS
    }
    for score in scores:
        question_id = score.get("id")
        pillar = (
            EXPECTED_WELL_ARCHITECTED_QUESTION_PILLAR_BY_ID.get(question_id)
            if isinstance(question_id, str)
            else None
        )
        value = score.get("score")
        if pillar is None or _invalid_question_score(value):
            continue
        scores_by_pillar[pillar].append(cast("int", value))
    if any(not pillar_scores for pillar_scores in scores_by_pillar.values()):
        return {}
    return {
        pillar: _rounded_average(pillar_scores)
        for pillar, pillar_scores in scores_by_pillar.items()
    }


def _rounded_average(values: Sequence[int]) -> float:
    """Return a stable two-decimal average for evidence summaries."""
    total = sum(Decimal(value) for value in values)
    average = total / Decimal(len(values))
    return float(average.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))


def _question_id_list_text(question_ids: Sequence[str]) -> str:
    """Return a compact human-readable question ID list for blockers."""
    return ", ".join(question_ids) if question_ids else "none"


def _missing_external_control_blockers(
    controls: Sequence[dict[str, Any]],
    required_control_ids: Sequence[str],
) -> list[str]:
    """Return blockers for omitted required external controls."""
    observed = {
        str(control.get("id"))
        for control in controls
        if isinstance(control.get("id"), str) and control.get("id")
    }
    missing = sorted(set(required_control_ids) - observed)
    return (
        [
            "External-control evidence is missing required controls: "
            f"{', '.join(missing)}."
        ]
        if missing
        else []
    )


def _external_control_id_blockers(
    controls: Sequence[dict[str, Any]],
    required_control_ids: Sequence[str],
) -> list[str]:
    """Return blockers for invalid, duplicate, or unknown external control IDs."""
    invalid_labels: list[str] = []
    observed_ids: list[str] = []
    for index, control in enumerate(controls, start=1):
        control_id = control.get("id")
        if not isinstance(control_id, str) or not control_id.strip():
            invalid_labels.append(f"entry {index}")
            continue
        observed_ids.append(control_id.strip())

    id_counts = Counter(observed_ids)
    duplicate_ids = sorted(
        control_id for control_id, count in id_counts.items() if count > 1
    )
    unknown_ids = sorted(set(observed_ids) - set(required_control_ids))
    blockers = []
    if invalid_labels:
        blockers.append(
            "External-control evidence controls must include non-empty string IDs "
            f"for: {', '.join(invalid_labels)}."
        )
    if duplicate_ids:
        blockers.append(
            "External-control evidence includes duplicate controls: "
            f"{', '.join(duplicate_ids)}."
        )
    if unknown_ids:
        blockers.append(
            "External-control evidence includes unknown controls: "
            f"{', '.join(unknown_ids)}."
        )
    return blockers


def _external_control_status_blockers(
    controls: Sequence[dict[str, Any]],
) -> list[str]:
    """Return blockers for unsupported external-control statuses."""
    invalid_labels = [
        str(control.get("id") or f"entry {index}")
        for index, control in enumerate(controls, start=1)
        if not _valid_structured_status(control.get("status"))
    ]
    return (
        [
            "External-control evidence statuses must be one of "
            f"{_allowed_status_text()} for: {', '.join(invalid_labels)}."
        ]
        if invalid_labels
        else []
    )


def _external_control_count_blockers(
    payload: dict[str, Any],
    controls: Sequence[dict[str, Any]],
) -> list[str]:
    """Return blockers when controlCount disagrees with control entries."""
    control_count = payload.get("controlCount")
    if not isinstance(control_count, int) or isinstance(control_count, bool):
        return []
    if control_count == len(controls):
        return []
    return [
        "External-control evidence controlCount must match the number "
        "of control entries."
    ]


def _external_control_unresolved_count_blockers(
    payload: dict[str, Any],
    controls: Sequence[dict[str, Any]],
) -> list[str]:
    """Return blockers when unresolvedControlCount disagrees with entries."""
    unresolved_count = payload.get("unresolvedControlCount")
    if not isinstance(unresolved_count, int) or isinstance(unresolved_count, bool):
        return []
    unresolved_ids = [
        str(control.get("id"))
        for control in controls
        if control.get("id") and control.get("status") != "passed"
    ]
    if unresolved_count == len(unresolved_ids):
        return []
    return [
        "External-control evidence unresolvedControlCount must match "
        "the number of non-passed control entries."
    ]


def _external_control_unresolved_id_blockers(
    payload: dict[str, Any],
    controls: Sequence[dict[str, Any]],
) -> list[str]:
    """Return blockers for stale or inconsistent unresolved external control IDs."""
    if "unresolvedControlIds" not in payload:
        return []
    declared_ids = _string_list(payload.get("unresolvedControlIds"))
    if declared_ids is None:
        return [
            "External-control evidence unresolvedControlIds must be a list of strings."
        ]
    expected_ids = _unresolved_control_ids_from_controls(controls)
    if declared_ids == expected_ids:
        return []
    expected_text = ", ".join(expected_ids) or "none"
    return [
        "External-control evidence unresolvedControlIds must match non-passed "
        f"controls: {expected_text}."
    ]


def _valid_structured_status(value: object) -> bool:
    """Return whether an evidence row status is an allowed exact value."""
    return isinstance(value, str) and value in STRUCTURED_EVIDENCE_ALLOWED_STATUSES


def _allowed_status_text() -> str:
    """Return allowed structured-evidence statuses for blocker text."""
    return ", ".join(sorted(STRUCTURED_EVIDENCE_ALLOWED_STATUSES))


def _external_control_proof_blockers(
    controls: Sequence[dict[str, Any]],
) -> list[str]:
    """Return blockers for missing evidence or unresolved reasons."""
    blockers: list[str] = []
    for index, control in enumerate(controls, start=1):
        control_id = control.get("id")
        label = str(control_id) if control_id else f"entry {index}"
        evidence = control.get("evidence")
        if not _non_empty_string_list(evidence):
            blockers.append(
                "External-control evidence control "
                f"{label} must include non-empty evidence."
            )
        if control.get("status") == "passed":
            continue
        unresolved_reason = control.get("unresolvedReason")
        if not isinstance(unresolved_reason, str) or not unresolved_reason.strip():
            blockers.append(
                "External-control evidence non-passed control "
                f"{label} must include an unresolvedReason."
            )
    return blockers


def _non_empty_string_list(value: object) -> bool:
    """Return whether a value is a non-empty list of non-empty strings."""
    return (
        isinstance(value, list)
        and bool(value)
        and all(isinstance(item, str) and item.strip() for item in value)
    )


def _structured_evidence_payload(
    payload: dict[str, Any],
    count_field: str,
    unresolved_field: str,
) -> dict[str, object]:
    """Return non-secret structured evidence fields."""
    evidence: dict[str, object] = {
        "workload": payload.get("workload"),
        "owner": payload.get("owner"),
        "reviewedAt": payload.get("reviewedAt"),
        "evidenceLocation": payload.get("evidenceLocation"),
        count_field: payload.get(count_field),
        unresolved_field: payload.get(unresolved_field),
        "controlIds": _control_ids(payload),
    }
    evidence.update(_question_matrix_payload_fields(payload))
    evidence.update(_external_control_payload_fields(payload))
    return evidence


def _control_ids(payload: dict[str, Any]) -> list[str]:
    """Return sorted control IDs from structured evidence."""
    controls = payload.get("controls")
    if not isinstance(controls, list):
        return []
    return sorted(
        str(control.get("id"))
        for control in controls
        if isinstance(control, dict) and control.get("id")
    )


def _question_matrix_payload_fields(payload: dict[str, Any]) -> dict[str, object]:
    """Return optional question-matrix summary fields."""
    fields: dict[str, object] = {}
    score_scale = _question_score_scale(payload.get("scoreScale"))
    if score_scale is not None:
        fields["scoreScale"] = score_scale
    scores = payload.get("questionScores")
    if isinstance(scores, list):
        fields["questionScoreCount"] = len(
            [score for score in scores if isinstance(score, dict)]
        )
    unresolved_question_ids = _string_list(payload.get("unresolvedQuestionIds"))
    if unresolved_question_ids is not None:
        fields["unresolvedQuestionIds"] = unresolved_question_ids
    unresolved_question_evidence_ref_ids = _unresolved_question_evidence_ref_ids(
        payload
    )
    if unresolved_question_evidence_ref_ids is not None:
        fields["unresolvedQuestionEvidenceRefCount"] = len(
            unresolved_question_evidence_ref_ids
        )
        fields["unresolvedQuestionEvidenceRefIds"] = (
            unresolved_question_evidence_ref_ids
        )
    question_score_averages = _string_key_number_map(
        payload.get("questionScoreAverages")
    )
    if question_score_averages is not None:
        fields["questionScoreAverages"] = question_score_averages
    pillar_unresolved_counts = _string_key_int_map(
        payload.get("pillarUnresolvedQuestionCounts")
    )
    if pillar_unresolved_counts is not None:
        fields["pillarUnresolvedQuestionCounts"] = pillar_unresolved_counts
    framework_source_verification = _framework_source_verification_summary(payload)
    if framework_source_verification:
        fields["frameworkSourceVerification"] = framework_source_verification
    return fields


def _question_score_scale(value: object) -> object | None:
    """Return a non-secret question score scale summary."""
    if isinstance(value, str) and value.strip():
        return value
    if not isinstance(value, dict):
        return None
    scale = {
        str(score): label.strip()
        for score, label in value.items()
        if isinstance(score, str) and isinstance(label, str) and label.strip()
    }
    if scale:
        return scale
    return None


def _external_control_payload_fields(payload: dict[str, Any]) -> dict[str, object]:
    """Return optional external-control summary fields."""
    unresolved_control_ids = _unresolved_control_ids(payload)
    if unresolved_control_ids:
        return {"unresolvedControlIds": unresolved_control_ids}
    return {}


def _unresolved_question_evidence_ref_ids(
    payload: dict[str, Any],
) -> list[str] | None:
    """Return question IDs whose non-passed entries include evidenceRefs."""
    scores = payload.get("questionScores")
    if not isinstance(scores, list):
        return None
    ids = [
        str(score.get("id"))
        for score in scores
        if isinstance(score, dict)
        and score.get("status") != "passed"
        and isinstance(score.get("id"), str)
        and _non_empty_string_list(score.get("evidenceRefs"))
    ]
    return sorted(ids)


def _framework_source_verification_summary(
    payload: dict[str, Any],
) -> dict[str, object]:
    """Return non-secret framework source verification evidence."""
    verification = payload.get("frameworkSourceVerification")
    if not isinstance(verification, dict):
        return {}
    summary: dict[str, object] = {}
    for key in ("checkedAt", "source"):
        value = verification.get(key)
        if isinstance(value, str):
            summary[key] = value
    question_counts = _string_key_int_map(verification.get("questionCounts"))
    if question_counts is not None:
        summary["questionCounts"] = question_counts
    source_urls = _string_list(verification.get("sourceUrls"))
    if source_urls is not None:
        summary["sourceUrlCount"] = len(source_urls)
    return summary


def _string_list(value: object) -> list[str] | None:
    """Return a JSON-safe string list when all values are strings."""
    if not isinstance(value, list):
        return None
    if not all(isinstance(item, str) for item in value):
        return None
    return cast("list[str]", list(value))


def _string_key_number_map(value: object) -> dict[str, int | float] | None:
    """Return a JSON-safe mapping with string keys and numeric values."""
    if not isinstance(value, dict):
        return None
    result: dict[str, int | float] = {}
    for key, item in value.items():
        if not isinstance(key, str) or isinstance(item, bool):
            return None
        if not isinstance(item, (int, float)):
            return None
        result[key] = item
    return result


def _string_key_int_map(value: object) -> dict[str, int] | None:
    """Return a JSON-safe mapping with string keys and integer values."""
    if not isinstance(value, dict):
        return None
    result: dict[str, int] = {}
    for key, item in value.items():
        if not isinstance(key, str) or isinstance(item, bool):
            return None
        if not isinstance(item, int):
            return None
        result[key] = item
    return result


def _unresolved_control_ids(payload: dict[str, Any]) -> list[str]:
    """Return non-passed external control ids from structured evidence."""
    controls = payload.get("controls")
    if not isinstance(controls, list):
        return []
    control_items = [control for control in controls if isinstance(control, dict)]
    return _unresolved_control_ids_from_controls(control_items)


def _unresolved_control_ids_from_controls(
    controls: Sequence[dict[str, Any]],
) -> list[str]:
    """Return non-passed external control IDs from control rows."""
    ids = [
        str(control.get("id"))
        for control in controls
        if (control.get("id") and control.get("status") != "passed")
    ]
    return sorted(ids)
