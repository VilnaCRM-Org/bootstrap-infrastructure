#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from decimal import ROUND_HALF_UP, Decimal
from pathlib import Path
from typing import Any, cast
from urllib.request import Request, urlopen

AWS_WELL_ARCHITECTED_TOC_URL = (
    "https://docs.aws.amazon.com/wellarchitected/latest/framework/toc-contents.json"
)
AWS_WELL_ARCHITECTED_DOC_BASE = (
    "https://docs.aws.amazon.com/wellarchitected/latest/framework/"
)
AWS_DOCS_REQUEST_HEADERS = {
    "Accept": "application/json,text/plain,*/*",
    "User-Agent": (
        "bootstrap-infrastructure-well-architected-verifier/1.0 "
        "(+https://github.com/VilnaCRM-Org/bootstrap-infrastructure)"
    ),
}
QUESTION_RE = re.compile(
    r"^(?P<prefix>OPS|SEC|REL|PERF|COST|SUS)\s+0*(?P<number>[1-9]\d?)"
    r"\.?\s+(?P<title>.+)$"
)
MARKDOWN_QUESTION_ROW_RE = re.compile(
    r"^\|\s*(?P<id>(?:OPS|SEC|REL|PERF|COST|SUS)[1-9]\d?)\s*\|"
)
MISSING_QUESTION_ID = "<missing>"
PILLAR_BY_PREFIX = {
    "OPS": "Operational Excellence",
    "SEC": "Security",
    "REL": "Reliability",
    "PERF": "Performance Efficiency",
    "COST": "Cost Optimization",
    "SUS": "Sustainability",
}
PILLAR_ORDER = tuple(PILLAR_BY_PREFIX.values())
MARKDOWN_PILLAR_RE = re.compile(
    rf"^## (?P<pillar>{'|'.join(re.escape(pillar) for pillar in PILLAR_ORDER)})$"
)


@dataclass(frozen=True)
class VerificationBlockerInputs:
    """Derived mismatch sets used to render verification blockers."""

    duplicate_aws_ids: Sequence[str]
    duplicate_evidence_ids: Sequence[str]
    missing_ids: Sequence[str]
    extra_ids: Sequence[str]
    invalid_score_ids: Sequence[str]
    invalid_status_ids: Sequence[str]
    score_status_mismatch_ids: Sequence[str]
    missing_evidence_ref_ids: Sequence[str]
    pillar_mismatch_ids: Sequence[str]
    evidence_question_count: object
    aws_question_count: int
    declared_counts: object
    aws_counts: dict[str, int]
    evidence_counts: dict[str, int]
    duplicate_markdown_ids: Sequence[str]
    missing_markdown_ids: Sequence[str]
    extra_markdown_ids: Sequence[str]
    markdown_pillar_mismatch_ids: Sequence[str]


def _load_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return payload


def _fetch_toc(url: str) -> dict[str, Any]:
    request = Request(url, headers=AWS_DOCS_REQUEST_HEADERS)
    with urlopen(request, timeout=20) as response:  # nosec B310 - docs-only verifier.
        payload = json.load(response)
    if not isinstance(payload, dict):
        raise ValueError("AWS Well-Architected TOC must be a JSON object")
    return payload


def _walk_toc(nodes: object, path: tuple[str, ...] = ()) -> Iterable[dict[str, str]]:
    if not isinstance(nodes, list):
        return
    for node in nodes:
        if not isinstance(node, dict):
            continue
        node_payload = cast("dict[str, Any]", node)
        title = str(node_payload.get("title", "")).replace("\xa0", " ").strip()
        href = str(node_payload.get("href", "")).strip()
        match = QUESTION_RE.match(title)
        if match:
            prefix = match.group("prefix")
            number = int(match.group("number"))
            yield {
                "id": f"{prefix}{number}",
                "pillar": PILLAR_BY_PREFIX[prefix],
                "title": match.group("title").strip(),
                "href": href,
                "url": f"{AWS_WELL_ARCHITECTED_DOC_BASE}{href}" if href else "",
                "path": " > ".join((*path, title)),
            }
        yield from _walk_toc(node_payload.get("contents"), (*path, title))


def extract_questions(toc: dict[str, Any]) -> list[dict[str, str]]:
    """Return AWS Well-Architected question entries from a TOC payload."""
    questions = list(_walk_toc(toc.get("contents")))
    return sorted(
        questions,
        key=lambda question: (
            PILLAR_ORDER.index(question["pillar"]),
            _question_number(question["id"]),
        ),
    )


def _question_number(question_id: str) -> int:
    match = re.search(r"\d+", question_id)
    return int(match.group(0)) if match else 0


def _question_scores(payload: dict[str, Any]) -> list[dict[str, Any]]:
    scores = payload.get("questionScores")
    if not isinstance(scores, list):
        return []
    return [item for item in scores if isinstance(item, dict)]


def _question_ids(items: Sequence[dict[str, Any]]) -> list[str]:
    return [str(item.get("id")) for item in items if isinstance(item.get("id"), str)]


def _count_by_pillar(questions: Sequence[dict[str, str]]) -> dict[str, int]:
    counter = Counter(question["pillar"] for question in questions)
    return {pillar: counter.get(pillar, 0) for pillar in PILLAR_ORDER}


def _count_scores_by_pillar(items: Sequence[dict[str, Any]]) -> dict[str, int]:
    counter = Counter(str(item.get("pillar")) for item in items)
    return {pillar: counter.get(pillar, 0) for pillar in PILLAR_ORDER}


def _duplicate_ids(ids: Sequence[str]) -> list[str]:
    counter = Counter(ids)
    return sorted(question_id for question_id, count in counter.items() if count > 1)


def _invalid_score_ids(items: Sequence[dict[str, Any]]) -> list[str]:
    invalid = []
    for item in items:
        score = item.get("score")
        if isinstance(score, bool) or not isinstance(score, int) or not 1 <= score <= 5:
            invalid.append(str(item.get("id", MISSING_QUESTION_ID)))
    return invalid


def _invalid_status_ids(items: Sequence[dict[str, Any]]) -> list[str]:
    return [
        str(item.get("id", MISSING_QUESTION_ID))
        for item in items
        if item.get("status") not in {"passed", "unresolved"}
    ]


def _score_status_mismatch_ids(items: Sequence[dict[str, Any]]) -> list[str]:
    mismatched = []
    for item in items:
        score = item.get("score")
        if isinstance(score, bool) or not isinstance(score, int) or not 1 <= score <= 5:
            continue
        status = item.get("status")
        if (status == "passed" and score != 5) or (status != "passed" and score == 5):
            mismatched.append(str(item.get("id", MISSING_QUESTION_ID)))
    return mismatched


def _expected_unresolved_question_ids(items: Sequence[dict[str, Any]]) -> list[str]:
    return _expected_question_id_order(
        str(item.get("id"))
        for item in items
        if item.get("status") != "passed" and isinstance(item.get("id"), str)
    )


def _expected_question_id_order(question_ids: Iterable[str]) -> list[str]:
    return sorted(question_ids, key=_question_id_sort_key)


def _question_id_sort_key(question_id: str) -> tuple[int, int, str]:
    for order, prefix in enumerate(PILLAR_BY_PREFIX):
        if question_id.startswith(prefix):
            suffix = question_id[len(prefix) :]
            number = int(suffix) if suffix.isdigit() else 0
            return order, number, question_id
    return len(PILLAR_BY_PREFIX), 0, question_id


def _expected_pillar_unresolved_question_counts(
    items: Sequence[dict[str, Any]],
    aws_pillar_by_id: dict[str, str],
) -> dict[str, int]:
    counts = {pillar: 0 for pillar in PILLAR_ORDER}
    for item in items:
        if item.get("status") == "passed":
            continue
        pillar = _aws_pillar_for_question_id(item.get("id"), aws_pillar_by_id)
        if pillar is not None:
            counts[pillar] += 1
    return counts


def _expected_pillar_question_score_averages(
    items: Sequence[dict[str, Any]],
    aws_pillar_by_id: dict[str, str],
) -> dict[str, float]:
    scores_by_pillar: dict[str, list[int]] = {pillar: [] for pillar in PILLAR_ORDER}
    for item in items:
        pillar = _aws_pillar_for_question_id(item.get("id"), aws_pillar_by_id)
        score = _valid_question_score(item.get("score"))
        if pillar is not None and score is not None:
            scores_by_pillar[pillar].append(score)
    if any(not pillar_scores for pillar_scores in scores_by_pillar.values()):
        return {}
    return {
        pillar: _rounded_average(pillar_scores)
        for pillar, pillar_scores in scores_by_pillar.items()
    }


def _aws_pillar_for_question_id(
    question_id: object,
    aws_pillar_by_id: dict[str, str],
) -> str | None:
    if not isinstance(question_id, str):
        return None
    return aws_pillar_by_id.get(question_id)


def _valid_question_score(score: object) -> int | None:
    if isinstance(score, bool) or not isinstance(score, int) or not 1 <= score <= 5:
        return None
    return score


def _rounded_average(values: Sequence[int]) -> float:
    total = sum(Decimal(value) for value in values)
    average = total / Decimal(len(values))
    return float(average.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))


def _string_list(value: object) -> list[str] | None:
    if not isinstance(value, list):
        return None
    if not all(isinstance(item, str) for item in value):
        return None
    return cast("list[str]", list(value))


def _string_key_number_map(value: object) -> dict[str, int | float] | None:
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


def _question_matrix_summary_blockers(
    *,
    evidence: dict[str, Any],
    expected_unresolved_count: int,
    expected_unresolved_ids: Sequence[str],
    expected_pillar_unresolved_counts: dict[str, int],
    expected_score_averages: dict[str, float],
) -> list[str]:
    blockers: list[str] = []
    if evidence.get("unresolvedQuestionCount") != expected_unresolved_count:
        blockers.append(
            "Question-matrix evidence unresolvedQuestionCount must match the "
            "number of non-passed questionScores entries."
        )
    declared_ids = _string_list(evidence.get("unresolvedQuestionIds"))
    if declared_ids is None:
        blockers.append(
            "Question-matrix evidence unresolvedQuestionIds must be a list of strings."
        )
    elif declared_ids != list(expected_unresolved_ids):
        blockers.append(
            "Question-matrix evidence unresolvedQuestionIds must match non-passed "
            "questionScores entries: "
            f"{_question_id_list_text(expected_unresolved_ids)}."
        )
    declared_counts = _string_key_int_map(
        evidence.get("pillarUnresolvedQuestionCounts")
    )
    if declared_counts is None:
        blockers.append(
            "Question-matrix evidence pillarUnresolvedQuestionCounts must be a "
            "string-keyed integer map."
        )
    elif declared_counts != expected_pillar_unresolved_counts:
        blockers.append(
            "Question-matrix evidence pillarUnresolvedQuestionCounts must match "
            "non-passed questionScores entries by pillar."
        )
    declared_averages = _string_key_number_map(evidence.get("questionScoreAverages"))
    if declared_averages is None:
        blockers.append(
            "Question-matrix evidence questionScoreAverages must be a "
            "string-keyed numeric map."
        )
    elif expected_score_averages and declared_averages != expected_score_averages:
        blockers.append(
            "Question-matrix evidence questionScoreAverages must match score "
            "averages computed from questionScores entries."
        )
    return blockers


def _question_id_list_text(question_ids: Sequence[str]) -> str:
    return ", ".join(question_ids) if question_ids else "none"


def _framework_source_metadata_blockers(verification: object) -> list[str]:
    if not isinstance(verification, dict):
        return [
            "Question-matrix evidence frameworkSourceVerification must be an object."
        ]
    blockers: list[str] = []
    checked_at = verification.get("checkedAt")
    if not _valid_iso_timestamp(checked_at):
        blockers.append(
            "Question-matrix framework source verification checkedAt must be "
            "an ISO-8601 timestamp."
        )
    source = verification.get("source")
    if not isinstance(source, str) or not source.strip():
        blockers.append(
            "Question-matrix framework source verification source is required."
        )
    source_urls = _string_list(verification.get("sourceUrls"))
    if source_urls is None or not _non_empty_strings(source_urls):
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


def _framework_source_metadata_summary(
    verification: object,
) -> dict[str, object] | None:
    if not isinstance(verification, dict):
        return None
    source_urls = _string_list(verification.get("sourceUrls"))
    return {
        "checkedAt": verification.get("checkedAt"),
        "source": verification.get("source"),
        "sourceUrlCount": len(source_urls) if source_urls is not None else None,
        "sourceUrls": source_urls,
        "officialTocUrlPresent": (
            AWS_WELL_ARCHITECTED_TOC_URL in source_urls
            if source_urls is not None
            else False
        ),
        "questionCounts": _string_key_int_map(verification.get("questionCounts")),
    }


def _valid_iso_timestamp(value: object) -> bool:
    if not isinstance(value, str) or not value.strip():
        return False
    try:
        dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return True


def _non_empty_strings(values: Sequence[str]) -> bool:
    return bool(values) and all(value.strip() for value in values)


def _missing_evidence_ref_ids(items: Sequence[dict[str, Any]]) -> list[str]:
    missing = []
    for item in items:
        if item.get("status") == "passed":
            continue
        refs = item.get("evidenceRefs")
        if not (
            isinstance(refs, list)
            and refs
            and all(isinstance(ref, str) and ref.strip() for ref in refs)
        ):
            missing.append(str(item.get("id", MISSING_QUESTION_ID)))
    return missing


def _pillar_mismatch_ids(
    items: Sequence[dict[str, Any]],
    aws_pillar_by_id: dict[str, str],
) -> list[str]:
    mismatched = []
    for item in items:
        question_id = item.get("id")
        if not isinstance(question_id, str):
            continue
        expected_pillar = aws_pillar_by_id.get(question_id)
        if expected_pillar is not None and item.get("pillar") != expected_pillar:
            mismatched.append(question_id)
    return sorted(mismatched)


def extract_markdown_questions(markdown: str) -> list[dict[str, str]]:
    """Return question IDs and section pillars from the Markdown matrix."""
    questions = []
    current_pillar = ""
    for line in markdown.splitlines():
        pillar_match = MARKDOWN_PILLAR_RE.match(line.strip())
        if pillar_match:
            current_pillar = pillar_match.group("pillar")
            continue
        if line.startswith("## "):
            current_pillar = ""
            continue
        row_match = MARKDOWN_QUESTION_ROW_RE.match(line)
        if row_match:
            questions.append(
                {
                    "id": row_match.group("id"),
                    "pillar": current_pillar,
                }
            )
    return questions


def _verification_blockers(inputs: VerificationBlockerInputs) -> list[str]:
    blocker_checks = (
        (
            bool(inputs.duplicate_aws_ids),
            "AWS Well-Architected TOC contains duplicate question IDs: "
            f"{', '.join(inputs.duplicate_aws_ids)}.",
        ),
        (
            bool(inputs.duplicate_evidence_ids),
            "Question-matrix evidence contains duplicate question IDs: "
            f"{', '.join(inputs.duplicate_evidence_ids)}.",
        ),
        (
            bool(inputs.missing_ids),
            "Question-matrix evidence is missing AWS questions: "
            f"{', '.join(inputs.missing_ids)}.",
        ),
        (
            bool(inputs.extra_ids),
            "Question-matrix evidence contains non-AWS question IDs: "
            f"{', '.join(inputs.extra_ids)}.",
        ),
        (
            bool(inputs.invalid_score_ids),
            "Question-matrix evidence scores must be integers from 1 to 5 for: "
            f"{', '.join(inputs.invalid_score_ids)}.",
        ),
        (
            bool(inputs.invalid_status_ids),
            "Question-matrix evidence statuses must be one of passed, "
            f"unresolved for: {', '.join(inputs.invalid_status_ids)}.",
        ),
        (
            bool(inputs.score_status_mismatch_ids),
            "Question-matrix passed entries must score 5 and non-passed entries "
            f"must score below 5 for: {', '.join(inputs.score_status_mismatch_ids)}.",
        ),
        (
            bool(inputs.missing_evidence_ref_ids),
            "Question-matrix non-passed entries must include evidenceRefs for: "
            f"{', '.join(inputs.missing_evidence_ref_ids)}.",
        ),
        (
            bool(inputs.pillar_mismatch_ids),
            "Question-matrix evidence pillar values must match AWS question IDs "
            f"for: {', '.join(inputs.pillar_mismatch_ids)}.",
        ),
        (
            inputs.evidence_question_count != inputs.aws_question_count,
            "Question-matrix evidence questionCount must match the AWS TOC "
            f"question count ({inputs.aws_question_count}).",
        ),
        (
            inputs.declared_counts != inputs.aws_counts,
            "Question-matrix frameworkSourceVerification.questionCounts must "
            "match the AWS TOC pillar counts.",
        ),
        (
            inputs.evidence_counts != inputs.aws_counts,
            "Question-matrix questionScores pillar counts must match the AWS "
            "TOC pillar counts.",
        ),
        (
            bool(inputs.duplicate_markdown_ids),
            "Question-matrix Markdown contains duplicate question rows: "
            f"{', '.join(inputs.duplicate_markdown_ids)}.",
        ),
        (
            bool(inputs.missing_markdown_ids),
            "Question-matrix Markdown is missing AWS question rows: "
            f"{', '.join(inputs.missing_markdown_ids)}.",
        ),
        (
            bool(inputs.extra_markdown_ids),
            "Question-matrix Markdown contains non-AWS question rows: "
            f"{', '.join(inputs.extra_markdown_ids)}.",
        ),
        (
            bool(inputs.markdown_pillar_mismatch_ids),
            "Question-matrix Markdown sections must match AWS question pillars "
            f"for: {', '.join(inputs.markdown_pillar_mismatch_ids)}.",
        ),
    )
    return [message for failed, message in blocker_checks if failed]


def verify_question_matrix(
    *,
    evidence: dict[str, Any],
    toc: dict[str, Any],
    toc_source: str,
    question_matrix_markdown: str | None = None,
) -> dict[str, Any]:
    """Compare question evidence with the live AWS Well-Architected TOC."""
    checked_at = dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")
    aws_questions = extract_questions(toc)
    aws_ids = [question["id"] for question in aws_questions]
    aws_pillar_by_id = {
        question["id"]: question["pillar"] for question in aws_questions
    }
    aws_counts = _count_by_pillar(aws_questions)
    score_items = _question_scores(evidence)
    evidence_ids = _question_ids(score_items)
    evidence_counts = _count_scores_by_pillar(score_items)
    markdown_items = (
        extract_markdown_questions(question_matrix_markdown)
        if question_matrix_markdown is not None
        else []
    )
    markdown_ids = _question_ids(markdown_items)
    source_verification = evidence.get("frameworkSourceVerification")
    if not isinstance(source_verification, dict):
        source_verification = {}
    declared_counts = source_verification.get("questionCounts")

    missing_ids = sorted(set(aws_ids) - set(evidence_ids))
    extra_ids = sorted(set(evidence_ids) - set(aws_ids))
    duplicate_aws_ids = _duplicate_ids(aws_ids)
    duplicate_evidence_ids = _duplicate_ids(evidence_ids)
    invalid_score_ids = _invalid_score_ids(score_items)
    invalid_status_ids = _invalid_status_ids(score_items)
    score_status_mismatch_ids = _score_status_mismatch_ids(score_items)
    missing_evidence_ref_ids = _missing_evidence_ref_ids(score_items)
    pillar_mismatch_ids = _pillar_mismatch_ids(score_items, aws_pillar_by_id)
    expected_unresolved_ids = _expected_unresolved_question_ids(score_items)
    expected_unresolved_count = len(expected_unresolved_ids)
    expected_pillar_unresolved_counts = _expected_pillar_unresolved_question_counts(
        score_items,
        aws_pillar_by_id,
    )
    expected_score_averages = _expected_pillar_question_score_averages(
        score_items,
        aws_pillar_by_id,
    )
    evidence_unresolved_ids = _string_list(evidence.get("unresolvedQuestionIds"))
    evidence_pillar_unresolved_counts = _string_key_int_map(
        evidence.get("pillarUnresolvedQuestionCounts")
    )
    evidence_score_averages = _string_key_number_map(
        evidence.get("questionScoreAverages")
    )
    duplicate_markdown_ids = _duplicate_ids(markdown_ids)
    missing_markdown_ids = (
        sorted(set(aws_ids) - set(markdown_ids))
        if question_matrix_markdown is not None
        else []
    )
    extra_markdown_ids = sorted(set(markdown_ids) - set(aws_ids))
    markdown_pillar_mismatch_ids = _pillar_mismatch_ids(
        markdown_items,
        aws_pillar_by_id,
    )
    blockers = _verification_blockers(
        VerificationBlockerInputs(
            duplicate_aws_ids=duplicate_aws_ids,
            duplicate_evidence_ids=duplicate_evidence_ids,
            missing_ids=missing_ids,
            extra_ids=extra_ids,
            invalid_score_ids=invalid_score_ids,
            invalid_status_ids=invalid_status_ids,
            score_status_mismatch_ids=score_status_mismatch_ids,
            missing_evidence_ref_ids=missing_evidence_ref_ids,
            pillar_mismatch_ids=pillar_mismatch_ids,
            evidence_question_count=evidence.get("questionCount"),
            aws_question_count=len(aws_ids),
            declared_counts=declared_counts,
            aws_counts=aws_counts,
            evidence_counts=evidence_counts,
            duplicate_markdown_ids=duplicate_markdown_ids,
            missing_markdown_ids=missing_markdown_ids,
            extra_markdown_ids=extra_markdown_ids,
            markdown_pillar_mismatch_ids=markdown_pillar_mismatch_ids,
        )
    )
    blockers.extend(
        _question_matrix_summary_blockers(
            evidence=evidence,
            expected_unresolved_count=expected_unresolved_count,
            expected_unresolved_ids=expected_unresolved_ids,
            expected_pillar_unresolved_counts=expected_pillar_unresolved_counts,
            expected_score_averages=expected_score_averages,
        )
    )
    blockers.extend(
        _framework_source_metadata_blockers(evidence.get("frameworkSourceVerification"))
    )

    return {
        "status": "passed" if not blockers else "failed",
        "checkedAt": checked_at,
        "tocSource": toc_source,
        "awsQuestionCount": len(aws_ids),
        "awsPillarQuestionCounts": aws_counts,
        "evidenceQuestionCount": evidence.get("questionCount"),
        "evidencePillarQuestionCounts": evidence_counts,
        "missingQuestionIds": missing_ids,
        "extraQuestionIds": extra_ids,
        "duplicateAwsQuestionIds": duplicate_aws_ids,
        "duplicateEvidenceQuestionIds": duplicate_evidence_ids,
        "invalidScoreQuestionIds": invalid_score_ids,
        "invalidStatusQuestionIds": invalid_status_ids,
        "scoreStatusMismatchQuestionIds": score_status_mismatch_ids,
        "missingEvidenceRefQuestionIds": missing_evidence_ref_ids,
        "pillarMismatchQuestionIds": pillar_mismatch_ids,
        "expectedUnresolvedQuestionCount": expected_unresolved_count,
        "evidenceUnresolvedQuestionCount": evidence.get("unresolvedQuestionCount"),
        "expectedUnresolvedQuestionIds": expected_unresolved_ids,
        "evidenceUnresolvedQuestionIds": evidence_unresolved_ids,
        "expectedPillarUnresolvedQuestionCounts": expected_pillar_unresolved_counts,
        "evidencePillarUnresolvedQuestionCounts": evidence_pillar_unresolved_counts,
        "expectedQuestionScoreAverages": expected_score_averages,
        "evidenceQuestionScoreAverages": evidence_score_averages,
        "evidenceFrameworkSourceVerification": (
            _framework_source_metadata_summary(
                evidence.get("frameworkSourceVerification")
            )
        ),
        "markdownQuestionCount": (
            len(markdown_ids) if question_matrix_markdown is not None else None
        ),
        "missingMarkdownQuestionIds": missing_markdown_ids,
        "extraMarkdownQuestionIds": extra_markdown_ids,
        "duplicateMarkdownQuestionIds": duplicate_markdown_ids,
        "markdownPillarMismatchQuestionIds": markdown_pillar_mismatch_ids,
        "blockers": blockers,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Verify the local Well-Architected question matrix against the "
            "AWS public Framework TOC."
        )
    )
    parser.add_argument(
        "--question-matrix-evidence",
        type=Path,
        default=Path(
            "specs/issue-17-well-architected-5-of-5/"
            "question-matrix-evidence-2026-05-17.json"
        ),
    )
    parser.add_argument(
        "--question-matrix",
        type=Path,
        default=Path("specs/issue-17-well-architected-5-of-5/question-matrix.md"),
    )
    parser.add_argument("--toc-url", default=AWS_WELL_ARCHITECTED_TOC_URL)
    parser.add_argument("--toc-json", type=Path)
    parser.add_argument("--output", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        evidence = _load_json(args.question_matrix_evidence)
        question_matrix_markdown = args.question_matrix.read_text(encoding="utf-8")
        if args.toc_json:
            toc = _load_json(args.toc_json)
            toc_source = str(args.toc_json)
        else:
            toc = _fetch_toc(args.toc_url)
            toc_source = args.toc_url
        report = verify_question_matrix(
            evidence=evidence,
            toc=toc,
            toc_source=toc_source,
            question_matrix_markdown=question_matrix_markdown,
        )
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
