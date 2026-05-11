#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
from collections import Counter
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any, cast
from urllib.request import urlopen

AWS_WELL_ARCHITECTED_TOC_URL = (
    "https://docs.aws.amazon.com/wellarchitected/latest/framework/toc-contents.json"
)
AWS_WELL_ARCHITECTED_DOC_BASE = (
    "https://docs.aws.amazon.com/wellarchitected/latest/framework/"
)
QUESTION_RE = re.compile(
    r"^(?P<prefix>OPS|SEC|REL|PERF|COST|SUS)\s+0*(?P<number>[1-9][0-9]?)"
    r"\.?\s+(?P<title>.+)$"
)
MARKDOWN_QUESTION_ROW_RE = re.compile(
    r"^\|\s*(?P<id>(?:OPS|SEC|REL|PERF|COST|SUS)[1-9][0-9]?)\s*\|"
)
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


def _load_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return payload


def _fetch_toc(url: str) -> dict[str, Any]:
    with urlopen(url, timeout=20) as response:  # nosec B310 - docs-only verifier.
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
            invalid.append(str(item.get("id", "<missing>")))
    return invalid


def _score_status_mismatch_ids(items: Sequence[dict[str, Any]]) -> list[str]:
    mismatched = []
    for item in items:
        score = item.get("score")
        if isinstance(score, bool) or not isinstance(score, int) or not 1 <= score <= 5:
            continue
        status = item.get("status")
        if (status == "passed" and score != 5) or (status != "passed" and score == 5):
            mismatched.append(str(item.get("id", "<missing>")))
    return mismatched


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
            missing.append(str(item.get("id", "<missing>")))
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


def _verification_blockers(
    *,
    duplicate_aws_ids: Sequence[str],
    duplicate_evidence_ids: Sequence[str],
    missing_ids: Sequence[str],
    extra_ids: Sequence[str],
    invalid_score_ids: Sequence[str],
    score_status_mismatch_ids: Sequence[str],
    missing_evidence_ref_ids: Sequence[str],
    pillar_mismatch_ids: Sequence[str],
    evidence_question_count: object,
    aws_question_count: int,
    declared_counts: object,
    aws_counts: dict[str, int],
    evidence_counts: dict[str, int],
    duplicate_markdown_ids: Sequence[str],
    missing_markdown_ids: Sequence[str],
    extra_markdown_ids: Sequence[str],
    markdown_pillar_mismatch_ids: Sequence[str],
) -> list[str]:
    blocker_checks = (
        (
            bool(duplicate_aws_ids),
            "AWS Well-Architected TOC contains duplicate question IDs: "
            f"{', '.join(duplicate_aws_ids)}.",
        ),
        (
            bool(duplicate_evidence_ids),
            "Question-matrix evidence contains duplicate question IDs: "
            f"{', '.join(duplicate_evidence_ids)}.",
        ),
        (
            bool(missing_ids),
            "Question-matrix evidence is missing AWS questions: "
            f"{', '.join(missing_ids)}.",
        ),
        (
            bool(extra_ids),
            "Question-matrix evidence contains non-AWS question IDs: "
            f"{', '.join(extra_ids)}.",
        ),
        (
            bool(invalid_score_ids),
            "Question-matrix evidence scores must be integers from 1 to 5 for: "
            f"{', '.join(invalid_score_ids)}.",
        ),
        (
            bool(score_status_mismatch_ids),
            "Question-matrix passed entries must score 5 and non-passed entries "
            f"must score below 5 for: {', '.join(score_status_mismatch_ids)}.",
        ),
        (
            bool(missing_evidence_ref_ids),
            "Question-matrix non-passed entries must include evidenceRefs for: "
            f"{', '.join(missing_evidence_ref_ids)}.",
        ),
        (
            bool(pillar_mismatch_ids),
            "Question-matrix evidence pillar values must match AWS question IDs "
            f"for: {', '.join(pillar_mismatch_ids)}.",
        ),
        (
            evidence_question_count != aws_question_count,
            "Question-matrix evidence questionCount must match the AWS TOC "
            f"question count ({aws_question_count}).",
        ),
        (
            declared_counts != aws_counts,
            "Question-matrix frameworkSourceVerification.questionCounts must "
            "match the AWS TOC pillar counts.",
        ),
        (
            evidence_counts != aws_counts,
            "Question-matrix questionScores pillar counts must match the AWS "
            "TOC pillar counts.",
        ),
        (
            bool(duplicate_markdown_ids),
            "Question-matrix Markdown contains duplicate question rows: "
            f"{', '.join(duplicate_markdown_ids)}.",
        ),
        (
            bool(missing_markdown_ids),
            "Question-matrix Markdown is missing AWS question rows: "
            f"{', '.join(missing_markdown_ids)}.",
        ),
        (
            bool(extra_markdown_ids),
            "Question-matrix Markdown contains non-AWS question rows: "
            f"{', '.join(extra_markdown_ids)}.",
        ),
        (
            bool(markdown_pillar_mismatch_ids),
            "Question-matrix Markdown sections must match AWS question pillars "
            f"for: {', '.join(markdown_pillar_mismatch_ids)}.",
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
    score_status_mismatch_ids = _score_status_mismatch_ids(score_items)
    missing_evidence_ref_ids = _missing_evidence_ref_ids(score_items)
    pillar_mismatch_ids = _pillar_mismatch_ids(score_items, aws_pillar_by_id)
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
        duplicate_aws_ids=duplicate_aws_ids,
        duplicate_evidence_ids=duplicate_evidence_ids,
        missing_ids=missing_ids,
        extra_ids=extra_ids,
        invalid_score_ids=invalid_score_ids,
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
        "scoreStatusMismatchQuestionIds": score_status_mismatch_ids,
        "missingEvidenceRefQuestionIds": missing_evidence_ref_ids,
        "pillarMismatchQuestionIds": pillar_mismatch_ids,
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
            "question-matrix-evidence-2026-05-09.json"
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
    except (OSError, ValueError, json.JSONDecodeError) as exc:
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
