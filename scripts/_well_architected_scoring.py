from __future__ import annotations

from collections.abc import Sequence

OPERATIONAL_EXCELLENCE_PILLAR = "Operational Excellence"
PERFORMANCE_EFFICIENCY_PILLAR = "Performance Efficiency"
COST_OPTIMIZATION_PILLAR = "Cost Optimization"

READINESS_GATES = (
    "question_matrix_evidence",
    "external_control_evidence",
)

PILLAR_CHECKS = {
    OPERATIONAL_EXCELLENCE_PILLAR: (
        "github_pr_checks",
        "github_pr_local_state",
        "github_review_threads",
        "github_branch_protection",
        "github_production_environment",
        "aws_sns_alert_route",
        "aws_cloudtrail_management_events",
    ),
    "Security": (
        "github_pr_checks",
        "github_pr_local_state",
        "github_review_threads",
        "github_branch_protection",
        "github_dependabot_alerts",
        "aws_identity",
        "aws_iam_account_access",
        "aws_cloudtrail_management_events",
    ),
    "Reliability": (
        "github_pr_checks",
        "github_pr_local_state",
        "github_production_environment",
        "aws_sns_alert_route",
        "restore_drill_evidence",
        "repository_fanout",
    ),
    PERFORMANCE_EFFICIENCY_PILLAR: ("repository_fanout",),
    COST_OPTIMIZATION_PILLAR: ("aws_cost_controls", "repository_fanout"),
    "Sustainability": ("repository_fanout",),
}
WELL_ARCHITECTED_SCORE_CAP = 4.0


def pillar_scores(checks: Sequence[dict[str, object]]) -> dict[str, float]:
    """Calculate proxy readiness scores from normalized metadata checks."""
    by_name = {str(check["name"]): check for check in checks}
    scores: dict[str, float] = {}
    for pillar, check_names in PILLAR_CHECKS.items():
        passed = sum(
            1
            for check_name in check_names
            if by_name.get(check_name, {}).get("status") == "passed"
        )
        scores[pillar] = round(5 * passed / len(check_names), 2)
    return scores


def well_architected_scores(
    proxy_scores: dict[str, float],
    checks: Sequence[dict[str, object]],
) -> dict[str, float]:
    """Cap final score claims until question-level evidence gates pass."""
    by_name = {str(check["name"]): check for check in checks}
    readiness_passed = all(
        by_name.get(gate, {}).get("status") == "passed" for gate in READINESS_GATES
    )
    if readiness_passed:
        return proxy_scores
    return {
        pillar: min(score, WELL_ARCHITECTED_SCORE_CAP)
        for pillar, score in proxy_scores.items()
    }


def score_blockers(checks: Sequence[dict[str, object]]) -> list[str]:
    """Return score-claim blockers for final Well-Architected scoring."""
    by_name = {str(check["name"]): check for check in checks}
    blockers: list[str] = []
    for gate in READINESS_GATES:
        status = by_name.get(gate, {}).get("status")
        if status == "passed":
            continue
        if status == "missing" or gate not in by_name:
            blockers.append(
                f"{gate} is required before proxy readiness scores can be treated "
                "as final Well-Architected scores."
            )
            continue
        blockers.append(
            f"{gate} must pass before proxy readiness scores can be treated "
            "as final Well-Architected scores."
        )
    return blockers
