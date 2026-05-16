from __future__ import annotations

from _script_support import run
from _well_architected_aws_iam_access import aws_identity
from _well_architected_evidence_common import Runner, _check, _run_json


def aws_cost_controls(
    account_id: str | None, *, runner: Runner = run
) -> dict[str, object]:
    """Collect account-level Budget and Cost Anomaly Detection availability."""
    if not account_id:
        account_id = _account_id_from_identity(aws_identity(runner=runner))
    if not account_id:
        return _check(
            "aws_cost_controls",
            status="unknown",
            blockers=["Unable to determine AWS account id."],
        )

    budget_ok, budget_count, budget_error = _run_count(
        [
            "aws",
            "budgets",
            "describe-budgets",
            "--account-id",
            account_id,
            "--max-results",
            "1",
            "--query",
            "length(Budgets)",
            "--output",
            "json",
        ],
        runner=runner,
    )
    anomaly_ok, anomaly_count, anomaly_error = _run_count(
        [
            "aws",
            "ce",
            "get-anomaly-monitors",
            "--max-results",
            "1",
            "--query",
            "length(AnomalyMonitors)",
            "--output",
            "json",
        ],
        runner=runner,
    )
    blockers = []
    if not budget_ok:
        blockers.append(f"Unable to query AWS Budgets: {budget_error}")
    elif budget_count < 1:
        blockers.append("No AWS Budgets were found in the target account.")
    if not anomaly_ok:
        blockers.append(f"Unable to query Cost Anomaly monitors: {anomaly_error}")
    elif anomaly_count < 1:
        blockers.append("No Cost Anomaly monitors were found in the target account.")
    return _check(
        "aws_cost_controls",
        status="passed" if not blockers else "failed",
        evidence={
            "account": account_id,
            "budgetCountAtLeast": budget_count if budget_ok else 0,
            "anomalyMonitorCountAtLeast": anomaly_count if anomaly_ok else 0,
        },
        blockers=blockers,
    )


def _account_id_from_identity(identity: dict[str, object]) -> str:
    """Return account id from a normalized identity check."""
    evidence = identity.get("evidence", {})
    if not isinstance(evidence, dict):
        return ""
    account = evidence.get("account")
    return str(account) if account is not None else ""


def _run_count(
    command: list[str],
    *,
    runner: Runner = run,
) -> tuple[bool, int, str]:
    """Run a count query and normalize the result."""
    ok, count, error = _run_json(command, runner=runner)
    if not ok:
        return False, 0, error
    return True, int(count or 0), ""
