"""Structural tests for the AI-safe CI/CD guardrail layer.

These checks intentionally mirror the workflow structure closely. Update them
alongside `.github/workflows/pulumi-pr-guardrails.yml` when job names, step
ordering, or `if` expressions change.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS_DIR = PROJECT_ROOT / ".github" / "workflows"
GUARDRAILS_DOC = PROJECT_ROOT / "docs" / "ci-guardrails.md"
PREVIEW_SCRIPT = PROJECT_ROOT / "scripts" / "run_pulumi_preview.py"
PREVIEW_SUMMARY_SCRIPT = PROJECT_ROOT / "scripts" / "publish_pulumi_preview_summary.py"
DRIFT_SCRIPT = PROJECT_ROOT / "scripts" / "run_pulumi_drift_check.py"
GITLEAKS_CONFIG = PROJECT_ROOT / ".gitleaks.toml"
ACTION_SHA_REF = re.compile(r"^[^@]+@[0-9a-f]{40}$")


def _workflow(name: str) -> dict:
    """Load a workflow YAML file from disk."""
    return yaml.safe_load((WORKFLOWS_DIR / name).read_text(encoding="utf-8"))


def _triggers(workflow: dict) -> dict:
    """Normalize the GitHub Actions `on` key when YAML parses it as a boolean."""
    return workflow.get("on", workflow.get(True, {}))


def test_preview_guardrail_workflow_requires_preview_diff_and_iam_jobs() -> None:
    """Keep the preview workflow aligned with the repo-local Make entrypoints."""
    workflow = _workflow("pulumi-pr-guardrails.yml")
    jobs = workflow["jobs"]
    destructive_diff_if = (
        "${{ always() && (needs.preview.result == 'success' || "
        "needs.preview_unprivileged.result == 'success') }}"
    )
    destructive_diff_runs = [
        step.get("run") for step in jobs["destructive_diff"]["steps"] if step.get("run")
    ]
    preview_mode_step = next(
        (
            step
            for step in jobs["preview_mode"]["steps"]
            if step.get("name") == "Select preview mode"
        ),
        None,
    )
    preview_upload_step = next(
        (
            step
            for step in jobs["preview"]["steps"]
            if step.get("uses", "").startswith("actions/upload-artifact@")
        ),
        None,
    )
    preview_preflight_step = next(
        (
            step
            for step in jobs["preview"]["steps"]
            if step.get("name") == "Validate preview prerequisites"
        ),
        None,
    )
    preview_oidc_step = next(
        (
            step
            for step in jobs["preview"]["steps"]
            if step.get("name") == "Configure AWS credentials via OIDC"
        ),
        None,
    )
    preview_run_step = next(
        (
            step
            for step in jobs["preview"]["steps"]
            if step.get("name") == "Run preview guardrail"
        ),
        None,
    )
    unprivileged_preview_run = next(
        (
            step.get("run", "")
            for step in jobs["preview_unprivileged"]["steps"]
            if step.get("name") == "Run unprivileged preview guardrail"
        ),
        "",
    )
    preview_download_step = next(
        (
            step
            for step in jobs["destructive_diff"]["steps"]
            if step.get("name") == "Download preview artifact"
        ),
        None,
    )
    cost_proxy_run = next(
        (
            step.get("run", "")
            for step in jobs["destructive_diff"]["steps"]
            if step.get("name") == "Enforce cost and quota proxy"
        ),
        "",
    )
    iam_download_step = next(
        (
            step
            for step in jobs["iam_validation"]["steps"]
            if step.get("name") == "Download preview artifact"
        ),
        None,
    )
    iam_oidc_step = next(
        (
            step
            for step in jobs["iam_validation"]["steps"]
            if step.get("name") == "Configure AWS credentials via OIDC"
        ),
        None,
    )
    iam_validation_run = next(
        (
            step.get("run", "")
            for step in jobs["iam_validation"]["steps"]
            if step.get("name") == "Validate IAM policies"
        ),
        "",
    )
    unprivileged_iam_run = next(
        (
            step.get("run", "")
            for step in jobs["iam_validation_unprivileged"]["steps"]
            if step.get("name") == "Validate IAM policies"
        ),
        "",
    )
    destructive_diff_job_if = " ".join(jobs["destructive_diff"]["if"].split())
    pr_backend_expression = (
        "${{ github.event_name == 'pull_request' && "
        + "vars.PULUMI_PR_BACKEND_URL || vars.PULUMI_BACKEND_URL }}"
    )
    pr_stack_expression = (
        "${{ github.event_name == 'pull_request' && "
        + "vars.PULUMI_PR_PREVIEW_STACKS || vars.PULUMI_PREVIEW_STACKS }}"
    )

    assert workflow["concurrency"]["cancel-in-progress"] is True
    assert "environment" not in jobs["preview_mode"]  # nosec B101
    assert "permissions" not in jobs["preview_mode"]  # nosec B101
    assert (  # nosec B101
        jobs["preview"]["if"]
        == "${{ needs.preview_mode.outputs.privileged == 'true' }}"
    )
    assert jobs["preview"]["needs"] == ["preview_mode"]  # nosec B101
    assert jobs["preview"]["environment"] == "test"  # nosec B101
    assert (  # nosec B101
        jobs["preview"]["env"]["PULUMI_BACKEND_URL"] == pr_backend_expression
    )
    assert (  # nosec B101
        jobs["preview"]["env"]["PULUMI_PREVIEW_STACKS"] == pr_stack_expression
    )
    assert jobs["preview"]["permissions"] == {  # nosec B101
        "contents": "read",
        "id-token": "write",
    }
    assert jobs["preview_unprivileged"]["permissions"] == {"contents": "read"}  # nosec B101
    assert "environment" not in jobs["preview_unprivileged"]  # nosec B101
    assert "id-token" not in jobs["preview_unprivileged"]["permissions"]  # nosec B101
    assert jobs["iam_validation"]["if"] == "${{ needs.preview.result == 'success' }}"  # nosec B101
    assert (  # nosec B101
        jobs["iam_validation_unprivileged"]["if"]
        == "${{ needs.preview_unprivileged.result == 'success' }}"
    )
    assert "environment" not in jobs["iam_validation_unprivileged"]  # nosec B101
    assert jobs["iam_validation_unprivileged"]["permissions"] == {"contents": "read"}  # nosec B101
    assert destructive_diff_job_if == destructive_diff_if  # nosec B101
    assert jobs["destructive_diff"]["needs"] == [  # nosec B101
        "preview",
        "preview_unprivileged",
    ]
    assert jobs["iam_validation"]["needs"] == ["preview"]  # nosec B101
    assert jobs["iam_validation_unprivileged"]["needs"] == ["preview_unprivileged"]  # nosec B101
    assert preview_mode_step is not None  # nosec B101
    assert "Fork pull request detected" in preview_mode_step["run"]  # nosec B101
    assert preview_preflight_step is not None  # nosec B101
    assert "AWS_ACCOUNT_ID" in preview_preflight_step["run"]  # nosec B101
    assert "AWS_PREVIEW_ROLE_ARN" in preview_preflight_step["run"]  # nosec B101
    assert "PULUMI_SECRETS_PROVIDER" in preview_preflight_step["run"]  # nosec B101
    assert "12-digit AWS account ID" in preview_preflight_step["run"]  # nosec B101
    assert "s3:// backend" in preview_preflight_step["run"]  # nosec B101
    assert "awskms:// URI" in preview_preflight_step["run"]  # nosec B101
    assert preview_oidc_step is not None, "preview OIDC step not found"  # nosec B101
    assert iam_oidc_step is not None, "IAM validation OIDC step not found"  # nosec B101
    assert preview_run_step is not None, "preview run step not found"  # nosec B101
    assert preview_upload_step is not None, "preview artifact upload step not found"  # nosec B101
    assert preview_upload_step["with"]["name"] == "pulumi-preview"  # nosec B101
    assert "if" not in preview_oidc_step  # nosec B101
    assert (  # nosec B101
        preview_oidc_step["with"]["role-to-assume"] == "${{ env.AWS_PREVIEW_ROLE_ARN }}"
    )
    assert (  # nosec B101
        preview_oidc_step["with"]["allowed-account-ids"] == "${{ env.AWS_ACCOUNT_ID }}"
    )
    assert preview_oidc_step["with"]["aws-region"] == "${{ env.AWS_REGION }}"  # nosec B101
    assert "if" not in iam_oidc_step  # nosec B101
    assert iam_oidc_step["with"]["role-to-assume"] == "${{ env.AWS_PREVIEW_ROLE_ARN }}"  # nosec B101
    assert iam_oidc_step["with"]["aws-region"] == "${{ env.AWS_REGION }}"  # nosec B101
    assert iam_oidc_step["with"]["allowed-account-ids"] == "${{ env.AWS_ACCOUNT_ID }}"  # nosec B101
    assert "make publish-pulumi-preview-summary" in preview_run_step["run"]  # nosec B101
    assert "make test-preview-unprivileged" in unprivileged_preview_run  # nosec B101
    assert preview_run_step["env"] == {  # nosec B101
        "PULUMI_REQUIRE_SHARED_BACKEND": "true",
        "GITHUB_TOKEN": "${{ github.token }}",
    }
    assert any(step.get("run") == "make start" for step in jobs["preview"]["steps"])  # nosec B101
    preview_unprivileged_started = any(
        step.get("run") == "make start"
        for step in jobs["preview_unprivileged"]["steps"]
    )
    assert preview_unprivileged_started  # nosec B101
    assert preview_download_step is not None  # nosec B101
    assert preview_download_step["with"]["name"] == "pulumi-preview"  # nosec B101
    assert iam_download_step is not None  # nosec B101
    assert iam_download_step["with"]["name"] == "pulumi-preview"  # nosec B101
    assert any(  # nosec B101
        step.get("run") == "make test-destructive-diff"
        for step in jobs["destructive_diff"]["steps"]
    )
    assert any(  # nosec B101
        "make test-cost-proxy" in step.get("run", "")
        for step in jobs["destructive_diff"]["steps"]
    )
    assert (  # nosec B101
        "cat .artifacts/pulumi-preview/reports/cost-proxy.md" in cost_proxy_run
    )
    assert any(  # nosec B101
        'cp "${GITHUB_EVENT_PATH}" .artifacts/github-event.json' in run
        for run in destructive_diff_runs
    )
    assert iam_validation_run == "make test-iam-validation"  # nosec B101
    assert unprivileged_iam_run == "make test-iam-validation-unprivileged"  # nosec B101


def test_guardrail_docs_define_required_privileged_check_contract() -> None:
    """Keep required-check guidance tied to concrete workflow job names."""
    workflow = _workflow("pulumi-pr-guardrails.yml")
    guardrails_doc = GUARDRAILS_DOC.read_text(encoding="utf-8")
    normalized_doc = " ".join(guardrails_doc.split())
    jobs = workflow["jobs"]

    for job_id in ("preview", "destructive_diff", "iam_validation"):
        check_name = f"{workflow['name']} / {jobs[job_id]['name']}"
        assert f"`{check_name}`" in guardrails_doc  # nosec B101
        assert f"`{job_id}`" in guardrails_doc  # nosec B101

    for job_id in ("preview_unprivileged", "iam_validation_unprivileged"):
        check_name = f"{workflow['name']} / {jobs[job_id]['name']}"
        assert f"`{check_name}`" in guardrails_doc  # nosec B101

    assert "must not be treated as equivalent to same-repo AWS validation" in (  # nosec B101
        normalized_doc
    )
    assert "not an acceptable skip for a same-repo infrastructure PR" in normalized_doc  # nosec B101
    assert "branch-protection owner" in normalized_doc  # nosec B101


def test_security_scan_workflow_runs_repo_make_targets() -> None:
    """Keep the security-scan workflow easy to reproduce locally."""
    workflow = _workflow("security-scans.yml")
    jobs = workflow["jobs"]

    assert jobs["secrets"]["timeout-minutes"] == 10
    assert jobs["dependency_audit"]["timeout-minutes"] == 15
    assert jobs["actionlint"]["timeout-minutes"] == 10
    assert any(  # nosec B101
        step.get("run") == "make test-secrets" for step in jobs["secrets"]["steps"]
    )
    assert any(
        step.get("run") == "make test-deps-security"
        for step in jobs["dependency_audit"]["steps"]
    )
    assert any(
        step.get("run") == "make test-actionlint"
        for step in jobs["actionlint"]["steps"]
    )


def test_codeql_workflow_covers_python_and_github_actions() -> None:
    """Require GitHub-native code scanning for both Python and workflow code."""
    workflow = _workflow("codeql.yml")
    matrix_languages = workflow["jobs"]["analyze"]["strategy"]["matrix"]["language"]
    uses_steps = [
        step.get("uses")
        for step in workflow["jobs"]["analyze"]["steps"]
        if step.get("uses")
    ]

    assert workflow["permissions"] == {
        "actions": "read",
        "contents": "read",
        "security-events": "write",
    }
    assert workflow["concurrency"] == {
        "group": (
            "${{ github.workflow }}-"
            "${{ github.event.pull_request.number || github.ref }}"
        ),
        "cancel-in-progress": True,
    }
    assert "concurrency" not in workflow["jobs"]["analyze"]
    assert matrix_languages == ["python", "actions"]
    assert any("github/codeql-action/init@" in uses for uses in uses_steps)
    assert any("github/codeql-action/analyze@" in uses for uses in uses_steps)


def test_nightly_guardrails_workflow_covers_drift_and_scorecard() -> None:
    """Keep the scheduled guardrail workflow focused and discoverable."""
    workflow = _workflow("nightly-guardrails.yml")
    jobs = workflow["jobs"]
    triggers = _triggers(workflow)
    scorecard_uses = [
        step.get("uses") for step in jobs["scorecard"]["steps"] if step.get("uses")
    ]
    test_drift_steps = jobs["test_drift_detection"]["steps"]
    prod_drift_steps = jobs["prod_drift_detection"]["steps"]
    preflight_step = next(
        (
            step
            for step in test_drift_steps
            if step.get("name") == "Validate drift detection prerequisites"
        ),
        None,
    )

    assert "schedule" in triggers  # nosec B101
    assert "workflow_dispatch" in triggers  # nosec B101
    assert workflow["concurrency"]["cancel-in-progress"] is False  # nosec B101
    assert (  # nosec B101
        jobs["test_drift_detection"]["concurrency"]["group"]
        == "bootstrap-infrastructure-test-state"
    )
    assert (  # nosec B101
        jobs["prod_drift_detection"]["concurrency"]["group"]
        == "bootstrap-infrastructure-prod-state"
    )
    assert jobs["test_drift_detection"]["environment"] == "test"  # nosec B101
    assert jobs["prod_drift_detection"]["environment"] == "prod-preview"  # nosec B101
    expected_drift_permissions = {
        "contents": "read",
        "id-token": "write",
    }
    expected_expression = "".join(("${{ secrets.", "PULUMI_ACCESS_", "TOKEN", " }}"))
    assert jobs["test_drift_detection"]["permissions"] == expected_drift_permissions  # nosec B101
    drift_access_token = jobs["test_drift_detection"]["env"]["PULUMI_ACCESS_TOKEN"]
    assert drift_access_token == expected_expression  # nosec B101
    assert preflight_step is not None, "drift preflight step not found"  # nosec B101
    assert "AWS_DRIFT_ROLE_ARN" in preflight_step["run"]  # nosec B101
    assert "PULUMI_BACKEND_URL" in preflight_step["run"]  # nosec B101
    assert "12-digit AWS account ID" in preflight_step["run"]  # nosec B101
    assert "s3:// backend" in preflight_step["run"]  # nosec B101
    assert "awskms:// URI" in preflight_step["run"]  # nosec B101
    for drift_steps in (test_drift_steps, prod_drift_steps):
        oidc_step = next(
            step
            for step in drift_steps
            if step.get("uses", "").startswith("aws-actions/configure-aws-credentials@")
        )
        assert oidc_step["with"]["role-to-assume"] == "${{ env.AWS_DRIFT_ROLE_ARN }}"  # nosec B101
        assert oidc_step["with"]["aws-region"] == "${{ env.AWS_REGION }}"  # nosec B101
        assert oidc_step["with"]["allowed-account-ids"] == "${{ env.AWS_ACCOUNT_ID }}"  # nosec B101
        assert any(step.get("run") == "make test-drift" for step in drift_steps)  # nosec B101
    assert any("ossf/scorecard-action@" in uses for uses in scorecard_uses)  # nosec B101
    assert any("upload-sarif@" in uses for uses in scorecard_uses)  # nosec B101


def test_well_architected_evidence_workflow_uploads_advisory_reports() -> None:
    """Keep the Well-Architected evidence workflow safe while blockers remain."""
    workflow = _workflow("well-architected-evidence.yml")
    jobs = workflow["jobs"]
    triggers = _triggers(workflow)
    evidence_steps = jobs["test_account_evidence"]["steps"]
    mode_step = next(
        step
        for step in jobs["evidence_mode"]["steps"]
        if step.get("name") == "Select evidence mode"
    )
    preflight_step = next(
        step
        for step in evidence_steps
        if step.get("name") == "Validate evidence prerequisites"
    )
    oidc_step = next(
        step
        for step in evidence_steps
        if step.get("uses", "").startswith("aws-actions/configure-aws-credentials@")
    )
    checkout_step = next(
        step
        for step in evidence_steps
        if step.get("uses", "").startswith("actions/checkout@")
    )
    wait_step = next(
        step
        for step in evidence_steps
        if step.get("name") == "Wait for PR checks before evidence snapshot"
    )
    collector_step = next(
        step
        for step in evidence_steps
        if step.get("name") == "Collect Well-Architected evidence"
    )
    upload_step = next(
        step
        for step in evidence_steps
        if step.get("uses", "").startswith("actions/upload-artifact@")
    )
    enforce_step = next(
        step
        for step in evidence_steps
        if step.get("name") == "Enforce Well-Architected evidence when enabled"
    )
    unprivileged_run = next(
        step.get("run", "")
        for step in jobs["unprivileged_evidence"]["steps"]
        if step.get("name") == "Record skipped AWS evidence"
    )

    assert "pull_request" in triggers  # nosec B101
    assert triggers["push"]["branches"] == ["main"]  # nosec B101
    assert triggers["schedule"] == [{"cron": "17 6 9 * *"}]  # nosec B101
    assert "workflow_dispatch" in triggers  # nosec B101
    assert workflow["permissions"] == {"contents": "read"}  # nosec B101
    assert workflow["concurrency"]["cancel-in-progress"] is True  # nosec B101
    assert jobs["evidence_mode"]["outputs"] == {  # nosec B101
        "privileged": "${{ steps.evidence_mode.outputs.privileged }}"
    }
    assert "Fork pull request detected" in mode_step["run"]  # nosec B101
    assert jobs["test_account_evidence"]["environment"] == "test"  # nosec B101
    assert jobs["test_account_evidence"]["permissions"] == {  # nosec B101
        "contents": "read",
        "id-token": "write",
        "pull-requests": "read",
        "security-events": "read",
    }
    assert (  # nosec B101
        checkout_step["with"]["ref"]
        == "${{ github.event.pull_request.head.sha || github.sha }}"
    )
    assert checkout_step["with"]["persist-credentials"] is False  # nosec B101
    assert "expected_checks=(" in wait_step["run"]  # nosec B101
    assert "Test Account Evidence (Advisory)" not in wait_step["run"]  # nosec B101
    assert "OPERATIONS_TOPIC_ARN" in preflight_step["run"]  # nosec B101
    assert "12-digit AWS account ID" in preflight_step["run"]  # nosec B101
    assert "SNS topic ARN" in preflight_step["run"]  # nosec B101
    assert (  # nosec B101
        jobs["test_account_evidence"]["env"]["DEPENDABOT_EXCEPTION_EVIDENCE"]
        == "${{ vars.DEPENDABOT_EXCEPTION_EVIDENCE }}"
    )
    assert (  # nosec B101
        jobs["test_account_evidence"]["env"]["ALERT_ROUTE_OBSERVATION_EVIDENCE"]
        == "${{ vars.ALERT_ROUTE_OBSERVATION_EVIDENCE }}"
    )
    assert (  # nosec B101
        jobs["test_account_evidence"]["env"]["SECURITY_ACCOUNT_ATTESTATION_EVIDENCE"]
        == "${{ vars.SECURITY_ACCOUNT_ATTESTATION_EVIDENCE }}"
    )
    assert (  # nosec B101
        jobs["test_account_evidence"]["env"]["PRODUCTION_DR_OWNER_EVIDENCE"]
        == "${{ vars.PRODUCTION_DR_OWNER_EVIDENCE }}"
    )
    assert oidc_step["with"]["role-to-assume"] == "${{ env.AWS_PREVIEW_ROLE_ARN }}"  # nosec B101
    assert oidc_step["with"]["allowed-account-ids"] == "${{ env.AWS_ACCOUNT_ID }}"  # nosec B101
    assert "uv==0.9.21" in " ".join(  # nosec B101
        step.get("run", "") for step in evidence_steps
    )
    assert "make report-well-architected-evidence" in collector_step["run"]  # nosec B101
    assert "make verify-well-architected-questions" in collector_step["run"]  # nosec B101
    assert "make report-well-architected-closeout" in collector_step["run"]  # nosec B101
    assert "owner-closeout-bundle.md" in collector_step["run"]  # nosec B101
    assert "Well-Architected Closeout Audit" in collector_step["run"]  # nosec B101
    assert "GITHUB_STEP_SUMMARY" in collector_step["run"]  # nosec B101
    assert "exit 1" not in collector_step["run"]  # nosec B101
    assert upload_step["with"]["name"] == "well-architected-evidence"  # nosec B101
    assert upload_step["with"]["path"] == ".artifacts/well-architected"  # nosec B101
    assert upload_step["with"]["retention-days"] == 90  # nosec B101
    assert "github.event_name != 'schedule'" in enforce_step["if"]  # nosec B101
    assert "WELL_ARCHITECTED_EVIDENCE_ENFORCE" in enforce_step["if"]  # nosec B101
    assert "exit 1" in enforce_step["run"]  # nosec B101
    assert "credentials are unavailable to untrusted forks" in unprivileged_run  # nosec B101


def test_new_guardrail_scripts_and_configs_are_present() -> None:
    """Keep the repo-local building blocks for CI guardrails discoverable."""
    preview_text = PREVIEW_SCRIPT.read_text(encoding="utf-8")
    preview_summary_text = PREVIEW_SUMMARY_SCRIPT.read_text(encoding="utf-8")
    drift_text = DRIFT_SCRIPT.read_text(encoding="utf-8")
    dockerfile_text = (PROJECT_ROOT / "Dockerfile").read_text(encoding="utf-8")

    assert GITLEAKS_CONFIG.exists()  # nosec B101
    assert PREVIEW_SUMMARY_SCRIPT.exists()  # nosec B101
    assert "gh auth token" not in preview_text  # nosec B101
    assert '"pulumi"' in preview_text  # nosec B101
    assert '"-C"' in preview_text  # nosec B101
    assert '"login"' in preview_text  # nosec B101
    assert '"--non-interactive"' in preview_text  # nosec B101
    assert "PULUMI_REQUIRE_SHARED_BACKEND" in preview_summary_text  # nosec B101
    assert '"make", "test-preview"' in preview_summary_text  # nosec B101
    assert "GITHUB_STEP_SUMMARY" in preview_summary_text  # nosec B101
    assert '"preview"' in preview_text  # nosec B101
    assert '"--stack"' in preview_text  # nosec B101
    assert '"summarize"' in preview_text  # nosec B101
    assert '"login"' in drift_text  # nosec B101
    assert "PULUMI_DIR '" in drift_text  # nosec B101
    assert "does not exist" in drift_text  # nosec B101
    assert "Checking drift for stack" in drift_text  # nosec B101
    assert "expect-no-changes" in drift_text  # nosec B101
    assert "ARG TARGETARCH=amd64" not in dockerfile_text  # nosec B101
    assert "actionlint" in dockerfile_text  # nosec B101
    assert "gitleaks" in dockerfile_text  # nosec B101


def test_guardrail_docs_are_indexed_from_root_docs() -> None:
    """Require operator docs for the new CI safety layer."""
    docs_index = (PROJECT_ROOT / "docs" / "README.md").read_text(encoding="utf-8")
    root_readme = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
    content = GUARDRAILS_DOC.read_text(encoding="utf-8")

    assert GUARDRAILS_DOC.exists()  # nosec B101
    assert "ci-guardrails.md" in docs_index  # nosec B101
    assert "docs/ci-guardrails.md" in root_readme  # nosec B101
    assert "AWS_PREVIEW_ROLE_ARN" in content  # nosec B101
    assert "prod-preview" in content  # nosec B101
    assert "required reviewers" in content  # nosec B101
    assert "allow-destructive-infra-change" in content  # nosec B101
    assert "CodeQL" in content  # nosec B101
    assert "Gitleaks" in content  # nosec B101


def test_new_workflows_keep_actions_pinned_to_full_shas() -> None:
    """Avoid drifting back to mutable action tags in the new workflows."""
    for workflow_name in (
        "pulumi-pr-guardrails.yml",
        "security-scans.yml",
        "codeql.yml",
        "nightly-guardrails.yml",
        "well-architected-evidence.yml",
        "pulumi-prod.yml",
        "pulumi-test-deploy.yml",
    ):
        workflow = _workflow(workflow_name)
        for job in workflow["jobs"].values():
            for step in job.get("steps", []):
                uses = step.get("uses")
                if uses is None:
                    continue
                assert ACTION_SHA_REF.match(uses), (
                    f"{workflow_name} must pin `{uses}` to a full commit SHA"
                )
