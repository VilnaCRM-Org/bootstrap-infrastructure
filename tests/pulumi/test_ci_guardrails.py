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
    destructive_diff_if = "${{ always() && needs.preview.result == 'success' }}"
    destructive_diff_runs = [
        step.get("run") for step in jobs["destructive_diff"]["steps"] if step.get("run")
    ]
    preview_mode_step = next(
        (
            step
            for step in jobs["preview"]["steps"]
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
    preview_download_step = next(
        (
            step
            for step in jobs["destructive_diff"]["steps"]
            if step.get("name") == "Download preview artifact"
        ),
        None,
    )
    iam_mode_step = next(
        (
            step
            for step in jobs["iam_validation"]["steps"]
            if step.get("name") == "Select IAM validation mode"
        ),
        None,
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
    iam_validation_run_lines = {
        line.strip() for line in iam_validation_run.splitlines()
    }
    destructive_diff_job_if = " ".join(jobs["destructive_diff"]["if"].split())

    assert workflow["concurrency"]["cancel-in-progress"] is True
    assert "if" not in jobs["preview"]  # nosec B101
    assert jobs["preview"]["permissions"] == {
        "contents": "read",
        "id-token": "write",
    }
    assert "if" not in jobs["iam_validation"]  # nosec B101
    assert destructive_diff_job_if == destructive_diff_if  # nosec B101
    assert jobs["destructive_diff"]["needs"] == ["preview"]  # nosec B101
    assert jobs["iam_validation"]["needs"] == ["preview"]  # nosec B101
    assert preview_mode_step is not None  # nosec B101
    assert "AWS_OIDC_ROLE_ARN" in preview_mode_step["run"]  # nosec B101
    assert "PULUMI_SECRETS_PROVIDER" in preview_mode_step["run"]  # nosec B101
    assert "PULUMI_ALLOW_UNPRIVILEGED_PR_GUARDRAILS" in preview_mode_step["run"]  # nosec B101
    assert iam_mode_step is not None  # nosec B101
    assert "AWS_OIDC_ROLE_ARN" in iam_mode_step["run"]  # nosec B101
    assert "PULUMI_SECRETS_PROVIDER" in iam_mode_step["run"]  # nosec B101
    assert "PULUMI_ALLOW_UNPRIVILEGED_PR_GUARDRAILS" in iam_mode_step["run"]  # nosec B101
    assert preview_oidc_step is not None, "preview OIDC step not found"
    assert iam_oidc_step is not None, "IAM validation OIDC step not found"
    assert preview_run_step is not None, "preview run step not found"
    assert preview_upload_step is not None, "preview artifact upload step not found"
    assert preview_upload_step["with"]["name"] == "pulumi-preview"
    assert (  # nosec B101
        preview_oidc_step["if"]
        == "${{ steps.preview_mode.outputs.privileged == 'true' }}"
    )
    assert iam_oidc_step["if"] == "${{ steps.iam_mode.outputs.privileged == 'true' }}"  # nosec B101
    assert "make publish-pulumi-preview-summary" in preview_run_step["run"]  # nosec B101
    assert "make test-preview-unprivileged" in preview_run_step["run"]  # nosec B101
    assert preview_run_step["env"] == {  # nosec B101
        "PULUMI_REQUIRE_SHARED_BACKEND": (
            "${{ steps.preview_mode.outputs.privileged }}"
        ),
        "GITHUB_TOKEN": "${{ github.token }}",
    }
    assert any(step.get("run") == "make start" for step in jobs["preview"]["steps"])
    assert preview_download_step is not None
    assert preview_download_step["with"]["name"] == "pulumi-preview"
    assert iam_download_step is not None
    assert iam_download_step["with"]["name"] == "pulumi-preview"
    assert any(
        step.get("run") == "make test-destructive-diff"
        for step in jobs["destructive_diff"]["steps"]
    )
    assert any(
        'cp "${GITHUB_EVENT_PATH}" .artifacts/github-event.json' in run
        for run in destructive_diff_runs
    )
    assert "make test-iam-validation" in iam_validation_run_lines  # nosec B101
    assert "make test-iam-validation-unprivileged" in iam_validation_run_lines  # nosec B101


def test_security_scan_workflow_runs_repo_make_targets() -> None:
    """Keep the security-scan workflow easy to reproduce locally."""
    workflow = _workflow("security-scans.yml")
    jobs = workflow["jobs"]

    assert jobs["secrets"]["timeout-minutes"] == 10
    assert jobs["dependency_audit"]["timeout-minutes"] == 15
    assert jobs["actionlint"]["timeout-minutes"] == 10
    assert any(
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
    drift_steps = jobs["drift_detection"]["steps"]
    preflight_step = next(
        (
            step
            for step in drift_steps
            if step.get("name") == "Validate drift detection prerequisites"
        ),
        None,
    )

    assert "schedule" in triggers
    assert "workflow_dispatch" in triggers
    assert workflow["concurrency"]["cancel-in-progress"] is False
    assert jobs["drift_detection"]["permissions"] == {
        "contents": "read",
        "id-token": "write",
    }
    assert (
        jobs["drift_detection"]["env"]["PULUMI_ACCESS_TOKEN"]
        == "${{ secrets.PULUMI_ACCESS_TOKEN }}"
    )
    assert preflight_step is not None, "drift preflight step not found"
    assert "vars.AWS_OIDC_ROLE_ARN" in preflight_step["run"]
    assert "vars.PULUMI_BACKEND_URL" in preflight_step["run"]
    assert any(step.get("run") == "make test-drift" for step in drift_steps)
    assert any("ossf/scorecard-action@" in uses for uses in scorecard_uses)
    assert any("upload-sarif@" in uses for uses in scorecard_uses)


def test_new_guardrail_scripts_and_configs_are_present() -> None:
    """Keep the repo-local building blocks for CI guardrails discoverable."""
    preview_text = PREVIEW_SCRIPT.read_text(encoding="utf-8")
    preview_summary_text = PREVIEW_SUMMARY_SCRIPT.read_text(encoding="utf-8")
    drift_text = DRIFT_SCRIPT.read_text(encoding="utf-8")
    dockerfile_text = (PROJECT_ROOT / "Dockerfile").read_text(encoding="utf-8")

    assert GITLEAKS_CONFIG.exists()
    assert PREVIEW_SUMMARY_SCRIPT.exists()
    assert "gh auth token" not in preview_text
    assert '"pulumi"' in preview_text
    assert '"--cwd"' in preview_text
    assert '"login"' in preview_text
    assert '"--non-interactive"' in preview_text
    assert "PULUMI_REQUIRE_SHARED_BACKEND" in preview_summary_text
    assert '"make", "test-preview"' in preview_summary_text
    assert "GITHUB_STEP_SUMMARY" in preview_summary_text
    assert '"preview"' in preview_text
    assert '"--stack"' in preview_text
    assert '"summarize"' in preview_text
    assert '"login"' in drift_text
    assert "PULUMI_DIR '" in drift_text
    assert "does not exist" in drift_text
    assert "Checking drift for stack" in drift_text
    assert "expect-no-changes" in drift_text
    assert "ARG TARGETARCH=amd64" not in dockerfile_text
    assert "actionlint" in dockerfile_text
    assert "gitleaks" in dockerfile_text


def test_guardrail_docs_are_indexed_from_root_docs() -> None:
    """Require operator docs for the new CI safety layer."""
    docs_index = (PROJECT_ROOT / "docs" / "README.md").read_text(encoding="utf-8")
    root_readme = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
    content = GUARDRAILS_DOC.read_text(encoding="utf-8")

    assert GUARDRAILS_DOC.exists()
    assert "ci-guardrails.md" in docs_index
    assert "docs/ci-guardrails.md" in root_readme
    assert "AWS_OIDC_ROLE_ARN" in content
    assert "<BRANCH_REF>" in content
    assert "allowed branch" in content
    assert "allow-destructive-infra-change" in content
    assert "CodeQL" in content
    assert "Gitleaks" in content


def test_new_workflows_keep_actions_pinned_to_full_shas() -> None:
    """Avoid drifting back to mutable action tags in the new workflows."""
    for workflow_name in (
        "pulumi-pr-guardrails.yml",
        "security-scans.yml",
        "codeql.yml",
        "nightly-guardrails.yml",
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
