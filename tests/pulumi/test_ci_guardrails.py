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
ACTIONLINT_CONFIG = PROJECT_ROOT / ".github" / "actionlint.yaml"
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
    preview_ci_config_step = next(
        step
        for step in jobs["preview"]["steps"]
        if step.get("uses")
        == (
            "VilnaCRM-Org/bootstrap-infrastructure/.github/actions/load-aws-ci-env"
            "@d1297f1f00658c351dd6b94e510b394835b13ede"
        )
    )
    iam_ci_config_step = next(
        step
        for step in jobs["iam_validation"]["steps"]
        if step.get("uses")
        == (
            "VilnaCRM-Org/bootstrap-infrastructure/.github/actions/load-aws-ci-env"
            "@d1297f1f00658c351dd6b94e510b394835b13ede"
        )
    )
    preview_ci_config_target_step = next(
        step
        for step in jobs["preview"]["steps"]
        if step.get("name") == "Select test AWS CI configuration"
    )
    iam_ci_config_target_step = next(
        step
        for step in jobs["iam_validation"]["steps"]
        if step.get("name") == "Select test AWS CI configuration"
    )
    pr_ci_environment = "${{ steps.ci_config_target.outputs.environment }}"

    assert workflow["concurrency"]["cancel-in-progress"] is True
    assert "environment" not in jobs["preview_mode"]  # nosec B101
    assert "permissions" not in jobs["preview_mode"]  # nosec B101
    assert (  # nosec B101
        jobs["preview"]["if"]
        == "${{ needs.preview_mode.outputs.privileged == 'true' }}"
    )
    assert jobs["preview"]["needs"] == ["preview_mode"]  # nosec B101
    assert "environment" not in jobs["preview"]  # nosec B101
    assert preview_ci_config_step["with"]["environment"] == pr_ci_environment  # nosec B101
    assert iam_ci_config_step["with"]["environment"] == pr_ci_environment  # nosec B101
    assert preview_ci_config_step["with"]["config-role-arn"] == (  # nosec B101
        "${{ steps.ci_config_target.outputs.config-role-arn }}"
    )
    assert iam_ci_config_step["with"]["config-role-arn"] == (  # nosec B101
        "${{ steps.ci_config_target.outputs.config-role-arn }}"
    )
    for target_step in (preview_ci_config_target_step, iam_ci_config_target_step):
        assert "AWS_TEST_PR_CI_CONFIG_ROLE_ARN" in target_step["run"]  # nosec B101
        assert "AWS_TEST_CI_CONFIG_ROLE_ARN" in target_step["run"]  # nosec B101
        assert "must be set" in target_step["run"]  # nosec B101
    assert "PULUMI_BACKEND_URL" in preview_ci_config_step["with"]["required-keys"]  # nosec B101
    assert "PULUMI_PREVIEW_STACKS" in preview_ci_config_step["with"]["required-keys"]  # nosec B101
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
    assert "environment" not in jobs["iam_validation"]  # nosec B101
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
        preview_oidc_step["with"]["role-to-assume"]
        == "${{ steps.ci_config.outputs.aws-preview-role-arn }}"
    )
    assert (  # nosec B101
        preview_oidc_step["with"]["allowed-account-ids"]
        == "${{ steps.ci_config.outputs.aws-account-id }}"
    )
    assert (  # nosec B101
        preview_oidc_step["with"]["aws-region"]
        == "${{ steps.ci_config.outputs.aws-region }}"
    )
    assert "if" not in iam_oidc_step  # nosec B101
    assert (  # nosec B101
        iam_oidc_step["with"]["role-to-assume"]
        == "${{ steps.ci_config.outputs.aws-preview-role-arn }}"
    )
    assert (  # nosec B101
        iam_oidc_step["with"]["aws-region"]
        == "${{ steps.ci_config.outputs.aws-region }}"
    )
    assert (  # nosec B101
        iam_oidc_step["with"]["allowed-account-ids"]
        == "${{ steps.ci_config.outputs.aws-account-id }}"
    )
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
    test_ci_config_step = next(
        step
        for step in test_drift_steps
        if step.get("uses") == "./.github/actions/load-aws-ci-env"
    )
    prod_ci_config_step = next(
        step
        for step in prod_drift_steps
        if step.get("uses") == "./.github/actions/load-aws-ci-env"
    )
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
    assert "environment" not in jobs["test_drift_detection"]  # nosec B101
    assert "environment" not in jobs["prod_drift_detection"]  # nosec B101
    assert test_ci_config_step["with"]["environment"] == "test"  # nosec B101
    assert prod_ci_config_step["with"]["environment"] == "prod-preview"  # nosec B101
    expected_drift_permissions = {
        "contents": "read",
        "id-token": "write",
    }
    assert jobs["test_drift_detection"]["permissions"] == expected_drift_permissions  # nosec B101
    assert jobs["test_drift_detection"]["env"] == {"PULUMI_SKIP_UPDATE_CHECK": "true"}  # nosec B101
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
        assert (  # nosec B101
            oidc_step["with"]["role-to-assume"]
            == "${{ steps.ci_config.outputs.aws-drift-role-arn }}"
        )
        assert (  # nosec B101
            oidc_step["with"]["aws-region"]
            == "${{ steps.ci_config.outputs.aws-region }}"
        )
        assert (  # nosec B101
            oidc_step["with"]["allowed-account-ids"]
            == "${{ steps.ci_config.outputs.aws-account-id }}"
        )
        assert any(step.get("run") == "make test-drift" for step in drift_steps)  # nosec B101
    assert any("ossf/scorecard-action@" in uses for uses in scorecard_uses)  # nosec B101
    assert any("upload-sarif@" in uses for uses in scorecard_uses)  # nosec B101


def test_well_architected_data_workflow_is_unprivileged_and_advisory() -> None:
    """PR data checks cannot impersonate the protected App evidence result."""
    workflow = _workflow("well-architected-evidence.yml")
    triggers = _triggers(workflow)
    assert set(triggers) == {"pull_request", "push", "schedule", "workflow_dispatch"}
    assert triggers["push"]["branches"] == ["main"]
    assert set(workflow["jobs"]) == {"evidence_data"}
    assert workflow["permissions"] == {"contents": "read"}
    job = workflow["jobs"]["evidence_data"]
    assert job["name"] == "Well-Architected Data Validation (Advisory)"
    assert job["permissions"] == {"contents": "read"}
    assert "environment" not in job
    steps = job["steps"]
    checkout = next(
        step for step in steps if step.get("uses", "").startswith("actions/checkout@")
    )
    assert checkout["with"]["persist-credentials"] is False
    commands = "\n".join(step.get("run", "") for step in steps)
    assert 'env -i HOME="$HOME" PATH="$PATH"' in commands
    assert "tests/unit/test_well_architected_evidence_data.py" in commands
    assert "--no-cov" in commands
    assert "does not grant Well-Architected acceptance" in commands
    assert "env" not in workflow and "env" not in job
    for step in steps:
        assert "env" not in step
        assert not step.get("uses", "").startswith(
            ("aws-actions/", "./", "VilnaCRM-Org/")
        )
    text = str(workflow)
    for credential in (
        "secrets.",
        "github.token",
        "id-token",
        "GH_TOKEN",
        "GITHUB_TOKEN",
        "AWS_",
    ):
        assert credential not in text
    assert "Test Account Evidence" not in {
        item["name"] for item in workflow["jobs"].values()
    }
    config = yaml.safe_load(ACTIONLINT_CONFIG.read_text())
    assert ".github/workflows/well-architected-evidence.yml" not in config.get(
        "paths", {}
    )


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
                if uses.startswith("./"):
                    continue
                assert ACTION_SHA_REF.match(uses), (
                    f"{workflow_name} must pin `{uses}` to a full commit SHA"
                )
