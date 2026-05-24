import ast
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
LEGACY_PULUMI_PASSPHRASE_ENV = "_".join(("PULUMI", "CONFIG", "PASSPHRASE"))


def test_pulumi_project_manifest_uses_python_runtime() -> None:
    manifest = yaml.safe_load((ROOT / "pulumi" / "Pulumi.yaml").read_text())
    assert manifest["name"] == "bootstrap-infrastructure"  # nosec B101
    assert manifest["runtime"]["name"] == "python"  # nosec B101
    assert "options" not in manifest["runtime"]  # nosec B101


def test_example_stack_file_avoids_legacy_passphrase_metadata() -> None:
    stack_text = (ROOT / "pulumi" / "Pulumi.example.yaml").read_text()

    assert "encryptionsalt" not in stack_text  # nosec B101
    assert LEGACY_PULUMI_PASSPHRASE_ENV not in stack_text  # nosec B101


def test_multi_account_stack_files_use_test_and_prod_contract() -> None:
    """Require real environment stacks while keeping examples out of discovery."""
    stack_file_names = {path.name for path in (ROOT / "pulumi").glob("Pulumi.*.yaml")}

    assert "Pulumi.test.yaml" in stack_file_names  # nosec B101
    assert "Pulumi.prod.yaml" in stack_file_names  # nosec B101
    assert "Pulumi.example.yaml" in stack_file_names  # nosec B101
    assert "Pulumi.dev.yaml" not in stack_file_names  # nosec B101


def test_multi_account_stack_files_are_non_secret() -> None:
    """Committed shared stack files should contain non-secret config only."""
    for stack_file in ("Pulumi.test.yaml", "Pulumi.prod.yaml"):
        stack_text = (ROOT / "pulumi" / stack_file).read_text()
        stack_config = yaml.safe_load(stack_text)

        assert "secure:" not in stack_text  # nosec B101
        assert "encryptedkey" not in stack_text  # nosec B101
        assert "encryptionsalt" not in stack_text  # nosec B101
        assert LEGACY_PULUMI_PASSPHRASE_ENV not in stack_text  # nosec B101
        assert "--secrets-provider" in stack_text  # nosec B101
        assert stack_config["secretsprovider"].startswith("awskms://")  # nosec B101


def test_multi_account_stack_replication_regions_match_policy_allowlist() -> None:
    """Committed stack defaults must pass the repository region guardrail."""
    policy_config = yaml.safe_load(
        (ROOT / "policy" / "vilnacrm_guardrails.yaml").read_text()
    )
    allowed_regions = set(policy_config["allowed_regions"])

    for stack_file in ("Pulumi.test.yaml", "Pulumi.prod.yaml"):
        config = yaml.safe_load((ROOT / "pulumi" / stack_file).read_text())["config"]
        primary_region = config["aws:region"]
        replication_region = config["bootstrap-infrastructure:replicationRegion"]

        assert primary_region in allowed_regions  # nosec B101
        assert replication_region in allowed_regions  # nosec B101
        assert replication_region != primary_region  # nosec B101


def test_committed_stack_discovery_ignores_example_stack_file() -> None:
    script_support = (ROOT / "scripts" / "_script_support.py").read_text()

    assert '"Pulumi.example.yaml"' in script_support  # nosec B101


def test_makefile_exposes_current_ci_targets() -> None:
    makefile = (ROOT / "Makefile").read_text()
    for target in (
        "publish-pulumi-preview-summary",
        "pulumi-preview",
        "pulumi-plan",
        "pulumi-up",
        "pulumi-up-plan",
        "test-pulumi",
        "test-policy",
        "test-crossguard",
        "test-quality",
        "test-repo-hygiene",
        "test-repository-catalogs",
        "test-repository-fanout",
        "test-security",
        "test-guardrails",
        "test-guardrails-unprivileged",
        "test-unit",
        "test-integration",
        "test-integration-unprivileged",
        "test-coverage",
        "test-preview-unprivileged",
        "test-cost-proxy",
        "test-iam-validation-unprivileged",
        "test-mutation",
        "test-cli",
        "ci-pr",
        "ci-pr-unprivileged",
        "ci",
        "nightly-quality",
    ):
        assert target in makefile  # nosec B101


def test_deploy_stack_exports_bootstrap_outputs() -> None:
    main_tree = ast.parse((ROOT / "pulumi" / "__main__.py").read_text())
    exported_names = {
        node.args[0].value
        for node in ast.walk(main_tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "pulumi"
        and node.func.attr == "export"
        and node.args
        and isinstance(node.args[0], ast.Constant)
        and isinstance(node.args[0].value, str)
    }

    for export_name in (
        "centralLogBucket",
        "centralLogBucketArn",
        "pulumiStateBuckets",
        "pulumiBackendUrls",
        "pulumiSecretsKeyArns",
        "pulumiSecretsAliases",
        "pulumiSecretsProviderUrls",
        "deployRoleArns",
        "ciConfigurationSecretIds",
        "ciConfigurationSecretArns",
        "pulumiEscSecretsReadRoleArn",
        "managedRepositoryProjects",
        "managedRepositoryMetadata",
        "backupVaultName",
        "backupVaultArn",
        "backupRoleArn",
        "operationsAlertTopicArn",
        "operationsCloudTrailBucketName",
        "operationsCloudTrailName",
        "operationsAlertRuleNames",
        "operationsAlertTopicKeyAliasName",
        "operationsAlertQueueArn",
        "operationsAlertQueueName",
        "operationsAlertQueueUrl",
        "operationsAlertQueueSubscriptionArn",
        "monthlyBudgetName",
        "costAnomalyMonitorArn",
        "costAnomalySubscriptionArn",
        "automationRoleArn",
        "operationsAlertTriageRoleArn",
        "runnerRepositoryName",
        "runnerRepositoryUrl",
    ):
        assert export_name in exported_names  # nosec B101


def test_repository_uses_current_python_tooling_contract() -> None:
    pyproject = (ROOT / "pyproject.toml").read_text()
    assert "[project]" in pyproject  # nosec B101
    assert "[dependency-groups]" in pyproject  # nosec B101
    assert "[tool.ruff]" in pyproject  # nosec B101
    assert (ROOT / "uv.lock").exists()  # nosec B101
    assert not (ROOT / "poetry.lock").exists()  # nosec B101


def test_quality_workflows_cover_current_local_targets() -> None:
    quality = (ROOT / ".github" / "workflows" / "python-quality.yml").read_text()

    for target in (
        "make test-ruff",
        "make test-ty",
        "make test-maintainability",
        "make test-architecture",
        "make test-dependency-hygiene",
        "make test-coverage",
    ):
        assert target in quality  # nosec B101


def test_security_workflows_cover_current_local_targets() -> None:
    security = (ROOT / ".github" / "workflows" / "security-scans.yml").read_text()

    for target in (
        "make test-secrets",
        "make test-deps-security",
        "make test-bandit",
        "make test-actionlint",
        "make test-yaml",
        "make test-dockerfile",
    ):
        assert target in security  # nosec B101


def test_pulumi_workflows_cover_current_local_targets() -> None:
    structural = (ROOT / ".github" / "workflows" / "pulumi-structural.yml").read_text()
    unit = (ROOT / ".github" / "workflows" / "pulumi-unit.yml").read_text()
    integration = (
        ROOT / ".github" / "workflows" / "pulumi-integration.yml"
    ).read_text()
    mutation = (ROOT / ".github" / "workflows" / "pulumi-mutation.yml").read_text()
    bats = (ROOT / ".github" / "workflows" / "bats-tests.yml").read_text()
    policy = (ROOT / ".github" / "workflows" / "pulumi-policy.yml").read_text()
    guardrails = (
        ROOT / ".github" / "workflows" / "pulumi-pr-guardrails.yml"
    ).read_text()
    local_battery = (ROOT / ".github" / "workflows" / "pulumi-local.yml").read_text()

    assert "make test-pulumi" in structural  # nosec B101
    assert "make test-repository-catalogs" in structural  # nosec B101
    assert "make test-repository-fanout" in structural  # nosec B101
    assert "make test-unit" in unit  # nosec B101
    assert "make test-integration" in integration  # nosec B101
    assert "make test-mutation" in mutation  # nosec B101
    assert "make test-cli" in bats  # nosec B101
    assert "make test-policy" in policy  # nosec B101
    assert "make publish-pulumi-preview-summary" in guardrails  # nosec B101
    assert "make test-destructive-diff" in guardrails  # nosec B101
    assert "make test-cost-proxy" in guardrails  # nosec B101
    assert "make test-iam-validation" in guardrails  # nosec B101
    assert "make ci-pr" in local_battery  # nosec B101


def test_nightly_workflows_cover_current_local_targets() -> None:
    nightly_quality = (
        ROOT / ".github" / "workflows" / "nightly-quality.yml"
    ).read_text()
    nightly_guardrails = (
        ROOT / ".github" / "workflows" / "nightly-guardrails.yml"
    ).read_text()
    codeql = (ROOT / ".github" / "workflows" / "codeql.yml").read_text()

    assert "make report-maintainability-trends" in nightly_quality  # nosec B101
    assert "make report-dead-code" in nightly_quality  # nosec B101
    assert "make report-docstrings" in nightly_quality  # nosec B101
    assert "make report-sbom" in nightly_quality  # nosec B101
    assert "make test-drift" in nightly_guardrails  # nosec B101
    assert "scorecard-action" in nightly_guardrails  # nosec B101
    assert "name: CodeQL" in codeql  # nosec B101
    assert "pull_request:" in codeql  # nosec B101


def test_docs_cover_current_testing_and_guardrail_guidance() -> None:
    docs_index = (ROOT / "docs" / "README.md").read_text()
    ci_doc = (ROOT / "docs" / "ci-guardrails.md").read_text()
    operations_doc = (ROOT / "docs" / "sre-operations.md").read_text()
    testing_doc = (ROOT / "docs" / "testing.md").read_text()

    for doc_name in (
        "ci-quality-gates.md",
        "ci-guardrails.md",
        "ci-architecture.md",
        "cost-performance-sustainability.md",
        "pulumi-guardrails.md",
        "security-baseline.md",
        "sre-operations.md",
        "testing.md",
    ):
        assert doc_name in docs_index  # nosec B101

    for phrase in (
        "make test-security",
        "make test-repo-hygiene",
        "make test-guardrails",
        "IAM Access Analyzer",
        "CodeQL",
        "CrossGuard",
    ):
        assert phrase in ci_doc  # nosec B101

    migration_doc = f"{docs_index}\n{operations_doc}"
    for phrase in (
        "replica-region migration",
        "Replica Region Migration",
        "bootstrap-infrastructure:replicationRegion: us-east-1",
        "manual replica drain",
        "pulumi/infra/pulumi_state.py",
        "pulumi/infra/logging_bucket.py",
    ):
        if phrase not in migration_doc:
            raise AssertionError(f"missing migration guidance phrase: {phrase}")

    for phrase in (
        "make test-pulumi",
        "make test-repository-catalogs",
        "make test-policy",
        "make test-quality",
        "make test-repo-hygiene",
        "make test-unit",
        "make test-integration",
        "make test-mutation",
        "make test-cli",
        "make ci-pr",
        "make ci",
        "make pulumi-preview",
        "make pulumi-up",
    ):
        assert phrase in testing_doc  # nosec B101


def test_alert_route_docs_keep_queue_depth_observation_only() -> None:
    """Avoid baking volatile SQS queue depth into retained review evidence."""
    alert_doc = (ROOT / "docs" / "alert-routing-evidence.md").read_text()
    operating_doc = (ROOT / "docs" / "operating-review-2026-05-09.md").read_text()
    reconcile_workflow = yaml.safe_load(
        (ROOT / ".github" / "workflows" / "operations-alert-reconcile.yml").read_text()
    )
    reconcile_triggers = reconcile_workflow.get("on", reconcile_workflow.get(True, {}))
    reconcile_run = reconcile_workflow["jobs"]["reconcile"]["steps"][0]["run"]
    docs = f"{alert_doc}\n{operating_doc}"

    assert "observation-only metadata" in alert_doc  # nosec B101
    assert "Legacy operations-alert issues" in alert_doc  # nosec B101
    assert "workflow searches issue bodies for the marker" in alert_doc  # nosec B101
    assert "Operations Alert Legacy Reconcile" in alert_doc  # nosec B101
    assert "operations-alert-reconcile" in alert_doc  # nosec B101
    assert (
        "I confirm these legacy issues match the canonical operations alert stream"
        in alert_doc
    )  # nosec B101
    assert "stable SNS/SQS route metadata" in operating_doc  # nosec B101
    assert "ApproximateNumberOfMessages=" not in docs  # nosec B101
    assert "two visible messages" not in docs  # nosec B101
    assert "workflow_dispatch" in reconcile_triggers  # nosec B101
    assert reconcile_workflow["jobs"]["reconcile"]["environment"] == (  # nosec B101
        "operations-alert-reconcile"
    )
    assert reconcile_workflow["permissions"] == {  # nosec B101
        "contents": "read",
        "issues": "write",
    }
    assert "id-token" not in reconcile_workflow["permissions"]  # nosec B101
    assert "operations-alert:fingerprint=" in reconcile_run  # nosec B101
    assert reconcile_workflow["jobs"]["reconcile"]["steps"][0]["shell"] == "bash"  # nosec B101
    assert "GH_REPO: ${{ github.repository }}" in yaml.safe_dump(  # nosec B101
        reconcile_workflow["jobs"]["reconcile"]["env"]
    )
    assert '--repo "${GH_REPO}"' in reconcile_run  # nosec B101
    assert "declare -A seen_issues" in reconcile_run  # nosec B101
    assert "legacy_issue_ids" in reconcile_run  # nosec B101
    assert "provide at least one legacy issue number" in reconcile_run  # nosec B101
    assert "gh issue close" in reconcile_run  # nosec B101
    assert "--duplicate-of" in reconcile_run  # nosec B101


def test_ci_guardrails_manual_follow_up_completes_esc_cutover() -> None:
    """Keep the issue 20 operator checklist aligned with the cleanup path."""
    ci_guardrails = (ROOT / "docs" / "ci-guardrails.md").read_text()

    assert "apply the Pulumi test and production stacks" in ci_guardrails  # nosec B101
    assert "AWS Secrets Manager values projected by the Pulumi" in ci_guardrails  # nosec B101
    assert "fn::open::aws-secrets" in ci_guardrails  # nosec B101
    assert "GitHub Environment Legacy Variable Cleanup" in ci_guardrails  # nosec B101
    assert "GH_ENVIRONMENT_ADMIN_TOKEN" in ci_guardrails  # nosec B101
    assert "no stale AWS trust subjects" in ci_guardrails  # nosec B101
    assert "protected `prod` approval boundary" in ci_guardrails  # nosec B101
    assert "operations-alert-reconcile" in ci_guardrails  # nosec B101


def test_issue20_closeout_evidence_tracks_external_manual_steps() -> None:
    """Keep current issue 20 closeout evidence explicit and secret-safe."""
    closeout = (
        ROOT
        / "specs"
        / "issue-20-pulumi-esc-ci-config"
        / "current-closeout-evidence-2026-05-25.md"
    ).read_text()

    for phrase in (
        "AWS Secrets Manager remains the source of truth",
        "Pulumi ESC is the fixed projection and OIDC layer",
        "invalid organization vilnacrm-org",
        "InvalidClientTokenId",
        "ResourceNotFoundException",
        "NoSuchEntityException",
        "canonical fingerprinted issue",
        "SRE confirms",
        "Manual secure setup required",
        "Generated BMAD/BMALPH/Ralph framework state remains intentionally uncommitted",
    ):
        assert phrase in closeout  # nosec B101

    for issue in ("#20", "#49", "#50", "#52", "#53", "#54", "#55", "#56"):
        assert issue in closeout  # nosec B101

    assert "No secret values" in closeout  # nosec B101
    assert "SecretAccessKey" not in closeout  # nosec B101


def test_github_environment_cleanup_is_manual_and_guarded() -> None:
    """Keep post-ESC GitHub Environment cleanup explicit and non-AWS."""
    cleanup_workflow = yaml.safe_load(
        (
            ROOT / ".github" / "workflows" / "github-environment-legacy-cleanup.yml"
        ).read_text()
    )
    cleanup_triggers = cleanup_workflow.get("on", cleanup_workflow.get(True, {}))
    cleanup_run = cleanup_workflow["jobs"]["cleanup"]["steps"][0]["run"]
    setup_doc = (ROOT / "docs" / "github-actions-secrets.md").read_text()

    assert "workflow_dispatch" in cleanup_triggers  # nosec B101
    assert cleanup_workflow["permissions"] == {  # nosec B101
        "contents": "read",
    }
    assert "actions" not in cleanup_workflow["permissions"]  # nosec B101
    assert "id-token" not in cleanup_workflow["permissions"]  # nosec B101
    assert cleanup_triggers["workflow_dispatch"]["inputs"]["dry_run"][  # nosec B101
        "default"
    ]
    assert cleanup_workflow["jobs"]["cleanup"]["steps"][0]["shell"] == "bash"  # nosec B101
    assert "GH_ENVIRONMENT_ADMIN_TOKEN" in cleanup_run  # nosec B101
    assert "github.token" not in yaml.safe_dump(cleanup_workflow)  # nosec B101
    assert "legacy GitHub Environment variables can be removed" in cleanup_run  # nosec B101
    assert "gh variable delete" in cleanup_run  # nosec B101
    assert '--env "${environment_name}"' in cleanup_run  # nosec B101
    assert "AWS_ACCOUNT_ID" in cleanup_run  # nosec B101
    assert "AWS_OPERATIONS_ALERT_TRIAGE_ROLE_ARN" in cleanup_run  # nosec B101
    assert "PULUMI_BACKEND_URL" in cleanup_run  # nosec B101
    assert "PULUMI_PR_BACKEND_URL" in cleanup_run  # nosec B101
    assert "PULUMI_PR_PREVIEW_STACKS" in cleanup_run  # nosec B101
    assert "remaining_names" in cleanup_run  # nosec B101
    assert "GitHub Environment Legacy Variable Cleanup" in setup_doc  # nosec B101
    assert "repository **Environments** write permission" in setup_doc  # nosec B101
    assert "`PULUMI_PR_*`" in setup_doc  # nosec B101
    assert "dry_run=false" in setup_doc  # nosec B101


def test_completion_audit_avoids_self_stale_exact_head_metadata() -> None:
    """Keep the tracked audit from invalidating itself on every commit."""
    audit_doc = (
        ROOT
        / "specs"
        / "issue-17-well-architected-5-of-5"
        / "completion-audit-2026-05-10.md"
    ).read_text()

    assert "Current collector state" in audit_doc  # nosec B101
    assert "Latest audited collector head" not in audit_doc  # nosec B101
    assert "Latest audited collector timestamp" not in audit_doc  # nosec B101
    assert re.search(r"\b[0-9a-f]{40}\b", audit_doc) is None  # nosec B101


def test_repository_tracks_current_policy_and_guardrail_support_files() -> None:
    policy_dir = ROOT / "policy"
    scripts_dir = ROOT / "scripts"

    assert (policy_dir / "PulumiPolicy.yaml").exists()  # nosec B101
    assert (policy_dir / "__main__.py").exists()  # nosec B101
    assert (policy_dir / "guardrails.py").exists()  # nosec B101
    assert (ROOT / ".gitleaks.toml").exists()  # nosec B101
    assert (ROOT / ".yamllint.yml").exists()  # nosec B101
    assert (ROOT / ".hadolint.yaml").exists()  # nosec B101
    assert (scripts_dir / "_script_support.py").exists()  # nosec B101
    assert (scripts_dir / "prepare_docker_context.py").exists()  # nosec B101
    assert (scripts_dir / "prepare_policy_pack.py").exists()  # nosec B101
    assert (scripts_dir / "pulumi_ci_guardrails.py").exists()  # nosec B101
    assert (scripts_dir / "run_pulumi_preview.py").exists()  # nosec B101
    assert (scripts_dir / "run_pulumi_drift_check.py").exists()  # nosec B101
    assert (scripts_dir / "validate_repository_catalogs.py").exists()  # nosec B101
    assert (ROOT / "pulumi" / "repositories.schema.json").exists()  # nosec B101


def test_bmad_bmalph_planning_uses_specs_directory() -> None:
    specs_dir = ROOT / "specs"
    agent_instructions = (ROOT / "AGENTS.md").read_text()
    gitignore = (ROOT / ".gitignore").read_text()
    planning_doc_names = {
        "architecture.md",
        "epics.md",
        "implementation-readiness-report.md",
        "prd.md",
        "well-architected-review.md",
    }

    assert specs_dir.is_dir()  # nosec B101
    assert planning_doc_names <= {path.name for path in specs_dir.rglob("*.md")}  # nosec B101

    for phrase in (
        "Keep BMAD and BMALPH planning artifacts under `specs/`.",
        "specs/<issue-or-feature-slug>/",
        "output_folder: specs",
        "planning_artifacts: specs",
        "Do not commit generated BMAD/BMALPH/Ralph framework or state files",
        "Do not commit alternate planning roots",
    ):
        assert phrase in agent_instructions  # nosec B101

    for ignored_path in (
        "_bmad/",
        "_bmad-output/",
        "bmalph/",
        ".ralph/",
        ".bmad/",
        ".bmad-core/",
        ".agents/skills/bmad-*/",
    ):
        assert ignored_path in gitignore  # nosec B101

    for forbidden_root in (
        "_bmad",
        "_bmad-output",
        "bmalph",
        ".ralph",
        "docs/planning",
        "planning",
        ".bmad",
        ".bmad-core",
    ):
        assert not (ROOT / forbidden_root).exists()  # nosec B101

    bmad_skill_dirs = list((ROOT / ".agents" / "skills").glob("bmad-*"))
    assert bmad_skill_dirs == []  # nosec B101


def test_removed_legacy_scaffold_paths_stay_absent() -> None:
    assert not (ROOT / ".importlinter").exists()  # nosec B101
    assert not (ROOT / "policy_pack").exists()  # nosec B101
    assert not (ROOT / ".github" / "workflows" / "devsecops-guardrails.yml").exists()  # nosec B101
    assert not (ROOT / ".github" / "workflows" / "pulumi-preview.yml").exists()  # nosec B101
    assert not (ROOT / ".github" / "workflows" / "pulumi.yml").exists()  # nosec B101


def test_qlty_cloud_uses_committed_repository_config() -> None:
    assert (ROOT / ".qlty" / "qlty.toml").is_file()  # nosec B101
    assert (ROOT / ".qlty" / ".gitignore").is_file()  # nosec B101
