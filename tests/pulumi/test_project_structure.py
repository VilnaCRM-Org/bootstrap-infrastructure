import ast
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
        "managedRepositoryProjects",
        "managedRepositoryMetadata",
        "backupVaultName",
        "backupVaultArn",
        "operationsAlertTopicArn",
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
    assert not (ROOT / ".qlty").exists()  # nosec B101
    assert not (ROOT / ".importlinter").exists()  # nosec B101
    assert not (ROOT / "policy_pack").exists()  # nosec B101
    assert not (ROOT / ".github" / "workflows" / "devsecops-guardrails.yml").exists()  # nosec B101
    assert not (ROOT / ".github" / "workflows" / "pulumi-preview.yml").exists()  # nosec B101
    assert not (ROOT / ".github" / "workflows" / "pulumi.yml").exists()  # nosec B101
