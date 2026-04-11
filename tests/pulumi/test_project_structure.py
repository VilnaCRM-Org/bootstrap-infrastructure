from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


def test_pulumi_project_manifest_uses_python_runtime() -> None:
    manifest = yaml.safe_load((ROOT / "pulumi" / "Pulumi.yaml").read_text())
    assert manifest["name"] == "bootstrap-infrastructure"  # nosec B101
    assert manifest["runtime"]["name"] == "python"  # nosec B101
    assert "options" not in manifest["runtime"]  # nosec B101


def test_example_stack_files_avoid_legacy_passphrase_metadata() -> None:
    for stack_file in ("Pulumi.dev.yaml", "Pulumi.example.yaml"):
        stack_text = (ROOT / "pulumi" / stack_file).read_text()
        assert "encryptionsalt" not in stack_text  # nosec B101
        assert "PULUMI_CONFIG_PASSPHRASE" not in stack_text  # nosec B101


def test_makefile_exposes_current_ci_targets() -> None:
    makefile = (ROOT / "Makefile").read_text()
    for target in (
        "publish-pulumi-preview-summary",
        "pulumi-preview",
        "pulumi-up",
        "test-pulumi",
        "test-policy",
        "test-crossguard",
        "test-quality",
        "test-repo-hygiene",
        "test-security",
        "test-guardrails",
        "test-unit",
        "test-integration",
        "test-coverage",
        "test-mutation",
        "test-cli",
        "ci-pr",
        "ci",
        "nightly-quality",
    ):
        assert target in makefile  # nosec B101


def test_deploy_stack_exports_bootstrap_outputs() -> None:
    main_text = (ROOT / "pulumi" / "__main__.py").read_text()
    for export_name in (
        "centralLogBucket",
        "pulumiBackendUrls",
        "pulumiSecretsKeyArns",
        "pulumiSecretsProviderUrls",
        "deployRoleArns",
        "automationRoleArn",
        "runnerRepositoryName",
        "runnerRepositoryUrl",
    ):
        assert f'pulumi.export("{export_name}"' in main_text  # nosec B101


def test_repository_uses_current_python_tooling_contract() -> None:
    pyproject = (ROOT / "pyproject.toml").read_text()
    assert "[project]" in pyproject  # nosec B101
    assert "[dependency-groups]" in pyproject  # nosec B101
    assert "[tool.ruff]" in pyproject  # nosec B101
    assert (ROOT / "uv.lock").exists()  # nosec B101
    assert not (ROOT / "poetry.lock").exists()  # nosec B101


def test_ci_workflows_cover_current_local_targets() -> None:
    quality = (ROOT / ".github" / "workflows" / "python-quality.yml").read_text()
    security = (ROOT / ".github" / "workflows" / "security-scans.yml").read_text()
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
    nightly_quality = (
        ROOT / ".github" / "workflows" / "nightly-quality.yml"
    ).read_text()
    nightly_guardrails = (
        ROOT / ".github" / "workflows" / "nightly-guardrails.yml"
    ).read_text()
    codeql = (ROOT / ".github" / "workflows" / "codeql.yml").read_text()

    for target in (
        "make test-ruff",
        "make test-ty",
        "make test-maintainability",
        "make test-architecture",
        "make test-dependency-hygiene",
        "make test-coverage",
    ):
        assert target in quality  # nosec B101

    for target in (
        "make test-secrets",
        "make test-deps-security",
        "make test-bandit",
        "make test-actionlint",
        "make test-yaml",
        "make test-dockerfile",
    ):
        assert target in security  # nosec B101

    assert "make test-pulumi" in structural  # nosec B101
    assert "make test-unit" in unit  # nosec B101
    assert "make test-integration" in integration  # nosec B101
    assert "make test-mutation" in mutation  # nosec B101
    assert "make test-cli" in bats  # nosec B101
    assert "make test-policy" in policy  # nosec B101
    assert "make publish-pulumi-preview-summary" in guardrails  # nosec B101
    assert "make test-destructive-diff" in guardrails  # nosec B101
    assert "make test-iam-validation" in guardrails  # nosec B101
    assert "make ci-pr" in local_battery  # nosec B101
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
    testing_doc = (ROOT / "docs" / "testing.md").read_text()

    for doc_name in (
        "ci-quality-gates.md",
        "ci-guardrails.md",
        "ci-architecture.md",
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

    for phrase in (
        "make test-pulumi",
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


def test_removed_legacy_scaffold_paths_stay_absent() -> None:
    assert not (ROOT / ".qlty").exists()  # nosec B101
    assert not (ROOT / ".importlinter").exists()  # nosec B101
    assert not (ROOT / "policy_pack").exists()  # nosec B101
    assert not (ROOT / ".github" / "workflows" / "devsecops-guardrails.yml").exists()  # nosec B101
    assert not (ROOT / ".github" / "workflows" / "pulumi-preview.yml").exists()  # nosec B101
    assert not (ROOT / ".github" / "workflows" / "pulumi.yml").exists()  # nosec B101
