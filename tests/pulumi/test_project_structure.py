from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


def test_pulumi_project_manifest_uses_python_runtime():
    manifest = yaml.safe_load((ROOT / "pulumi" / "Pulumi.yaml").read_text())
    assert manifest["name"] == "bootstrap-infrastructure"  # nosec B101
    assert manifest["runtime"]["name"] == "python"  # nosec B101
    assert "options" not in manifest["runtime"]  # nosec B101


def test_stack_file_does_not_use_encryptionsalt():
    stack_text = (ROOT / "pulumi" / "Pulumi.test.yaml").read_text()
    assert "encryptionsalt" not in stack_text  # nosec B101
    assert "pulumi-platform-bootstrap-test" in stack_text  # nosec B101


def test_makefile_exposes_full_test_matrix():
    makefile = (ROOT / "Makefile").read_text()
    assert "check-format" in makefile  # nosec B101
    assert "check-lint" in makefile  # nosec B101
    assert "check-radon" in makefile  # nosec B101
    assert "check-xenon" in makefile  # nosec B101
    assert "check-imports" in makefile  # nosec B101
    assert "check-deptry" in makefile  # nosec B101
    assert "check-spelling" in makefile  # nosec B101
    assert "check-toml" in makefile  # nosec B101
    assert "check-types" in makefile  # nosec B101
    assert "check-ty" in makefile  # nosec B101
    assert "check-package" in makefile  # nosec B101
    assert "check-qlty" in makefile  # nosec B101
    assert "check-bandit" in makefile  # nosec B101
    assert "check-deps" in makefile  # nosec B101
    assert "check-sbom" in makefile  # nosec B101
    assert "check-secrets" in makefile  # nosec B101
    assert "check-iam" in makefile  # nosec B101
    assert "check-preview" in makefile  # nosec B101
    assert "check-yaml" in makefile  # nosec B101
    assert "check-actionlint" in makefile  # nosec B101
    assert "check-docker" in makefile  # nosec B101
    assert "check-shell" in makefile  # nosec B101
    assert "check-iac" in makefile  # nosec B101
    assert "report-wily" in makefile  # nosec B101
    assert "report-vulture" in makefile  # nosec B101
    assert "report-docstrings" in makefile  # nosec B101
    assert "report-sbom" in makefile  # nosec B101
    assert "report-drift" in makefile  # nosec B101
    assert "test-pulumi" in makefile  # nosec B101
    assert "test-cost" in makefile  # nosec B101
    assert "test-policy" in makefile  # nosec B101
    assert "test-crossguard" in makefile  # nosec B101
    assert "test-unit" in makefile  # nosec B101
    assert "test-integration" in makefile  # nosec B101
    assert "test-mutation" in makefile  # nosec B101
    assert "test-e2e" in makefile  # nosec B101
    assert "test-bats" in makefile  # nosec B101
    assert "check-coverage" in makefile  # nosec B101
    assert "ci" in makefile  # nosec B101
    assert "ci-nightly" in makefile  # nosec B101


def test_deploy_stack_exports_pulumi_kms_outputs():
    main_text = (ROOT / "pulumi" / "__main__.py").read_text()
    assert 'pulumi.export("pulumiSecretsKeyArns"' in main_text  # nosec B101
    assert 'pulumi.export("pulumiSecretsProviderUrls"' in main_text  # nosec B101
    assert 'pulumi.export("automationRoleArn"' in main_text  # nosec B101
    assert 'pulumi.export("runnerRepositoryUrl"' in main_text  # nosec B101


def test_repository_uses_uv_for_python_tooling():
    pyproject = (ROOT / "pyproject.toml").read_text()
    assert "[project]" in pyproject  # nosec B101
    assert "[dependency-groups]" in pyproject  # nosec B101
    assert "[tool.uv]" in pyproject  # nosec B101
    assert "[tool.ruff]" in pyproject  # nosec B101
    assert '"scripts"' in pyproject  # nosec B101
    assert (ROOT / "uv.lock").exists()  # nosec B101
    assert not (ROOT / "poetry.lock").exists()  # nosec B101


def test_ci_workflows_cover_local_test_targets():
    quality = (ROOT / ".github" / "workflows" / "python-quality.yml").read_text()
    guardrails = (
        ROOT / ".github" / "workflows" / "devsecops-guardrails.yml"
    ).read_text()
    structural = (ROOT / ".github" / "workflows" / "pulumi-structural.yml").read_text()
    unit = (ROOT / ".github" / "workflows" / "pulumi-unit.yml").read_text()
    integration = (
        ROOT / ".github" / "workflows" / "pulumi-integration.yml"
    ).read_text()
    mutation = (ROOT / ".github" / "workflows" / "pulumi-mutation.yml").read_text()
    bats = (ROOT / ".github" / "workflows" / "bats-tests.yml").read_text()
    codeql = (ROOT / ".github" / "workflows" / "codeql.yml").read_text()
    e2e = (ROOT / ".github" / "workflows" / "pulumi-e2e.yml").read_text()
    policy = (ROOT / ".github" / "workflows" / "pulumi-policy.yml").read_text()
    preview = (ROOT / ".github" / "workflows" / "pulumi-preview.yml").read_text()
    coverage = (ROOT / ".github" / "workflows" / "pulumi-coverage.yml").read_text()
    repo_health = (ROOT / ".github" / "workflows" / "repo-health.yml").read_text()
    dependency_review = (
        ROOT / ".github" / "workflows" / "dependency-review.yml"
    ).read_text()
    quality_monitoring = (
        ROOT / ".github" / "workflows" / "quality-monitoring.yml"
    ).read_text()
    runner_image = (
        ROOT / ".github" / "workflows" / "pulumi-runner-image.yml"
    ).read_text()
    pr_commands = (
        ROOT / ".github" / "workflows" / "pulumi-pr-commands.yml"
    ).read_text()
    pr_runner = (
        ROOT / ".github" / "workflows" / "pulumi-pr-command-runner.yml"
    ).read_text()
    drift = (ROOT / ".github" / "workflows" / "pulumi-drift.yml").read_text()
    deploy_test = (ROOT / ".github" / "workflows" / "pulumi.yml").read_text()
    deploy_prod = (ROOT / ".github" / "workflows" / "pulumi-prod.yml").read_text()
    assert "check-format" in quality  # nosec B101
    assert "check-lint" in quality  # nosec B101
    assert "check-radon" in quality  # nosec B101
    assert "check-xenon" in quality  # nosec B101
    assert "check-imports" in quality  # nosec B101
    assert "check-deptry" in quality  # nosec B101
    assert "check-spelling" in quality  # nosec B101
    assert "check-toml" in quality  # nosec B101
    assert "check-types" in quality  # nosec B101
    assert "check-ty" in quality  # nosec B101
    assert "check-package" in quality  # nosec B101
    assert "check-bandit" in guardrails  # nosec B101
    assert "check-deps" in guardrails  # nosec B101
    assert "check-sbom" in guardrails  # nosec B101
    assert "check-secrets" in guardrails  # nosec B101
    assert "check-yaml" in guardrails  # nosec B101
    assert "check-actionlint" in guardrails  # nosec B101
    assert "check-docker" in guardrails  # nosec B101
    assert "check-shell" in guardrails  # nosec B101
    assert "check-iac" in guardrails  # nosec B101
    assert "check-qlty" in guardrails  # nosec B101
    assert "test-cost" in guardrails  # nosec B101
    assert "make test-pulumi" in structural  # nosec B101
    assert "docker compose build pulumi" in structural  # nosec B101
    assert "make test-unit" in unit  # nosec B101
    assert "docker compose build pulumi" in unit  # nosec B101
    assert "make test-integration" in integration  # nosec B101
    assert "docker compose build pulumi" in integration  # nosec B101
    assert "make test-mutation" in mutation  # nosec B101
    assert "docker compose build pulumi" in mutation  # nosec B101
    assert "make test-bats" in bats  # nosec B101
    assert "language: actions" in codeql  # nosec B101
    assert "language: python" in codeql  # nosec B101
    assert "make test-e2e" in e2e  # nosec B101
    assert "docker compose build pulumi" in e2e  # nosec B101
    assert "pull_request:" in e2e  # nosec B101
    assert "CrossGuard" in policy  # nosec B101
    assert "make test-crossguard" in policy  # nosec B101
    assert "docker compose build pulumi" in policy  # nosec B101
    assert "scripts/analyze_pulumi_preview.py" in preview  # nosec B101
    assert "make check-iam" in preview  # nosec B101
    assert "workflow_dispatch:" in repo_health  # nosec B101
    assert "scorecard-action" in repo_health  # nosec B101
    assert "dependency-review-action" in dependency_review  # nosec B101
    assert "pull_request:" in dependency_review  # nosec B101
    assert "report-wily" in quality_monitoring  # nosec B101
    assert "report-vulture" in quality_monitoring  # nosec B101
    assert "report-docstrings" in quality_monitoring  # nosec B101
    assert "report-sbom" in quality_monitoring  # nosec B101
    assert "schedule:" in quality_monitoring  # nosec B101
    assert "make check-coverage" in coverage  # nosec B101
    assert "docker compose build pulumi" in coverage  # nosec B101
    assert "make runner-image-build" in runner_image  # nosec B101
    assert "make runner-image-smoke" in runner_image  # nosec B101
    assert "make runner-image-push" in runner_image  # nosec B101
    assert "issue_comment:" in pr_commands  # nosec B101
    assert "dispatches" in pr_commands  # nosec B101
    assert "pull_request_number" in pr_runner  # nosec B101
    assert "./scripts/run_pulumi_command.sh" in pr_runner  # nosec B101
    assert "upload-artifact" in pr_runner  # nosec B101
    assert "run_pulumi_command.sh drift" in drift  # nosec B101
    assert "schedule:" in drift  # nosec B101
    assert "PULUMI_STACK: test" in deploy_test  # nosec B101
    assert "PULUMI_STACK: prod" in deploy_prod  # nosec B101
    assert "setup-uv" in deploy_test  # nosec B101
    assert "setup-uv" in deploy_prod  # nosec B101
    assert "uv sync" in deploy_test  # nosec B101
    assert "uv sync" in deploy_prod  # nosec B101
    assert "run_pulumi_command.sh up" in deploy_test  # nosec B101
    assert "run_pulumi_command.sh up" in deploy_prod  # nosec B101
    assert "poetry" not in deploy_test  # nosec B101
    assert "poetry" not in deploy_prod  # nosec B101


def test_docs_cover_testing_and_bootstrap_architecture():
    docs_index = (ROOT / "docs" / "README.md").read_text()
    ci_doc = (ROOT / "docs" / "ci-guardrails.md").read_text()
    testing_doc = (ROOT / "docs" / "testing.md").read_text()
    kms_doc = (ROOT / "docs" / "pulumi-bootstrap-kms.md").read_text()
    automation_doc = (ROOT / "docs" / "pulumi-github-automation.md").read_text()
    policy_doc = (ROOT / "docs" / "pulumi-policy-pack.md").read_text()
    assert "testing.md" in docs_index  # nosec B101
    assert "ci-guardrails.md" in docs_index  # nosec B101
    assert "pulumi-bootstrap-kms.md" in docs_index  # nosec B101
    assert "pulumi-github-automation.md" in docs_index  # nosec B101
    assert "pulumi-policy-pack.md" in docs_index  # nosec B101
    assert "Python Quality Checks" in ci_doc  # nosec B101
    assert "DevSecOps Guardrails" in ci_doc  # nosec B101
    assert "Pulumi Preview Guardrails" in ci_doc  # nosec B101
    assert "CodeQL" in ci_doc  # nosec B101
    assert "Repository Health" in ci_doc  # nosec B101
    assert "Dependency Review" in ci_doc  # nosec B101
    assert "Quality Monitoring" in ci_doc  # nosec B101
    assert "Radon" in ci_doc  # nosec B101
    assert "Xenon" in ci_doc  # nosec B101
    assert "Import Linter" in ci_doc  # nosec B101
    assert "Deptry" in ci_doc  # nosec B101
    assert "shfmt" in ci_doc  # nosec B101
    assert "Qlty" in ci_doc  # nosec B101
    assert "check-preview" in ci_doc  # nosec B101
    assert "ci-nightly" in ci_doc  # nosec B101
    assert "uv" in ci_doc  # nosec B101
    assert "Ruff" in testing_doc  # nosec B101
    assert "Typos" in testing_doc  # nosec B101
    assert "Taplo" in testing_doc  # nosec B101
    assert "Ty" in testing_doc  # nosec B101
    assert "Radon" in testing_doc  # nosec B101
    assert "Xenon" in testing_doc  # nosec B101
    assert "Import Linter" in testing_doc  # nosec B101
    assert "Deptry" in testing_doc  # nosec B101
    assert "shfmt" in testing_doc  # nosec B101
    assert "Wily" in testing_doc  # nosec B101
    assert "Vulture" in testing_doc  # nosec B101
    assert "docstr-coverage" in testing_doc  # nosec B101
    assert "Qlty" in testing_doc  # nosec B101
    assert "Structural" in testing_doc  # nosec B101
    assert "Cost Guardrails" in testing_doc  # nosec B101
    assert "Mutation" in testing_doc  # nosec B101
    assert "CrossGuard" in testing_doc  # nosec B101
    assert "Coverage" in testing_doc  # nosec B101
    assert "check-preview" in testing_doc  # nosec B101
    assert "report-drift" in testing_doc  # nosec B101
    assert "ci-nightly" in testing_doc  # nosec B101
    assert "Stage-0" in kms_doc  # nosec B101
    assert "pulumiSecretsProviderUrls" in kms_doc  # nosec B101
    assert "pulumi plan" in automation_doc  # nosec B101
    assert "pulumi up" in automation_doc  # nosec B101
    assert "ECR" in automation_doc  # nosec B101
    assert "CrossGuard" in policy_doc  # nosec B101
    assert "approved-bootstrap-resource-types" in policy_doc  # nosec B101
    assert "check-coverage" in policy_doc  # nosec B101
    assert "approved region allowlist" in policy_doc  # nosec B101
    assert "wildcard IAM permissions" in policy_doc  # nosec B101


def test_repository_tracks_policy_pack_files():
    policy_pack = ROOT / "policy_pack"
    assert (policy_pack / "PulumiPolicy.yaml").exists()  # nosec B101
    assert (policy_pack / "__main__.py").exists()  # nosec B101
    assert (policy_pack / "guardrails.py").exists()  # nosec B101


def test_repository_tracks_qlty_configuration():
    qlty_dir = ROOT / ".qlty"
    assert (qlty_dir / "qlty.toml").exists()  # nosec B101
    assert (qlty_dir / ".gitignore").exists()  # nosec B101
    assert (qlty_dir / "configs" / ".hadolint.yaml").exists()  # nosec B101
    assert (qlty_dir / "configs" / ".shellcheckrc").exists()  # nosec B101


def test_repository_tracks_ci_guardrail_support_files():
    assert (ROOT / ".gitleaks.toml").exists()  # nosec B101
    assert (ROOT / ".importlinter").exists()  # nosec B101
    assert (ROOT / "scripts" / "analyze_pulumi_preview.py").exists()  # nosec B101
    assert (ROOT / "scripts" / "__init__.py").exists()  # nosec B101
    assert (ROOT / "scripts" / "check_radon_maintainability.py").exists()  # nosec B101
    assert (ROOT / "scripts" / "run_wily_report.py").exists()  # nosec B101
    assert (ROOT / "scripts" / "validate_iam_policies.py").exists()  # nosec B101
