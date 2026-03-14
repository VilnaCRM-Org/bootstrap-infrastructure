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
    assert "check-spelling" in makefile  # nosec B101
    assert "check-toml" in makefile  # nosec B101
    assert "check-types" in makefile  # nosec B101
    assert "check-ty" in makefile  # nosec B101
    assert "check-package" in makefile  # nosec B101
    assert "check-qlty" in makefile  # nosec B101
    assert "check-bandit" in makefile  # nosec B101
    assert "check-deps" in makefile  # nosec B101
    assert "check-sbom" in makefile  # nosec B101
    assert "check-yaml" in makefile  # nosec B101
    assert "check-actionlint" in makefile  # nosec B101
    assert "check-docker" in makefile  # nosec B101
    assert "check-shell" in makefile  # nosec B101
    assert "check-iac" in makefile  # nosec B101
    assert "test-pulumi" in makefile  # nosec B101
    assert "test-cost" in makefile  # nosec B101
    assert "test-unit" in makefile  # nosec B101
    assert "test-integration" in makefile  # nosec B101
    assert "test-mutation" in makefile  # nosec B101
    assert "test-e2e" in makefile  # nosec B101
    assert "test-bats" in makefile  # nosec B101
    assert "ci" in makefile  # nosec B101


def test_deploy_stack_exports_pulumi_kms_outputs():
    main_text = (ROOT / "pulumi" / "__main__.py").read_text()
    assert 'pulumi.export("pulumiSecretsKeyArns"' in main_text  # nosec B101
    assert 'pulumi.export("pulumiSecretsProviderUrls"' in main_text  # nosec B101


def test_repository_uses_uv_for_python_tooling():
    pyproject = (ROOT / "pyproject.toml").read_text()
    assert "[project]" in pyproject  # nosec B101
    assert "[dependency-groups]" in pyproject  # nosec B101
    assert "[tool.uv]" in pyproject  # nosec B101
    assert "[tool.ruff]" in pyproject  # nosec B101
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
    e2e = (ROOT / ".github" / "workflows" / "pulumi-e2e.yml").read_text()
    deploy_test = (ROOT / ".github" / "workflows" / "pulumi.yml").read_text()
    deploy_prod = (ROOT / ".github" / "workflows" / "pulumi-prod.yml").read_text()
    assert "check-format" in quality  # nosec B101
    assert "check-lint" in quality  # nosec B101
    assert "check-spelling" in quality  # nosec B101
    assert "check-toml" in quality  # nosec B101
    assert "check-types" in quality  # nosec B101
    assert "check-ty" in quality  # nosec B101
    assert "check-package" in quality  # nosec B101
    assert "check-bandit" in guardrails  # nosec B101
    assert "check-deps" in guardrails  # nosec B101
    assert "check-sbom" in guardrails  # nosec B101
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
    assert "make test-e2e" in e2e  # nosec B101
    assert "docker compose build pulumi" in e2e  # nosec B101
    assert "pull_request:" in e2e  # nosec B101
    assert "PULUMI_STACK: test" in deploy_test  # nosec B101
    assert "PULUMI_STACK: prod" in deploy_prod  # nosec B101
    assert "setup-uv" in deploy_test  # nosec B101
    assert "setup-uv" in deploy_prod  # nosec B101
    assert "uv sync" in deploy_test  # nosec B101
    assert "uv sync" in deploy_prod  # nosec B101
    assert "poetry" not in deploy_test  # nosec B101
    assert "poetry" not in deploy_prod  # nosec B101


def test_docs_cover_testing_and_bootstrap_architecture():
    docs_index = (ROOT / "docs" / "README.md").read_text()
    ci_doc = (ROOT / "docs" / "ci-guardrails.md").read_text()
    testing_doc = (ROOT / "docs" / "testing.md").read_text()
    kms_doc = (ROOT / "docs" / "pulumi-bootstrap-kms.md").read_text()
    assert "testing.md" in docs_index  # nosec B101
    assert "ci-guardrails.md" in docs_index  # nosec B101
    assert "pulumi-bootstrap-kms.md" in docs_index  # nosec B101
    assert "Python Quality Checks" in ci_doc  # nosec B101
    assert "DevSecOps Guardrails" in ci_doc  # nosec B101
    assert "Qlty" in ci_doc  # nosec B101
    assert "uv" in ci_doc  # nosec B101
    assert "Ruff" in testing_doc  # nosec B101
    assert "Typos" in testing_doc  # nosec B101
    assert "Taplo" in testing_doc  # nosec B101
    assert "Ty" in testing_doc  # nosec B101
    assert "Qlty" in testing_doc  # nosec B101
    assert "Structural" in testing_doc  # nosec B101
    assert "Cost Guardrails" in testing_doc  # nosec B101
    assert "Mutation" in testing_doc  # nosec B101
    assert "Stage-0" in kms_doc  # nosec B101
    assert "pulumiSecretsProviderUrls" in kms_doc  # nosec B101


def test_repository_tracks_qlty_configuration():
    qlty_dir = ROOT / ".qlty"
    assert (qlty_dir / "qlty.toml").exists()  # nosec B101
    assert (qlty_dir / ".gitignore").exists()  # nosec B101
    assert (qlty_dir / "configs" / ".hadolint.yaml").exists()  # nosec B101
    assert (qlty_dir / "configs" / ".shellcheckrc").exists()  # nosec B101
