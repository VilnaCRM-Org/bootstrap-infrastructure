"""Structural tests for release automation and repository hardening."""

import os
import re
import stat
import subprocess
from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS_DIR = PROJECT_ROOT / ".github" / "workflows"
AWS_CI_LOADER_ACTION = (
    PROJECT_ROOT / ".github" / "actions" / "load-aws-ci-env" / "action.yml"
)
DOCKERFILE = PROJECT_ROOT / "Dockerfile"
DOCKER_COMPOSE = PROJECT_ROOT / "docker-compose.yml"
SECRETS_DOC = PROJECT_ROOT / "docs" / "github-actions-secrets.md"
BATS_FILE = PROJECT_ROOT / "tests" / "unit" / "make_targets.bats"
UV_LOCKFILE = PROJECT_ROOT / "uv.lock"
RELEASE_WORKFLOWS = ("autorelease.yml",)
TEMPLATE_SYNC_WORKFLOWS = ("template-sync-app.yml", "template-sync-pat.yml")
PULL_REQUEST_WORKFLOW_TIMEOUTS = {
    "bats-tests.yml": {"bats_tests": 15},
    "pulumi-integration.yml": {"integration": 20},
    "pulumi-local.yml": {"local_battery": 30},
    "pulumi-mutation.yml": {"mutation": 45},
    "pulumi-policy.yml": {"policy": 15},
    "pulumi-pr-guardrails.yml": {
        "preview_mode": 5,
        "preview": 20,
        "preview_unprivileged": 10,
        "destructive_diff": 10,
        "iam_validation": 15,
        "iam_validation_unprivileged": 10,
    },
    "pulumi-structural.yml": {"structural": 15},
    "pulumi-unit.yml": {"unit": 45},
    "python-quality.yml": {
        "ruff": 15,
        "ty": 15,
        "maintainability": 15,
        "architecture": 15,
        "dependency_hygiene": 15,
        "coverage": 30,
    },
    "security-scans.yml": {
        "secrets": 10,
        "dependency_audit": 15,
        "bandit": 10,
        "actionlint": 10,
        "yamllint": 10,
        "hadolint": 10,
    },
}
DOCS_INDEX = PROJECT_ROOT / "docs" / "README.md"
ROOT_README = PROJECT_ROOT / "README.md"
PREPARE_SCRIPT = PROJECT_ROOT / "scripts" / "prepare_docker_context.py"
PREPARE_POLICY_SCRIPT = PROJECT_ROOT / "scripts" / "prepare_policy_pack.py"
SCRIPT_SUPPORT = PROJECT_ROOT / "scripts" / "_script_support.py"
DETAILED_DOCS = (
    "ci-quality-gates.md",
    "ci-guardrails.md",
    "ci-architecture.md",
    "pulumi-guardrails.md",
    "security-baseline.md",
    "sre-operations.md",
)
ACTION_SHA_REF = re.compile(r"^[^@]+@[0-9a-f]{40}$")


def _triggers(workflow: dict) -> dict:
    return workflow.get("on", workflow.get(True, {}))


def _release_job(workflow: dict, *, workflow_name: str) -> dict:
    for job in workflow["jobs"].values():
        step_names = {step.get("name") for step in job.get("steps", [])}
        if "Create Release" in step_names:
            return job
    raise AssertionError(f"Create Release step not found in {workflow_name}")


def _checkout_step(steps: list[dict], *, workflow_name: str) -> dict:
    """Return the checkout step without depending on step ordering."""
    for step in steps:
        uses = step.get("uses", "")
        if uses.startswith("actions/checkout@"):
            return step
    raise AssertionError(f"actions/checkout not found in {workflow_name}")


def _run_lines(steps: list[dict]) -> list[str]:
    """Flatten workflow shell snippets into normalized lines for contract checks."""
    lines: list[str] = []
    for step in steps:
        run = step.get("run")
        if not run:
            continue
        lines.extend(
            line.strip()
            for line in run.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        )
    return lines


def _environment_name(job: dict) -> str | None:
    """Return the GitHub environment name from either supported workflow shape."""
    environment = job.get("environment")
    if isinstance(environment, str):
        return environment
    if isinstance(environment, dict):
        name = environment.get("name")
        if isinstance(name, str):
            return name
    return None


def _workflow_jobs() -> list[tuple[str, str, dict]]:
    jobs: list[tuple[str, str, dict]] = []
    for workflow_path in sorted(WORKFLOWS_DIR.glob("*.yml")):
        workflow = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
        jobs.extend(
            (workflow_path.name, job_name, job)
            for job_name, job in workflow.get("jobs", {}).items()
        )
    return jobs


def test_release_workflows_use_repo_token_with_github_token_fallback() -> None:
    """Keep the release workflows aligned with the documented secret contract."""
    secrets_doc = SECRETS_DOC.read_text(encoding="utf-8")

    assert secrets_doc.startswith("# GitHub Actions Secrets and Variables\n")
    assert "fall back to `GITHUB_TOKEN`" in secrets_doc
    assert not (WORKFLOWS_DIR / "autoprerelase.yml").exists()

    for workflow_name in RELEASE_WORKFLOWS:
        workflow = yaml.safe_load(
            (WORKFLOWS_DIR / workflow_name).read_text(encoding="utf-8")
        )
        release_job = _release_job(workflow, workflow_name=workflow_name)
        steps = release_job["steps"]
        checkout_step = _checkout_step(steps, workflow_name=workflow_name)
        changelog_step = next(
            step
            for step in steps
            if step.get("name") == "Conventional Changelog Action"
        )

        assert (
            release_job["env"]["RELEASE_TOKEN"]
            == "${{ secrets.REPO_GITHUB_TOKEN || secrets.GITHUB_TOKEN }}"
        )
        assert release_job["env"]["CHANGELOG_BRANCH"] == "${{ github.ref_name }}"
        assert any(step.get("name") == "Create Release" for step in steps)
        assert release_job["timeout-minutes"] == 10
        assert checkout_step["with"]["ref"] == "${{ env.CHANGELOG_BRANCH }}"
        assert checkout_step["with"]["fetch-depth"] == 0
        assert checkout_step["with"]["persist-credentials"] is False
        assert changelog_step["with"]["output-file"] == "false"
        assert changelog_step["with"]["git-branch"] == "${{ env.CHANGELOG_BRANCH }}"
        assert changelog_step["with"]["skip-version-file"] == "true"
        assert changelog_step["with"]["skip-commit"] == "true"
        assert "version-file" not in changelog_step["with"]
        assert "version-path" not in changelog_step["with"]
        assert workflow["concurrency"]["cancel-in-progress"] is False


def test_dockerfile_pins_base_image_and_verifies_downloads() -> None:
    """Require checksum verification for externally downloaded tooling."""
    dockerfile_text = DOCKERFILE.read_text(encoding="utf-8")

    assert "python:3.11.15-slim-bookworm@" in dockerfile_text
    assert "FROM ${BASE_IMAGE} AS tooling" in dockerfile_text
    assert "FROM ${BASE_IMAGE} AS runtime-base" in dockerfile_text
    assert "ARG TARGETARCH" in dockerfile_text
    assert "ARG TARGETARCH=amd64" not in dockerfile_text
    assert "PULUMI_SHA256_AMD64" in dockerfile_text
    assert "PULUMI_SHA256_ARM64" in dockerfile_text
    assert "AWSCLI_SHA256_AMD64" in dockerfile_text
    assert "AWSCLI_SHA256_ARM64" in dockerfile_text
    assert "UV_SHA256_AMD64" in dockerfile_text
    assert "UV_SHA256_ARM64" in dockerfile_text
    assert "BATS_SHA256" in dockerfile_text
    assert "UV_PROJECT_ENVIRONMENT" in dockerfile_text
    assert "PULUMI_PYTHON_CMD" in dockerfile_text
    assert 'AWS_PAGER=""' in dockerfile_text
    assert "PULUMI_HOME" in dockerfile_text
    assert "PULUMI_SKIP_UPDATE_CHECK=true" in dockerfile_text
    assert "PYTHONDONTWRITEBYTECODE=1" in dockerfile_text
    assert "PYTHONUNBUFFERED=1" in dockerfile_text
    assert "uv venv --seed" in dockerfile_text
    assert 'getent group "${GID}"' in dockerfile_text
    assert 'getent passwd "${UID}"' in dockerfile_text
    assert (
        'useradd --gid "${group_name}" --create-home "${USERNAME}"' in dockerfile_text
    )
    assert (
        'useradd --uid "${UID}" --gid "${group_name}" --create-home "${USERNAME}"'
        in dockerfile_text
    )
    assert UV_LOCKFILE.exists()
    assert dockerfile_text.count('case "${TARGETARCH}" in') >= 3
    assert "/opt/pulumi/pulumi-language-dotnet" in dockerfile_text
    assert "/usr/local/aws-cli/v2/current/dist/awscli/examples" in dockerfile_text
    assert dockerfile_text.count("sha256sum -c -") >= 4


def test_docker_compose_keeps_workspace_and_credentials_contract() -> None:
    """Keep the local container contract stable for developers and CI."""
    compose = yaml.safe_load(DOCKER_COMPOSE.read_text(encoding="utf-8"))
    service = compose["services"]["pulumi"]

    assert service["build"]["context"] == "."
    assert service["build"]["dockerfile"] == "Dockerfile"
    assert service["build"]["target"] == "${COMPOSE_TARGET:-dev}"
    assert service["build"]["args"]["UID"] == "${UID:-1000}"
    assert service["build"]["args"]["GID"] == "${GID:-1000}"
    assert service["build"]["args"]["USERNAME"] == "dev"
    assert service["working_dir"] == "/workspace"
    assert service["tty"] is True
    assert service["stdin_open"] is True

    volumes = service["volumes"]
    assert any(
        volume["source"] == "." and volume["target"] == "/workspace"
        for volume in volumes
    )
    assert any(
        volume["source"] == "${HOME}/.aws"
        and volume["target"] == "/home/dev/.aws"
        and volume["read_only"] is True
        for volume in volumes
    )

    assert service["env_file"] == [{"path": ".env", "required": False}]
    assert service["environment"] == [
        "PULUMI_BACKEND_URL",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_PROFILE",
        "AWS_REGION",
        "AWS_DEFAULT_REGION",
        "PYTHONPATH=/workspace/pulumi",
    ]


def test_prepare_docker_context_script_creates_expected_files(tmp_path: Path) -> None:
    """Keep the shared CI/local bootstrap script idempotent and predictable."""
    home_dir = tmp_path / "home"
    repo_dir = tmp_path / "repo"
    home_dir.mkdir()
    repo_dir.mkdir()
    (repo_dir / ".env.empty").write_text(
        "PULUMI_SKIP_UPDATE_CHECK=true\n",
        encoding="utf-8",
    )

    subprocess.run(
        ["python3", str(PREPARE_SCRIPT)],
        check=True,
        cwd=repo_dir,
        env={**os.environ, "HOME": str(home_dir)},
        timeout=30,
    )

    aws_dir = home_dir / ".aws"
    assert aws_dir.is_dir()
    assert stat.S_IMODE(aws_dir.stat().st_mode) == 0o700
    assert (repo_dir / ".env").read_text(encoding="utf-8") == (
        "PULUMI_SKIP_UPDATE_CHECK=true\n"
    )
    assert stat.S_IMODE((repo_dir / ".env").stat().st_mode) == 0o600
    assert (repo_dir / ".pulumi-backend").is_dir()
    assert stat.S_IMODE((repo_dir / ".pulumi-backend").stat().st_mode) == 0o700


def test_prepare_docker_context_script_preserves_existing_env_file(
    tmp_path: Path,
) -> None:
    """Avoid overwriting developer-specific env files during bootstrap."""
    home_dir = tmp_path / "home"
    repo_dir = tmp_path / "repo"
    home_dir.mkdir()
    repo_dir.mkdir()
    (repo_dir / ".env.empty").write_text("DEFAULT=value\n", encoding="utf-8")
    (repo_dir / ".env").write_text("LOCAL=value\n", encoding="utf-8")

    subprocess.run(
        ["python3", str(PREPARE_SCRIPT)],
        check=True,
        cwd=repo_dir,
        env={**os.environ, "HOME": str(home_dir)},
        timeout=30,
    )

    assert (repo_dir / ".env").read_text(encoding="utf-8") == "LOCAL=value\n"
    assert stat.S_IMODE((repo_dir / ".env").stat().st_mode) == 0o600


def test_prepare_docker_context_script_rejects_non_regular_env_path(
    tmp_path: Path,
) -> None:
    """Fail fast when .env exists as a symlink or directory."""
    home_dir = tmp_path / "home"
    repo_dir = tmp_path / "repo"
    target_file = tmp_path / "target.env"
    home_dir.mkdir()
    repo_dir.mkdir()
    target_file.write_text("TARGET=value\n", encoding="utf-8")
    (repo_dir / ".env.empty").write_text("DEFAULT=value\n", encoding="utf-8")
    (repo_dir / ".env").symlink_to(target_file)

    result = subprocess.run(
        ["python3", str(PREPARE_SCRIPT)],
        check=False,
        cwd=repo_dir,
        capture_output=True,
        text=True,
        env={**os.environ, "HOME": str(home_dir)},
        timeout=30,
    )

    assert result.returncode != 0
    assert "error: .env must be a regular file" in result.stderr
    assert target_file.read_text(encoding="utf-8") == "TARGET=value\n"


def test_prepare_docker_context_script_rejects_symlinked_backend_dir(
    tmp_path: Path,
) -> None:
    """Fail fast when the local backend path is a symlinked directory."""
    home_dir = tmp_path / "home"
    repo_dir = tmp_path / "repo"
    backend_target = tmp_path / "backend-target"
    home_dir.mkdir()
    repo_dir.mkdir()
    backend_target.mkdir()
    (repo_dir / ".env.empty").write_text("DEFAULT=value\n", encoding="utf-8")
    (repo_dir / ".pulumi-backend").symlink_to(backend_target, target_is_directory=True)

    result = subprocess.run(
        ["python3", str(PREPARE_SCRIPT)],
        check=False,
        cwd=repo_dir,
        capture_output=True,
        text=True,
        env={**os.environ, "HOME": str(home_dir)},
        timeout=30,
    )

    assert result.returncode != 0
    assert "error: .pulumi-backend must be a regular directory" in result.stderr


def test_prepare_docker_context_script_requires_env_template(tmp_path: Path) -> None:
    """Fail clearly when the committed fallback env file is missing."""
    home_dir = tmp_path / "home"
    repo_dir = tmp_path / "repo"
    home_dir.mkdir()
    repo_dir.mkdir()

    result = subprocess.run(
        ["python3", str(PREPARE_SCRIPT)],
        check=False,
        cwd=repo_dir,
        capture_output=True,
        text=True,
        env={**os.environ, "HOME": str(home_dir)},
        timeout=30,
    )

    assert result.returncode != 0
    assert "error: .env.empty not found" in result.stderr


def test_prepare_policy_pack_script_uses_shared_uv_environment() -> None:
    """Keep policy-pack bootstrap aligned with the shared uv-managed interpreter."""
    script_text = PREPARE_POLICY_SCRIPT.read_text(encoding="utf-8")
    support_text = SCRIPT_SUPPORT.read_text(encoding="utf-8")

    assert PREPARE_POLICY_SCRIPT.exists()
    assert SCRIPT_SUPPORT.exists()
    assert (
        'POLICY_VENV", f"{Path.home()}/.venvs/bootstrap-infrastructure"' in script_text
    )
    assert 'policy_link = policy_dir / ".venv"' in script_text
    assert "policy_link.symlink_to(policy_venv)" in script_text
    assert 'env["UV_PROJECT_ENVIRONMENT"] = str(policy_venv)' in script_text
    assert '"uv", "sync", "--frozen", "--all-groups"' in script_text
    assert "policy_import_probe(root_dir)" in script_text
    assert "sys.path.insert(0," in support_text
    assert "import pulumi" in support_text
    assert "import pulumi_policy" in support_text
    assert "import policy.config" in support_text
    assert "import policy.guardrails" in support_text
    assert "import policy.pack" in support_text


def test_new_helper_scripts_keep_local_ci_behaviour_explicit() -> None:
    """Keep extracted helper scripts discoverable and safe to execute locally."""
    doctor_script = (PROJECT_ROOT / "scripts" / "doctor.py").read_text(encoding="utf-8")
    preview_summary_script = (
        PROJECT_ROOT / "scripts" / "publish_pulumi_preview_summary.py"
    ).read_text(encoding="utf-8")
    wily_script = (
        PROJECT_ROOT / "scripts" / "report_maintainability_trends.py"
    ).read_text(encoding="utf-8")

    assert (
        'compose_version = _version(["docker", "compose", "version", "--short"])'
        in doctor_script
    )
    assert "effective env file:" in doctor_script
    assert "pulumi directory missing:" in doctor_script
    assert 'root_dir = Path(os.environ.get("ROOT_DIR"' in wily_script
    assert "quality_artifact_dir = Path(" in wily_script
    assert "if not quality_artifact_dir.is_absolute()" in wily_script
    assert '"git", "rev-parse", "--verify", "HEAD"' in wily_script
    assert "Wily maintainability report skipped" in wily_script
    assert "Current maintainability snapshot from radon" in wily_script
    assert "PULUMI_REQUIRE_SHARED_BACKEND" in preview_summary_script
    assert '"make", "test-preview"' in preview_summary_script
    assert "GITHUB_STEP_SUMMARY" in preview_summary_script


def test_coverage_bearing_make_targets_enforce_full_line_coverage() -> None:
    """Prevent drift in the line- and branch-coverage contracts for Python suites."""
    makefile_text = (PROJECT_ROOT / "Makefile").read_text(encoding="utf-8")
    coverage_config = (PROJECT_ROOT / ".coveragerc").read_text(encoding="utf-8")

    assert "branch = True" in coverage_config
    assert "rm -f .coverage.unit .coverage.unit.*" in makefile_text
    assert "rm -f .coverage.integration .coverage.integration.*" in makefile_text
    assert "rm -f .coverage.policy .coverage.policy.*" in makefile_text
    assert "TOTAL_COVERAGE_INCLUDE   ?= pulumi/*,policy/*,scripts/*" in makefile_text
    assert "BRANCH_COVERAGE_MIN      ?= 100" in makefile_text
    assert "UNIT_COVERAGE_INCLUDE    ?= pulumi/*,scripts/*" in makefile_text
    assert (
        "coverage report --show-missing --include='$(UNIT_COVERAGE_INCLUDE)' "
        "--fail-under=100" in makefile_text
    )
    assert (
        "INTEGRATION_COVERAGE_INCLUDE ?= pulumi/__main__.py,pulumi/app/*"
        in makefile_text
    )
    assert (
        "coverage run --parallel-mode -m pytest -q tests/integration" in makefile_text
    )
    assert (
        "coverage report --show-missing --fail-under=100 "
        "--include='$(INTEGRATION_COVERAGE_INCLUDE)'" in makefile_text
    )
    assert "coverage report --show-missing --include='policy/*' --fail-under=100" in (
        makefile_text
    )
    assert (
        "coverage combine --keep .coverage.unit .coverage.integration "
        ".coverage.policy" in makefile_text
    )
    assert (
        "coverage report --show-missing --fail-under=$(BRANCH_COVERAGE_MIN) "
        '--include="$(TOTAL_COVERAGE_INCLUDE)"' in makefile_text
    )
    assert "scripts" in coverage_config
    assert "/workspace/pulumi" in coverage_config
    assert "/workspace/policy" in coverage_config
    assert "/workspace/scripts" in coverage_config
    assert "pulumi/sitecustomize.py" not in coverage_config


def test_makefile_keeps_pulumi_guardrails_secret_safe() -> None:
    """Protect preview and drift targets from leaking tokens or creating typo stacks."""
    makefile_text = (PROJECT_ROOT / "Makefile").read_text(encoding="utf-8")
    pulumi_command_text = (
        PROJECT_ROOT / "scripts" / "run_pulumi_command.py"
    ).read_text(encoding="utf-8")
    pulumi_command_support_text = (
        PROJECT_ROOT / "scripts" / "_pulumi_command_support.py"
    ).read_text(encoding="utf-8")
    pulumi_command_combined_text = pulumi_command_text + pulumi_command_support_text
    guardrail_runs = "$(COMPOSE_GITHUB_TOKEN) $(COMPOSE_PULUMI_ENV)"

    assert "GITHUB_TOKEN='$(GITHUB_TOKEN)'" not in makefile_text  # nosec B101
    assert "export GITHUB_TOKEN" in makefile_text  # nosec B101
    assert "PULUMI_CWD_FLAG   = -C $(PULUMI_DIR)" in makefile_text  # nosec B101
    assert '-e PULUMI_DIR="$(PULUMI_DIR)"' in makefile_text  # nosec B101
    assert "Pulumi.dev.yaml" in makefile_text  # nosec B101
    assert "Pulumi.test.yaml" in makefile_text  # nosec B101
    assert "export PULUMI_STACK" in makefile_text  # nosec B101
    assert "./scripts/run_pulumi_command.py refresh" in makefile_text  # nosec B101
    assert "./scripts/run_pulumi_command.py destroy" in makefile_text  # nosec B101
    assert makefile_text.count(guardrail_runs) >= 6  # nosec B101
    assert "shared backend stack {stack} does not exist" in pulumi_command_combined_text  # nosec B101
    assert "stack change-secrets-provider" not in pulumi_command_combined_text  # nosec B101
    assert '"--save-plan"' in pulumi_command_combined_text  # nosec B101
    assert '"summarize"' in pulumi_command_combined_text  # nosec B101
    assert "direct Pulumi up is disabled in GitHub Actions" in (  # nosec B101
        pulumi_command_combined_text
    )


def test_bats_suite_covers_every_public_make_target() -> None:
    """Keep public and shared aggregate make targets under CLI regression tests."""
    bats_text = BATS_FILE.read_text(encoding="utf-8")
    expected_invocations = [
        "make help",
        "make all",
        "make -n build",
        "make -n ci",
        "make -n ci-pr",
        "make -n doctor",
        "make -n start",
        "make -n nightly-quality",
        "make -n publish-pulumi-preview-summary",
        "make -n pulumi-preview",
        "make -n pulumi-plan",
        "make -n pulumi-up",
        "make -n pulumi-up-plan",
        "make -n pulumi-refresh",
        "make -n pulumi-destroy",
        "make -n report-dead-code",
        "make -n report-docstrings",
        "make -n report-maintainability-trends",
        "make -n report-quality",
        "make -n report-sbom",
        "make -n sh",
        "make -n down",
        "make -n test-battery",
        "make -n test-actionlint",
        "make -n test-architecture",
        "make -n test-bandit",
        "make -n test-coverage",
        "make -n test-crossguard",
        "make -n test-dependency-hygiene",
        "make -n test-deps-security",
        "make -n test-dockerfile",
        "make -n test-destructive-diff",
        "make -n test-drift",
        "make -n test-guardrails",
        "make -n test-iam-validation",
        "make -n test-preview",
        "make -n test-lockfile",
        "make -n test-maintainability",
        "make -n test-repo-hygiene",
        "make -n test-repository-catalogs",
        "make -n test-security",
        "make -n test-secrets",
        "make -n test-yaml",
        "make -n test-quality",
        "make -n test-ruff",
        "make -n test-ty",
        "make -n test-unit",
        "make -n test-integration",
        "make -n test-pulumi",
        "make -n test-policy",
        "make -n test-mutation",
        "make -n test-cli",
        "make -n test",
        "make -n clean",
    ]

    for invocation in expected_invocations:
        assert invocation in bats_text


def test_local_battery_workflow_avoids_duplicate_mutation_runs() -> None:
    """Ensure GitHub Actions keeps mutation isolated to the dedicated workflow."""
    workflow = yaml.safe_load(
        (WORKFLOWS_DIR / "pulumi-local.yml").read_text(encoding="utf-8")
    )
    triggers = _triggers(workflow)
    steps = workflow["jobs"]["local_battery"]["steps"]
    step_names = [step.get("name") for step in steps]
    run_lines = _run_lines(steps)

    assert triggers["push"]["branches"] == ["main"]
    assert "pull_request" in triggers
    assert workflow["jobs"]["local_battery"]["timeout-minutes"] == 30
    assert "Start development environment" in step_names
    assert "Run non-mutation PR battery inside Docker" in step_names
    assert any("make ci-pr" in line for line in run_lines)
    assert not any("make ci" == line for line in run_lines)
    assert not any("make test-mutation" in line for line in run_lines)


def test_makefile_secret_and_guardrail_targets_stay_developer_safe() -> None:
    """Keep secret and preview guardrails aligned with local developer workflows."""
    makefile_text = (PROJECT_ROOT / "Makefile").read_text(encoding="utf-8")

    assert (
        'gitleaks git . --log-opts="-1" --config .gitleaks.toml --no-banner --redact'
        in makefile_text
    )
    assert "gitleaks dir ." not in makefile_text
    guardrails_block = makefile_text.split("test-guardrails:", maxsplit=1)[1].split(
        "test-drift:",
        maxsplit=1,
    )
    assert "\n\t$(MAKE) test-iam-validation\n" not in guardrails_block[0]  # nosec B101


def test_ci_workflows_keep_make_entrypoints_in_sync() -> None:
    """Keep each PR validation workflow wired to its corresponding make target."""
    expected_runs = {
        "bats-tests.yml": ["make test-cli"],
        "pulumi-integration.yml": ["make test-integration"],
        "pulumi-local.yml": ["make ci-pr"],
        "pulumi-mutation.yml": ["make test-mutation"],
        "pulumi-policy.yml": ["make test-policy"],
        "pulumi-pr-guardrails.yml": [
            "make publish-pulumi-preview-summary",
            "make test-preview-unprivileged",
            "make test-destructive-diff",
            "make test-iam-validation",
            "make test-iam-validation-unprivileged",
        ],
        "pulumi-structural.yml": [
            "make test-pulumi",
            "make test-repository-catalogs",
        ],
        "pulumi-unit.yml": ["make test-unit"],
        "python-quality.yml": [
            "make test-ruff",
            "make test-ty",
            "make test-maintainability",
            "make test-architecture",
            "make test-dependency-hygiene",
            "make test-coverage",
        ],
        "security-scans.yml": [
            "make test-secrets",
            "make test-deps-security",
            "make test-bandit",
            "make test-actionlint",
            "make test-yaml",
            "make test-dockerfile",
        ],
    }

    for workflow_name, commands in expected_runs.items():
        workflow = yaml.safe_load(
            (WORKFLOWS_DIR / workflow_name).read_text(encoding="utf-8")
        )
        steps = [
            step for job in workflow["jobs"].values() for step in job.get("steps", [])
        ]
        run_lines = _run_lines(steps)

        for command in commands:
            assert any(command in line for line in run_lines), (
                f"{workflow_name} is missing `{command}`"
            )


def test_ci_workflows_use_guardrails_and_shared_bootstrap() -> None:
    """Require consistent concurrency, timeout, and bootstrap rules in CI."""
    assert PREPARE_SCRIPT.exists()

    for workflow_name, jobs in PULL_REQUEST_WORKFLOW_TIMEOUTS.items():
        workflow = yaml.safe_load(
            (WORKFLOWS_DIR / workflow_name).read_text(encoding="utf-8")
        )
        triggers = _triggers(workflow)

        assert triggers["push"]["branches"] == ["main"]
        assert "pull_request" in triggers
        assert workflow["permissions"] == {"contents": "read"}
        assert workflow["defaults"]["run"]["shell"] == "bash"
        assert workflow["concurrency"]["cancel-in-progress"] is True
        assert "${{ github.workflow }}" in workflow["concurrency"]["group"]
        assert (
            "${{ github.event.pull_request.number || github.ref }}"
            in workflow["concurrency"]["group"]
        )

        for job_name, expected_timeout in jobs.items():
            job = workflow["jobs"][job_name]
            assert job["timeout-minutes"] == expected_timeout
            if job_name == "preview_mode":
                continue
            assert any("make start" in line for line in _run_lines(job["steps"])), (
                f"{workflow_name}:{job_name} must use the shared Docker bootstrap"
            )


def test_actions_are_pinned_to_full_commit_shas() -> None:
    """Keep GitHub Actions dependencies pinned to immutable refs."""
    for workflow_path in sorted(WORKFLOWS_DIR.glob("*.yml")):
        workflow = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))

        for job in workflow.get("jobs", {}).values():
            uses = job.get("uses")
            if uses and not uses.startswith("./"):
                assert ACTION_SHA_REF.match(uses), (
                    f"{workflow_path.name} must pin reusable workflow `{uses}` "
                    "to a full commit SHA"
                )
            for step in job.get("steps", []):
                uses = step.get("uses")
                if not uses or uses.startswith("./"):
                    continue

                assert ACTION_SHA_REF.match(uses), (
                    f"{workflow_path.name} must pin `{uses}` to a full commit SHA"
                )


def test_aws_ci_loader_reads_secrets_manager_without_pulumi_cloud() -> None:
    """Load CI config directly from AWS Secrets Manager through GitHub OIDC."""
    action_text = AWS_CI_LOADER_ACTION.read_text(encoding="utf-8")
    action = yaml.safe_load(action_text)
    resolve_step = action["runs"]["steps"][0]
    configure_aws_step = next(
        step
        for step in action["runs"]["steps"]
        if step.get("name") == "Configure AWS config-read credentials"
    )
    load_step = next(
        step
        for step in action["runs"]["steps"]
        if step.get("name") == "Load AWS Secrets Manager CI values"
    )
    install_uv_step = next(
        step
        for step in action["runs"]["steps"]
        if step.get("name") == "Install uv for validation"
    )
    validate_step = next(
        step
        for step in action["runs"]["steps"]
        if step.get("name") == "Validate AWS Secrets Manager CI environment"
    )
    boundary_step = next(
        step
        for step in action["runs"]["steps"]
        if step.get("name") == "Record AWS Secrets Manager source-of-truth boundary"
    )

    assert action["name"] == "Load AWS Secrets Manager CI environment"  # nosec B101
    assert "organization" not in action["inputs"]  # nosec B101
    assert "config-role-arn" in action["inputs"]  # nosec B101
    assert "aws-region" in action["inputs"]  # nosec B101
    assert "pulumi/auth-actions" not in action_text  # nosec B101
    assert "pulumi/esc-action" not in action_text  # nosec B101
    assert "PULUMI_ESC" not in action_text  # nosec B101
    assert ".github/ci/pulumi-esc.json" not in action_text  # nosec B101
    assert "secretsmanager get-secret-value" in load_step["run"]  # nosec B101
    assert "--query SecretString" in load_step["run"]  # nosec B101
    assert "Secret ID:" in boundary_step["run"]  # nosec B101
    assert "Pulumi Cloud/ESC: not used" in boundary_step["run"]  # nosec B101
    assert action["runs"]["steps"].index(resolve_step) < action["runs"]["steps"].index(  # nosec B101
        boundary_step
    )
    assert action["runs"]["steps"].index(boundary_step) < action["runs"]["steps"].index(  # nosec B101
        configure_aws_step
    )
    assert configure_aws_step["with"]["role-to-assume"] == (  # nosec B101
        "${{ inputs.config-role-arn }}"
    )
    assert configure_aws_step["with"]["allowed-account-ids"] == (  # nosec B101
        "${{ steps.aws-target.outputs.config_account_id }}"
    )
    assert "GITHUB_STEP_SUMMARY" in boundary_step["run"]  # nosec B101
    assert "version" in install_uv_step["with"]  # nosec B101
    assert (  # nosec B101
        "uv run python scripts/validate_ci_environment.py" in validate_step["run"]
    )
    assert "--purpose" in validate_step["run"]  # nosec B101
    assert (  # nosec B101
        "python3 scripts/validate_ci_environment.py" not in validate_step["run"]
    )


def test_multi_account_workflows_use_fixed_aws_ci_config_contracts() -> None:
    """Load privileged CI config from fixed AWS Secrets Manager secrets."""
    test_pr_environment = "${{ steps.ci_config_target.outputs.environment }}"
    expected_contracts_by_job = {
        ("nightly-guardrails.yml", "test_drift_detection"): (
            "test",
            "${{ steps.ci_config.outputs.aws-drift-role-arn }}",
        ),
        ("nightly-guardrails.yml", "prod_drift_detection"): (
            "prod-preview",
            "${{ steps.ci_config.outputs.aws-drift-role-arn }}",
        ),
        ("well-architected-evidence.yml", "test_account_evidence"): (
            test_pr_environment,
            "${{ steps.ci_config.outputs.aws-preview-role-arn }}",
        ),
        ("operations-alert-triage.yml", "triage_operations_alerts"): (
            "test",
            "${{ steps.ci_config.outputs.aws-operations-alert-triage-role-arn }}",
        ),
        ("pulumi-pr-command-runner.yml", "test_preview"): (
            "test",
            "${{ steps.ci_config.outputs.aws-preview-role-arn }}",
        ),
        ("pulumi-pr-command-runner.yml", "test_iam_validation"): (
            "test",
            "${{ steps.ci_config.outputs.aws-preview-role-arn }}",
        ),
        ("pulumi-pr-command-runner.yml", "test_apply"): (
            "test",
            "${{ steps.ci_config.outputs.aws-apply-role-arn }}",
        ),
        ("pulumi-pr-command-runner.yml", "test_post_apply_drift"): (
            "test",
            "${{ steps.ci_config.outputs.aws-drift-role-arn }}",
        ),
        ("pulumi-pr-command-runner.yml", "prod_preview"): (
            "prod-preview",
            "${{ steps.ci_config.outputs.aws-preview-role-arn }}",
        ),
        ("pulumi-pr-command-runner.yml", "prod_iam_validation"): (
            "prod-preview",
            "${{ steps.ci_config.outputs.aws-preview-role-arn }}",
        ),
        ("pulumi-pr-command-runner.yml", "prod_apply"): (
            "prod",
            "${{ steps.ci_config.outputs.aws-apply-role-arn }}",
        ),
        ("pulumi-pr-command-runner.yml", "prod_post_apply_drift"): (
            "prod-preview",
            "${{ steps.ci_config.outputs.aws-drift-role-arn }}",
        ),
        ("pulumi-pr-guardrails.yml", "preview"): (
            test_pr_environment,
            "${{ steps.ci_config.outputs.aws-preview-role-arn }}",
        ),
        ("pulumi-pr-guardrails.yml", "iam_validation"): (
            test_pr_environment,
            "${{ steps.ci_config.outputs.aws-preview-role-arn }}",
        ),
        ("pulumi-prod.yml", "preview"): (
            "prod-preview",
            "${{ steps.ci_config.outputs.aws-preview-role-arn }}",
        ),
        ("pulumi-prod.yml", "iam_validation"): (
            "prod-preview",
            "${{ steps.ci_config.outputs.aws-preview-role-arn }}",
        ),
        ("pulumi-prod.yml", "apply"): (
            "prod",
            "${{ steps.ci_config.outputs.aws-apply-role-arn }}",
        ),
        ("pulumi-prod.yml", "post_apply_drift"): (
            "prod-preview",
            "${{ steps.ci_config.outputs.aws-drift-role-arn }}",
        ),
        ("pulumi-test-deploy.yml", "preview"): (
            "test",
            "${{ steps.ci_config.outputs.aws-preview-role-arn }}",
        ),
        ("pulumi-test-deploy.yml", "iam_validation"): (
            "test",
            "${{ steps.ci_config.outputs.aws-preview-role-arn }}",
        ),
        ("pulumi-test-deploy.yml", "apply"): (
            "test",
            "${{ steps.ci_config.outputs.aws-apply-role-arn }}",
        ),
        ("pulumi-test-deploy.yml", "post_apply_drift"): (
            "test",
            "${{ steps.ci_config.outputs.aws-drift-role-arn }}",
        ),
    }
    approval_only_environment_jobs = {
        ("pulumi-prod.yml", "apply"),
        ("pulumi-pr-command-runner.yml", "prod_apply"),
    }
    forbidden_job_env_keys = {
        "AWS_ACCOUNT_ID",
        "AWS_REGION",
        "AWS_DEFAULT_REGION",
        "AWS_PREVIEW_ROLE_ARN",
        "AWS_APPLY_ROLE_ARN",
        "AWS_DRIFT_ROLE_ARN",
        "AWS_OPERATIONS_ALERT_TRIAGE_ROLE_ARN",
        "PULUMI_BACKEND_URL",
        "PULUMI_SECRETS_PROVIDER",
        "PULUMI_PREVIEW_STACKS",
        "PULUMI_DRIFT_STACKS",
        "PULUMI_ACCESS_TOKEN",
    }
    expected_config_role_by_environment = {
        test_pr_environment: "${{ steps.ci_config_target.outputs.config-role-arn }}",
        "test": "${{ vars.AWS_TEST_CI_CONFIG_ROLE_ARN }}",
        "prod-preview": "${{ vars.AWS_PROD_PREVIEW_CI_CONFIG_ROLE_ARN }}",
        "prod": "${{ vars.AWS_PROD_CI_CONFIG_ROLE_ARN }}",
    }
    expected_region_by_environment = {
        test_pr_environment: "${{ vars.AWS_TEST_REGION }}",
        "test": "${{ vars.AWS_TEST_REGION }}",
        "prod-preview": "${{ vars.AWS_PROD_REGION }}",
        "prod": "${{ vars.AWS_PROD_REGION }}",
    }

    for workflow_name, job_name, job in _workflow_jobs():
        workflow_job = (workflow_name, job_name)
        environment_name = _environment_name(job)
        if workflow_job in approval_only_environment_jobs:
            assert environment_name == "prod"  # nosec B101
        elif workflow_job in expected_contracts_by_job:
            assert environment_name is None  # nosec B101

        if workflow_job not in expected_contracts_by_job:
            continue

        job_env = job.get("env", {})
        assert not forbidden_job_env_keys.intersection(job_env), workflow_job

        expected_ci_environment, expected_role = expected_contracts_by_job[workflow_job]
        ci_config_step = next(
            step
            for step in job.get("steps", [])
            if step.get("uses") == "./.github/actions/load-aws-ci-env"
        )
        if expected_ci_environment == test_pr_environment:
            ci_config_target_step = next(
                step
                for step in job.get("steps", [])
                if step.get("name") == "Select test AWS CI configuration"
            )
            assert "AWS_TEST_PR_CI_CONFIG_ROLE_ARN" in (  # nosec B101
                ci_config_target_step["run"]
            )
            assert "AWS_TEST_CI_CONFIG_ROLE_ARN" in (  # nosec B101
                ci_config_target_step["run"]
            )
            assert "must be set" in ci_config_target_step["run"]  # nosec B101
        assert ci_config_step["id"] == "ci_config"  # nosec B101
        assert ci_config_step["with"]["environment"] == expected_ci_environment  # nosec B101
        assert (
            ci_config_step["with"]["config-role-arn"]
            == (  # nosec B101
                expected_config_role_by_environment[expected_ci_environment]
            )
        )
        assert "||" not in ci_config_step["with"]["config-role-arn"]  # nosec B101
        assert (
            ci_config_step["with"]["aws-region"]
            == (  # nosec B101
                expected_region_by_environment[expected_ci_environment]
            )
        )
        assert "organization" not in ci_config_step["with"]  # nosec B101
        assert "/" not in ci_config_step["with"]["environment"]  # nosec B101
        assert "inputs." not in ci_config_step["with"]["environment"]  # nosec B101
        assert "client_payload" not in ci_config_step["with"]["environment"]  # nosec B101
        required_keys = ci_config_step["with"]["required-keys"]
        for required_key in ("AWS_ACCOUNT_ID", "AWS_REGION"):
            assert required_key in required_keys  # nosec B101
        assert "PULUMI_SECRETS_PROVIDER" not in job_env  # nosec B101
        assert job.get("permissions", {}).get("id-token") == "write"  # nosec B101

        oidc_steps = [
            step
            for step in job.get("steps", [])
            if step.get("uses", "").startswith("aws-actions/configure-aws-credentials@")
        ]
        assert oidc_steps, workflow_job
        for step in oidc_steps:
            step_with = step["with"]
            assert step_with["role-to-assume"] == expected_role  # nosec B101
            assert (
                step_with["aws-region"] == "${{ steps.ci_config.outputs.aws-region }}"
            )  # nosec B101
            assert step_with["allowed-account-ids"] == (  # nosec B101
                "${{ steps.ci_config.outputs.aws-account-id }}"
            )


def test_operations_alert_triage_uses_repo_python_runner() -> None:
    """Keep alert rendering on the repo-managed Python command path."""
    workflow = yaml.safe_load(
        (WORKFLOWS_DIR / "operations-alert-triage.yml").read_text(encoding="utf-8")
    )
    steps = workflow["jobs"]["triage_operations_alerts"]["steps"]
    install_step = next(
        step for step in steps if step.get("name") == "Install uv for triage renderer"
    )
    triage_step = next(
        step
        for step in steps
        if step.get("name")
        == "Create or update GitHub issue for queued operations alerts"
    )

    assert "uv==0.9.21" in install_step["run"]  # nosec B101
    assert "GITHUB_PATH" in install_step["run"]  # nosec B101
    assert (  # nosec B101
        "uv run python scripts/operations_alert_triage.py" in triage_step["run"]
    )
    assert "--groups-file" in triage_step["run"]  # nosec B101
    assert "jq '.groups | length'" in triage_step["run"]  # nosec B101
    assert "for ((group_index = 0;" in triage_step["run"]  # nosec B101
    assert "--visibility-timeout 600" in triage_step["run"]  # nosec B101
    assert "python3 scripts/operations_alert_triage.py" not in triage_step["run"]  # nosec B101


def test_operations_alert_triage_searches_fingerprint_before_queue_delete() -> None:
    """Update or create canonical alert issues before deleting SQS messages."""
    workflow = yaml.safe_load(
        (WORKFLOWS_DIR / "operations-alert-triage.yml").read_text(encoding="utf-8")
    )
    steps = workflow["jobs"]["triage_operations_alerts"]["steps"]
    triage_run = next(
        step["run"]
        for step in steps
        if step.get("name")
        == "Create or update GitHub issue for queued operations alerts"
    )

    group_loop_index = triage_run.index("for ((group_index = 0;")
    fingerprint_index = triage_run.index('fingerprint="$(cat "${fingerprint_file}")"')
    search_index = triage_run.index(
        '--search "operations-alert:fingerprint=${fingerprint} in:body"'
    )
    comment_index = triage_run.index("gh issue comment")
    create_index = triage_run.index("gh issue create")
    receipt_index = triage_run.index("jq -r '.Messages[].ReceiptHandle'")
    delete_index = triage_run.index("aws sqs delete-message")

    assert group_loop_index < search_index  # nosec B101
    assert fingerprint_index < search_index  # nosec B101
    assert search_index < comment_index < receipt_index < delete_index  # nosec B101
    assert search_index < create_index < receipt_index < delete_index  # nosec B101
    assert '--repo "${GITHUB_REPOSITORY_NAME}"' in triage_run  # nosec B101
    assert "--state open" in triage_run  # nosec B101
    assert "--json number" in triage_run  # nosec B101
    assert "--jq '.[0].number // \"\"'" in triage_run  # nosec B101
    assert 'existing_issue="$(' in triage_run  # nosec B101
    assert 'if [[ -n "${existing_issue}" ]]; then' in triage_run  # nosec B101
    assert '--body-file "${body_file}"' in triage_run  # nosec B101
    assert (  # nosec B101
        '--title "Operations alerts queued: ${group_alert_count} message(s)"'
        in triage_run
    )
    assert triage_run.count("aws sqs delete-message") == 1  # nosec B101


def test_operations_alert_backfill_requires_protected_manual_confirmation() -> None:
    """Backfilled canonical alert issues must be protected and fingerprinted."""
    workflow = yaml.safe_load(
        (WORKFLOWS_DIR / "operations-alert-backfill.yml").read_text(encoding="utf-8")
    )
    triggers = _triggers(workflow)
    job = workflow["jobs"]["backfill"]
    run = job["steps"][1]["run"]

    assert "workflow_dispatch" in triggers  # nosec B101
    assert len(triggers["workflow_dispatch"]["inputs"]) <= 10  # nosec B101
    assert "stable_event_json" in triggers["workflow_dispatch"]["inputs"]  # nosec B101
    assert job["environment"] == "operations-alert-reconcile"  # nosec B101
    assert workflow["permissions"] == {"contents": "read", "issues": "write"}  # nosec B101
    assert "id-token" not in workflow["permissions"]  # nosec B101
    assert job["steps"][0]["uses"] == (  # nosec B101
        "actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5"
    )
    assert (  # nosec B101
        "I confirm these stable fields represent the canonical operations alert stream"
        in run
    )
    assert "sre_confirmation_reference must be an HTTPS URL" in run  # nosec B101
    assert "stable_event_json.source is required" in run  # nosec B101
    assert "python3 scripts/operations_alert_triage.py" in run  # nosec B101
    assert "operations-alert:fingerprint=${fingerprint} in:body" in run  # nosec B101
    assert "gh issue create" in run  # nosec B101
    assert "gh issue comment" in run  # nosec B101


def test_prod_workflow_requires_successful_test_deploy_for_same_sha() -> None:
    """Production release input must already have a green test deployment."""
    prod_workflow = yaml.safe_load(
        (WORKFLOWS_DIR / "pulumi-prod.yml").read_text(encoding="utf-8")
    )
    test_workflow = yaml.safe_load(
        (WORKFLOWS_DIR / "pulumi-test-deploy.yml").read_text(encoding="utf-8")
    )
    test_preview_ci_config = next(
        step
        for step in test_workflow["jobs"]["preview"]["steps"]
        if step.get("uses") == "./.github/actions/load-aws-ci-env"
    )
    test_iam_ci_config = next(
        step
        for step in test_workflow["jobs"]["iam_validation"]["steps"]
        if step.get("uses") == "./.github/actions/load-aws-ci-env"
    )
    test_apply_ci_config = next(
        step
        for step in test_workflow["jobs"]["apply"]["steps"]
        if step.get("uses") == "./.github/actions/load-aws-ci-env"
    )
    test_drift_ci_config = next(
        step
        for step in test_workflow["jobs"]["post_apply_drift"]["steps"]
        if step.get("uses") == "./.github/actions/load-aws-ci-env"
    )
    prod_preview_lines = "\n".join(
        _run_lines(prod_workflow["jobs"]["preview"]["steps"])
    )
    prod_apply_lines = "\n".join(_run_lines(prod_workflow["jobs"]["apply"]["steps"]))
    test_preview_lines = "\n".join(
        _run_lines(test_workflow["jobs"]["preview"]["steps"])
    )
    test_apply_lines = "\n".join(_run_lines(test_workflow["jobs"]["apply"]["steps"]))

    assert prod_workflow["permissions"]["actions"] == "read"  # nosec B101
    assert (  # nosec B101
        test_workflow["concurrency"]["group"] == "bootstrap-infrastructure-test-state"
    )
    assert (  # nosec B101
        prod_workflow["concurrency"]["group"] == "bootstrap-infrastructure-prod-state"
    )
    assert prod_workflow["jobs"]["preview"]["permissions"]["actions"] == "read"  # nosec B101
    assert "12-digit AWS account ID" in prod_preview_lines  # nosec B101
    assert "s3:// backend" in prod_preview_lines  # nosec B101
    assert "awskms:// URI" in prod_preview_lines  # nosec B101
    assert "AWS_DRIFT_ROLE_ARN" in prod_preview_lines  # nosec B101
    assert "PULUMI_DRIFT_STACKS" in prod_preview_lines  # nosec B101
    assert "12-digit AWS account ID" in test_preview_lines  # nosec B101
    assert "s3:// backend" in test_preview_lines  # nosec B101
    assert "awskms:// URI" in test_preview_lines  # nosec B101
    assert test_preview_ci_config["with"]["environment"] == "test"  # nosec B101
    assert "AWS_APPLY_ROLE_ARN" in test_preview_ci_config["with"]["required-keys"]  # nosec B101
    assert "PULUMI_DRIFT_STACKS" in test_preview_ci_config["with"]["required-keys"]  # nosec B101
    assert "PULUMI_BACKEND_URL" in test_iam_ci_config["with"]["required-keys"]  # nosec B101
    assert "PULUMI_PREVIEW_STACKS" in test_iam_ci_config["with"]["required-keys"]  # nosec B101
    assert "AWS_APPLY_ROLE_ARN" in test_apply_ci_config["with"]["required-keys"]  # nosec B101
    assert "PULUMI_BACKEND_URL" in test_apply_ci_config["with"]["required-keys"]  # nosec B101
    assert "AWS_DRIFT_ROLE_ARN" in test_drift_ci_config["with"]["required-keys"]  # nosec B101
    test_deploy_query = (
        "pulumi-test-deploy.yml/runs?head_sha=${TARGET_SHA}"
        + "&status=completed&per_page=100"
    )
    assert "--paginate" in prod_preview_lines  # nosec B101
    assert "mapfile -t run_ids" in prod_preview_lines  # nosec B101
    assert "| head -n 1" not in prod_preview_lines  # nosec B101
    assert test_deploy_query in prod_preview_lines  # nosec B101
    assert 'select(.conclusion == "success" and .head_branch == "main")' in (  # nosec B101
        prod_preview_lines
    )
    assert "REQUESTED_SHA" in prod_preview_lines  # nosec B101
    assert "full 40-character commit SHA" in prod_preview_lines  # nosec B101
    assert "REQUESTED_SHA" in prod_apply_lines  # nosec B101
    assert "git rev-parse HEAD" not in prod_apply_lines  # nosec B101
    assert "make pulumi-plan" in prod_preview_lines  # nosec B101
    assert "make pulumi-plan" in test_preview_lines  # nosec B101
    assert "make pulumi-up-plan" in test_apply_lines  # nosec B101
    assert "decrypting secret value: cipher: message authentication failed" not in (  # nosec B101
        test_apply_lines
    )
    assert not re.search(r"(?m)^\s*make pulumi-up$", test_apply_lines)  # nosec B101
    assert "decrypting secret value: cipher: message authentication failed" not in (  # nosec B101
        prod_apply_lines
    )
    assert not re.search(r"(?m)^\s*make pulumi-up$", prod_apply_lines)  # nosec B101
    assert "make publish-pulumi-preview-summary" not in prod_preview_lines  # nosec B101
    assert "make publish-pulumi-preview-summary" not in test_preview_lines  # nosec B101


def test_pr_comment_workflows_gate_prod_after_successful_test_apply() -> None:
    """PR comments must run through test before production can plan or apply."""
    intake = yaml.safe_load(
        (WORKFLOWS_DIR / "pulumi-pr-commands.yml").read_text(encoding="utf-8")
    )
    runner = yaml.safe_load(
        (WORKFLOWS_DIR / "pulumi-pr-command-runner.yml").read_text(encoding="utf-8")
    )
    intake_lines = "\n".join(_run_lines(intake["jobs"]["dispatch"]["steps"]))
    preflight_lines = "\n".join(_run_lines(runner["jobs"]["preflight"]["steps"]))
    comment_result_lines = "\n".join(
        _run_lines(runner["jobs"]["comment_result"]["steps"])
    )
    test_apply_lines = "\n".join(_run_lines(runner["jobs"]["test_apply"]["steps"]))
    prod_apply_lines = "\n".join(_run_lines(runner["jobs"]["prod_apply"]["steps"]))

    assert _triggers(intake)["issue_comment"]["types"] == ["created"]  # nosec B101
    assert "github.event.issue.state == 'open'" in intake["jobs"]["dispatch"]["if"]  # nosec B101
    assert intake["permissions"] == {  # nosec B101
        "contents": "write",
        "issues": "write",
        "pull-requests": "read",
    }
    assert intake["jobs"]["dispatch"]["permissions"] == {  # nosec B101
        "contents": "write",
        "issues": "write",
        "pull-requests": "write",
    }
    assert "scripts/pulumi_pr_comment.py" in intake_lines  # nosec B101
    assert (
        intake_lines.count('gh api "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}"')
        == 1
    )  # nosec B101
    assert "event_type='pulumi-pr-command'" in intake_lines  # nosec B101
    assert "client_payload[head_sha]" in intake_lines  # nosec B101
    assert "gh pr comment" not in intake_lines  # nosec B101
    assert "/issues/${{ github.event.issue.number }}/comments" in intake_lines  # nosec B101
    assert "head_repo == github.repository" in str(intake)  # nosec B101
    assert "state == 'open'" in str(intake)  # nosec B101
    assert "merged == 'false'" in str(intake)  # nosec B101

    triggers = _triggers(runner)
    assert triggers["repository_dispatch"]["types"] == ["pulumi-pr-command"]  # nosec B101
    assert "workflow_dispatch" in triggers  # nosec B101
    assert runner["concurrency"]["cancel-in-progress"] is False  # nosec B101
    assert runner["permissions"] == {  # nosec B101
        "contents": "read",
        "issues": "read",
        "pull-requests": "read",
    }
    assert runner["jobs"]["preflight"]["permissions"] == {  # nosec B101
        "issues": "write",
        "pull-requests": "write",
    }
    assert runner["jobs"]["comment_result"]["permissions"] == {  # nosec B101
        "issues": "write",
        "pull-requests": "write",
    }

    assert "head_sha must be a full lowercase 40-character commit SHA" in (  # nosec B101
        preflight_lines
    )
    assert "actual_head_sha" in preflight_lines  # nosec B101
    assert "actual_head_repo" in preflight_lines  # nosec B101
    assert "actual_pr_state" in preflight_lines  # nosec B101
    assert (
        preflight_lines.count(
            'gh api "repos/${GITHUB_REPOSITORY}/pulls/${REQUEST_PR_NUMBER}"'
        )
        == 1
    )  # nosec B101
    assert "gh pr comment" not in preflight_lines  # nosec B101
    assert "/issues/${pr_number}/comments" in preflight_lines  # nosec B101
    assert "gh pr comment" not in comment_result_lines  # nosec B101
    assert "/issues/${pr_number}/comments" in comment_result_lines  # nosec B101
    assert "pull request is closed or merged" in preflight_lines  # nosec B101
    assert "pull request head moved after the command was queued" in preflight_lines  # nosec B101

    prod_preview = runner["jobs"]["prod_preview"]
    assert prod_preview["needs"] == ["preflight", "test_post_apply_drift"]  # nosec B101
    assert (
        "needs.test_post_apply_drift.result == 'success'"
        in (  # nosec B101
            prod_preview["if"]
        )
    )

    assert "make pulumi-plan" in "\n".join(  # nosec B101
        _run_lines(runner["jobs"]["test_preview"]["steps"])
    )
    assert "make test-destructive-diff" in "\n".join(  # nosec B101
        _run_lines(runner["jobs"]["test_destructive_diff"]["steps"])
    )
    assert "make test-iam-validation" in "\n".join(  # nosec B101
        _run_lines(runner["jobs"]["test_iam_validation"]["steps"])
    )
    assert "make pulumi-up-plan" in test_apply_lines  # nosec B101
    assert "decrypting secret value: cipher: message authentication failed" not in (  # nosec B101
        test_apply_lines
    )
    assert not re.search(r"(?m)^\s*make pulumi-up$", test_apply_lines)  # nosec B101
    assert "make test-drift" in "\n".join(  # nosec B101
        _run_lines(runner["jobs"]["test_post_apply_drift"]["steps"])
    )

    assert "make pulumi-plan" in "\n".join(  # nosec B101
        _run_lines(runner["jobs"]["prod_preview"]["steps"])
    )
    assert "make test-destructive-diff" in "\n".join(  # nosec B101
        _run_lines(runner["jobs"]["prod_destructive_diff"]["steps"])
    )
    assert "make test-iam-validation" in "\n".join(  # nosec B101
        _run_lines(runner["jobs"]["prod_iam_validation"]["steps"])
    )
    assert "make pulumi-up-plan" in prod_apply_lines  # nosec B101
    assert "decrypting secret value: cipher: message authentication failed" not in (  # nosec B101
        prod_apply_lines
    )
    assert not re.search(r"(?m)^\s*make pulumi-up$", prod_apply_lines)  # nosec B101
    assert "make test-drift" in "\n".join(  # nosec B101
        _run_lines(runner["jobs"]["prod_post_apply_drift"]["steps"])
    )


def test_multi_account_environment_docs_are_explicit() -> None:
    """Document AWS Secrets Manager-backed fixed CI configuration."""
    docs = "\n".join(
        (
            SECRETS_DOC.read_text(encoding="utf-8"),
            (PROJECT_ROOT / "docs" / "ci-guardrails.md").read_text(encoding="utf-8"),
            (PROJECT_ROOT / ".github" / "github-actions-secrets.md").read_text(
                encoding="utf-8"
            ),
            (PROJECT_ROOT / "docs" / "ci-architecture.md").read_text(encoding="utf-8"),
            (PROJECT_ROOT / "docs" / "security-operating-evidence.md").read_text(
                encoding="utf-8"
            ),
            (PROJECT_ROOT / "docs" / "sre-operations.md").read_text(encoding="utf-8"),
            (PROJECT_ROOT / "docs" / "aws-secrets-manager-ci-cutover.md").read_text(
                encoding="utf-8"
            ),
            (
                PROJECT_ROOT
                / "specs"
                / "issue-20-pulumi-esc-ci-config"
                / "architecture.md"
            ).read_text(encoding="utf-8"),
        )
    )
    normalized_docs = docs.lower()

    assert "aws secrets manager" in normalized_docs  # nosec B101
    assert "githubciconfigread" in normalized_docs  # nosec B101
    assert "pulumi cloud and pulumi esc are not used" in normalized_docs  # nosec B101
    assert "pulumi_access_token" in normalized_docs  # nosec B101
    assert "put-secret-value" in normalized_docs  # nosec B101
    assert "get-secret-value` for verification" in normalized_docs  # nosec B101
    assert "aws_test_pr_ci_config_role_arn" in normalized_docs  # nosec B101
    assert "aws_prod_preview_ci_config_role_arn" in normalized_docs  # nosec B101
    assert "githubciconfigreadrolearns" in normalized_docs  # nosec B101
    assert "pulumi-esc.json" not in normalized_docs  # nosec B101
    assert "pulumi/auth-actions" not in normalized_docs  # nosec B101
    assert "pulumi/esc-action" not in normalized_docs  # nosec B101
    assert (  # nosec B101
        "account-configuration boundary is the pulumi esc environment"
        not in normalized_docs
    )
    assert (  # nosec B101
        "load privileged account configuration from the correct fixed esc environment"
        not in normalized_docs
    )
    assert "aws secrets manager is the account-configuration boundary" in (  # nosec B101
        normalized_docs
    )
    assert "pulumiescsecretsreadrolearn" not in normalized_docs  # nosec B101
    assert "github environment" in normalized_docs  # nosec B101
    for variable_name in (
        "AWS_ACCOUNT_ID",
        "AWS_PREVIEW_ROLE_ARN",
        "AWS_APPLY_ROLE_ARN",
        "AWS_DRIFT_ROLE_ARN",
        "AWS_OPERATIONS_ALERT_TRIAGE_ROLE_ARN",
        "PULUMI_BACKEND_URL",
        "PULUMI_SECRETS_PROVIDER",
    ):
        assert variable_name in docs  # nosec B101
    for secret_id in (
        "/bootstrap-infrastructure/ci/test-pr",
        "/bootstrap-infrastructure/ci/test",
        "/bootstrap-infrastructure/ci/prod-preview",
        "/bootstrap-infrastructure/ci/prod",
    ):
        assert secret_id in docs  # nosec B101


def test_template_sync_workflows_keep_guardrails() -> None:
    """Lock down template sync permissions, concurrency, and schedules."""
    app_workflow = yaml.safe_load(
        (WORKFLOWS_DIR / "template-sync-app.yml").read_text(encoding="utf-8")
    )
    pat_workflow = yaml.safe_load(
        (WORKFLOWS_DIR / "template-sync-pat.yml").read_text(encoding="utf-8")
    )

    for workflow_name in TEMPLATE_SYNC_WORKFLOWS:
        workflow = yaml.safe_load(
            (WORKFLOWS_DIR / workflow_name).read_text(encoding="utf-8")
        )
        assert "schedule" in _triggers(workflow)
        assert "workflow_dispatch" in _triggers(workflow)
        assert workflow["concurrency"]["cancel-in-progress"] is True
        assert workflow["jobs"]["repo-sync"]["timeout-minutes"] == 20

    assert app_workflow["jobs"]["repo-sync"]["permissions"] == {"contents": "read"}
    assert (
        _checkout_step(
            app_workflow["jobs"]["repo-sync"]["steps"],
            workflow_name="template-sync-app.yml",
        )["with"]["persist-credentials"]
        is False
    )
    assert pat_workflow["jobs"]["repo-sync"]["permissions"] == {
        "contents": "write",
        "pull-requests": "write",
    }
    assert (
        _checkout_step(
            pat_workflow["jobs"]["repo-sync"]["steps"],
            workflow_name="template-sync-pat.yml",
        )["with"]["persist-credentials"]
        is False
    )


def test_bats_workflow_runs_on_push_and_pull_request() -> None:
    """Keep the CLI regression suite aligned with other local-only checks."""
    workflow = yaml.safe_load(
        (WORKFLOWS_DIR / "bats-tests.yml").read_text(encoding="utf-8")
    )
    triggers = _triggers(workflow)

    assert triggers["push"]["branches"] == ["main"]
    assert "pull_request" in triggers


def test_quality_workflow_runs_quality_gates_on_push_and_pull_request() -> None:
    """Keep the blocking Python quality gates wired into CI."""
    workflow = yaml.safe_load(
        (WORKFLOWS_DIR / "python-quality.yml").read_text(encoding="utf-8")
    )
    triggers = _triggers(workflow)
    jobs = workflow.get("jobs", {})

    assert "ruff" in jobs, "python-quality.yml missing 'ruff' job"
    assert "ty" in jobs, "python-quality.yml missing 'ty' job"
    assert "maintainability" in jobs
    assert "architecture" in jobs
    assert "dependency_hygiene" in jobs
    assert "coverage" in jobs
    assert (
        jobs["coverage"]["env"]["PULUMI_BACKEND_URL"]
        == "file:///workspace/.pulumi-backend"
    )

    ruff_runs = [step.get("run") for step in jobs.get("ruff", {}).get("steps", [])]
    ty_runs = [step.get("run") for step in jobs.get("ty", {}).get("steps", [])]
    maintainability_runs = [
        step.get("run") for step in jobs.get("maintainability", {}).get("steps", [])
    ]
    architecture_runs = [
        step.get("run") for step in jobs.get("architecture", {}).get("steps", [])
    ]
    dependency_hygiene_runs = [
        step.get("run") for step in jobs.get("dependency_hygiene", {}).get("steps", [])
    ]
    coverage_runs = [
        step.get("run") for step in jobs.get("coverage", {}).get("steps", [])
    ]

    assert triggers["push"]["branches"] == ["main"]
    assert "pull_request" in triggers
    assert any(run and "make test-ruff" in run for run in ruff_runs)
    assert any(run and "make test-ty" in run for run in ty_runs)
    assert any(
        run and "make test-maintainability" in run for run in maintainability_runs
    )
    assert any(run and "make test-architecture" in run for run in architecture_runs)
    assert any(
        run and "make test-dependency-hygiene" in run for run in dependency_hygiene_runs
    )
    assert any(run and "make test-coverage" in run for run in coverage_runs)


def test_policy_workflow_runs_on_push_and_pull_request() -> None:
    """Keep Pulumi policy validation wired into the PR check surface."""
    workflow = yaml.safe_load(
        (WORKFLOWS_DIR / "pulumi-policy.yml").read_text(encoding="utf-8")
    )
    triggers = _triggers(workflow)
    steps = workflow["jobs"]["policy"]["steps"]
    runs = [step.get("run") for step in steps if step.get("run")]

    assert triggers["push"]["branches"] == ["main"]
    assert "pull_request" in triggers
    assert any(run and "make test-policy" in run for run in runs)


def test_operator_docs_are_present_and_indexed() -> None:
    """Keep the root documentation discoverable from the handbook and README."""
    docs_index = DOCS_INDEX.read_text(encoding="utf-8")
    root_readme = ROOT_README.read_text(encoding="utf-8")

    for doc_name in DETAILED_DOCS:
        assert (PROJECT_ROOT / "docs" / doc_name).exists()
        assert doc_name in docs_index
        assert f"docs/{doc_name}" in root_readme

    assert "/home/dev/.venvs/bootstrap-infrastructure" not in docs_index
    assert "/home/dev/.venvs/bootstrap-infrastructure" not in root_readme
    assert "docker-compose.yml" in docs_index
    assert "docker-compose.yml" in root_readme


def test_testing_docs_call_out_full_coverage_contract() -> None:
    """Keep the operator docs explicit about mandatory coverage contracts."""
    testing_doc = (PROJECT_ROOT / "docs" / "testing.md").read_text(encoding="utf-8")
    guardrails_doc = (PROJECT_ROOT / "docs" / "pulumi-guardrails.md").read_text(
        encoding="utf-8"
    )

    assert "100% line coverage" in testing_doc
    assert "100% branch coverage" in testing_doc
    assert "100% line coverage" in guardrails_doc


def test_ci_architecture_docs_match_make_entrypoints() -> None:
    """Keep the CI architecture guide aligned with the current make targets."""
    architecture_doc = (PROJECT_ROOT / "docs" / "ci-architecture.md").read_text(
        encoding="utf-8"
    )
    quality_doc = (PROJECT_ROOT / "docs" / "ci-quality-gates.md").read_text(
        encoding="utf-8"
    )

    assert "Docker-backed CI workflows" in architecture_doc
    assert "GitHub-native" in architecture_doc
    assert "CodeQL" in architecture_doc
    assert "prerequisite sanity check" in architecture_doc
    assert "Pulumi structural tests" in architecture_doc
    assert "make ci-pr" in architecture_doc
    assert "tracked Git content" in quality_doc
    assert "separate privileged step" in quality_doc
    assert "excluded from `make ci-pr`" in quality_doc
    assert "without live AWS credentials" in quality_doc


def test_agents_guidance_keeps_make_start_wording_current() -> None:
    """Keep agent-facing CI bootstrap guidance aligned with the current workflow."""
    agents_doc = (PROJECT_ROOT / "AGENTS.md").read_text(encoding="utf-8")

    assert "Run `make start` when changing Docker-backed CI jobs" in agents_doc


def test_sre_docs_map_blocking_ci_checks_back_to_local_commands() -> None:
    """Keep the day-2 guide aligned with the blocking check surface."""
    operations_doc = (PROJECT_ROOT / "docs" / "sre-operations.md").read_text(
        encoding="utf-8"
    )

    assert "`Maintainability` -> `make test-maintainability`" in operations_doc
    assert "`Architecture` -> `make test-architecture`" in operations_doc
    assert "`Dependency Hygiene` -> `make test-dependency-hygiene`" in operations_doc
    assert (  # nosec B101
        "`Coverage` -> `make test-unit && make test-integration-unprivileged && "
        "make test-policy && make test-coverage`" in operations_doc
    )
    assert "`Integration` -> `make test-integration-unprivileged`" in operations_doc  # nosec B101
    assert "`Local Battery` -> `make ci-pr-unprivileged`" in operations_doc  # nosec B101
    assert "`Bandit` -> `make test-bandit`" in operations_doc
    assert "`Yamllint` -> `make test-yaml`" in operations_doc
    assert "`Hadolint` -> `make test-dockerfile`" in operations_doc
    assert "stack change-secrets-provider" in operations_doc  # nosec B101
    assert "awskms://alias/ALIAS_NAME?region=REGION" in operations_doc  # nosec B101
