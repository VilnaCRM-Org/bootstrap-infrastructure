"""Structural tests for release automation and repository hardening."""

import os
import re
import stat
import subprocess
from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS_DIR = PROJECT_ROOT / ".github" / "workflows"
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

    assert "python:3.11.9-slim-bookworm@" in dockerfile_text
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
        "PULUMI_ACCESS_TOKEN",
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


def test_multi_account_workflows_use_environment_scoped_oidc_contracts() -> None:
    """Bind privileged AWS jobs to GitHub environments and account allow-lists."""
    expected_environments = {"test", "prod-preview", "prod"}
    preview_role = "${{ env.AWS_PREVIEW_ROLE_ARN }}"
    apply_role = "${{ env.AWS_APPLY_ROLE_ARN }}"
    drift_role = "${{ env.AWS_DRIFT_ROLE_ARN }}"
    expected_contracts_by_job = {
        ("nightly-guardrails.yml", "test_drift_detection"): ("test", drift_role),
        ("nightly-guardrails.yml", "prod_drift_detection"): (
            "prod-preview",
            drift_role,
        ),
        ("pulumi-pr-guardrails.yml", "preview"): ("test", preview_role),
        ("pulumi-pr-guardrails.yml", "iam_validation"): ("test", preview_role),
        ("pulumi-prod.yml", "preview"): ("prod-preview", preview_role),
        ("pulumi-prod.yml", "iam_validation"): ("prod-preview", preview_role),
        ("pulumi-prod.yml", "apply"): ("prod", apply_role),
        ("pulumi-prod.yml", "post_apply_drift"): ("prod-preview", drift_role),
        ("pulumi-test-deploy.yml", "preview"): ("test", preview_role),
        ("pulumi-test-deploy.yml", "iam_validation"): ("test", preview_role),
        ("pulumi-test-deploy.yml", "apply"): ("test", apply_role),
        ("pulumi-test-deploy.yml", "post_apply_drift"): ("test", drift_role),
    }
    environment_jobs = [
        (workflow_name, job_name, job, environment_name)
        for workflow_name, job_name, job in _workflow_jobs()
        if (environment_name := _environment_name(job)) is not None
    ]

    assert {item[3] for item in environment_jobs} == expected_environments  # nosec B101

    for workflow_name, job_name, job, environment_name in environment_jobs:
        assert environment_name in expected_environments  # nosec B101

        job_env = job.get("env", {})
        role_message = (
            f"{workflow_name}:{job_name} must use environment-scoped "
            "purpose-specific role variables directly from the OIDC step"
        )
        assert "AWS_OIDC_ROLE_ARN" not in job_env, role_message  # nosec B101

        oidc_steps = [
            step
            for step in job.get("steps", [])
            if step.get("uses", "").startswith("aws-actions/configure-aws-credentials@")
        ]
        if not oidc_steps:
            continue

        expected_environment, expected_role = expected_contracts_by_job[
            (workflow_name, job_name)
        ]
        assert environment_name == expected_environment  # nosec B101
        assert job.get("permissions", {}).get("id-token") == "write"  # nosec B101
        for step in oidc_steps:
            step_with = step["with"]
            assert step_with["role-to-assume"] == expected_role  # nosec B101
            assert step_with["aws-region"] == "${{ env.AWS_REGION }}"  # nosec B101
            assert step_with["allowed-account-ids"] == "${{ env.AWS_ACCOUNT_ID }}"  # nosec B101


def test_prod_workflow_requires_successful_test_deploy_for_same_sha() -> None:
    """Production release input must already have a green test deployment."""
    prod_workflow = yaml.safe_load(
        (WORKFLOWS_DIR / "pulumi-prod.yml").read_text(encoding="utf-8")
    )
    test_workflow = yaml.safe_load(
        (WORKFLOWS_DIR / "pulumi-test-deploy.yml").read_text(encoding="utf-8")
    )
    prod_preview_lines = "\n".join(
        _run_lines(prod_workflow["jobs"]["preview"]["steps"])
    )
    prod_apply_lines = "\n".join(_run_lines(prod_workflow["jobs"]["apply"]["steps"]))
    test_preview_lines = "\n".join(
        _run_lines(test_workflow["jobs"]["preview"]["steps"])
    )

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
    assert "make publish-pulumi-preview-summary" not in prod_preview_lines  # nosec B101
    assert "make publish-pulumi-preview-summary" not in test_preview_lines  # nosec B101


def test_multi_account_environment_docs_are_explicit() -> None:
    """Document that account-specific CI config belongs to GitHub environments."""
    docs = "\n".join(
        (
            SECRETS_DOC.read_text(encoding="utf-8"),
            (PROJECT_ROOT / "docs" / "ci-guardrails.md").read_text(encoding="utf-8"),
        )
    )
    normalized_docs = docs.lower()

    assert "environment-scoped configuration" in normalized_docs  # nosec B101
    assert "github environment" in normalized_docs  # nosec B101
    for environment_name in ("test", "prod-preview", "prod"):
        assert environment_name in docs  # nosec B101
    for variable_name in (
        "AWS_ACCOUNT_ID",
        "AWS_PREVIEW_ROLE_ARN",
        "AWS_APPLY_ROLE_ARN",
        "AWS_DRIFT_ROLE_ARN",
        "PULUMI_BACKEND_URL",
        "PULUMI_SECRETS_PROVIDER",
    ):
        assert variable_name in docs  # nosec B101


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
