"""Structure-only checks for the ``user-service-infrastructure`` scaffold (E5.S1).

These assert the in-repo template assets under ``pulumi/user-service-infrastructure/``
satisfy the Story 5.1 contract WITHOUT running ``pulumi preview`` — the scaffold
*consumes* governance-provided resources (state bucket, KMS key/alias, deploy roles)
and repo variables that only exist after the operator applies governance, so preview
is blocked until then (FEASIBILITY-6). The tests cover:

- asset presence (manifest, two real stacks, example, thin ``__main__.py``, docs),
- two-account model (test -> ``891377212104``, prod -> ``933245420672``;
  region ``eu-central-1``),
- the scaffold references the governance-provided backend URL
  (``s3://pulumi-user-service-infrastructure-{env}-state``) + secrets alias,
- the scaffold creates NO IAM roles / OIDC trust for itself,
- no inline secrets / passphrase / static AWS keys,
- the example stack is excluded from committed stack discovery.

Name parity for the deploy/config-read role names is asserted against the
rendered governance helper output (single source of truth) in
``test_user_service_role_name_parity``.
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
SCAFFOLD_DIR = ROOT / "pulumi" / "user-service-infrastructure"
PULUMI_DIR = SCAFFOLD_DIR / "pulumi"
SCRIPTS_DIR = ROOT / "scripts"
INFRA_DIR = ROOT / "pulumi"
for extra_path in (str(SCRIPTS_DIR), str(INFRA_DIR)):
    if extra_path not in sys.path:
        sys.path.insert(0, extra_path)

REPO_SLUG = "user-service-infrastructure"
TEST_ACCOUNT_ID = "891377212104"
PROD_ACCOUNT_ID = "933245420672"
REGION = "eu-central-1"
LEGACY_PULUMI_PASSPHRASE_ENV = "_".join(("PULUMI", "CONFIG", "PASSPHRASE"))
# Markers that must never appear in DEPLOYABLE scaffold assets (the Pulumi program
# + stack files). The repo-local docs (AGENTS.md/README.md) legitimately *name*
# these markers to forbid them, so the doc scan below only rejects real key VALUES
# (an ``AKIA`` access-key-id prefix), not the prohibition prose.
_STATIC_AWS_KEY_MARKERS = (
    "aws_access_key_id",
    "aws_secret_access_key",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AKIA",
)
_DEPLOYABLE_SUFFIXES = (".yaml", ".yml", ".py")


def _stack_config(stack_file: str) -> dict[str, str]:
    """Return the parsed ``config`` block for a scaffold stack file."""
    payload = yaml.safe_load((PULUMI_DIR / stack_file).read_text())
    return payload["config"]


def test_scaffold_assets_are_present() -> None:
    """Every Story 5.1 template asset exists at the documented path."""
    for relative in (
        "pulumi/Pulumi.yaml",
        "pulumi/Pulumi.test.yaml",
        "pulumi/Pulumi.prod.yaml",
        "pulumi/Pulumi.example.yaml",
        "pulumi/__main__.py",
        "AGENTS.md",
        "README.md",
    ):
        assert (SCAFFOLD_DIR / relative).is_file()  # nosec B101


def test_manifest_declares_user_service_python_project() -> None:
    """Manifest name is exactly the repo slug on the python runtime."""
    manifest = yaml.safe_load((PULUMI_DIR / "Pulumi.yaml").read_text())

    assert manifest["name"] == REPO_SLUG  # nosec B101
    assert manifest["runtime"]["name"] == "python"  # nosec B101
    assert "options" not in manifest["runtime"]  # nosec B101


def test_stack_files_are_valid_yaml_with_expected_set() -> None:
    """Exactly the example/test/prod stack files exist and parse as YAML."""
    stack_file_names = {path.name for path in PULUMI_DIR.glob("Pulumi.*.yaml")}

    assert stack_file_names == {  # nosec B101
        "Pulumi.example.yaml",
        "Pulumi.prod.yaml",
        "Pulumi.test.yaml",
    }
    for stack_file in stack_file_names:
        assert isinstance(  # nosec B101
            yaml.safe_load((PULUMI_DIR / stack_file).read_text()), dict
        )


def test_test_stack_pins_its_own_account_region_and_repo() -> None:
    """The test stack resolves to ``891377212104`` in ``eu-central-1``."""
    config = _stack_config("Pulumi.test.yaml")

    assert config["aws:region"] == REGION  # nosec B101
    assert config[f"{REPO_SLUG}:environment"] == "test"  # nosec B101
    assert config[f"{REPO_SLUG}:repoSlug"] == REPO_SLUG  # nosec B101
    assert config[f"{REPO_SLUG}:awsAccountId"] == TEST_ACCOUNT_ID  # nosec B101


def test_prod_stack_pins_its_own_account_region_and_repo() -> None:
    """The prod stack resolves to ``933245420672`` in ``eu-central-1``."""
    config = _stack_config("Pulumi.prod.yaml")

    assert config["aws:region"] == REGION  # nosec B101
    assert config[f"{REPO_SLUG}:environment"] == "prod"  # nosec B101
    assert config[f"{REPO_SLUG}:repoSlug"] == REPO_SLUG  # nosec B101
    assert config[f"{REPO_SLUG}:awsAccountId"] == PROD_ACCOUNT_ID  # nosec B101


def test_each_stack_pins_only_its_own_account() -> None:
    """The test stack omits the prod account and vice versa (blast-radius)."""
    test_text = (PULUMI_DIR / "Pulumi.test.yaml").read_text()
    prod_text = (PULUMI_DIR / "Pulumi.prod.yaml").read_text()

    assert PROD_ACCOUNT_ID not in test_text  # nosec B101
    assert TEST_ACCOUNT_ID not in prod_text  # nosec B101


def test_stacks_consume_governance_backend_and_secrets_alias() -> None:
    """Each stack references the governance-provided backend URL + secrets alias."""
    for stack_file, env, account in (
        ("Pulumi.test.yaml", "test", TEST_ACCOUNT_ID),
        ("Pulumi.prod.yaml", "prod", PROD_ACCOUNT_ID),
    ):
        stack_text = (PULUMI_DIR / stack_file).read_text()
        document = yaml.safe_load(stack_text)
        config = document["config"]
        backend_url = f"s3://pulumi-{REPO_SLUG}-{env}-state"
        alias = f"alias/pulumi-{REPO_SLUG}-{env}-secrets"
        provider = f"awskms://{alias}?region={REGION}"

        assert backend_url in stack_text  # nosec B101
        assert config[f"{REPO_SLUG}:pulumiBackendUrl"] == backend_url  # nosec B101
        assert config[f"{REPO_SLUG}:pulumiSecretsProvider"] == provider  # nosec B101
        assert document["secretsprovider"] == provider  # nosec B101
        assert document["secretsprovider"].startswith("awskms://")  # nosec B101
        assert "--secrets-provider" in stack_text  # nosec B101
        # The scaffold consumes its own account's resources, never the platform key.
        assert "pulumi-platform-bootstrap" not in stack_text  # nosec B101


def test_secrets_alias_account_is_implicit_not_pinned() -> None:
    """The secrets alias is account-agnostic (alias, not a cross-account ARN)."""
    test_text = (PULUMI_DIR / "Pulumi.test.yaml").read_text()
    prod_text = (PULUMI_DIR / "Pulumi.prod.yaml").read_text()

    # No cross-account leakage through the secrets provider string.
    assert f"alias/pulumi-{REPO_SLUG}-test-secrets" in test_text  # nosec B101
    assert f"alias/pulumi-{REPO_SLUG}-prod-secrets" in prod_text  # nosec B101


def test_stack_files_carry_no_inline_secret_metadata() -> None:
    """Committed stack files contain non-secret config only (no passphrase/salt)."""
    for stack_file in ("Pulumi.test.yaml", "Pulumi.prod.yaml", "Pulumi.example.yaml"):
        stack_text = (PULUMI_DIR / stack_file).read_text()

        assert "secure:" not in stack_text  # nosec B101
        assert "encryptedkey" not in stack_text  # nosec B101
        assert "encryptionsalt" not in stack_text  # nosec B101
        assert "PULUMI_ACCESS_TOKEN" not in stack_text  # nosec B101
        assert LEGACY_PULUMI_PASSPHRASE_ENV not in stack_text  # nosec B101


def test_scaffold_assets_carry_no_static_aws_keys() -> None:
    """No static AWS key material anywhere in the scaffold (OIDC-only posture).

    Deployable assets (Pulumi program + stack YAML) must contain none of the
    static-key markers at all. The repo-local Markdown docs forbid those markers
    by name, so they are scanned only for a real access-key-id ``AKIA`` value.
    """
    for path in SCAFFOLD_DIR.rglob("*"):
        if not path.is_file():
            continue
        text = path.read_text()
        if path.suffix in _DEPLOYABLE_SUFFIXES and path.name != "docker-compose.yml":
            for marker in _STATIC_AWS_KEY_MARKERS:
                assert marker not in text  # nosec B101
        else:
            assert "AKIA" not in text  # nosec B101


def test_entrypoint_consumes_governance_resources_and_creates_no_iam() -> None:
    """The thin ``__main__.py`` consumes the backend/KMS, never creating IAM/OIDC."""
    entrypoint = (PULUMI_DIR / "__main__.py").read_text()

    # Consumes the governance-provided backend + secrets provider via config.
    assert "pulumiBackendUrl" in entrypoint  # nosec B101
    assert "pulumiSecretsProvider" in entrypoint  # nosec B101
    assert "repoSlug" in entrypoint  # nosec B101

    # Creates no IAM roles / OIDC trust for itself — those are governance-owned.
    for forbidden in (
        "aws.iam.Role",
        "aws.iam.RolePolicy",
        "aws.iam.Policy",
        "OpenIdConnectProvider",
        "GitHubCiBootstrap",
        "GovernanceStack",
        "RepoGovernance",
        "assume_role_policy",
        "AssumeRoleWithWebIdentity",
    ):
        assert forbidden not in entrypoint  # nosec B101


def test_example_stack_is_not_discovered() -> None:
    """The example stack is excluded from committed stack discovery."""
    import _script_support  # noqa: PLC0415

    discovered = _script_support.discover_stacks(PULUMI_DIR, None)

    assert "example" not in discovered  # nosec B101
    assert set(discovered) == {"test", "prod"}  # nosec B101


def test_scaffold_is_outside_top_level_project_discovery() -> None:
    """The scaffold is nested and never shadows the real bootstrap-infra project."""
    top_level_stacks = {path.name for path in (ROOT / "pulumi").glob("Pulumi.*.yaml")}

    # The scaffold's stacks live under pulumi/user-service-infrastructure/pulumi/,
    # so they are NOT in the top-level pulumi/ stack glob that the makefile targets.
    assert "Pulumi.test.yaml" in top_level_stacks  # nosec B101
    assert not (ROOT / "pulumi" / "Pulumi.user-service-infrastructure.yaml").exists()  # nosec B101


def test_user_service_role_name_parity() -> None:
    """Scaffold-referenced governance role names are byte-equal to rendered names.

    The scaffold itself references the governance-provided backend/alias (asserted
    above); the deploy/config-read ROLE names it will consume via repo-variables
    (set by the operator from the governance ``githubVariables`` output) must match
    the names the governance component renders for this repo. This test pins the
    rendered names so any drift (e.g. a ``user-service`` short-name) fails CI; the
    self-deploy template (E5.S2) asserts byte-equality against these same names.
    """
    from infra.bootstrap_settings import BootstrapSettings  # noqa: PLC0415
    from infra.ci_bootstrap import _ci_role_name  # noqa: PLC0415
    from infra.ci_config import _ci_config_read_role_name  # noqa: PLC0415

    def _settings(env: str) -> BootstrapSettings:
        return BootstrapSettings(
            org="VilnaCRM-Org",
            repo=None,
            environment=env,
            owner="platform",
            cost_center="core",
            data_classification="internal",
            criticality="high",
            retention_class="standard",
            github_branch="main",
            logging_prefix="company",
            replication_region="eu-west-1",
            github_token=None,
            github_oidc_provider_arn=None,
        )

    test_settings = _settings("test")
    project = test_settings.sanitize_bucket_component(REPO_SLUG, "repoSlug").replace(
        ".", "-"
    )

    assert project == REPO_SLUG  # nosec B101 (full slug is the canonical {project})
    assert (  # nosec B101
        _ci_role_name(test_settings, "apply", project)
        == "GitHubCiApply-user-service-infrastructure-test"
    )
    assert (  # nosec B101
        _ci_role_name(test_settings, "preview", project)
        == "GitHubCiPreview-user-service-infrastructure-test"
    )
    assert (  # nosec B101
        _ci_role_name(test_settings, "drift", project)
        == "GitHubCiDrift-user-service-infrastructure-test"
    )
    assert (  # nosec B101
        _ci_config_read_role_name(test_settings, "test", REPO_SLUG)
        == "GitHubCiConfigRead-user-service-infrastructure-test"
    )
    prod_settings = _settings("prod")
    assert (  # nosec B101
        _ci_role_name(prod_settings, "apply", project)
        == "GitHubCiApply-user-service-infrastructure-prod"
    )
    assert (  # nosec B101
        _ci_config_read_role_name(prod_settings, "prod-preview", REPO_SLUG)
        == "GitHubCiConfigRead-user-service-infrastructure-prod-preview"
    )
