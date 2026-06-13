"""Scaffold-level checks for the new ``pulumi/governance`` Pulumi project (E1.S5).

These assert the project manifest + per-stack config + thin entrypoint satisfy
the Story 1.6 contract WITHOUT running ``pulumi preview`` (the full governance
structural test is E6.S1). They guard the two-account model (test ->
``891377212104``, prod -> ``933245420672``, region ``eu-central-1``), the
``awskms://`` secrets provider, the non-discovered example stack, and the thin
entrypoint that resolves settings + catalog and exports the §3.4 outputs.
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
PROJECT_DIR = ROOT / "pulumi" / "governance"
SCRIPTS_DIR = ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))
TEST_ACCOUNT_ID = "891377212104"
PROD_ACCOUNT_ID = "933245420672"
REGION = "eu-central-1"
LEGACY_PULUMI_PASSPHRASE_ENV = "_".join(("PULUMI", "CONFIG", "PASSPHRASE"))


def _stack_config(stack_file: str) -> dict[str, str]:
    """Return the parsed ``config`` block for a governance stack file."""
    payload = yaml.safe_load((PROJECT_DIR / stack_file).read_text())
    return payload["config"]


def test_manifest_declares_governance_python_project() -> None:
    """Manifest name is exactly ``governance`` on the python runtime."""
    manifest = yaml.safe_load((PROJECT_DIR / "Pulumi.yaml").read_text())

    assert manifest["name"] == "governance"  # nosec B101
    assert manifest["runtime"]["name"] == "python"  # nosec B101
    assert "options" not in manifest["runtime"]  # nosec B101


def test_stack_files_are_valid_yaml_with_expected_set() -> None:
    """Exactly the example/test/prod stack files exist and parse as YAML."""
    stack_file_names = {path.name for path in PROJECT_DIR.glob("Pulumi.*.yaml")}

    assert stack_file_names == {  # nosec B101
        "Pulumi.example.yaml",
        "Pulumi.prod.yaml",
        "Pulumi.test.yaml",
    }
    for stack_file in stack_file_names:
        assert isinstance(  # nosec B101
            yaml.safe_load((PROJECT_DIR / stack_file).read_text()), dict
        )


def test_test_stack_pins_its_own_account_and_region() -> None:
    """The test stack resolves to ``891377212104`` in ``eu-central-1``."""
    config = _stack_config("Pulumi.test.yaml")

    assert config["governance:awsAccountId"] == TEST_ACCOUNT_ID  # nosec B101
    assert config["governance:environment"] == "test"  # nosec B101
    assert config["aws:region"] == REGION  # nosec B101
    assert (  # nosec B101
        config["governance:repositoryCatalogPath"] == "../repositories.governance.json"
    )
    assert (  # nosec B101
        f"::{TEST_ACCOUNT_ID}:oidc-provider/"
        in config["governance:githubOidcProviderArn"]
    )


def test_prod_stack_pins_its_own_account_and_region() -> None:
    """The prod stack resolves to ``933245420672`` in ``eu-central-1``."""
    config = _stack_config("Pulumi.prod.yaml")

    assert config["governance:awsAccountId"] == PROD_ACCOUNT_ID  # nosec B101
    assert config["governance:environment"] == "prod"  # nosec B101
    assert config["aws:region"] == REGION  # nosec B101
    assert (  # nosec B101
        config["governance:repositoryCatalogPath"] == "../repositories.governance.json"
    )
    assert (  # nosec B101
        f"::{PROD_ACCOUNT_ID}:oidc-provider/"
        in config["governance:githubOidcProviderArn"]
    )


def test_secrets_provider_uses_awskms_per_stack() -> None:
    """Both real stacks declare an ``awskms://`` secrets provider for their env."""
    for stack_file, env in (("Pulumi.test.yaml", "test"), ("Pulumi.prod.yaml", "prod")):
        stack_text = (PROJECT_DIR / stack_file).read_text()
        config = yaml.safe_load(stack_text)

        assert config["secretsprovider"].startswith("awskms://")  # nosec B101
        assert (  # nosec B101
            f"pulumi-platform-bootstrap-{env}"
            in config["config"]["governance:pulumiSecretsProvider"]
        )
        assert "--secrets-provider" in stack_text  # nosec B101


def test_each_stack_pins_only_its_own_account() -> None:
    """The test stack omits the prod account and vice versa."""
    test_text = (PROJECT_DIR / "Pulumi.test.yaml").read_text()
    prod_text = (PROJECT_DIR / "Pulumi.prod.yaml").read_text()

    assert PROD_ACCOUNT_ID not in test_text  # nosec B101
    assert TEST_ACCOUNT_ID not in prod_text  # nosec B101


def test_example_stack_is_not_discovered() -> None:
    """The example stack is excluded from committed stack discovery."""
    script_support = importlib.import_module("_script_support")
    discovered = script_support.discover_stacks(PROJECT_DIR, None)

    assert "example" not in discovered  # nosec B101
    assert set(discovered) == {"test", "prod"}  # nosec B101


def test_stack_files_carry_no_inline_secret_metadata() -> None:
    """Committed stack files contain non-secret config only (no passphrase/salt)."""
    for stack_file in ("Pulumi.test.yaml", "Pulumi.prod.yaml", "Pulumi.example.yaml"):
        stack_text = (PROJECT_DIR / stack_file).read_text()

        assert "secure:" not in stack_text  # nosec B101
        assert "encryptedkey" not in stack_text  # nosec B101
        assert "encryptionsalt" not in stack_text  # nosec B101
        assert "PULUMI_ACCESS_TOKEN" not in stack_text  # nosec B101
        assert LEGACY_PULUMI_PASSPHRASE_ENV not in stack_text  # nosec B101


def test_entrypoint_builds_governance_stack_and_exports_outputs() -> None:
    """The thin entrypoint wires ``GovernanceStack`` and exports the §3.4 keys."""
    entrypoint = (PROJECT_DIR / "__main__.py").read_text()

    assert "GovernanceStack" in entrypoint  # nosec B101
    assert "GovernanceStackArgs" in entrypoint  # nosec B101
    assert 'expected_account_id=cfg.get("awsAccountId")' in entrypoint  # nosec B101
    assert (  # nosec B101
        'oidc_provider_arn=cfg.get("githubOidcProviderArn")' in entrypoint
    )
    for export_name in ("perRepo", "oidcProviderArn", "managedRepositories"):
        assert f'pulumi.export("{export_name}"' in entrypoint  # nosec B101


def test_entrypoint_pulumi_dir_default_targets_managed_repo_project_root() -> None:
    """The pulumiDir default is the repo-root ``pulumi`` for downstream repos (F5).

    ``pulumi_dir`` flows into each managed repo's generated CI-config payload, and
    the managed *-infrastructure repo hosts its Pulumi project at the repo-root
    ``pulumi/`` directory (architecture §8.1) — never at ``pulumi/governance``
    (that path exists only inside THIS bootstrap repo). A wrong default would point
    the downstream self-deploy at a non-existent ``pulumi/governance`` directory.
    """
    entrypoint = (PROJECT_DIR / "__main__.py").read_text()

    assert 'pulumi_dir=cfg.get("pulumiDir") or "pulumi"' in entrypoint  # nosec B101
    assert 'or "pulumi/governance"' not in entrypoint  # nosec B101


def test_requirements_mirror_bootstrap_project() -> None:
    """The governance requirements pin pulumi-aws like github-ci-bootstrap."""
    requirements = (PROJECT_DIR / "requirements.txt").read_text()

    assert "-r ../requirements.txt" in requirements  # nosec B101
    assert "pulumi-aws" in requirements  # nosec B101
