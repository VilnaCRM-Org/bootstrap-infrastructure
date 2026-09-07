"""Governance retention and exact owned-vault authorization regressions."""

import json
from dataclasses import replace
from pathlib import Path

import pytest
import yaml
from iam_statement_matcher import iam_statement_matches
from infra import backup, config
from infra.automation import _automation_policy, _automation_policy_documents
from infra.utils.outputs import future_output
from pulumi.runtime.sync_await import _sync_await


@pytest.mark.parametrize("environment", ["test", "prod"])
def test_backup_lock_preserves_plan_and_reversible_protection(
    pulumi_mocks, monkeypatch, environment
):
    captured = []
    original = backup.aws.backup.VaultLockConfiguration

    def capture(*args, **kwargs):
        captured.append(kwargs)
        return original(*args, **kwargs)

    monkeypatch.setattr(backup.aws.backup, "VaultLockConfiguration", capture)
    component = backup.S3BackupPlan(
        "retention",
        settings=replace(config.settings, environment=environment),
        backup_target_arns=["arn:aws:s3:::existing-state"],
    )
    assert _sync_await(future_output(component.vault_lock.min_retention_days)) == 90
    _sync_await(future_output(component.plan.rules))
    assert captured[0]["opts"].protect is True
    assert captured[0]["opts"].parent is component
    lock = next(
        state
        for typ, _, state in pulumi_mocks.resources
        if typ == "aws:backup/vaultLockConfiguration:VaultLockConfiguration"
    )
    assert lock["backupVaultName"] == "retention-vault"
    assert lock["minRetentionDays"] == 90
    assert "changeableForDays" not in lock
    assert "maxRetentionDays" not in lock
    plan = next(
        state
        for typ, _, state in pulumi_mocks.resources
        if typ == "aws:backup/plan:Plan"
    )
    assert plan["rules"][0]["lifecycle"]["deleteAfter"] == 90
    assert plan["rules"][0]["targetVaultName"] == lock["backupVaultName"]


@pytest.mark.parametrize(
    "environment,account,suffix",
    [
        ("test", "891377212104", "3b9f5bf"),
        ("prod", "933245420672", "3dab3a7"),
    ],
)
def test_only_exact_owned_vault_receives_constrained_put(
    pulumi_mocks, environment, account, suffix
):
    arn = f"arn:aws:backup:eu-central-1:{account}:backup-vault:s3-backup-vault-{suffix}"
    settings = replace(
        config.settings,
        environment=environment,
        repo="bootstrap-infrastructure",
        platform_backup_vault_arn=arn,
    )
    original = json.loads(
        _automation_policy(
            account, replace(settings, platform_backup_vault_arn=None), settings.repo
        )
    )
    policy = json.loads(_automation_policy(account, settings, settings.repo))
    grant = next(
        s
        for s in policy["Statement"]
        if s["Sid"] == "ConfigureBootstrapBackupRetentionLock"
    )
    assert [s for s in policy["Statement"] if s != grant] == original["Statement"]
    assert grant["Condition"] == {
        "StringEquals": {
            "aws:ResourceTag/Environment": environment,
            "aws:ResourceTag/Purpose": "s3-backup",
        },
        "NumericEquals": {"backup:MinRetentionDays": "90"},
        "Null": {"backup:ChangeableForDays": "true", "backup:MaxRetentionDays": "true"},
    }
    assert iam_statement_matches(grant, "backup:PutBackupVaultLockConfiguration", arn)
    for foreign in (
        arn + "other",
        arn.replace("eu-central-1", "eu-west-1"),
        arn.replace(account, "111111111111"),
    ):
        assert not iam_statement_matches(
            grant, "backup:PutBackupVaultLockConfiguration", foreign
        )
    for action in (
        "backup:DeleteBackupVaultLockConfiguration",
        "backup:DeleteRecoveryPoint",
        "backup:UpdateRecoveryPointLifecycle",
    ):
        assert not any(
            iam_statement_matches(s, action, arn)
            for s in policy["Statement"]
            if s["Effect"] == "Allow"
        )
    # Existing policy split/size validation must include the new grant exactly once.
    documents = _automation_policy_documents(account, settings, settings.repo)
    assert (
        sum("ConfigureBootstrapBackupRetentionLock" in text for _, text in documents)
        == 1
    )


@pytest.mark.parametrize(
    "arn",
    [
        "",
        "*",
        "arn:aws:backup:*:123456789012:backup-vault:owned",
        "arn:aws:backup:eu-central-1:999999999999:backup-vault:owned",
        "arn:aws:backup:eu-central-1:123456789012:backup-vault:*",
        "arn:aws:backup:eu-central-1:123456789012:backup-vault:owned\n",
        "arn:aws:backup:eu-central-1:123456789012:recovery-point:owned",
    ],
)
def test_invalid_or_foreign_vault_cannot_expand_policy(pulumi_mocks, arn):
    settings = replace(config.settings, platform_backup_vault_arn=arn)
    with pytest.raises(ValueError, match="exact account-local vault ARN"):
        _automation_policy("123456789012", settings, "bootstrap-infrastructure")


@pytest.mark.parametrize(
    "environment,account,suffix",
    [
        ("test", "891377212104", "3b9f5bf"),
        ("prod", "933245420672", "3dab3a7"),
    ],
)
def test_checked_operator_config_binds_the_existing_vault(environment, account, suffix):
    path = (
        Path(__file__).resolve().parents[2]
        / "pulumi"
        / "github-ci-bootstrap"
        / f"Pulumi.{environment}.yaml"
    )
    data = yaml.safe_load(path.read_text())
    assert data["config"]["github-ci-bootstrap:platformBackupVaultArn"] == (
        f"arn:aws:backup:eu-central-1:{account}:backup-vault:s3-backup-vault-{suffix}"
    )
    assert data["secretsprovider"].startswith("awskms://")
