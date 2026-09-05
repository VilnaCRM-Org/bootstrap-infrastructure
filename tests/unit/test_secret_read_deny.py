"""Secret-leaking-read Deny coverage for E1.S3 (§5.2a/§5.3/§5.4, FR22, SECURITY-5).

These tests pin the three Deny guardrails introduced in Story 1.3:

* the **config-read** policy gains a ``DenySecretLeakingReads`` statement that
  EXCLUDES ``secretsmanager:GetSecretValue`` (so the role keeps its own Allow)
  while keeping its repo-scoped ``GetSecretValue`` Allow (§5.4);
* the **read-only** policy (preview/drift) gains the Deny block INCLUDING
  ``secretsmanager:GetSecretValue`` but EXCLUDING ``kms:Decrypt`` (§5.3): the
  preview/drift roles also carry the alias-scoped ``kms:Decrypt`` Allow from the
  pulumi-backend policy so ``pulumi preview``/drift can decrypt the stack's
  encrypted config, and an explicit ``kms:Decrypt`` Deny would override that Allow;
* the **apply** role gains a surgical ``DenySecretLeakingReadsApply`` with a
  ``NotResource`` carve-out for its own ``/{project}/ci/*`` secrets and WITHOUT
  ``kms:Decrypt`` (§5.2a, SECURITY-5); the pulumi-backend policy carries no Deny
  and retains its ``kms:Decrypt`` Allow.

The ``repo=None`` config-read path stays byte-identical to the pre-change Allow
statement (NFR6). Every new statement is ``Effect == "Deny"``, which is exactly
what makes it CrossGuard-exempt (``_statement_contains_wildcard_permissions``
returns ``False`` for any non-Allow effect), so ``make test-policy`` stays green.
"""

from __future__ import annotations

import json
from typing import Any

from infra import ci_bootstrap, ci_config, config

_ACCOUNT_ID = "123456789012"
_PARTITION = "aws"
_REGION = "eu-central-1"


def _settings(environment: str = "test") -> config.BootstrapSettings:
    """Return settings for the single-repo golden render."""
    return config.BootstrapSettings(
        org="VilnaCRM-Org",
        repo="bootstrap-infrastructure",
        environment=environment,
        owner="platform",
        cost_center="core",
        data_classification="internal",
        criticality="high",
        retention_class="standard",
        github_branch="main",
        logging_prefix="company",
        replication_region=None,
        github_token=None,
        github_oidc_provider_arn=None,
        manage_cost_allocation_tags=environment == "test",
    )


def _statements(policy_json: str) -> dict[str, Any]:
    """Return a policy's statements keyed by Sid."""
    document = json.loads(policy_json)
    return {statement["Sid"]: statement for statement in document["Statement"]}


# ---------------------------------------------------------------------------
# Config-read policy (§5.4 / §3.3)
# ---------------------------------------------------------------------------


def test_config_read_deny_omits_get_secret_value_but_keeps_own_allow() -> None:
    """config-read denies the leak surface yet keeps its repo-scoped GetSecretValue."""
    settings = _settings()
    statements = _statements(
        ci_config._ci_config_read_policy(
            account_id=_ACCOUNT_ID,
            partition=_PARTITION,
            settings=settings,
            suffixes=("test",),
        )
    )

    deny = statements["DenySecretLeakingReads"]
    assert deny["Effect"] == "Deny"  # nosec B101
    assert deny["Resource"] == "*"  # nosec B101
    # GetSecretValue is EXCLUDED from the Deny (Deny would otherwise void Allow).
    assert "secretsmanager:GetSecretValue" not in deny["Action"]  # nosec B101
    # Every other leak action IS denied.
    for action in (
        "kms:Decrypt",
        "ssm:GetParameter*",
        "lambda:GetFunction",
        "ec2:GetPasswordData",
        "ecr:GetAuthorizationToken",
        "sts:GetSessionToken",
        "cognito-identity:Get*",
    ):
        assert action in deny["Action"]  # nosec B101

    allow = statements["ReadCiConfigurationSecrets"]
    assert allow["Effect"] == "Allow"  # nosec B101
    assert allow["Action"] == [  # nosec B101
        "secretsmanager:DescribeSecret",
        "secretsmanager:GetSecretValue",
    ]
    assert allow["Resource"] == [  # nosec B101
        "arn:aws:secretsmanager:*:123456789012:secret:"
        "/bootstrap-infrastructure/ci/test-*"
    ]


def test_config_read_repo_none_allow_is_byte_identical_to_pre_change() -> None:
    """repo=None keeps the pre-change config-read Allow shape byte-for-byte (NFR6)."""
    settings = _settings()
    statements = _statements(
        ci_config._ci_config_read_policy(
            account_id=_ACCOUNT_ID,
            partition=_PARTITION,
            settings=settings,
            suffixes=("test-pr", "test"),
            repo=None,
        )
    )
    # Statement 0 (the Allow) is exactly what it was before the Deny was added.
    expected_allow = {
        "Sid": "ReadCiConfigurationSecrets",
        "Effect": "Allow",
        "Action": [
            "secretsmanager:DescribeSecret",
            "secretsmanager:GetSecretValue",
        ],
        "Resource": [
            "arn:aws:secretsmanager:*:123456789012:secret:"
            "/bootstrap-infrastructure/ci/test-pr-*",
            "arn:aws:secretsmanager:*:123456789012:secret:"
            "/bootstrap-infrastructure/ci/test-*",
        ],
    }
    assert statements["ReadCiConfigurationSecrets"] == expected_allow  # nosec B101


def test_config_read_repo_override_scopes_to_other_repo_only() -> None:
    """An explicit repo scopes the Allow ARN to that repo, never the settings repo."""
    settings = _settings()
    other = "user-service-infrastructure"
    statements = _statements(
        ci_config._ci_config_read_policy(
            account_id=_ACCOUNT_ID,
            partition=_PARTITION,
            settings=settings,
            suffixes=("prod-preview",),
            repo=other,
        )
    )
    allow_resource = statements["ReadCiConfigurationSecrets"]["Resource"]
    assert allow_resource == [  # nosec B101
        "arn:aws:secretsmanager:*:123456789012:secret:"
        "/user-service-infrastructure/ci/prod-preview-*"
    ]
    assert all("bootstrap-infrastructure" not in arn for arn in allow_resource)  # nosec B101


def test_ci_configuration_args_repo_defaults_to_none() -> None:
    """The new repo arg defaults to None (single-repo behaviour unchanged)."""
    assert ci_config.CiConfigurationArgs().repo is None  # nosec B101
    assert (  # nosec B101
        ci_config.CiConfigurationArgs(repo="user-service-infrastructure").repo
        == "user-service-infrastructure"
    )


def test_ci_config_project_honours_repo_override() -> None:
    """_ci_config_project uses repo override when supplied, settings.repo otherwise."""
    settings = _settings()
    assert ci_config._ci_config_project(settings) == "bootstrap-infrastructure"  # nosec B101
    assert (  # nosec B101
        ci_config._ci_config_project(settings, "user-service-infrastructure")
        == "user-service-infrastructure"
    )


def test_config_read_trust_subjects_follow_repo_override() -> None:
    """Repo-scoped trust subjects use the override repo (governance loop path)."""
    settings = _settings()
    subjects = ci_config._github_actions_subjects(
        settings, "prod", "user-service-infrastructure"
    )
    assert subjects == [  # nosec B101
        "repo:VilnaCRM-Org/user-service-infrastructure:environment:prod"
    ]
    trust = json.loads(
        ci_config._ci_config_read_assume_role_policy(
            "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com",
            settings,
            "prod",
            "user-service-infrastructure",
        )
    )
    condition = trust["Statement"][0]["Condition"]["StringEquals"]
    assert condition["token.actions.githubusercontent.com:repository"] == (  # nosec B101
        "VilnaCRM-Org/user-service-infrastructure"
    )


# ---------------------------------------------------------------------------
# Read-only policy (§5.3) — preview/drift
# ---------------------------------------------------------------------------


def test_read_only_deny_includes_get_secret_value_but_excludes_kms_decrypt() -> None:
    """read-only Deny has GetSecretValue but NOT kms:Decrypt (preview/drift decrypt)."""
    settings = _settings()
    statements = _statements(
        ci_bootstrap._read_only_policy_document(_ACCOUNT_ID, _PARTITION, settings)
    )
    deny = statements["DenySecretLeakingReads"]
    assert deny["Effect"] == "Deny"  # nosec B101
    assert deny["Resource"] == "*"  # nosec B101
    for action in (
        "secretsmanager:GetSecretValue",
        "ssm:GetParameter",
        "ssm:GetParameters",
        "ssm:GetParametersByPath",
        "lambda:GetFunction",
        "ec2:GetPasswordData",
        "ecr:GetAuthorizationToken",
        "sts:GetSessionToken",
        "cognito-identity:GetCredentialsForIdentity",
        "cognito-identity:GetId",
        "cognito-identity:GetOpenIdToken",
        "cognito-identity:GetOpenIdTokenForDeveloperIdentity",
    ):
        assert action in deny["Action"]  # nosec B101
    # kms:Decrypt is NOT denied: the pulumi-backend policy on preview/drift roles
    # grants alias-scoped kms:Decrypt so `pulumi preview`/drift can decrypt the
    # stack's encrypted config; a broad Deny here would override that Allow.
    assert "kms:Decrypt" not in deny["Action"]  # nosec B101
    # The single-action legacy Deny Sid is gone.
    assert "DenySecretValueReads" not in statements  # nosec B101


def test_preview_and_drift_attach_the_full_read_only_deny() -> None:
    """preview/drift roles carry the full read-only Deny block, no apply Deny."""
    settings = _settings()
    for purpose in ("preview", "drift"):
        docs = dict(
            ci_bootstrap._role_policy_documents(
                _ACCOUNT_ID, _PARTITION, settings, purpose
            )
        )
        assert set(docs) == {"pulumi-backend", "read-only"}  # nosec B101
        assert "secret-read-deny" not in docs  # nosec B101
        read_only = _statements(docs["read-only"])
        assert (  # nosec B101
            "secretsmanager:GetSecretValue"
            in read_only["DenySecretLeakingReads"]["Action"]
        )


# ---------------------------------------------------------------------------
# Apply role surgical Deny (§5.2a, SECURITY-5)
# ---------------------------------------------------------------------------


def _apply_docs(
    settings: config.BootstrapSettings,
    *,
    repo: str | None = None,
    project: str | None = None,
) -> dict[str, str]:
    """Return the apply role's policy documents keyed by suffix."""
    return dict(
        ci_bootstrap._role_policy_documents(
            _ACCOUNT_ID,
            _PARTITION,
            settings,
            "apply",
            repo,
            _REGION,
            project,
        )
    )


def test_apply_role_denies_get_secret_value_without_kms_decrypt() -> None:
    """The apply Deny blocks GetSecretValue but deliberately omits kms:Decrypt."""
    settings = _settings()
    docs = _apply_docs(settings)
    assert "secret-read-deny" in docs  # nosec B101

    statements = _statements(docs["secret-read-deny"])
    deny = statements["DenySecretLeakingReadsApply"]
    assert deny["Effect"] == "Deny"  # nosec B101
    assert "secretsmanager:GetSecretValue" in deny["Action"]  # nosec B101
    # kms:Decrypt is NOT denied — apply needs it for its own secrets key (§5.2).
    assert "kms:Decrypt" not in deny["Action"]  # nosec B101
    for action in (
        "ssm:GetParameter",
        "ssm:GetParameters",
        "ssm:GetParametersByPath",
        "ec2:GetPasswordData",
        "lambda:GetFunction",
        "ecr:GetAuthorizationToken",
        "sts:GetSessionToken",
        "cognito-identity:GetCredentialsForIdentity",
        "cognito-identity:GetId",
        "cognito-identity:GetOpenIdToken",
        "cognito-identity:GetOpenIdTokenForDeveloperIdentity",
    ):
        assert action in deny["Action"]  # nosec B101


def test_apply_deny_not_resource_carves_out_own_ci_secrets_only() -> None:
    """The NotResource allows the apply role's own /{project}/ci/* secrets only."""
    settings = _settings()
    deny = _statements(_apply_docs(settings)["secret-read-deny"])[
        "DenySecretLeakingReadsApply"
    ]
    assert deny["NotResource"] == [  # nosec B101
        "arn:aws:secretsmanager:eu-central-1:123456789012:secret:"
        "/bootstrap-infrastructure/ci/*"
    ]
    # An arbitrary OTHER secret is NOT in the carve-out -> the apply role is
    # denied GetSecretValue on it.
    other_arn = (
        "arn:aws:secretsmanager:eu-central-1:123456789012:secret:/other-repo/secret"
    )
    own_arn = (
        "arn:aws:secretsmanager:eu-central-1:123456789012:secret:"
        "/bootstrap-infrastructure/ci/test-AbCdEf"
    )
    assert other_arn not in deny["NotResource"]  # nosec B101
    assert own_arn.rsplit("/", 1)[0].startswith(  # nosec B101
        "arn:aws:secretsmanager:eu-central-1:123456789012:secret:"
        "/bootstrap-infrastructure/ci"
    )


def test_apply_deny_not_resource_follows_repo_override() -> None:
    """Governance loop repos get their own /{project}/ci/* carve-out (cross-repo)."""
    settings = _settings()
    other = "user-service-infrastructure"
    deny = _statements(
        _apply_docs(settings, repo=other, project=other)["secret-read-deny"]
    )["DenySecretLeakingReadsApply"]
    assert deny["NotResource"] == [  # nosec B101
        "arn:aws:secretsmanager:eu-central-1:123456789012:secret:"
        "/user-service-infrastructure/ci/*"
    ]
    assert all(  # nosec B101
        "bootstrap-infrastructure" not in arn for arn in deny["NotResource"]
    )


def test_apply_deny_region_threads_from_caller_not_hardcoded() -> None:
    """The NotResource region comes from the caller, not a baked-in literal."""
    settings = _settings()
    docs = dict(
        ci_bootstrap._role_policy_documents(
            _ACCOUNT_ID, _PARTITION, settings, "apply", None, "us-east-1", None
        )
    )
    deny = _statements(docs["secret-read-deny"])["DenySecretLeakingReadsApply"]
    assert deny["NotResource"] == [  # nosec B101
        "arn:aws:secretsmanager:us-east-1:123456789012:secret:"
        "/bootstrap-infrastructure/ci/*"
    ]


def test_pulumi_backend_policy_has_no_deny_and_keeps_kms_decrypt() -> None:
    """The pulumi-backend policy carries no Deny and retains its kms:Decrypt Allow."""
    settings = _settings()
    docs = _apply_docs(settings)
    backend = json.loads(docs["pulumi-backend"])
    effects = {statement["Effect"] for statement in backend["Statement"]}
    assert "Deny" not in effects  # nosec B101
    kms_statement = next(
        statement
        for statement in backend["Statement"]
        if statement["Sid"] == "UsePulumiSecretsProviderKey"
    )
    assert "kms:Decrypt" in kms_statement["Action"]  # nosec B101


# ---------------------------------------------------------------------------
# test-policy intent: every new statement is Deny -> CrossGuard-exempt (FR23)
# ---------------------------------------------------------------------------


def test_new_deny_statements_are_crossguard_exempt_effect_deny() -> None:
    """All three new guardrail statements use Effect=Deny (CrossGuard-exempt)."""
    settings = _settings()

    config_deny = _statements(
        ci_config._ci_config_read_policy(
            account_id=_ACCOUNT_ID,
            partition=_PARTITION,
            settings=settings,
            suffixes=("test",),
        )
    )["DenySecretLeakingReads"]
    read_only_deny = _statements(
        ci_bootstrap._read_only_policy_document(_ACCOUNT_ID, _PARTITION, settings)
    )["DenySecretLeakingReads"]
    apply_deny = _statements(_apply_docs(settings)["secret-read-deny"])[
        "DenySecretLeakingReadsApply"
    ]
    for deny in (config_deny, read_only_deny, apply_deny):
        assert deny["Effect"] == "Deny"  # nosec B101

    # No Effect=Allow statement carries an Action:* or unscoped Resource:* in the
    # changed surfaces (FR23). The only Allow with Resource:* is the unscopable
    # sts:GetCallerIdentity in the backend policy.
    backend = json.loads(_apply_docs(settings)["pulumi-backend"])
    for statement in backend["Statement"]:
        if statement["Effect"] != "Allow":
            continue
        actions = statement["Action"]
        assert "*" not in actions  # nosec B101
        if statement.get("Resource") == "*":
            assert actions == ["sts:GetCallerIdentity"]  # nosec B101
