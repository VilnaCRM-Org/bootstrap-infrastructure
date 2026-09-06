"""Per-repo governance components for the multi-repo IAM/OIDC stack.

This module is the **per-repo half** of the governance stack (Story 1.4 /
E1.S4a). It wires, for ONE managed ``*-infrastructure`` repository, the AWS
resources a governed repo needs to run its own Pulumi CI against its account:

- a per-repo Pulumi state bucket + replica (``PulumiStateBuckets`` driven by a
  single-repo catalog, FR5),
- a per-repo KMS key + alias for Pulumi secrets (``PulumiSecretsKeys``, FR6),
- per-repo CI-config secret(s) + config-read role(s) (``CiConfiguration`` with
  the ``repo`` override, FR4),
- the preview/apply/drift deploy trio via the shared ``_create_roles`` resource
  builder with explicit backend-only service permissions. Apply trusts only
  the account-specific protected test/prod environment; preview and drift
  have separate subjects and cannot mint apply credentials.

The ``GovernanceStack`` loop (part 2, Story 1.5 / E1.S4b) consumes the
per-account OIDC provider by pinned ARN and instantiates one ``RepoGovernance``
per catalog repo; it is added in a later story.

Every rendered ARN uses ``{account_id}``/``{region}`` interpolation (the
injectable ``region``), never a literal ``891377212104``/``eu-central-1``
(FEAS-3), so the documents render under the session Pulumi mocks (account
``123456789012``, region ``us-east-1``).
"""

from __future__ import annotations

import dataclasses
import json
from collections.abc import Mapping
from dataclasses import dataclass

import pulumi_aws as aws

import pulumi

from .bootstrap_settings import BootstrapSettings
from .ci_bootstrap import (
    _PULUMI_BACKEND_S3_ACTIONS,
    _PULUMI_KMS_ACTIONS,
    _READ_ONLY_SECRET_DENY_ACTIONS,
    _apply_secret_deny_document,
    _BootstrapBuildContext,
    _ci_role_name,
    _ci_secret_suffixes,
    _CiRoleSpec,
    _create_roles,
    _deployment_role_subjects,
    _environment_part,
    _github_variables,
    _iam_role_exists,  # re-exported so tests can stub role existence here
    _pulumi_secrets_alias_conditions,
    _secret_string,
)
from .ci_config import CiConfiguration, CiConfigurationArgs, _ci_config_project
from .iam.github_oidc import _repo_suffix
from .managed_repository import ManagedRepository
from .pulumi_secrets import PulumiSecretsKeys
from .pulumi_state import PulumiStateBuckets
from .repository_catalog import ManagedRepositoryCatalog
from .utils.outputs import apply_output

__all__ = [
    "GovernanceStack",
    "GovernanceStackArgs",
    "RepoGovernance",
    "_governance_payloads",
    "_iam_role_exists",
]


@dataclass(frozen=True)
class GovernanceStackArgs:
    """Inputs for the governance stack loop (consumed by ``GovernanceStack``).

    ``oidc_provider_arn`` is the per-account GitHub OIDC provider ARN consumed
    by ``.get()`` — never created here (AWS-SRE-2). ``region`` is injectable so
    tests pass the mock region (``us-east-1``) and policy/secret ARNs stay
    mock-renderable; production stacks pass ``eu-central-1`` via stack config.
    ``expected_account_id`` carries the per-stack D1 account assertion
    (``governance:awsAccountId``); the literal lives in stack config, never in
    component code.
    """

    settings: BootstrapSettings | None = None
    repository_catalog: ManagedRepositoryCatalog | None = None
    expected_account_id: str | None = None
    oidc_provider_arn: str | None = None
    region: str = "eu-central-1"
    pulumi_dir: str = "pulumi"
    pulumi_backend_url: str | None = None
    pulumi_secrets_provider: str | None = None
    write_secret_values: bool = True
    protect_resources: bool = True


def _governance_boundary_arn(
    *,
    account_id: str,
    partition: str,
    settings: BootstrapSettings,
    project: str,
    replication: bool = False,
) -> str:
    """Reference an immutable permission ceiling owned by the bootstrap stack."""
    family = "GovernanceReplicationBoundary" if replication else "GovernanceBoundary"
    name = f"{family}-{project}-{_environment_part(settings)}"
    return f"arn:{partition}:iam::{account_id}:policy/{name}"


def _governance_backend_policy_document(
    account_id: str,
    partition: str,
    settings: BootstrapSettings,
    repo: str,
    region: str,
    *,
    purpose: str = "apply",
) -> str:
    """Return the repo-scoped Pulumi backend policy for a governed repo (§5.2).

    Differs from the single-repo bootstrap ``_pulumi_backend_policy_document``
    in two security-load-bearing ways (closing AWS-SRE-1 / SECURITY-KMS-medium /
    FR3): the KMS ``Resource`` is region-pinned (``arn:{partition}:kms:{region}``,
    no region wildcard) and the alias condition list is EXACTLY this repo's own
    ``alias/pulumi-{repo}-{env}-secrets`` — the platform-bootstrap alias is gone,
    so a governed repo can never decrypt the platform master key or another
    repo's secrets. ARNs interpolate ``{account_id}``/``{region}`` (FEAS-3).

    Preview/drift read checkpoints and only create/delete lock objects under
    ``.pulumi/locks/`` in this repo's bucket. Pulumi's DIY backend documents that
    layout and its lock.go uses WriteAll/Delete, not object-version deletion:
    https://www.pulumi.com/docs/iac/operations/stack-management/using-a-diy-backend/
    Only apply receives checkpoint/history write access.
    """
    bucket_arn = f"arn:aws:s3:::{settings.state_bucket_name_for_repo(repo)}"
    object_arns = (bucket_arn + "/state/*", bucket_arn + "/.pulumi/*")
    alias_conditions = _pulumi_secrets_alias_conditions(
        settings,
        repo,
        _environment_part(settings),
        include_platform_bootstrap=False,
    )
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "ReadCallerIdentity",
                    "Effect": "Allow",
                    "Action": ["sts:GetCallerIdentity"],
                    "Resource": "*",
                },
                {
                    "Sid": "UsePulumiStateBucket",
                    "Effect": "Allow",
                    "Action": (
                        list(_PULUMI_BACKEND_S3_ACTIONS)
                        if purpose == "apply"
                        else ["s3:ListBucket", "s3:GetObject", "s3:GetObjectVersion"]
                    ),
                    "Resource": [bucket_arn, *object_arns],
                },
                *(
                    _governance_read_state_guardrails(bucket_arn)
                    if purpose != "apply"
                    else []
                ),
                {
                    "Sid": "UsePulumiSecretsProviderKey",
                    "Effect": "Allow",
                    "Action": list(_PULUMI_KMS_ACTIONS),
                    "Resource": f"arn:{partition}:kms:{region}:{account_id}:key/*",
                    "Condition": {
                        "ForAnyValue:StringLike": {
                            "kms:ResourceAliases": alias_conditions
                        }
                    },
                },
            ],
        },
        sort_keys=True,
    )


def _governance_read_state_guardrails(bucket_arn: str) -> list[dict[str, object]]:
    """Allow read-role lock management while explicitly denying checkpoint writes."""
    lock_objects = f"{bucket_arn}/.pulumi/locks/*"
    return [
        {
            "Sid": "ManagePulumiLocks",
            "Effect": "Allow",
            "Action": ["s3:PutObject", "s3:DeleteObject"],
            "Resource": lock_objects,
        },
        {
            "Sid": "DenyWritesOutsidePulumiLocks",
            "Effect": "Deny",
            "Action": ["s3:PutObject", "s3:DeleteObject"],
            "NotResource": lock_objects,
        },
        {
            "Sid": "DenyStateVersionDeletion",
            "Effect": "Deny",
            "Action": ["s3:DeleteObjectVersion"],
            "Resource": "*",
        },
    ]


def _governance_read_only_policy_document(
    account_id: str,
    partition: str,
    settings: BootstrapSettings,
    repo: str,
    region: str,
    project: str,
) -> str:
    """Read only metadata already permitted by the service backend boundary.

    Service membership never inherits platform-wide inventory permissions. CI
    secret values remain explicitly denied; the separate configuration role
    supplies runner configuration before deployment credentials are assumed.
    """
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "ReadOwnStateBucketMetadata",
                    "Effect": "Allow",
                    "Action": ["s3:GetBucketLocation"],
                    "Resource": (
                        f"arn:{partition}:s3:::"
                        f"{settings.state_bucket_name_for_repo(repo)}"
                    ),
                },
                {
                    "Sid": "ReadOwnPulumiKeyMetadata",
                    "Effect": "Allow",
                    "Action": ["kms:DescribeKey"],
                    "Resource": f"arn:{partition}:kms:{region}:{account_id}:key/*",
                    "Condition": {
                        "ForAnyValue:StringEquals": {
                            "kms:ResourceAliases": [
                                settings.pulumi_secrets_alias_name_for_repo(repo)
                            ]
                        }
                    },
                },
                {
                    "Sid": "ReadOwnCiConfigurationMetadata",
                    "Effect": "Allow",
                    "Action": [
                        "secretsmanager:DescribeSecret",
                        "secretsmanager:GetResourcePolicy",
                        "secretsmanager:ListSecretVersionIds",
                    ],
                    "Resource": [
                        f"arn:{partition}:secretsmanager:{region}:{account_id}:"
                        f"secret:/{project}/ci/{suffix}-??????"
                        for suffix in _ci_secret_suffixes(settings)
                    ],
                },
                {
                    "Sid": "DenySecretLeakingReads",
                    "Effect": "Deny",
                    "Action": list(_READ_ONLY_SECRET_DENY_ACTIONS),
                    "Resource": "*",
                },
            ],
        },
        sort_keys=True,
    )


def _governance_policy_documents(
    *,
    purpose: str,
    backend_policy: str,
    account_id: str,
    partition: str,
    settings: BootstrapSettings,
    region: str,
    project: str,
    repo: str,
) -> list[tuple[str, str]]:
    """Return service permissions without delegating platform administration.

    New service repositories initially receive only their Pulumi backend access.
    Preview and drift additionally read their own backend metadata; apply retains
    its explicit secret-read deny. In particular, an apply role cannot modify IAM roles,
    policies, OIDC providers, state bucket policies, or KMS key policies. Reusing
    the platform automation policy here would let a service grant itself admin
    through an assumable role, bypassing every repo-scoped backend restriction.

    Real service resources require additional, explicitly reviewed capabilities
    in governance IaC. Catalog membership alone must never grant the platform
    bootstrap policy, and this initial permission set does not deploy an existing
    application's resources. Any later IAM delegation must use an operator-owned
    boundary that the service cannot replace or edit.
    """
    documents = [("pulumi-backend", backend_policy)]
    if purpose == "apply":
        documents.append(
            (
                "secret-read-deny",
                _apply_secret_deny_document(account_id, partition, region, project),
            )
        )
    else:
        documents.append(
            (
                "read-only",
                _governance_read_only_policy_document(
                    account_id, partition, settings, repo, region, project
                ),
            )
        )
    return documents


def _governance_role_specs(
    *,
    account_id: str,
    partition: str,
    settings: BootstrapSettings,
    region: str,
    repo: str,
    project: str,
) -> list[_CiRoleSpec]:
    """Build service role specs independently of platform bootstrap policies."""
    return [
        _CiRoleSpec(
            purpose=purpose,
            role_name=_ci_role_name(settings, purpose, project),
            permissions_boundary=_governance_boundary_arn(
                account_id=account_id,
                partition=partition,
                settings=settings,
                project=project,
            ),
            subjects=_deployment_role_subjects(settings, purpose, repo),
            policy_documents=_governance_policy_documents(
                purpose=purpose,
                backend_policy=_governance_backend_policy_document(
                    account_id, partition, settings, repo, region, purpose=purpose
                ),
                account_id=account_id,
                partition=partition,
                settings=settings,
                region=region,
                project=project,
                repo=repo,
            ),
        )
        for purpose in ("preview", "apply", "drift")
    ]


def _governance_backend_url(
    settings: BootstrapSettings,
    repo: ManagedRepository,
    override: str | None,
) -> str:
    """Keep service payloads within their derived, immutable backend scope."""
    derived = f"s3://{settings.state_bucket_name_for_repo(repo.name)}"
    if override is not None and override != derived:
        raise ValueError(
            "Managed repository backend override must equal its derived bucket URL"
        )
    return derived


def _governance_secrets_provider(
    settings: BootstrapSettings,
    repo: ManagedRepository,
    region: str,
    override: str | None,
) -> str:
    """Return the repo-scoped Pulumi secrets-provider URL for governance."""
    # The controller stack's provider override is not a managed repo capability.
    return settings.pulumi_secrets_provider_for_repo(repo.name, region)


def _governance_payloads(
    *,
    settings: BootstrapSettings,
    repo: ManagedRepository,
    account_id: str,
    region: str,
    pulumi_dir: str,
    role_arns: Mapping[str, pulumi.Input[str]],
    pulumi_backend_url: str | None = None,
    pulumi_secrets_provider: str | None = None,
) -> dict[str, dict[str, pulumi.Input[str]]]:
    """Return governance CI-config payloads keyed by fixed secret suffix.

    Mirrors ``ci_bootstrap._payloads`` but WITHOUT the operations-triage
    requirement (§3.5): governance repos do not own operations triage. Backend
    URL and secrets provider are repo-scoped (``pulumi-{repo}-{env}-*``) and the
    region is the injectable governance region.
    """
    environment = settings.environment
    common = {
        "AWS_ACCOUNT_ID": account_id,
        "AWS_REGION": region,
        "PULUMI_BACKEND_URL": _governance_backend_url(
            settings, repo, pulumi_backend_url
        ),
        "PULUMI_DIR": pulumi_dir,
        "PULUMI_SECRETS_PROVIDER": _governance_secrets_provider(
            settings, repo, region, pulumi_secrets_provider
        ),
    }
    preview_common = {
        **common,
        "AWS_PREVIEW_ROLE_ARN": role_arns["preview"],
        "PULUMI_PREVIEW_STACKS": environment,
    }
    drift_common = {
        "AWS_DRIFT_ROLE_ARN": role_arns["drift"],
        "PULUMI_DRIFT_STACKS": environment,
    }
    if environment == "test":
        return {
            "test-pr": {**preview_common},
            "test": {
                **preview_common,
                **drift_common,
                "AWS_APPLY_ROLE_ARN": role_arns["apply"],
            },
        }
    if environment == "prod":
        return {
            "prod-preview": {**preview_common, **drift_common},
            "prod": {
                **common,
                "AWS_APPLY_ROLE_ARN": role_arns["apply"],
                # Parity with ci_bootstrap._payloads: the prod apply env also
                # carries PULUMI_PREVIEW_STACKS so the saved-plan apply targets
                # the same stack set the preview produced.
                "PULUMI_PREVIEW_STACKS": environment,
            },
        }
    return {
        environment: {
            **preview_common,
            **drift_common,
            "AWS_APPLY_ROLE_ARN": role_arns["apply"],
        }
    }


def _single_repo_catalog(repo: ManagedRepository) -> ManagedRepositoryCatalog:
    """Return a one-entry catalog so per-repo helpers stay single-repo scoped."""
    return ManagedRepositoryCatalog([repo])


class RepoGovernance(pulumi.ComponentResource):
    """All governance AWS resources for ONE managed ``*-infrastructure`` repo."""

    def __init__(
        self,
        name: str,
        *,
        repo: ManagedRepository,
        settings: BootstrapSettings,
        provider_arn: pulumi.Input[str],
        account_id: str,
        partition: str,
        region: str,
        pulumi_dir: str,
        pulumi_backend_url: str | None,
        pulumi_secrets_provider: str | None,
        write_secret_values: bool,
        protect_resources: bool,
        opts: pulumi.ResourceOptions | None = None,
    ) -> None:
        _governance_backend_url(settings, repo, pulumi_backend_url)
        super().__init__("bootstrap:governance:RepoGovernance", name, None, opts)

        self._repo = repo
        repo_settings = self._repo_settings(settings, repo)
        project = _ci_config_project(repo_settings, repo.name)

        state_buckets, secrets_keys = self._create_state_and_secrets(
            name,
            repo=repo,
            settings=repo_settings,
            replication_permissions_boundary=_governance_boundary_arn(
                account_id=account_id,
                partition=partition,
                settings=repo_settings,
                project=project,
                replication=True,
            ),
        )
        ci_configuration = self._create_ci_configuration(
            name,
            settings=repo_settings,
            repo=repo,
            provider_arn=provider_arn,
            protect=protect_resources,
            permissions_boundary=_governance_boundary_arn(
                account_id=account_id,
                partition=partition,
                settings=repo_settings,
                project=project,
            ),
        )
        context = _BootstrapBuildContext(
            parent=self,
            name=name,
            account_id=account_id,
            partition=partition,
            region=region,
            settings=repo_settings,
            provider_arn=provider_arn,
            pulumi_dir=pulumi_dir,
            protect_resources=protect_resources,
            repo=repo.name,
            project=project,
        )
        roles = _create_roles(
            context,
            specs=_governance_role_specs(
                account_id=account_id,
                partition=partition,
                settings=repo_settings,
                region=region,
                repo=repo.name,
                project=project,
            ),
        )
        self.deployment_role_arns = {
            purpose: role.arn for purpose, role in roles.items()
        }
        self.secret_payloads = _governance_payloads(
            settings=repo_settings,
            repo=repo,
            account_id=account_id,
            region=region,
            pulumi_dir=pulumi_dir,
            role_arns=self.deployment_role_arns,
            pulumi_backend_url=pulumi_backend_url,
            pulumi_secrets_provider=pulumi_secrets_provider,
        )
        self.secret_versions = self._write_secret_versions(
            name,
            settings=repo_settings,
            ci_configuration=ci_configuration,
            write_secret_values=write_secret_values,
        )
        self._record_outputs(
            state_buckets=state_buckets,
            secrets_keys=secrets_keys,
            ci_configuration=ci_configuration,
        )

    @staticmethod
    def _repo_settings(
        settings: BootstrapSettings, repo: ManagedRepository
    ) -> BootstrapSettings:
        """Return settings pinned to this repo so derived helpers stay scoped."""
        if settings.repo == repo.name and repo.repository_id is None:
            return (
                settings
                if settings.github_branch == repo.default_branch
                else dataclasses.replace(settings, github_branch=repo.default_branch)
            )
        rescoped: BootstrapSettings = dataclasses.replace(
            settings,
            repo=repo.name,
            github_branch=repo.default_branch,
            github_repository_id=repo.repository_id,
            github_repository_owner_id=repo.repository_owner_id,
        )
        return rescoped

    def _create_state_and_secrets(
        self,
        name: str,
        *,
        repo: ManagedRepository,
        settings: BootstrapSettings,
        replication_permissions_boundary: str,
    ) -> tuple[PulumiStateBuckets, PulumiSecretsKeys]:
        """Create the per-repo state bucket+replica and KMS key+alias."""
        catalog = _single_repo_catalog(repo)
        state_buckets = PulumiStateBuckets(
            f"{name}-state",
            repositories=catalog.repositories,
            access_log_prefix="aws-logs/",
            settings=settings,
            replication_permissions_boundary=replication_permissions_boundary,
            opts=pulumi.ResourceOptions(parent=self),
        )
        secrets_keys = PulumiSecretsKeys(
            f"{name}-secrets",
            repositories=catalog.repositories,
            settings=settings,
            opts=pulumi.ResourceOptions(parent=self),
        )
        return state_buckets, secrets_keys

    def _create_ci_configuration(
        self,
        name: str,
        *,
        settings: BootstrapSettings,
        repo: ManagedRepository,
        provider_arn: pulumi.Input[str],
        protect: bool,
        permissions_boundary: str,
    ) -> CiConfiguration:
        """Create the per-repo CI-config secrets and config-read roles."""
        return CiConfiguration(
            f"{name}-configuration",
            args=CiConfigurationArgs(
                settings=settings,
                oidc_provider_arn=provider_arn,
                protect_resources=protect,
                repo=repo.name,
                permissions_boundary=permissions_boundary,
                governed_service_workflows=True,
            ),
            opts=pulumi.ResourceOptions(parent=self),
        )

    def _write_secret_versions(
        self,
        name: str,
        *,
        settings: BootstrapSettings,
        ci_configuration: CiConfiguration,
        write_secret_values: bool,
    ) -> dict[str, aws.secretsmanager.SecretVersion]:
        """Write the governance CI-config secret values when managed here."""
        if not write_secret_values:
            return {}
        return {
            suffix: aws.secretsmanager.SecretVersion(
                f"{name}-secret-value-{suffix}",
                secret_id=ci_configuration.secret_ids[suffix],
                secret_string=pulumi.Output.secret(
                    _secret_string(self.secret_payloads[suffix])
                ),
                opts=pulumi.ResourceOptions(
                    parent=self,
                    depends_on=[
                        ci_configuration.secrets[suffix],
                        *ci_configuration.read_roles.values(),
                    ],
                    protect=False,
                ),
            )
            for suffix in _ci_secret_suffixes(settings)
        }

    def _record_outputs(
        self,
        *,
        state_buckets: PulumiStateBuckets,
        secrets_keys: PulumiSecretsKeys,
        ci_configuration: CiConfiguration,
    ) -> None:
        """Expose per-repo outputs and register the stable component mapping."""
        repo_name = self._repo.name
        self.ci_configuration = ci_configuration
        self.state_bucket_name = state_buckets.state_buckets[repo_name]
        self.state_bucket_arn = state_buckets.bucket_arns[repo_name]
        self.secrets_alias_name = secrets_keys.alias_names[repo_name]
        self.secrets_key_arn = secrets_keys.key_arns[repo_name]
        self.secrets_provider_url = secrets_keys.provider_urls[repo_name]
        self.ci_config_secret_ids = dict(ci_configuration.secret_ids)
        self.config_read_role_arns = dict(ci_configuration.read_role_arns)
        self.secret_payload_keys = {
            suffix: sorted(payload) for suffix, payload in self.secret_payloads.items()
        }
        self.register_outputs(
            {
                "state_bucket_name": self.state_bucket_name,
                "secrets_alias_name": self.secrets_alias_name,
                "deployment_role_arns": self.deployment_role_arns,
                "config_read_role_arns": self.config_read_role_arns,
                "ci_config_secret_ids": self.ci_config_secret_ids,
                "secret_payload_keys": self.secret_payload_keys,
            }
        )


def _resolve_oidc_provider_arn(
    args: GovernanceStackArgs, *, account_id: str, partition: str
) -> str:
    """Return the pinned per-account OIDC provider ARN or raise (AWS-SRE-2, FR7).

    The governance stack NEVER creates/adopts the provider: each account already
    owns exactly one (`token.actions.githubusercontent.com`) via its bootstrap
    stack, so the ARN is config-pinned (`governance:githubOidcProviderArn`) and
    consumed by ``.get()``. An unset ARN is a hard error — there is no
    create fallback that could race or mutate the other stack's state.
    """
    if not args.oidc_provider_arn:
        raise ValueError(
            "governance stack requires a pinned oidc_provider_arn "
            "(set governance:githubOidcProviderArn from the bootstrap stack's "
            "oidcProviderArn output); it never creates the OIDC provider."
        )
    expected = (
        f"arn:{partition}:iam::{account_id}:"
        "oidc-provider/token.actions.githubusercontent.com"
    )
    if args.oidc_provider_arn != expected:
        raise ValueError("Governance OIDC provider must be the account's GitHub issuer")
    return args.oidc_provider_arn


def _assert_governance_account(
    account_id: str, expected_account_id: str | None
) -> None:
    """Assert the live account matches the per-stack expectation (D1).

    ``expected_account_id`` is the injectable ``governance:awsAccountId`` (test
    stack → ``891377212104``, prod stack → ``933245420672``); the literal lives
    in stack config, never here. When unset the assertion is skipped (e.g. early
    scaffolding). The injectable seam lets tests drive BOTH branches under the
    mocks (match → proceeds; mismatch → raises) without a hardcoded literal.
    """
    if expected_account_id is not None and account_id != expected_account_id:
        raise ValueError(
            "governance stack must run in account "
            f"{expected_account_id!r}, but the live account is {account_id!r}."
        )


def _governance_github_variables(
    settings: BootstrapSettings,
    *,
    region: str,
    account_id: str,
    ci_configuration: CiConfiguration,
) -> dict[str, pulumi.Input[str]]:
    """Return per-env GitHub variables for a governed repo (reuse §3.4).

    Reuses the bootstrap ``_github_variables`` builder so the variable shape
    stays identical to the single-repo path, with the injectable governance
    region threaded through (never a hardcoded ``eu-central-1``).
    """
    return _github_variables(
        settings,
        region=region,
        account_id=account_id,
        ci_configuration=ci_configuration,
    )


def _repo_outputs(
    *,
    settings: BootstrapSettings,
    repo: ManagedRepository,
    region: str,
    account_id: str,
    component: RepoGovernance,
) -> dict[str, pulumi.Input[object]]:
    """Return the §3.4 per-repo output entry for one governed repo."""
    repo_settings = (
        settings
        if settings.repo == repo.name
        else dataclasses.replace(settings, repo=repo.name)
    )
    return {
        "stateBucketName": component.state_bucket_name,
        "stateBackendUrl": apply_output(
            component.state_bucket_name, lambda bucket: f"s3://{bucket}"
        ),
        "secretsAlias": component.secrets_alias_name,
        "secretsProvider": component.secrets_provider_url,
        "deploymentRoleArns": dict(component.deployment_role_arns),
        "configReadRoleArns": dict(component.config_read_role_arns),
        "ciConfigSecretIds": dict(component.ci_config_secret_ids),
        "githubVariables": _governance_github_variables(
            repo_settings,
            region=region,
            account_id=account_id,
            ci_configuration=component.ci_configuration,
        ),
    }


class GovernanceStack(pulumi.ComponentResource):
    """Account OIDC provider (consumed by ARN) + ``RepoGovernance`` per repo.

    Consumes its account's GitHub OIDC provider **by pinned ARN via ``.get()``**
    (zero create branch — AWS-SRE-2, FR7), asserts the live account against the
    injectable, per-stack ``expected_account_id`` (D1), then instantiates one
    ``RepoGovernance`` per catalog repo and registers the stable §3.4 outputs
    map. ``region`` is injectable (AWS-SRE-5) so tests render under the mock
    region and never assert a hardcoded ``eu-central-1`` literal.
    """

    def __init__(
        self,
        name: str,
        *,
        args: GovernanceStackArgs | None = None,
        opts: pulumi.ResourceOptions | None = None,
    ) -> None:
        resolved = args or GovernanceStackArgs()
        settings = resolved.settings or BootstrapSettings.from_pulumi_config()
        catalog = resolved.repository_catalog or ManagedRepositoryCatalog.from_settings(
            settings
        )
        for repo in catalog.repositories:
            _governance_backend_url(settings, repo, resolved.pulumi_backend_url)
        super().__init__("bootstrap:governance:GovernanceStack", name, None, opts)
        account_id = aws.get_caller_identity().account_id
        _assert_governance_account(account_id, resolved.expected_account_id)
        partition = aws.get_partition().partition
        provider_arn = _resolve_oidc_provider_arn(
            resolved, account_id=account_id, partition=partition
        )
        region = resolved.region

        provider = aws.iam.OpenIdConnectProvider.get(
            f"{name}-oidc",
            provider_arn,
            opts=pulumi.ResourceOptions(parent=self),
        )
        self.oidc_provider_arn = provider.arn

        self.repo_components = self._build_repo_components(
            name,
            settings=settings,
            catalog=catalog,
            provider_arn=provider.arn,
            account_id=account_id,
            partition=partition,
            region=region,
            args=resolved,
        )
        self.managed_repositories = sorted(self.repo_components)
        self.per_repo = {
            repo.name: _repo_outputs(
                settings=settings,
                repo=repo,
                region=region,
                account_id=account_id,
                component=self.repo_components[repo.name],
            )
            for repo in catalog.repositories
        }
        self.register_outputs(
            {
                "oidcProviderArn": self.oidc_provider_arn,
                "managedRepositories": self.managed_repositories,
                "perRepo": self.per_repo,
            }
        )

    def _build_repo_components(
        self,
        name: str,
        *,
        settings: BootstrapSettings,
        catalog: ManagedRepositoryCatalog,
        provider_arn: pulumi.Input[str],
        account_id: str,
        partition: str,
        region: str,
        args: GovernanceStackArgs,
    ) -> dict[str, RepoGovernance]:
        """Instantiate one ``RepoGovernance`` per catalog repo, keyed by name."""
        components: dict[str, RepoGovernance] = {}
        for repo in catalog.repositories:
            suffix = _repo_suffix(repo.name, settings)
            components[repo.name] = RepoGovernance(
                f"{name}-{suffix}",
                repo=repo,
                settings=settings,
                provider_arn=provider_arn,
                account_id=account_id,
                partition=partition,
                region=region,
                pulumi_dir=args.pulumi_dir,
                pulumi_backend_url=args.pulumi_backend_url,
                pulumi_secrets_provider=args.pulumi_secrets_provider,
                write_secret_values=args.write_secret_values,
                protect_resources=args.protect_resources,
                opts=pulumi.ResourceOptions(parent=self),
            )
        return components
