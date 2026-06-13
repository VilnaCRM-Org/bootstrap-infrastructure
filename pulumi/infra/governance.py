"""Per-repo governance components for the multi-repo IAM/OIDC stack.

This module is the **per-repo half** of the governance stack (Story 1.4 /
E1.S4a). It wires, for ONE managed ``*-infrastructure`` repository, the AWS
resources a governed repo needs to run its own Pulumi CI against its account:

- a per-repo Pulumi state bucket + replica (``PulumiStateBuckets`` driven by a
  single-repo catalog, FR5),
- a per-repo KMS key + alias for Pulumi secrets (``PulumiSecretsKeys``, FR6),
- per-repo CI-config secret(s) + config-read role(s) (``CiConfiguration`` with
  the ``repo`` override, FR4),
- the preview/apply/drift deploy trio via the lifted ``_create_roles`` /
  ``_role_specs`` from ``ci_bootstrap`` (FR2/FR3), with the governance
  apply-subject override (``_governance_apply_subjects``, §5.1a, SECURITY-2):
  the apply role trusts ONLY ``environment:governance`` for BOTH the test and
  prod stacks, binding the IAM trust to the @Kravalg-gated GitHub environment.

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
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

import pulumi_aws as aws

import pulumi

from .bootstrap_settings import BootstrapSettings
from .ci_bootstrap import (
    _PULUMI_BACKEND_S3_ACTIONS,
    _PULUMI_KMS_ACTIONS,
    _BootstrapBuildContext,
    _ci_secret_suffixes,
    _CiRoleSpec,
    _create_roles,
    _default_backend_url,
    _environment_part,
    _iam_role_exists,  # re-exported so tests can stub role existence here
    _pulumi_secrets_alias_conditions,
    _role_specs,
    _secret_string,
    _state_bucket_resources,
)
from .ci_config import CiConfiguration, CiConfigurationArgs, _ci_config_project
from .managed_repository import ManagedRepository
from .pulumi_secrets import PulumiSecretsKeys
from .pulumi_state import PulumiStateBuckets
from .repository_catalog import ManagedRepositoryCatalog

__all__ = [
    "GovernanceStackArgs",
    "RepoGovernance",
    "_governance_apply_subjects",
    "_governance_payloads",
    "_iam_role_exists",
]

_GOVERNANCE_ENVIRONMENT = "governance"


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


def _governance_apply_subjects(
    settings: BootstrapSettings, repository: str
) -> list[str]:
    """Return the governance apply-role trust subjects (§5.1a, SECURITY-2).

    The governance ``apply`` role does NOT reuse ``_deployment_role_subjects``:
    that helper emits a bare branch-ref subject for the ``test`` apply, which
    would let an OIDC token assume the apply role without passing the
    @Kravalg-gated ``environment: governance`` reviewer. Both the test-stack and
    prod-stack governance applies therefore trust ONLY
    ``repo:{org}/{repo}:environment:governance`` — satisfiable only through the
    env-gated apply job, never a push or a raw ``repository_dispatch``.
    """
    return [f"repo:{repository}:environment:{_GOVERNANCE_ENVIRONMENT}"]


def _governance_backend_policy_document(
    account_id: str,
    partition: str,
    settings: BootstrapSettings,
    repo: str,
    region: str,
) -> str:
    """Return the repo-scoped Pulumi backend policy for a governed repo (§5.2).

    Differs from the single-repo bootstrap ``_pulumi_backend_policy_document``
    in two security-load-bearing ways (closing AWS-SRE-1 / SECURITY-KMS-medium /
    FR3): the KMS ``Resource`` is region-pinned (``arn:{partition}:kms:{region}``,
    no region wildcard) and the alias condition list is EXACTLY this repo's own
    ``alias/pulumi-{repo}-{env}-secrets`` — the platform-bootstrap alias is gone,
    so a governed repo can never decrypt the platform master key or another
    repo's secrets. ARNs interpolate ``{account_id}``/``{region}`` (FEAS-3).
    """
    bucket_arn, object_arns = _state_bucket_resources(settings, repo)
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
                    "Action": list(_PULUMI_BACKEND_S3_ACTIONS),
                    "Resource": [bucket_arn, *object_arns],
                },
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


def _governance_policy_documents(
    spec_documents: Sequence[tuple[str, str]],
    backend_policy: str,
) -> list[tuple[str, str]]:
    """Return spec policy docs with the governance backend policy swapped in."""
    return [
        (suffix, backend_policy if suffix == "pulumi-backend" else document)
        for suffix, document in spec_documents
    ]


def _governance_role_specs(
    *,
    account_id: str,
    partition: str,
    settings: BootstrapSettings,
    region: str,
    repo: str,
    project: str,
    repository: str,
) -> list[_CiRoleSpec]:
    """Return the deploy trio specs with the governance apply-subject override.

    Reuses the lifted ``_role_specs`` (so the preview/drift subjects and all
    policy documents stay identical to the repo-scoped bootstrap path) and
    replaces ONLY the ``apply`` spec's subjects with the env-gated governance
    subject set (§5.1a).
    """
    specs = _role_specs(
        account_id=account_id,
        partition=partition,
        settings=settings,
        region=region,
        repo=repo,
        project=project,
    )
    governance_subjects = _governance_apply_subjects(settings, repository)
    backend_policy = _governance_backend_policy_document(
        account_id, partition, settings, repo, region
    )
    return [
        dataclasses.replace(
            spec,
            subjects=(
                governance_subjects if spec.purpose == "apply" else spec.subjects
            ),
            policy_documents=_governance_policy_documents(
                spec.policy_documents, backend_policy
            ),
        )
        for spec in specs
    ]


def _governance_backend_url(
    settings: BootstrapSettings,
    repo: ManagedRepository,
    override: str | None,
) -> str:
    """Return the repo-scoped Pulumi backend URL for governance payloads."""
    if override is not None:
        return override
    return _default_backend_url(
        dataclasses.replace(settings, repo=repo.name)
        if settings.repo != repo.name
        else settings
    )


def _governance_secrets_provider(
    settings: BootstrapSettings,
    repo: ManagedRepository,
    region: str,
    override: str | None,
) -> str:
    """Return the repo-scoped Pulumi secrets-provider URL for governance."""
    if override is not None:
        return override
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
            "prod": {**common, "AWS_APPLY_ROLE_ARN": role_arns["apply"]},
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
        super().__init__("bootstrap:governance:RepoGovernance", name, None, opts)

        self._repo = repo
        repo_settings = self._repo_settings(settings, repo)
        project = _ci_config_project(repo_settings, repo.name)

        state_buckets, secrets_keys = self._create_state_and_secrets(
            name, repo=repo, settings=repo_settings
        )
        ci_configuration = self._create_ci_configuration(
            name,
            settings=repo_settings,
            repo=repo,
            provider_arn=provider_arn,
            protect=protect_resources,
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
                repository=f"{repo_settings.org}/{repo.name}",
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
        if settings.repo == repo.name:
            return settings
        return dataclasses.replace(settings, repo=repo.name)

    def _create_state_and_secrets(
        self,
        name: str,
        *,
        repo: ManagedRepository,
        settings: BootstrapSettings,
    ) -> tuple[PulumiStateBuckets, PulumiSecretsKeys]:
        """Create the per-repo state bucket+replica and KMS key+alias."""
        catalog = _single_repo_catalog(repo)
        state_buckets = PulumiStateBuckets(
            f"{name}-state",
            repositories=catalog.repositories,
            settings=settings,
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
    ) -> CiConfiguration:
        """Create the per-repo CI-config secrets and config-read roles."""
        return CiConfiguration(
            f"{name}-configuration",
            args=CiConfigurationArgs(
                settings=settings,
                oidc_provider_arn=provider_arn,
                protect_resources=protect,
                repo=repo.name,
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
