"""Operator ownership of legacy platform control IAM, without workload resources."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

import pulumi_aws as aws

import pulumi

from . import platform_iam
from .automation import (
    GitHubAutomation,
    _automation_policy_documents,
    _validate_automation_policy_documents,
)
from .bootstrap_infrastructure import _repository_project
from .bootstrap_settings import BootstrapSettings
from .iam.github_oidc import GitHubOidcRoles, _repo_suffix, _role_name_for_suffix
from .managed_repository import ManagedRepository
from .platform_iam import PlatformReplicationIam
from .security_account_controls import ConfigRecorderIam


def _validate_policy_pin(role, prefix, name, allowed):
    """Validate one explicit pin against the immutable role/prefix inventory."""
    if (role, prefix) not in allowed or not isinstance(name, str) or not name:
        raise ValueError("Inline policy override prefix/name is invalid")


def _inline_policy_overrides(settings, repositories, configured):
    """Reject pins outside the reviewed operator role/policy inventory."""
    allowed = {
        (settings.automation_role_name(settings.repo), "github-automation-policy"),
        *(
            (
                _role_name_for_suffix(_repo_suffix(repo.name, settings)),
                f"github-oidc-policy-{_repo_suffix(repo.name, settings)}",
            )
            for repo in repositories
        ),
    }
    if not isinstance(configured, dict):
        raise ValueError("Inline policy overrides must be a role/prefix/name map")
    result = {}
    for role, policies in configured.items():
        if role not in {item[0] for item in allowed} or not isinstance(policies, dict):
            raise ValueError(
                "Inline policy override role is outside operator inventory"
            )
        for prefix, name in policies.items():
            _validate_policy_pin(role, prefix, name, allowed)
            result[(role, prefix)] = name
    return result


def _control_guard_identity(repository: str | None):
    """Namespace guard identities while preserving their existing logical names."""
    if repository is None:
        return ("automation", ""), "automation"
    return ("deploy", repository), (
        "deploy:automation" if repository == "automation" else repository
    )


def _validate_platform_catalog(settings, repositories):
    """Only the primary repository is covered by the fixed platform ceiling."""
    if any(repository.name != settings.repo for repository in repositories):
        raise ValueError(
            "Platform control IAM supports only the primary bootstrap repository; "
            "onboard service repositories through governance."
        )


class PlatformControlIam(pulumi.ComponentResource):
    """Adopt control identities once; normal platform stacks only reference them."""

    def __init__(
        self,
        name: str,
        *,
        settings: BootstrapSettings,
        repositories: Sequence[ManagedRepository],
        account_id: str,
        partition: str,
        region: str,
        provider_arn: pulumi.Input[str],
        boundary_arns: Mapping[str, pulumi.Input[str]],
        inline_policy_names: Mapping[str, Mapping[str, str]] | None = None,
        automation_retained_policy_arns: Sequence[pulumi.Input[str]] = (),
        opts: pulumi.ResourceOptions | None = None,
    ) -> None:
        _validate_platform_catalog(settings, repositories)
        preferred = _inline_policy_overrides(
            settings,
            repositories,
            {} if inline_policy_names is None else inline_policy_names,
        )
        super().__init__("bootstrap:iam:PlatformControlIam", name, None, opts)
        options = pulumi.ResourceOptions(parent=self, protect=True)
        control_boundary_arn = boundary_arns["control"]
        key_arns = {
            repository.name: aws.kms.get_alias(
                name=settings.pulumi_secrets_alias_name_for_repo(repository.name)
            ).target_key_arn
            for repository in repositories
        }
        self.state_guards = {}
        state_guard = platform_iam.platform_control_state_guard(
            account_id, settings, purpose="apply"
        )
        # The operator adds this guard alongside Automation's own inline policy.
        _validate_automation_policy_documents(
            _automation_policy_documents(account_id, settings, settings.repo or ""),
            additional_inline_documents=(state_guard,),
        )

        def create_guard(repository, role):
            identity, key = _control_guard_identity(repository)
            guard = aws.iam.RolePolicy(
                f"{name}-{key}-state-guard",
                name="PlatformControlStateGuard",
                role=role.name,
                policy=state_guard,
                opts=options,
            )
            self.state_guards[identity] = guard
            return guard

        # Existing names are intentional: migration retains physical IAM policy IDs.
        self.oidc = GitHubOidcRoles(
            "github-oidc",
            settings=settings,
            repositories=repositories,
            secrets_key_arns=key_arns,
            provider_arn=provider_arn,
            manage_provider=False,
            manage_roles=True,
            permissions_boundary=control_boundary_arn,
            adopt_existing_policies=True,
            role_guard_factory=create_guard,
            preferred_inline_policy_names={
                repo.name: preferred[
                    (
                        _role_name_for_suffix(_repo_suffix(repo.name, settings)),
                        f"github-oidc-policy-{_repo_suffix(repo.name, settings)}",
                    )
                ]
                for repo in repositories
                if (
                    _role_name_for_suffix(_repo_suffix(repo.name, settings)),
                    f"github-oidc-policy-{_repo_suffix(repo.name, settings)}",
                )
                in preferred
            },
            opts=options,
        )
        self.automation = GitHubAutomation(
            "github-automation",
            settings=settings,
            repository_project=_repository_project(repositories, settings.repo or ""),
            oidc_provider_arn=provider_arn,
            manage_repository=False,
            manage_roles=True,
            manage_triage=settings.environment == "prod",
            permissions_boundary=control_boundary_arn,
            adopt_existing_policies=True,
            role_guard_factory=lambda role: create_guard(None, role),
            preferred_inline_policy_name=preferred.get(
                (
                    settings.automation_role_name(settings.repo),
                    "github-automation-policy",
                )
            ),
            retained_policy_arns=automation_retained_policy_arns,
            opts=options,
        )
        self.config = ConfigRecorderIam(
            "security-account-controls-iam",
            settings=settings,
            account_id=account_id,
            partition=partition,
            region=region,
            adopt_existing=True,
            opts=options,
        )
        self.replication = PlatformReplicationIam(
            "platform-replication",
            settings=settings,
            repositories=repositories,
            account_id=account_id,
            region=region,
            partition=partition,
            adopt_existing=True,
            boundary_arns=boundary_arns,
            opts=options,
        )
        self.register_outputs(
            {
                "automationRoleArn": self.automation.role.arn,
                "deployRoleArns": self.oidc.deploy_role_arns,
                "configRecorderRoleArn": self.config.role.arn,
                "replicationRoleArns": {
                    key: role.arn for key, role in self.replication.roles.items()
                },
                "operationsAlertTriageRoleArn": (
                    self.automation.operations_alert_triage_role.arn
                ),
            }
        )
