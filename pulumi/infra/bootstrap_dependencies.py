"""Dependency injection defaults for the bootstrap infrastructure orchestrator."""

from __future__ import annotations

from dataclasses import dataclass

from .automation import GitHubAutomation
from .backup import S3BackupPlan
from .ci_config import CiConfiguration
from .cost_controls import CostControls
from .iam import GitHubOidcRoles
from .logging_bucket import CentralLoggingBuckets
from .operations_monitoring import OperationsMonitoring
from .pulumi_secrets import PulumiSecretsKeys
from .pulumi_state import PulumiStateBuckets
from .security_account_controls import SecurityAccountControls


@dataclass(frozen=True)
class BootstrapInfrastructureDependencies:
    """Default component classes used by the bootstrap orchestrator."""

    logging_buckets_cls: type[CentralLoggingBuckets] = CentralLoggingBuckets
    state_buckets_cls: type[PulumiStateBuckets] = PulumiStateBuckets
    secrets_keys_cls: type[PulumiSecretsKeys] = PulumiSecretsKeys
    oidc_roles_cls: type[GitHubOidcRoles] = GitHubOidcRoles
    automation_cls: type[GitHubAutomation] = GitHubAutomation
    backup_plan_cls: type[S3BackupPlan] = S3BackupPlan
    monitoring_cls: type[OperationsMonitoring] = OperationsMonitoring
    cost_controls_cls: type[CostControls] = CostControls
    security_account_controls_cls: type[SecurityAccountControls] = (
        SecurityAccountControls
    )
    ci_config_cls: type[CiConfiguration] = CiConfiguration
