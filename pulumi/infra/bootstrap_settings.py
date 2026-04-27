"""Typed Pulumi settings and naming rules for bootstrap infrastructure."""

from __future__ import annotations

import ipaddress
import math
import os
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

import pulumi

if TYPE_CHECKING:
    from .managed_repository import ManagedRepository


_VALID_CHARS_PATTERN = re.compile(r"[^a-z0-9.-]")
_SEQUENTIAL_DOTS = re.compile(r"\.{2,}")
_SEQUENTIAL_HYPHENS = re.compile(r"-{2,}")
_DOT_HYPHEN_ADJACENT = re.compile(r"\.-|-\.")
_IPV4_PATTERN = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_COST_ANOMALY_MONITOR_ARN_PATTERN = re.compile(
    r"^arn:[a-z0-9-]+:ce::\d{12}:anomalymonitor/[A-Za-z0-9][A-Za-z0-9._/-]*$"
)


@dataclass
class BootstrapSettings:
    """Strongly typed stack settings plus naming helpers."""

    org: str
    repo: str | None
    environment: str
    owner: str
    cost_center: str
    data_classification: str
    criticality: str
    retention_class: str
    github_branch: str | None
    logging_prefix: str
    replication_region: str | None
    github_token: pulumi.Output[str] | None
    github_oidc_provider_arn: str | None
    repository_catalog_path: str | None = None
    managed_repo_overrides: list["ManagedRepository"] | None = None
    monthly_budget_limit_usd: str = "100"
    cost_anomaly_threshold_usd: str = "10"
    cost_anomaly_monitor_arn: str | None = None
    manage_cost_allocation_tags: bool = False

    @classmethod
    def from_pulumi_config(
        cls,
        cfg: pulumi.Config | None = None,
    ) -> "BootstrapSettings":
        """Load settings from Pulumi configuration."""
        config = cfg or pulumi.Config()
        return cls(
            org=cls.require_config_value(config, "githubOrg", "test-org"),
            repo=config.get("repoSlug"),
            environment=config.get("environment") or pulumi.get_stack(),
            owner=config.get("owner") or "platform",
            cost_center=config.get("costCenter") or "core",
            data_classification=config.get("dataClassification") or "internal",
            criticality=config.get("criticality") or "high",
            retention_class=config.get("retentionClass") or "standard",
            github_branch=config.get("githubBranch"),
            logging_prefix=config.get("loggingPrefix") or "company",
            replication_region=config.get("replicationRegion"),
            monthly_budget_limit_usd=cls.positive_decimal_config_value(
                config,
                "monthlyBudgetLimitUsd",
                "100",
            ),
            cost_anomaly_threshold_usd=cls.positive_decimal_config_value(
                config,
                "costAnomalyThresholdUsd",
                "10",
            ),
            cost_anomaly_monitor_arn=cls.optional_cost_anomaly_monitor_arn(config),
            manage_cost_allocation_tags=cls.optional_bool_config_value(
                config,
                "manageCostAllocationTags",
                False,
            ),
            github_token=config.get_secret("githubToken"),
            github_oidc_provider_arn=config.get("githubOidcProviderArn"),
            repository_catalog_path=config.get("repositoryCatalogPath"),
        )

    @staticmethod
    def allow_test_defaults() -> bool:
        """Return True when tests allow fallback configuration defaults."""
        return os.getenv("PULUMI_ALLOW_TEST_DEFAULTS") == "1"

    @classmethod
    def require_config_value(
        cls,
        cfg: pulumi.Config,
        key: str,
        fallback: str,
    ) -> str:
        """Load a required Pulumi config value with optional test fallback."""
        value = cfg.get(key)
        if value is None:
            if cls.allow_test_defaults():
                return fallback
            raise pulumi.ConfigMissingError(key, False)
        return value

    @staticmethod
    def positive_decimal_config_value(
        cfg: pulumi.Config,
        key: str,
        fallback: str,
    ) -> str:
        """Load a positive decimal config value as the string AWS APIs expect."""
        value = cfg.get(key) or fallback
        try:
            numeric_value = float(value)
        except ValueError as exc:
            raise ValueError(f"{key} must be a positive decimal value.") from exc
        if numeric_value <= 0:
            raise ValueError(f"{key} must be a positive decimal value.")
        if not math.isfinite(numeric_value):
            raise ValueError(f"{key} must be a finite positive decimal value.")
        return value

    @staticmethod
    def optional_cost_anomaly_monitor_arn(cfg: pulumi.Config) -> str | None:
        """Load and validate an optional existing Cost Anomaly monitor ARN."""
        value = cfg.get("costAnomalyMonitorArn")
        if value is None:
            return None
        if not _COST_ANOMALY_MONITOR_ARN_PATTERN.fullmatch(value):
            raise ValueError(
                "costAnomalyMonitorArn must be a Cost Anomaly monitor ARN."
            )
        return value

    @staticmethod
    def optional_bool_config_value(
        cfg: pulumi.Config,
        key: str,
        fallback: bool,
    ) -> bool:
        """Load an optional boolean while keeping tests' config doubles simple."""
        get_bool = getattr(cfg, "get_bool", None)
        if get_bool is not None:
            value = get_bool(key)
            return fallback if value is None else value
        raw_value = cfg.get(key)
        if raw_value is None:
            return fallback
        return raw_value.lower() == "true"

    def bootstrap_requested(self, cfg: pulumi.Config | None = None) -> bool:
        """Return True when bootstrap infrastructure should be materialized."""
        config = cfg or pulumi.Config()
        return bool(
            self.repo
            or self.repository_catalog_path
            or self.managed_repo_overrides
            or config.get_object("managedRepositories")
        )

    def sanitize_bucket_component(self, value: str, label: str) -> str:
        """Return a DNS-safe S3 bucket component derived from user input."""
        normalized = value.strip().lower()

        if _IPV4_PATTERN.match(normalized):
            raise ValueError(f"{label} cannot be an IPv4 address.")
        try:
            parsed_address = ipaddress.ip_address(normalized)
        except ValueError:
            parsed_address = None
        if isinstance(parsed_address, ipaddress.IPv6Address):
            raise ValueError(f"{label} cannot be an IPv6 address.")

        candidate = normalized
        candidate = _VALID_CHARS_PATTERN.sub("-", candidate)
        candidate = _SEQUENTIAL_DOTS.sub(".", candidate)
        candidate = _SEQUENTIAL_HYPHENS.sub("-", candidate)
        candidate = candidate.strip(".-")

        if _DOT_HYPHEN_ADJACENT.search(candidate):
            raise ValueError(
                f"{label} cannot contain dot-hyphen adjacency for S3 buckets."
            )
        if _IPV4_PATTERN.match(candidate):
            raise ValueError(f"{label} cannot be an IPv4 address.")
        if not candidate:
            raise ValueError(
                f"{label} cannot be fully sanitized; please use a different value."
            )
        if len(candidate) > 63:
            raise ValueError(
                f"{label} must resolve to no more than 63 characters for S3 buckets."
            )

        return candidate

    def state_bucket_name_for_repo(self, repo_name: str) -> str:
        """Compute the full state bucket name for a repository."""
        repo_part = self.sanitize_bucket_component(repo_name, "repoSlug")
        env_part = self.sanitize_bucket_component(self.environment, "environment")
        name = f"pulumi-{repo_part}-{env_part}-state"
        if len(name) > 63:
            raise ValueError(
                "Combined repo/environment "
                f"('{repo_part}', '{env_part}') produce bucket name "
                f"'{name}' longer than 63 characters."
            )
        return name

    def state_bucket_name(self) -> str:
        """Compute the state bucket name for the configured repository."""
        if not self.repo:
            raise ValueError(
                "repoSlug config is not set; use state_bucket_name_for_repo(repo) "
                "instead."
            )
        return self.state_bucket_name_for_repo(self.repo)

    def pulumi_secrets_alias_name_for_repo(self, repo_name: str) -> str:
        """Compute the KMS alias used for Pulumi secrets for a repository."""
        repo_part = self.sanitize_bucket_component(repo_name, "repoSlug").replace(
            ".",
            "-",
        )
        env_part = self.sanitize_bucket_component(
            self.environment,
            "environment",
        ).replace(".", "-")
        return f"alias/pulumi-{repo_part}-{env_part}-secrets"

    def pulumi_secrets_provider_for_repo(self, repo_name: str, region: str) -> str:
        """Build the Pulumi AWS KMS secrets provider URI for a repository."""
        region_part = self.sanitize_bucket_component(region, "region")
        return (
            f"awskms://{self.pulumi_secrets_alias_name_for_repo(repo_name)}"
            f"?region={region_part}"
        )

    def runner_ecr_repository_name(self, repo_name: str) -> str:
        """Compute the ECR repository name used by automation runners."""
        repo_part = self.sanitize_bucket_component(repo_name, "repoSlug").replace(
            ".",
            "-",
        )
        env_part = self.sanitize_bucket_component(self.environment, "environment")
        return f"pulumi-runner/{repo_part}-{env_part}"

    def automation_role_name(self, repo_name: str) -> str:
        """Compute the GitHub automation role name for this repo/environment."""
        repo_part = self.sanitize_bucket_component(repo_name, "repoSlug").replace(
            ".",
            "-",
        )
        env_part = self.sanitize_bucket_component(self.environment, "environment")
        name = f"PulumiAutomation-{repo_part}-{env_part}"
        if len(name) > 64:
            raise ValueError(
                "Combined repo/environment produce automation role name "
                f"'{name}' longer than 64 characters."
            )
        return name

    def central_logging_bucket_name(self, region: str) -> str:
        """Compute the central logging bucket name for a given region."""
        prefix_part = self.sanitize_bucket_component(
            self.logging_prefix,
            "loggingPrefix",
        )
        env_part = self.sanitize_bucket_component(self.environment, "environment")
        region_part = self.sanitize_bucket_component(region, "region")
        name = f"{prefix_part}-central-logs-{region_part}-{env_part}"
        if len(name) > 63:
            raise ValueError(
                "Combined logging prefix/region/environment results in an S3 "
                "bucket name longer than 63 characters."
            )
        return name

    def base_tags(
        self,
        extra: dict[str, str] | None = None,
        *,
        app_name: str | None = None,
    ) -> dict[str, str]:
        """Return the standard tag set merged with optional extra tags."""
        tags = {
            "Project": pulumi.get_project(),
            "Environment": self.environment,
            "Owner": self.owner,
            "CostCenter": self.cost_center,
            "DataClassification": self.data_classification,
            "Criticality": self.criticality,
            "RetentionClass": self.retention_class,
        }
        resolved_app = app_name or self.repo
        if resolved_app:
            tags["App"] = resolved_app
        if extra:
            tags.update(extra)
        return tags
