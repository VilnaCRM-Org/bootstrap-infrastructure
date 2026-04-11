"""Pulumi policy definitions for the VilnaCRM infrastructure template."""

from __future__ import annotations

try:
    from policy.config import load_policy_config
    from policy.guardrails import (
        extract_tags,
        has_public_s3_acl,
        has_public_s3_bucket_policy,
        invalid_region,
        is_public_bucket_allowlisted,
        logging_violations,
        missing_required_tags,
        open_admin_ports,
        production_database_violations,
        storage_encryption_violations,
        wildcard_iam_violations,
    )
except ModuleNotFoundError as exc:  # pragma: no cover - direct script startup.
    if exc.name not in {"policy", "policy.config", "policy.guardrails"}:
        raise
    from config import load_policy_config
    from guardrails import (
        extract_tags,
        has_public_s3_acl,
        has_public_s3_bucket_policy,
        invalid_region,
        is_public_bucket_allowlisted,
        logging_violations,
        missing_required_tags,
        open_admin_ports,
        production_database_violations,
        storage_encryption_violations,
        wildcard_iam_violations,
    )
from pulumi_policy import (
    EnforcementLevel,
    ReportViolation,
    ResourceValidationArgs,
    ResourceValidationPolicy,
)

POLICY_PACK_NAME = "vilnacrm-guardrails"
CONFIG = load_policy_config()


def require_default_tags(
    args: ResourceValidationArgs, report_violation: ReportViolation
) -> None:
    """Require mandatory VilnaCRM default tags on tagged AWS resources."""
    if not args.resource_type.startswith("aws:"):
        return
    if "tags" not in args.props and "tagsAll" not in args.props:
        return

    missing = missing_required_tags(extract_tags(args.props), CONFIG)
    if missing:
        report_violation(
            "Tagged AWS resources must include the VilnaCRM default tags: "
            + ", ".join(missing)
            + "."
        )


def enforce_allowed_regions(
    args: ResourceValidationArgs, report_violation: ReportViolation
) -> None:
    """Restrict stack execution to the repository region allowlist."""
    region = invalid_region(args.resource_type, args.props, CONFIG)
    if region:
        report_violation(
            f"AWS region `{region}` is not in the VilnaCRM allowlist: "
            + ", ".join(CONFIG.allowed_regions)
            + "."
        )


def block_public_s3_exposure(
    args: ResourceValidationArgs, report_violation: ReportViolation
) -> None:
    """Prevent accidental public S3 buckets unless explicitly allowlisted."""
    if is_public_bucket_allowlisted(args.props, CONFIG):
        return

    if has_public_s3_acl(args.resource_type, args.props):
        report_violation(
            "S3 buckets must not use public ACLs unless the resource is "
            "explicitly allowlisted."
        )

    if has_public_s3_bucket_policy(args.resource_type, args.props):
        report_violation(
            "S3 bucket policies must not grant public access unless the "
            "resource is explicitly allowlisted."
        )


def require_storage_encryption(
    args: ResourceValidationArgs, report_violation: ReportViolation
) -> None:
    """Require encryption at rest on critical persistent AWS resources."""
    for violation in storage_encryption_violations(args.resource_type, args.props):
        report_violation(violation)


def require_logging(
    args: ResourceValidationArgs, report_violation: ReportViolation
) -> None:
    """Require logging on supported resources."""
    for violation in logging_violations(args.resource_type, args.props):
        report_violation(violation)


def block_wildcard_iam(
    args: ResourceValidationArgs, report_violation: ReportViolation
) -> None:
    """Reject wildcard IAM permissions unless the resource is allowlisted."""
    for violation in wildcard_iam_violations(args.resource_type, args.props, CONFIG):
        report_violation(violation)


def require_production_database_safety(
    args: ResourceValidationArgs, report_violation: ReportViolation
) -> None:
    """Require safer defaults for production-like database resources."""
    for violation in production_database_violations(
        args.resource_type, args.props, CONFIG
    ):
        report_violation(violation)


def block_open_admin_ports(
    args: ResourceValidationArgs, report_violation: ReportViolation
) -> None:
    """Prevent public exposure of SSH and RDP through security groups."""
    ports = open_admin_ports(args.resource_type, args.props)
    if ports:
        report_violation(
            "Security groups must not expose admin ports to the public internet: "
            + ", ".join(str(port) for port in ports)
            + "."
        )


def build_policies() -> list[ResourceValidationPolicy]:
    """Construct the policy list exported by the Pulumi policy pack."""
    return [
        ResourceValidationPolicy(
            name="aws-resource-required-default-tags",
            description="Require VilnaCRM default tags on tagged AWS resources.",
            enforcement_level=EnforcementLevel.MANDATORY,
            validate=require_default_tags,
        ),
        ResourceValidationPolicy(
            name="aws-region-allowlist",
            description="Restrict AWS resources to approved VilnaCRM regions.",
            enforcement_level=EnforcementLevel.MANDATORY,
            validate=enforce_allowed_regions,
        ),
        ResourceValidationPolicy(
            name="s3-no-public-exposure",
            description="Prevent public S3 ACLs and bucket policies.",
            enforcement_level=EnforcementLevel.MANDATORY,
            validate=block_public_s3_exposure,
        ),
        ResourceValidationPolicy(
            name="critical-storage-encrypted",
            description="Require encryption at rest for critical storage resources.",
            enforcement_level=EnforcementLevel.MANDATORY,
            validate=require_storage_encryption,
        ),
        ResourceValidationPolicy(
            name="supported-resources-logging-enabled",
            description="Require access logging for supported AWS resources.",
            enforcement_level=EnforcementLevel.MANDATORY,
            validate=require_logging,
        ),
        ResourceValidationPolicy(
            name="iam-no-wildcards",
            description=(
                "Reject wildcard IAM permissions unless explicitly allowlisted."
            ),
            enforcement_level=EnforcementLevel.MANDATORY,
            validate=block_wildcard_iam,
        ),
        ResourceValidationPolicy(
            name="production-database-safety",
            description="Require safer defaults for production-like databases.",
            enforcement_level=EnforcementLevel.MANDATORY,
            validate=require_production_database_safety,
        ),
        ResourceValidationPolicy(
            name="security-group-no-open-admin-ports",
            description="Disallow public SSH and RDP exposure in security groups.",
            enforcement_level=EnforcementLevel.MANDATORY,
            validate=block_open_admin_ports,
        ),
    ]
