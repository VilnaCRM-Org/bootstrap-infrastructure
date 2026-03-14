"""Pulumi Policy Pack guardrails for bootstrap infrastructure resources."""

from __future__ import annotations

import json
import os
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from pulumi_policy import (
    EnforcementLevel,
    Policy,
    PolicyPack,
    ResourceValidationArgs,
    ResourceValidationPolicy,
)

ResourceProps = Mapping[str, Any]
ReportViolation = Callable[[str, str | None], None]

S3_BUCKET_RESOURCE_TYPE = "aws:s3/bucket:Bucket"
DISALLOWED_RESOURCE_PREFIXES = (
    "aws:ec2/",
    "aws:ecs/",
    "aws:eks/",
    "aws:elasticache/",
    "aws:elbv2/",
    "aws:lambda/provisionedConcurrencyConfig:",
    "aws:natgateway/",
    "aws:rds/",
    "aws:redshift/",
)
STATE_BUCKET_PURPOSES = {"pulumi-state", "pulumi-state-replica"}
TAGGABLE_RESOURCE_TYPES = {
    "aws:backup/plan:Plan",
    "aws:backup/vault:Vault",
    "aws:ecr/repository:Repository",
    "aws:kms/key:Key",
    S3_BUCKET_RESOURCE_TYPE,
}
IAM_POLICY_RESOURCE_TYPES = {
    "aws:iam/policy:Policy",
    "aws:iam/rolePolicy:RolePolicy",
}
PRODUCTION_ENVIRONMENTS = {"prod", "production"}
PUBLIC_BUCKET_ACLS = {"public-read", "public-read-write", "website"}
DEFAULT_ALLOWED_REGIONS = ("eu-central-1", "us-east-1", "us-west-2")
REQUIRED_TAG_KEYS = ("App", "Environment", "Owner", "CostCenter", "Purpose")


def _prop(props: ResourceProps, *names: str) -> Any | None:
    for name in names:
        if name in props:
            return props[name]
    return None


def _mapping(value: Any) -> ResourceProps | None:
    return value if isinstance(value, Mapping) else None


def _sequence(value: Any) -> Sequence[Any] | None:
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return value
    return None


def _bool_true(value: Any) -> bool:
    return value is True


def _string(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    values = _sequence(value)
    if values is None:
        return []
    return [item for item in values if isinstance(item, str)]


def _json_document(value: Any) -> ResourceProps | None:
    if isinstance(value, Mapping):
        return value
    if not isinstance(value, str):
        return None
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, Mapping) else None


def _report(messages: Sequence[str], report_violation: ReportViolation) -> None:
    for message in messages:
        report_violation(message, None)


def _allowed_regions() -> set[str]:
    raw_value = os.getenv("VILNACRM_ALLOWED_AWS_REGIONS", "")
    if not raw_value.strip():
        return set(DEFAULT_ALLOWED_REGIONS)
    return {region.strip() for region in raw_value.split(",") if region.strip()} or set(
        DEFAULT_ALLOWED_REGIONS
    )


def _allowlisted_wildcard_sids() -> set[str]:
    raw_value = os.getenv("VILNACRM_IAM_WILDCARD_ALLOWLIST_SIDS", "")
    if not raw_value.strip():
        return set()
    return {sid.strip() for sid in raw_value.split(",") if sid.strip()}


def disallowed_resource_type_messages(
    resource_type: str,
) -> list[str]:
    for prefix in DISALLOWED_RESOURCE_PREFIXES:
        if resource_type.startswith(prefix):
            return [
                "bootstrap-infrastructure forbids "
                f"{resource_type}; keep bootstrap stacks out of expensive "
                "compute and data-plane services."
            ]
    return []


def finops_tag_messages(resource_type: str, props: ResourceProps) -> list[str]:
    if resource_type not in TAGGABLE_RESOURCE_TYPES or "tags" not in props:
        return []

    tags = _mapping(props["tags"])
    if tags is None:
        return ["resource tags must be supplied as a map."]

    messages: list[str] = []
    for key in REQUIRED_TAG_KEYS:
        if not _string(tags.get(key)):
            messages.append(f"resource tags must include a non-empty {key} value.")
    return messages


def allowed_region_messages(resource_type: str, props: ResourceProps) -> list[str]:
    if not resource_type.startswith("aws:"):
        return []

    region = _string(_prop(props, "region", "bucketRegion", "bucket_region"))
    if region is None:
        return []

    allowed_regions = _allowed_regions()
    if region in allowed_regions:
        return []
    return [
        "AWS resources must stay inside the approved region allowlist: "
        f"{', '.join(sorted(allowed_regions))}; got {region}."
    ]


def public_bucket_acl_messages(resource_type: str, props: ResourceProps) -> list[str]:
    if resource_type != S3_BUCKET_RESOURCE_TYPE:
        return []

    acl = _string(_prop(props, "acl"))
    if acl is None or acl not in PUBLIC_BUCKET_ACLS:
        return []

    tags = _mapping(_prop(props, "tags")) or {}
    if _string(tags.get("AllowPublicAccess")) == "true":
        return []
    return [
        "S3 buckets must not use public ACLs unless tags.AllowPublicAccess=true "
        f"explicitly records the exception; got acl={acl}."
    ]


def state_bucket_messages(resource_type: str, props: ResourceProps) -> list[str]:
    if resource_type != S3_BUCKET_RESOURCE_TYPE:
        return []

    tags = _mapping(_prop(props, "tags"))
    purpose = _string(tags.get("Purpose")) if tags is not None else None
    if purpose not in STATE_BUCKET_PURPOSES:
        return []

    messages: list[str] = []

    versioning = _mapping(_prop(props, "versioning"))
    if versioning is None or not _bool_true(_prop(versioning, "enabled")):
        messages.append("Pulumi state buckets must enable versioning.")

    sse = _mapping(
        _prop(
            props,
            "serverSideEncryptionConfiguration",
            "server_side_encryption_configuration",
        )
    )
    rule = _mapping(_prop(sse or {}, "rule"))
    default = _mapping(
        _prop(
            rule or {},
            "applyServerSideEncryptionByDefault",
            "apply_server_side_encryption_by_default",
        )
    )
    algorithm = _string(_prop(default or {}, "sseAlgorithm", "sse_algorithm"))
    if algorithm != "AES256":
        messages.append(
            "Pulumi state buckets must default to AES256 server-side encryption."
        )

    return messages


def public_access_block_messages(resource_type: str, props: ResourceProps) -> list[str]:
    if resource_type != "aws:s3/bucketPublicAccessBlock:BucketPublicAccessBlock":
        return []

    messages: list[str] = []
    required_flags = {
        "blockPublicAcls": "blockPublicAcls must be true.",
        "blockPublicPolicy": "blockPublicPolicy must be true.",
        "ignorePublicAcls": "ignorePublicAcls must be true.",
        "restrictPublicBuckets": "restrictPublicBuckets must be true.",
    }
    for flag, message in required_flags.items():
        snake_case = "".join(
            [
                "_" + character.lower() if character.isupper() else character
                for character in flag
            ]
        ).lstrip("_")
        if not _bool_true(_prop(props, flag, snake_case)):
            messages.append(message)
    return messages


def bucket_versioning_messages(resource_type: str, props: ResourceProps) -> list[str]:
    if resource_type != "aws:s3/bucketVersioning:BucketVersioning":
        return []

    configuration = _mapping(
        _prop(props, "versioningConfiguration", "versioning_configuration")
    )
    status = _string(_prop(configuration or {}, "status"))
    if status == "Enabled":
        return []
    return ["BucketVersioning resources must set status=Enabled."]


def bucket_encryption_messages(resource_type: str, props: ResourceProps) -> list[str]:
    if resource_type != (
        "aws:s3/bucketServerSideEncryptionConfiguration:"
        "BucketServerSideEncryptionConfiguration"
    ):
        return []

    rules = _sequence(_prop(props, "rules"))
    if rules:
        first_rule = _mapping(rules[0])
    else:
        first_rule = _mapping(_prop(props, "rule"))
    default = _mapping(
        _prop(
            first_rule or {},
            "applyServerSideEncryptionByDefault",
            "apply_server_side_encryption_by_default",
        )
    )
    algorithm = _string(_prop(default or {}, "sseAlgorithm", "sse_algorithm"))
    if algorithm == "AES256":
        return []
    return ["Bucket encryption resources must enforce AES256 by default."]


def tls_bucket_policy_messages(resource_type: str, props: ResourceProps) -> list[str]:
    if resource_type != "aws:s3/bucketPolicy:BucketPolicy":
        return []

    document = _json_document(_prop(props, "policy"))
    if document is None:
        return ["Bucket policies must be valid JSON."]

    statements = _sequence(document.get("Statement")) or ()
    for statement in statements:
        mapping = _mapping(statement)
        if mapping is None:
            continue
        if _string(mapping.get("Effect")) != "Deny":
            continue
        condition = _mapping(mapping.get("Condition"))
        secure_transport = _mapping(condition.get("Bool")) if condition else None
        if _string((secure_transport or {}).get("aws:SecureTransport")) == "false":
            return []

    return ["Bucket policies must deny non-TLS access via aws:SecureTransport=false."]


def kms_key_messages(resource_type: str, props: ResourceProps) -> list[str]:
    if resource_type != "aws:kms/key:Key":
        return []

    messages: list[str] = []
    if not _bool_true(_prop(props, "enableKeyRotation", "enable_key_rotation")):
        messages.append("KMS keys must enable automatic key rotation.")

    deletion_window = _prop(props, "deletionWindowInDays", "deletion_window_in_days")
    if not isinstance(deletion_window, int) or deletion_window < 30:
        messages.append("KMS keys must use a deletion window of at least 30 days.")

    return messages


def ecr_repository_messages(resource_type: str, props: ResourceProps) -> list[str]:
    if resource_type != "aws:ecr/repository:Repository":
        return []

    messages: list[str] = []
    if (
        _string(_prop(props, "imageTagMutability", "image_tag_mutability"))
        != "IMMUTABLE"
    ):
        messages.append("ECR repositories must use immutable tags.")

    scanning = _mapping(
        _prop(props, "imageScanningConfiguration", "image_scanning_configuration")
    )
    if not _bool_true(_prop(scanning or {}, "scanOnPush", "scan_on_push")):
        messages.append("ECR repositories must enable scanOnPush.")

    return messages


def backup_plan_messages(resource_type: str, props: ResourceProps) -> list[str]:
    if resource_type != "aws:backup/plan:Plan":
        return []

    rules = _sequence(_prop(props, "rules"))
    if not rules:
        return ["Backup plans must define at least one backup rule."]

    first_rule = _mapping(rules[0])
    lifecycle = _mapping(_prop(first_rule or {}, "lifecycle"))
    delete_after = _prop(lifecycle or {}, "deleteAfter", "delete_after")
    if isinstance(delete_after, int) and delete_after <= 90:
        return []
    return ["Backup plans must expire recovery points within 90 days."]


def _policy_statement_messages(
    index: int,
    statement: ResourceProps,
    allowlisted_sids: set[str],
) -> list[str]:
    if _string(statement.get("Effect")) != "Allow":
        return []

    sid = _string(statement.get("Sid"))
    if sid and sid in allowlisted_sids:
        return []

    actions = _strings(statement.get("Action"))
    resources = _strings(statement.get("Resource"))
    messages: list[str] = []
    if "*" in actions:
        messages.append(f"IAM policy statement {index} must not use Action='*'.")
    if any(action == "iam:*" for action in actions):
        messages.append(f"IAM policy statement {index} must not use Action='iam:*'.")
    if "*" in resources and any(
        action == "*" or action.startswith("iam:") for action in actions
    ):
        messages.append(
            "IAM policy statement "
            f"{index} must not use Resource='*' for IAM permissions."
        )
    return messages


def iam_policy_wildcard_messages(
    resource_type: str,
    props: ResourceProps,
) -> list[str]:
    if resource_type not in IAM_POLICY_RESOURCE_TYPES:
        return []

    document = _json_document(
        _prop(props, "policy", "policyDocument", "policy_document")
    )
    if document is None:
        return ["IAM policies must be valid JSON."]

    statements = _sequence(document.get("Statement")) or ()
    allowlisted_sids = _allowlisted_wildcard_sids()
    messages: list[str] = []
    for index, statement in enumerate(statements):
        mapping = _mapping(statement)
        if mapping is None:
            continue
        messages.extend(_policy_statement_messages(index, mapping, allowlisted_sids))
    return messages


def production_risky_default_messages(
    resource_type: str,
    props: ResourceProps,
) -> list[str]:
    if resource_type != S3_BUCKET_RESOURCE_TYPE:
        return []

    tags = _mapping(_prop(props, "tags")) or {}
    environment = _string(tags.get("Environment"))
    if environment not in PRODUCTION_ENVIRONMENTS:
        return []

    if not _bool_true(_prop(props, "forceDestroy", "force_destroy")):
        return []
    return ["Production-like S3 buckets must not enable forceDestroy."]


def validate_disallowed_resource_types(
    args: ResourceValidationArgs,
    report_violation: ReportViolation,
) -> None:
    _report(
        disallowed_resource_type_messages(args.resource_type),
        report_violation,
    )


def validate_finops_tags(
    args: ResourceValidationArgs,
    report_violation: ReportViolation,
) -> None:
    _report(finops_tag_messages(args.resource_type, args.props), report_violation)


def validate_allowed_regions(
    args: ResourceValidationArgs,
    report_violation: ReportViolation,
) -> None:
    _report(allowed_region_messages(args.resource_type, args.props), report_violation)


def validate_state_buckets(
    args: ResourceValidationArgs,
    report_violation: ReportViolation,
) -> None:
    _report(state_bucket_messages(args.resource_type, args.props), report_violation)


def validate_bucket_public_access(
    args: ResourceValidationArgs,
    report_violation: ReportViolation,
) -> None:
    _report(
        public_access_block_messages(args.resource_type, args.props),
        report_violation,
    )


def validate_bucket_public_acls(
    args: ResourceValidationArgs,
    report_violation: ReportViolation,
) -> None:
    _report(
        public_bucket_acl_messages(args.resource_type, args.props),
        report_violation,
    )


def validate_bucket_versioning(
    args: ResourceValidationArgs,
    report_violation: ReportViolation,
) -> None:
    _report(
        bucket_versioning_messages(args.resource_type, args.props),
        report_violation,
    )


def validate_bucket_encryption(
    args: ResourceValidationArgs,
    report_violation: ReportViolation,
) -> None:
    _report(
        bucket_encryption_messages(args.resource_type, args.props),
        report_violation,
    )


def validate_bucket_policies(
    args: ResourceValidationArgs,
    report_violation: ReportViolation,
) -> None:
    _report(
        tls_bucket_policy_messages(args.resource_type, args.props),
        report_violation,
    )


def validate_kms_keys(
    args: ResourceValidationArgs,
    report_violation: ReportViolation,
) -> None:
    _report(kms_key_messages(args.resource_type, args.props), report_violation)


def validate_ecr_repositories(
    args: ResourceValidationArgs,
    report_violation: ReportViolation,
) -> None:
    _report(
        ecr_repository_messages(args.resource_type, args.props),
        report_violation,
    )


def validate_backup_plans(
    args: ResourceValidationArgs,
    report_violation: ReportViolation,
) -> None:
    _report(backup_plan_messages(args.resource_type, args.props), report_violation)


def validate_iam_policy_wildcards(
    args: ResourceValidationArgs,
    report_violation: ReportViolation,
) -> None:
    _report(
        iam_policy_wildcard_messages(args.resource_type, args.props),
        report_violation,
    )


def validate_production_defaults(
    args: ResourceValidationArgs,
    report_violation: ReportViolation,
) -> None:
    _report(
        production_risky_default_messages(args.resource_type, args.props),
        report_violation,
    )


def build_policies() -> list[Policy]:
    return [
        ResourceValidationPolicy(
            name="approved-bootstrap-resource-types",
            description="Blocks high-cost AWS service families in the bootstrap stack.",
            enforcement_level=EnforcementLevel.MANDATORY,
            validate=validate_disallowed_resource_types,
        ),
        ResourceValidationPolicy(
            name="taggable-bootstrap-resources-have-finops-tags",
            description=(
                "Requires App, Environment, Owner, CostCenter, and Purpose tags "
                "on taggable bootstrap resources."
            ),
            enforcement_level=EnforcementLevel.MANDATORY,
            validate=validate_finops_tags,
        ),
        ResourceValidationPolicy(
            name="bootstrap-resources-stay-in-approved-regions",
            description="Restricts AWS resources to the VilnaCRM region allowlist.",
            enforcement_level=EnforcementLevel.MANDATORY,
            validate=validate_allowed_regions,
        ),
        ResourceValidationPolicy(
            name="pulumi-state-buckets-use-inline-guardrails",
            description=(
                "Requires Pulumi state buckets to enable versioning and "
                "AES256 encryption inline."
            ),
            enforcement_level=EnforcementLevel.MANDATORY,
            validate=validate_state_buckets,
        ),
        ResourceValidationPolicy(
            name="s3-public-access-blocks-are-locked-down",
            description=(
                "Requires every S3 public access block resource to deny "
                "public access completely."
            ),
            enforcement_level=EnforcementLevel.MANDATORY,
            validate=validate_bucket_public_access,
        ),
        ResourceValidationPolicy(
            name="s3-buckets-must-not-use-public-acls",
            description=(
                "Disallows public bucket ACLs unless AllowPublicAccess=true "
                "explicitly marks the exception."
            ),
            enforcement_level=EnforcementLevel.MANDATORY,
            validate=validate_bucket_public_acls,
        ),
        ResourceValidationPolicy(
            name="s3-versioning-resources-are-enabled",
            description=(
                "Requires every S3 bucket versioning resource to set status=Enabled."
            ),
            enforcement_level=EnforcementLevel.MANDATORY,
            validate=validate_bucket_versioning,
        ),
        ResourceValidationPolicy(
            name="s3-encryption-resources-default-to-aes256",
            description=(
                "Requires every S3 bucket encryption resource to default to AES256."
            ),
            enforcement_level=EnforcementLevel.MANDATORY,
            validate=validate_bucket_encryption,
        ),
        ResourceValidationPolicy(
            name="s3-bucket-policies-enforce-tls",
            description="Requires S3 bucket policies to deny non-TLS access.",
            enforcement_level=EnforcementLevel.MANDATORY,
            validate=validate_bucket_policies,
        ),
        ResourceValidationPolicy(
            name="kms-keys-enable-rotation",
            description=(
                "Requires KMS keys to rotate automatically and use a 30-day "
                "deletion window."
            ),
            enforcement_level=EnforcementLevel.MANDATORY,
            validate=validate_kms_keys,
        ),
        ResourceValidationPolicy(
            name="ecr-repositories-are-hardened",
            description=(
                "Requires bootstrap ECR repositories to use immutable tags "
                "and scanOnPush."
            ),
            enforcement_level=EnforcementLevel.MANDATORY,
            validate=validate_ecr_repositories,
        ),
        ResourceValidationPolicy(
            name="backup-plans-expire-recovery-points",
            description=(
                "Requires backup plans to expire recovery points within 90 days."
            ),
            enforcement_level=EnforcementLevel.MANDATORY,
            validate=validate_backup_plans,
        ),
        ResourceValidationPolicy(
            name="iam-policies-avoid-wildcard-iam-permissions",
            description=(
                "Disallows Action='*', Action='iam:*', and Resource='*' for IAM "
                "permissions unless an explicit Sid allowlist is configured."
            ),
            enforcement_level=EnforcementLevel.MANDATORY,
            validate=validate_iam_policy_wildcards,
        ),
        ResourceValidationPolicy(
            name="production-buckets-avoid-risky-defaults",
            description=("Disallows forceDestroy on production-like S3 buckets."),
            enforcement_level=EnforcementLevel.MANDATORY,
            validate=validate_production_defaults,
        ),
    ]


def create_policy_pack() -> PolicyPack:
    return PolicyPack(
        name="bootstrap-infrastructure-guardrails",
        policies=build_policies(),
        description="Pulumi guardrails for bootstrap-infrastructure.",
    )
