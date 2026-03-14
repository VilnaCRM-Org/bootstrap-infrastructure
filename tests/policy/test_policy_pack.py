import importlib
import json
import sys
from pathlib import Path
from typing import Any, cast

from policy_pack import guardrails
from pulumi_policy import EnforcementLevel, Policy, ResourceValidationArgs


def _args(resource_type: str, props: dict[str, object]) -> ResourceValidationArgs:
    return ResourceValidationArgs(
        resource_type=resource_type,
        props=cast(dict[str, Any], props),
        name="example",
        urn="urn:pulumi:test::bootstrap::example",
        opts=cast(Any, None),
        provider=None,
    )


def test_disallowed_resource_type_messages_cover_allowed_and_blocked_types():
    assert guardrails.disallowed_resource_type_messages("aws:s3/bucket:Bucket") == []  # nosec B101
    assert guardrails.disallowed_resource_type_messages("aws:ec2/vpc:Vpc") == [  # nosec B101
        "bootstrap-infrastructure forbids aws:ec2/vpc:Vpc; keep bootstrap "
        "stacks out of expensive compute and data-plane services."
    ]


def test_finops_tag_messages_require_expected_keys():
    assert guardrails.finops_tag_messages("aws:iam/role:Role", {}) == []  # nosec B101
    assert guardrails.finops_tag_messages("aws:kms/key:Key", {"tags": "invalid"}) == [  # nosec B101
        "resource tags must be supplied as a map."
    ]
    assert (
        guardrails.finops_tag_messages(
            "aws:kms/key:Key",
            {
                "tags": {
                    "App": "bootstrap-infrastructure",
                    "Environment": "test",
                    "Owner": "platform",
                    "CostCenter": "core",
                    "Purpose": "kms",
                }
            },
        )
        == []
    )  # nosec B101
    assert guardrails.finops_tag_messages(
        "aws:kms/key:Key",
        {
            "tags": {
                "App": "bootstrap-infrastructure",
                "Environment": "",
                "Owner": "",
                "CostCenter": "core",
            }
        },
    ) == [  # nosec B101
        "resource tags must include a non-empty Environment value.",
        "resource tags must include a non-empty Owner value.",
        "resource tags must include a non-empty Purpose value.",
    ]


def test_allowed_region_messages_respect_default_and_custom_allowlists(monkeypatch):
    monkeypatch.delenv("VILNACRM_ALLOWED_AWS_REGIONS", raising=False)
    assert (
        guardrails.allowed_region_messages(
            "pulumi:providers:aws",
            {"region": "eu-central-1"},
        )
        == []
    )  # nosec B101
    assert (
        guardrails.allowed_region_messages(
            "aws:s3/bucket:Bucket",
            {},
        )
        == []
    )  # nosec B101
    assert (
        guardrails.allowed_region_messages(
            "aws:s3/bucket:Bucket",
            {"region": "eu-central-1"},
        )
        == []
    )  # nosec B101
    assert guardrails.allowed_region_messages(
        "aws:s3/bucket:Bucket",
        {"region": "ap-south-1"},
    ) == [  # nosec B101
        "AWS resources must stay inside the approved region allowlist: "
        "eu-central-1, us-east-1, us-west-2; got ap-south-1."
    ]

    monkeypatch.setenv("VILNACRM_ALLOWED_AWS_REGIONS", "eu-central-1,ap-south-1")
    assert (
        guardrails.allowed_region_messages(
            "aws:s3/bucket:Bucket",
            {"region": "ap-south-1"},
        )
        == []
    )  # nosec B101


def test_public_bucket_acl_messages_require_explicit_allowlist_tag():
    assert guardrails.public_bucket_acl_messages("aws:kms/key:Key", {}) == []  # nosec B101
    assert (
        guardrails.public_bucket_acl_messages(
            "aws:s3/bucket:Bucket",
            {"acl": "private"},
        )
        == []
    )  # nosec B101
    assert guardrails.public_bucket_acl_messages(
        "aws:s3/bucket:Bucket",
        {"acl": "public-read"},
    ) == [  # nosec B101
        "S3 buckets must not use public ACLs unless tags.AllowPublicAccess=true "
        "explicitly records the exception; got acl=public-read."
    ]
    assert (
        guardrails.public_bucket_acl_messages(
            "aws:s3/bucket:Bucket",
            {"acl": "public-read", "tags": {"AllowPublicAccess": "true"}},
        )
        == []
    )  # nosec B101


def test_state_bucket_messages_enforce_inline_versioning_and_encryption():
    assert guardrails.state_bucket_messages("aws:kms/key:Key", {}) == []  # nosec B101
    assert (
        guardrails.state_bucket_messages(
            "aws:s3/bucket:Bucket",
            {"tags": {"Purpose": "central-logging"}},
        )
        == []
    )  # nosec B101
    assert guardrails.state_bucket_messages(
        "aws:s3/bucket:Bucket",
        {"tags": {"Purpose": "pulumi-state"}},
    ) == [  # nosec B101
        "Pulumi state buckets must enable versioning.",
        "Pulumi state buckets must default to AES256 server-side encryption.",
    ]
    assert (
        guardrails.state_bucket_messages(
            "aws:s3/bucket:Bucket",
            {
                "tags": {"Purpose": "pulumi-state-replica"},
                "versioning": {"enabled": True},
                "serverSideEncryptionConfiguration": {
                    "rule": {
                        "applyServerSideEncryptionByDefault": {"sseAlgorithm": "AES256"}
                    }
                },
            },
        )
        == []
    )  # nosec B101


def test_public_access_block_messages_accepts_camel_and_snake_case_props():
    assert guardrails.public_access_block_messages("aws:s3/bucket:Bucket", {}) == []  # nosec B101
    assert guardrails.public_access_block_messages(
        "aws:s3/bucketPublicAccessBlock:BucketPublicAccessBlock",
        {
            "block_public_acls": True,
            "block_public_policy": True,
            "ignore_public_acls": True,
            "restrict_public_buckets": False,
        },
    ) == [  # nosec B101
        "restrictPublicBuckets must be true."
    ]
    assert (
        guardrails.public_access_block_messages(
            "aws:s3/bucketPublicAccessBlock:BucketPublicAccessBlock",
            {
                "blockPublicAcls": True,
                "blockPublicPolicy": True,
                "ignorePublicAcls": True,
                "restrictPublicBuckets": True,
            },
        )
        == []
    )  # nosec B101


def test_bucket_versioning_messages_require_enabled_status():
    assert guardrails.bucket_versioning_messages("aws:s3/bucket:Bucket", {}) == []  # nosec B101
    assert guardrails.bucket_versioning_messages(
        "aws:s3/bucketVersioning:BucketVersioning",
        {"versioningConfiguration": {"status": "Suspended"}},
    ) == [  # nosec B101
        "BucketVersioning resources must set status=Enabled."
    ]
    assert (
        guardrails.bucket_versioning_messages(
            "aws:s3/bucketVersioning:BucketVersioning",
            {"versioning_configuration": {"status": "Enabled"}},
        )
        == []
    )  # nosec B101


def test_bucket_encryption_messages_require_aes256():
    assert guardrails.bucket_encryption_messages("aws:s3/bucket:Bucket", {}) == []  # nosec B101
    assert guardrails.bucket_encryption_messages(
        "aws:s3/bucketServerSideEncryptionConfiguration:BucketServerSideEncryptionConfiguration",
        {
            "rule": {
                "apply_server_side_encryption_by_default": {"sse_algorithm": "aws:kms"}
            }
        },
    ) == [  # nosec B101
        "Bucket encryption resources must enforce AES256 by default."
    ]
    assert (
        guardrails.bucket_encryption_messages(
            "aws:s3/bucketServerSideEncryptionConfiguration:BucketServerSideEncryptionConfiguration",
            {
                "rules": [
                    {"applyServerSideEncryptionByDefault": {"sseAlgorithm": "AES256"}}
                ]
            },
        )
        == []
    )  # nosec B101


def test_tls_bucket_policy_messages_require_valid_json_and_tls_deny():
    assert guardrails.tls_bucket_policy_messages("aws:s3/bucket:Bucket", {}) == []  # nosec B101
    assert guardrails.tls_bucket_policy_messages(
        "aws:s3/bucketPolicy:BucketPolicy",
        {"policy": 7},
    ) == ["Bucket policies must be valid JSON."]  # nosec B101
    assert guardrails.tls_bucket_policy_messages(
        "aws:s3/bucketPolicy:BucketPolicy",
        {"policy": "{invalid"},
    ) == ["Bucket policies must be valid JSON."]  # nosec B101
    assert guardrails.tls_bucket_policy_messages(
        "aws:s3/bucketPolicy:BucketPolicy",
        {
            "policy": {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                    },
                    "invalid-statement",
                ]
            }
        },
    ) == [  # nosec B101
        "Bucket policies must deny non-TLS access via aws:SecureTransport=false."
    ]
    assert (
        guardrails.tls_bucket_policy_messages(
            "aws:s3/bucketPolicy:BucketPolicy",
            {
                "policy": {
                    "Statement": [
                        {
                            "Effect": "Deny",
                            "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                        }
                    ]
                }
            },
        )
        == []
    )  # nosec B101


def test_kms_key_messages_require_rotation_and_window():
    assert guardrails.kms_key_messages("aws:s3/bucket:Bucket", {}) == []  # nosec B101
    assert guardrails.kms_key_messages(
        "aws:kms/key:Key",
        {"enable_key_rotation": False, "deletion_window_in_days": 7},
    ) == [  # nosec B101
        "KMS keys must enable automatic key rotation.",
        "KMS keys must use a deletion window of at least 30 days.",
    ]
    assert (
        guardrails.kms_key_messages(
            "aws:kms/key:Key",
            {"enableKeyRotation": True, "deletionWindowInDays": 30},
        )
        == []
    )  # nosec B101


def test_ecr_repository_messages_require_immutability_and_scanning():
    assert guardrails.ecr_repository_messages("aws:s3/bucket:Bucket", {}) == []  # nosec B101
    assert guardrails.ecr_repository_messages(
        "aws:ecr/repository:Repository",
        {"imageTagMutability": "MUTABLE", "imageScanningConfiguration": {}},
    ) == [  # nosec B101
        "ECR repositories must use immutable tags.",
        "ECR repositories must enable scanOnPush.",
    ]
    assert (
        guardrails.ecr_repository_messages(
            "aws:ecr/repository:Repository",
            {
                "image_tag_mutability": "IMMUTABLE",
                "image_scanning_configuration": {"scan_on_push": True},
            },
        )
        == []
    )  # nosec B101


def test_backup_plan_messages_require_retention_rule():
    assert guardrails.backup_plan_messages("aws:kms/key:Key", {}) == []  # nosec B101
    assert guardrails.backup_plan_messages(
        "aws:backup/plan:Plan",
        {},
    ) == ["Backup plans must define at least one backup rule."]  # nosec B101
    assert guardrails.backup_plan_messages(
        "aws:backup/plan:Plan",
        {"rules": [{"lifecycle": {"deleteAfter": 120}}]},
    ) == [  # nosec B101
        "Backup plans must expire recovery points within 90 days."
    ]
    assert (
        guardrails.backup_plan_messages(
            "aws:backup/plan:Plan",
            {"rules": [{"lifecycle": {"delete_after": 90}}]},
        )
        == []
    )  # nosec B101


def test_iam_policy_wildcard_messages_block_risky_iam_statements(monkeypatch):
    monkeypatch.delenv("VILNACRM_IAM_WILDCARD_ALLOWLIST_SIDS", raising=False)
    assert (
        guardrails.iam_policy_wildcard_messages(
            "aws:iam/role:Role",
            {},
        )
        == []
    )  # nosec B101
    assert guardrails.iam_policy_wildcard_messages(
        "aws:iam/rolePolicy:RolePolicy",
        {
            "policy": json.dumps(
                {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": ["iam:*"],
                            "Resource": "*",
                        }
                    ]
                }
            )
        },
    ) == [  # nosec B101
        "IAM policy statement 0 must not use Action='iam:*'.",
        "IAM policy statement 0 must not use Resource='*' for IAM permissions.",
    ]
    assert guardrails.iam_policy_wildcard_messages(
        "aws:iam/rolePolicy:RolePolicy",
        {
            "policy": json.dumps(
                {
                    "Statement": [
                        {"Effect": "Deny", "Action": "*", "Resource": "*"},
                        {"Effect": "Allow", "Action": "*", "Resource": "*"},
                        "not-a-mapping",
                    ]
                }
            )
        },
    ) == [  # nosec B101
        "IAM policy statement 1 must not use Action='*'.",
        "IAM policy statement 1 must not use Resource='*' for IAM permissions.",
    ]
    assert guardrails.iam_policy_wildcard_messages(
        "aws:iam/rolePolicy:RolePolicy",
        {"policy": "{invalid"},
    ) == ["IAM policies must be valid JSON."]  # nosec B101

    monkeypatch.setenv("VILNACRM_IAM_WILDCARD_ALLOWLIST_SIDS", "ApprovedException")
    assert (
        guardrails.iam_policy_wildcard_messages(
            "aws:iam/rolePolicy:RolePolicy",
            {
                "policy": json.dumps(
                    {
                        "Statement": [
                            {
                                "Sid": "ApprovedException",
                                "Effect": "Allow",
                                "Action": ["iam:*"],
                                "Resource": "*",
                            }
                        ]
                    }
                )
            },
        )
        == []
    )  # nosec B101


def test_production_risky_default_messages_block_force_destroy():
    assert (
        guardrails.production_risky_default_messages(
            "aws:kms/key:Key",
            {"tags": {"Environment": "prod"}, "forceDestroy": True},
        )
        == []
    )  # nosec B101
    assert (
        guardrails.production_risky_default_messages(
            "aws:s3/bucket:Bucket",
            {"tags": {"Environment": "test"}, "forceDestroy": True},
        )
        == []
    )  # nosec B101
    assert (
        guardrails.production_risky_default_messages(
            "aws:s3/bucket:Bucket",
            {"tags": {"Environment": "prod"}, "forceDestroy": False},
        )
        == []
    )  # nosec B101
    assert guardrails.production_risky_default_messages(
        "aws:s3/bucket:Bucket",
        {"tags": {"Environment": "prod"}, "force_destroy": True},
    ) == ["Production-like S3 buckets must not enable forceDestroy."]  # nosec B101


def test_iam_policy_wildcard_messages_ignore_non_sequence_actions_and_resources():
    assert (
        guardrails.iam_policy_wildcard_messages(
            "aws:iam/rolePolicy:RolePolicy",
            {
                "policy": json.dumps(
                    {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": {"unexpected": "shape"},
                                "Resource": {"unexpected": "shape"},
                            }
                        ]
                    }
                )
            },
        )
        == []
    )  # nosec B101


def test_validation_wrappers_report_messages():
    report: list[str] = []

    def record(message: str, _urn: str | None = None) -> None:
        report.append(message)

    guardrails.validate_disallowed_resource_types(
        _args("aws:ec2/vpc:Vpc", {}),
        record,
    )
    guardrails.validate_finops_tags(
        _args(
            "aws:kms/key:Key",
            {"tags": {"App": "bootstrap", "Environment": "test", "Owner": "platform"}},
        ),
        record,
    )
    guardrails.validate_allowed_regions(
        _args("aws:s3/bucket:Bucket", {"region": "ap-south-1"}),
        record,
    )
    guardrails.validate_state_buckets(
        _args("aws:s3/bucket:Bucket", {"tags": {"Purpose": "pulumi-state"}}),
        record,
    )
    guardrails.validate_bucket_public_acls(
        _args("aws:s3/bucket:Bucket", {"acl": "public-read"}),
        record,
    )
    guardrails.validate_bucket_public_access(
        _args(
            "aws:s3/bucketPublicAccessBlock:BucketPublicAccessBlock",
            {"blockPublicAcls": False},
        ),
        record,
    )
    guardrails.validate_bucket_versioning(
        _args(
            "aws:s3/bucketVersioning:BucketVersioning",
            {"versioningConfiguration": {"status": "Suspended"}},
        ),
        record,
    )
    guardrails.validate_bucket_encryption(
        _args(
            "aws:s3/bucketServerSideEncryptionConfiguration:BucketServerSideEncryptionConfiguration",
            {"rule": {}},
        ),
        record,
    )
    guardrails.validate_bucket_policies(
        _args("aws:s3/bucketPolicy:BucketPolicy", {"policy": "{}"}),
        record,
    )
    guardrails.validate_kms_keys(
        _args("aws:kms/key:Key", {"enableKeyRotation": False}),
        record,
    )
    guardrails.validate_ecr_repositories(
        _args("aws:ecr/repository:Repository", {"imageTagMutability": "MUTABLE"}),
        record,
    )
    guardrails.validate_backup_plans(
        _args("aws:backup/plan:Plan", {"rules": []}),
        record,
    )
    guardrails.validate_iam_policy_wildcards(
        _args(
            "aws:iam/rolePolicy:RolePolicy",
            {
                "policy": json.dumps(
                    {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": ["iam:*"],
                                "Resource": "*",
                            }
                        ]
                    }
                )
            },
        ),
        record,
    )
    guardrails.validate_production_defaults(
        _args(
            "aws:s3/bucket:Bucket",
            {"tags": {"Environment": "prod"}, "forceDestroy": True},
        ),
        record,
    )

    assert report  # nosec B101
    assert any(
        "bootstrap-infrastructure forbids aws:ec2/vpc:Vpc" in msg for msg in report
    )  # nosec B101
    assert any(
        "resource tags must include a non-empty CostCenter value." in msg
        for msg in report
    )  # nosec B101
    assert any(
        "AWS resources must stay inside the approved region allowlist" in msg
        for msg in report
    )  # nosec B101
    assert any("Pulumi state buckets must enable versioning." in msg for msg in report)  # nosec B101
    assert any("S3 buckets must not use public ACLs" in msg for msg in report)  # nosec B101
    assert any("blockPublicAcls must be true." in msg for msg in report)  # nosec B101
    assert any(
        "BucketVersioning resources must set status=Enabled." in msg for msg in report
    )  # nosec B101
    assert any(
        "Bucket encryption resources must enforce AES256" in msg for msg in report
    )  # nosec B101
    assert any("Bucket policies must deny non-TLS access" in msg for msg in report)  # nosec B101
    assert any("KMS keys must enable automatic key rotation." in msg for msg in report)  # nosec B101
    assert any("ECR repositories must use immutable tags." in msg for msg in report)  # nosec B101
    assert any(
        "Backup plans must define at least one backup rule." in msg for msg in report
    )  # nosec B101
    assert any(
        "IAM policy statement 0 must not use Action='iam:*'." in msg for msg in report
    )  # nosec B101
    assert any(
        "Production-like S3 buckets must not enable forceDestroy." in msg
        for msg in report
    )  # nosec B101


def test_build_policies_and_create_policy_pack():
    policies = guardrails.build_policies()
    assert len(policies) == 14  # nosec B101
    assert policies[0].name == "approved-bootstrap-resource-types"  # nosec B101
    assert policies[-1].name == "production-buckets-avoid-risky-defaults"  # nosec B101
    assert all(
        policy.enforcement_level == EnforcementLevel.MANDATORY for policy in policies
    )  # nosec B101

    captured: dict[str, object] = {}

    class FakePolicyPack:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    original = guardrails.PolicyPack
    guardrails.PolicyPack = FakePolicyPack  # type: ignore[assignment]
    try:
        guardrails.create_policy_pack()
    finally:
        guardrails.PolicyPack = original

    assert captured["name"] == "bootstrap-infrastructure-guardrails"  # nosec B101
    assert captured["description"] == "Pulumi guardrails for bootstrap-infrastructure."  # nosec B101
    captured_policies = cast(list[Policy], captured["policies"])
    assert [policy.name for policy in captured_policies] == [  # nosec B101
        policy.name for policy in policies
    ]


def test_policy_pack_main_invokes_create_policy_pack(monkeypatch):
    called = {"value": False}
    root = str(Path(__file__).resolve().parents[2])

    def fake_create_policy_pack():
        called["value"] = True
        return None

    monkeypatch.setattr(guardrails, "create_policy_pack", fake_create_policy_pack)
    monkeypatch.setattr(
        sys,
        "path",
        [entry for entry in sys.path if entry and entry != root],
    )
    sys.modules.pop("policy_pack.__main__", None)
    importlib.import_module("policy_pack.__main__")
    assert called["value"] is True  # nosec B101
    assert sys.path[0] == root  # nosec B101
