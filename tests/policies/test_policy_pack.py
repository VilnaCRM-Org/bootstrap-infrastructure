"""Tests for the VilnaCRM Pulumi policy pack and reusable guardrail helpers."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import runpy
import sys
from collections.abc import Generator
from pathlib import Path
from types import MappingProxyType, SimpleNamespace
from typing import Any, cast

import pytest
from pulumi_policy import EnforcementLevel

PROJECT_ROOT = Path(__file__).resolve().parents[2]
POLICY_DIR = PROJECT_ROOT / "policy"
POLICY_MAIN = POLICY_DIR / "__main__.py"


@pytest.fixture
def policy_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> Generator[SimpleNamespace, None, None]:
    """Import the policy modules without leaking globals across tests."""
    module_names = (
        "config",
        "guardrails",
        "pack",
        "policy.config",
        "policy.guardrails",
        "policy.pack",
        "reviewed_iam",
        "policy.reviewed_iam",
    )
    for module_name in module_names:
        monkeypatch.delitem(sys.modules, module_name, raising=False)

    injected_modules: set[str] = set()

    def load_module(module_name: str, path: Path):
        """Load a policy module from disk without polluting the interpreter."""
        spec = importlib.util.spec_from_file_location(module_name, path)
        assert spec is not None
        assert spec.loader is not None

        module = importlib.util.module_from_spec(spec)
        injected_modules.add(module_name)
        sys.modules[module_name] = module
        try:
            spec.loader.exec_module(module)
        except Exception:
            injected_modules.discard(module_name)
            sys.modules.pop(module_name, None)
            raise
        return module

    config = load_module("config", POLICY_DIR / "config.py")
    load_module("policy.config", POLICY_DIR / "config.py")
    load_module("reviewed_iam", POLICY_DIR / "reviewed_iam.py")
    load_module("policy.reviewed_iam", POLICY_DIR / "reviewed_iam.py")
    guardrails = load_module("guardrails", POLICY_DIR / "guardrails.py")
    load_module("policy.guardrails", POLICY_DIR / "guardrails.py")
    pack = load_module("pack", POLICY_DIR / "pack.py")
    load_module("policy.pack", POLICY_DIR / "pack.py")

    try:
        yield SimpleNamespace(
            PolicyConfig=config.PolicyConfig,
            POLICY_CONFIG_FILE=config.POLICY_CONFIG_FILE,
            load_policy_config=config.load_policy_config,
            extract_tags=guardrails.extract_tags,
            has_public_s3_acl=guardrails.has_public_s3_acl,
            has_public_s3_bucket_policy=guardrails.has_public_s3_bucket_policy,
            iam_policy_identifier=guardrails.iam_policy_identifier,
            invalid_region=guardrails.invalid_region,
            is_public_bucket_allowlisted=guardrails.is_public_bucket_allowlisted,
            logging_stack_violations=guardrails.logging_stack_violations,
            logging_violations=guardrails.logging_violations,
            missing_required_tags=guardrails.missing_required_tags,
            open_admin_ports=guardrails.open_admin_ports,
            production_database_violations=guardrails.production_database_violations,
            storage_encryption_stack_violations=(
                guardrails.storage_encryption_stack_violations
            ),
            storage_encryption_violations=guardrails.storage_encryption_violations,
            reviewed_iam_document_matches=guardrails.reviewed_iam_document_matches,
            wildcard_iam_violations=guardrails.wildcard_iam_violations,
            POLICY_PACK_NAME=pack.POLICY_PACK_NAME,
            block_open_admin_ports=pack.block_open_admin_ports,
            block_public_s3_exposure=pack.block_public_s3_exposure,
            block_wildcard_iam=pack.block_wildcard_iam,
            build_policies=pack.build_policies,
            enforce_allowed_regions=pack.enforce_allowed_regions,
            require_default_tags=pack.require_default_tags,
            require_logging=pack.require_logging,
            require_logging_stack=pack.require_logging_stack,
            require_production_database_safety=pack.require_production_database_safety,
            require_storage_encryption=pack.require_storage_encryption,
            require_storage_encryption_stack=pack.require_storage_encryption_stack,
        )
    finally:
        for module_name in injected_modules:
            sys.modules.pop(module_name, None)


def _custom_config(policy_runtime: SimpleNamespace, **overrides: object) -> object:
    """Create a fully populated config with targeted overrides."""
    defaults = {
        "required_tags": ("Project", "Environment", "Owner", "CostCenter"),
        "allowed_regions": ("eu-central-1", "eu-west-1"),
        "production_environments": ("prod", "production"),
        "public_s3_bucket_allowlist": frozenset(),
        "reviewed_iam_documents": {},
        "annotations": {
            "public_s3_tag": "AllowPublicBucket",
            "wildcard_iam_tag": "AllowWildcardIam",
            "wildcard_iam_reason_tag": "AllowWildcardIamReason",
        },
    }
    defaults.update(overrides)
    annotations = cast(dict[str, str], defaults["annotations"])
    defaults["annotations"] = MappingProxyType(dict(annotations))
    return policy_runtime.PolicyConfig(**defaults)


def _policy_args(resource_type: str, props: dict[str, Any]) -> SimpleNamespace:
    """Create the subset of Pulumi policy args needed by the validators."""
    return SimpleNamespace(resource_type=resource_type, props=props)


def _collect_violations(
    validator, *, resource_type: str, props: dict[str, Any]
) -> list[str]:
    """Run a validator and capture every reported violation."""
    violations: list[str] = []
    validator(_policy_args(resource_type, props), violations.append)
    return violations


def _stack_resource(
    resource_type: str,
    props: dict[str, Any],
    *,
    urn: str,
    dependencies: list[Any] | None = None,
    property_dependencies: dict[str, list[Any]] | None = None,
) -> SimpleNamespace:
    """Create the subset of a PolicyResource used by stack validators."""
    return SimpleNamespace(
        resource_type=resource_type,
        props=props,
        urn=urn,
        dependencies=dependencies or [],
        property_dependencies=property_dependencies or {},
    )


def _collect_stack_violations(
    validator, *, resources: list[Any]
) -> list[tuple[str | None, str]]:
    """Run a stack validator and capture every reported violation."""
    violations: list[tuple[str | None, str]] = []

    def report_violation(message: str, urn: str | None = None) -> None:
        violations.append((urn, message))

    validator(SimpleNamespace(resources=resources), report_violation)
    return violations


def _json(document: dict[str, Any]) -> str:
    """Serialize a policy document into stable JSON."""
    return json.dumps(document, sort_keys=True)


def test_repo_policy_config_declares_expected_defaults(
    policy_runtime: SimpleNamespace,
) -> None:
    """Keep the committed policy config aligned with the documented guardrails."""
    config = policy_runtime.load_policy_config()

    assert config.required_tags == (  # nosec B101
        "Project",
        "Environment",
        "Owner",
        "CostCenter",
        "DataClassification",
        "Criticality",
        "RetentionClass",
    )
    assert config.allowed_regions == ("eu-central-1", "eu-west-1")
    assert config.production_environments == ("prod", "production", "live")
    assert config.annotations["public_s3_tag"] == "AllowPublicBucket"
    assert config.public_s3_bucket_allowlist == frozenset()
    assert config.reviewed_iam_documents
    assert all(
        "Governance" not in identity
        and ("GitHubCi" not in identity or "-bootstrap-infrastructure-" in identity)
        for identity in config.reviewed_iam_documents
    )
    assert all(
        len(digest) == 64
        for digests in config.reviewed_iam_documents.values()
        for digest in digests
    )


def test_load_policy_config_defaults_optional_sections(
    policy_runtime: SimpleNamespace, tmp_path: Path
) -> None:
    """Allow small downstream configs while normalizing empty optional sections."""
    path = tmp_path / "guardrails.yaml"
    path.write_text(
        (
            "required_tags:\n"
            "  - Project\n"
            "allowed_regions:\n"
            "  - eu-central-1\n"
            "production_environments: []\n"
        ),
        encoding="utf-8",
    )

    config = policy_runtime.load_policy_config(path)

    assert config.required_tags == ("Project",)
    assert config.allowed_regions == ("eu-central-1",)
    assert config.production_environments == ()
    assert config.annotations == {}
    assert config.public_s3_bucket_allowlist == frozenset()
    assert config.reviewed_iam_documents == {}


def test_load_policy_config_freezes_annotations_mapping(
    policy_runtime: SimpleNamespace, tmp_path: Path
) -> None:
    """Keep annotations immutable once the config has been loaded."""
    path = tmp_path / "guardrails.yaml"
    path.write_text(
        (
            "required_tags:\n"
            "  - Project\n"
            "allowed_regions:\n"
            "  - eu-central-1\n"
            "production_environments:\n"
            "  - prod\n"
            "annotations:\n"
            "  public_s3_tag: AllowPublicBucket\n"
        ),
        encoding="utf-8",
    )

    config = policy_runtime.load_policy_config(path)

    with pytest.raises(TypeError):
        cast(Any, config.annotations)["public_s3_tag"] = "Override"


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("[]\n", "must contain a top-level mapping"),
        ("allowed_regions:\n  - eu-central-1\n", "required_tags is required"),
        ("required_tags:\n  - Project\n", "allowed_regions is required"),
        (
            "required_tags:\n  - Project\nallowed_regions:\n  - eu-central-1\n",
            "production_environments is required",
        ),
        ("required_tags: nope\n", "required_tags must be a list"),
        (
            "required_tags:\n"
            "  - Project\n"
            "allowed_regions:\n"
            "  - eu-central-1\n"
            "production_environments: []\n"
            "annotations: []\n",
            "annotations must be a mapping",
        ),
        ("required_tags:\n  - ''\n", "required_tags must be a non-empty string"),
    ],
)
def test_load_policy_config_rejects_invalid_documents(
    policy_runtime: SimpleNamespace, tmp_path: Path, content: str, message: str
) -> None:
    """Fail early when the policy configuration shape is invalid."""
    path = tmp_path / "guardrails.yaml"
    path.write_text(content, encoding="utf-8")

    with pytest.raises(ValueError, match=message):
        policy_runtime.load_policy_config(path)


@pytest.mark.parametrize("digest", ["short", "A" * 64, "z" * 64])
def test_reviewed_policy_config_rejects_invalid_hashes(
    policy_runtime: SimpleNamespace, tmp_path: Path, digest: str
) -> None:
    """A malformed review pin must fail configuration loading."""
    path = tmp_path / "guardrails.yaml"
    path.write_text(
        "required_tags: []\nallowed_regions: []\nproduction_environments: []\n"
        "reviewed_iam_documents:\n  reviewed-policy:\n    - " + digest + "\n"
    )
    with pytest.raises(ValueError, match="lowercase SHA256"):
        policy_runtime.load_policy_config(path)


@pytest.mark.parametrize("value", ["[]", "null", ""])
def test_empty_review_pins_are_rejected(policy_runtime, tmp_path, value):
    """An explicit identity must include at least one reviewed document digest."""
    path = tmp_path / "guardrails.yaml"
    path.write_text(
        "required_tags: []\nallowed_regions: []\nproduction_environments: []\n"
        f"reviewed_iam_documents:\n  approved-policy: {value}\n"
    )
    with pytest.raises(ValueError, match="must not be empty"):
        policy_runtime.load_policy_config(path)


def test_reviewed_policy_config_cannot_mutate_or_use_legacy_name_bypass(
    policy_runtime: SimpleNamespace, tmp_path: Path
) -> None:
    """Legacy names cannot allow arbitrary policy content; pins are immutable."""
    path = tmp_path / "guardrails.yaml"
    path.write_text(
        "required_tags: []\nallowed_regions: []\nproduction_environments: []\n"
        "allowlists:\n  wildcard_iam: [formerly-allowed]\n"
        "reviewed_iam_documents:\n  approved-policy:\n    - '" + "a" * 64 + "'\n"
    )
    config = policy_runtime.load_policy_config(path)
    assert config.reviewed_iam_documents == {"approved-policy": ("a" * 64,)}
    with pytest.raises(TypeError):
        cast(Any, config.reviewed_iam_documents)["new"] = ("b" * 64,)
    assert policy_runtime.wildcard_iam_violations(
        "aws:iam/policy:Policy",
        {
            "name": "formerly-allowed",
            "policy": _json(
                {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
            ),
        },
        config,
    )


def test_extract_tags_prefers_tags_all_and_merges_explicit_overrides(
    policy_runtime: SimpleNamespace,
) -> None:
    """Support provider default tags while letting resource tags override them."""
    assert policy_runtime.extract_tags(
        {
            "tagsAll": {"Project": "defaults", "Owner": "platform"},
            "tags": {"Project": "svc", "Environment": "dev"},
        }
    ) == {
        "Project": "svc",
        "Owner": "platform",
        "Environment": "dev",
    }
    assert policy_runtime.extract_tags(
        {"tags": "invalid", "tagsAll": {"Environment": "dev"}}
    ) == {"Environment": "dev"}
    assert policy_runtime.extract_tags({}) is None


def test_missing_required_tags_reports_blank_or_missing_values(
    policy_runtime: SimpleNamespace,
) -> None:
    """Detect blank or absent required default tags."""
    config = _custom_config(policy_runtime)

    assert policy_runtime.missing_required_tags(None, config) == [
        "Project",
        "Environment",
        "Owner",
        "CostCenter",
    ]
    assert (
        policy_runtime.missing_required_tags(
            {
                "Project": "svc",
                "Environment": "dev",
                "Owner": "platform",
                "CostCenter": "eng",
            },
            config,
        )
        == []
    )
    assert policy_runtime.missing_required_tags(
        {"Project": "svc", "Environment": "dev", "Owner": " ", "CostCenter": "eng"},
        config,
    ) == ["Owner"]


def test_public_s3_helpers_cover_acl_policy_and_allowlist_paths(
    policy_runtime: SimpleNamespace,
) -> None:
    """Keep the public S3 guardrails readable and intentional."""
    config = _custom_config(
        policy_runtime,
        public_s3_bucket_allowlist=frozenset({"public-bucket"}),
    )
    public_policy = _json(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"}
            ],
        }
    )
    mapped_policy = _json(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": ["*"]},
                    "Action": "s3:GetObject",
                }
            ],
        }
    )

    assert policy_runtime.has_public_s3_acl(
        "aws:s3/bucketAclV2:BucketAclV2", {"acl": "public-read"}
    )
    assert not policy_runtime.has_public_s3_acl(
        "aws:s3/object:Object", {"acl": "public-read"}
    )
    assert policy_runtime.has_public_s3_bucket_policy(
        "aws:s3/bucketPolicy:BucketPolicy",
        {"policy": public_policy},
    )
    assert policy_runtime.has_public_s3_bucket_policy(
        "aws:s3/bucketPolicy:BucketPolicy",
        {"policyDocument": mapped_policy},
    )
    assert policy_runtime.has_public_s3_bucket_policy(
        "aws:s3/bucketPolicy:BucketPolicy",
        {
            "policyDocument": {
                "Statement": {"Effect": "Allow", "Principal": {"AWS": "*"}}
            }
        },
    )
    assert policy_runtime.has_public_s3_bucket_policy(
        "aws:s3/bucket:Bucket",
        {"policy": public_policy},
    )
    assert policy_runtime.has_public_s3_bucket_policy(
        "aws:s3/bucketPolicy:BucketPolicy",
        {
            "policy": {"Statement": {"Effect": "Deny", "Principal": {"AWS": "*"}}},
            "policyDocument": mapped_policy,
        },
    )
    assert not policy_runtime.has_public_s3_bucket_policy(
        "aws:s3/object:Object",
        {"policy": public_policy},
    )
    assert not policy_runtime.has_public_s3_bucket_policy(
        "aws:s3/bucketPolicy:BucketPolicy",
        {"policyDocument": {"Statement": "invalid"}},
    )
    assert not policy_runtime.has_public_s3_bucket_policy(
        "aws:s3/bucketPolicy:BucketPolicy",
        {"policyDocument": {"Statement": {"Effect": "Deny", "Principal": "*"}}},
    )
    assert not policy_runtime.has_public_s3_bucket_policy(
        "aws:s3/bucketPolicy:BucketPolicy",
        {
            "policyDocument": {
                "Statement": {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
                }
            }
        },
    )
    assert policy_runtime.has_public_s3_bucket_policy(
        "aws:s3/bucketPolicy:BucketPolicy",
        {
            "policyDocument": {
                "Statement": {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Condition": {"IpAddress": {"aws:SourceIp": "0.0.0.0/0"}},
                }
            }
        },
    )
    assert policy_runtime.has_public_s3_bucket_policy(
        "aws:s3/bucketPolicy:BucketPolicy",
        {
            "policyDocument": {
                "Statement": {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Condition": {"NotIpAddress": {"aws:SourceIp": ["10.0.0.0/8"]}},
                }
            }
        },
    )
    assert policy_runtime.has_public_s3_bucket_policy(
        "aws:s3/bucketPolicy:BucketPolicy",
        {
            "policyDocument": {
                "Statement": {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Condition": {
                        "StringNotEquals": {"aws:SourceVpc": "vpc-1234567890abcdef0"}
                    },
                }
            }
        },
    )
    assert policy_runtime.has_public_s3_bucket_policy(
        "aws:s3/bucketPolicy:BucketPolicy",
        {
            "policyDocument": {
                "Statement": {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Condition": {"StringEquals": {"aws:SourceVpce": "vpce-*"}},
                }
            }
        },
    )
    assert policy_runtime.has_public_s3_bucket_policy(
        "aws:s3/bucketPolicy:BucketPolicy",
        {
            "policyDocument": {
                "Statement": {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Condition": {"StringEquals": "vpce-1234567890abcdef0"},
                }
            }
        },
    )
    assert policy_runtime.has_public_s3_bucket_policy(
        "aws:s3/bucketPolicy:BucketPolicy",
        {
            "policyDocument": {
                "Statement": {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Condition": {"StringEquals": {"aws:SourceVpce": 1}},
                }
            }
        },
    )
    assert not policy_runtime.has_public_s3_bucket_policy(
        "aws:s3/bucketPolicy:BucketPolicy",
        {
            "policyDocument": {
                "Statement": {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Condition": {
                        "IpAddress": {"aws:SourceIp": ["10.0.0.0/8", "192.168.0.0/16"]}
                    },
                }
            }
        },
    )
    assert policy_runtime.has_public_s3_bucket_policy(
        "aws:s3/bucketPolicy:BucketPolicy",
        {
            "policyDocument": {
                "Statement": {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Condition": {"Bool": "true"},
                }
            }
        },
    )
    assert not policy_runtime.has_public_s3_bucket_policy(
        "aws:s3/bucketPolicy:BucketPolicy",
        {
            "policyDocument": {
                "Statement": {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": ["arn:aws:iam::123456789012:root"],
                        "CanonicalUser": "trusted-user",
                    },
                }
            }
        },
    )
    assert not policy_runtime.has_public_s3_bucket_policy(
        "aws:s3/bucketPolicy:BucketPolicy",
        {
            "policyDocument": {
                "Statement": {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Condition": {
                        "StringEquals": {"aws:SecureTransport": "true"},
                        "ForAnyValue:StringEquals": {
                            "aws:SourceVpce": "vpce-1234567890abcdef0"
                        },
                    },
                }
            }
        },
    )
    assert not policy_runtime.has_public_s3_bucket_policy(
        "aws:s3/bucketPolicy:BucketPolicy",
        {"policyDocument": {"Statement": {"Effect": "Allow", "Principal": {}}}},
    )
    assert not policy_runtime.has_public_s3_bucket_policy(
        "aws:s3/bucketPolicy:BucketPolicy",
        {
            "policyDocument": {
                "Statement": {
                    "Effect": "Allow",
                    "Principal": "arn:aws:iam::123456789012:root",
                }
            }
        },
    )
    assert not policy_runtime.has_public_s3_bucket_policy(
        "aws:s3/bucketPolicy:BucketPolicy",
        {"policy": "{not-json}"},
    )
    assert policy_runtime.is_public_bucket_allowlisted(
        {"bucket": "public-bucket"}, config
    )
    assert policy_runtime.is_public_bucket_allowlisted(
        {"tags": {"AllowPublicBucket": "true"}}, config
    )
    assert not policy_runtime.is_public_bucket_allowlisted(
        {"bucket": "private"}, config
    )
    assert not policy_runtime.has_public_s3_bucket_policy(
        "aws:s3/bucketPolicy:BucketPolicy",
        {
            "policyDocument": {
                "Statement": {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Condition": {
                        "StringEquals": {"aws:SourceVpce": "vpce-1234567890abcdef0"}
                    },
                }
            }
        },
    )
    assert not policy_runtime.has_public_s3_bucket_policy(
        "aws:s3/bucketPolicy:BucketPolicy",
        {
            "policyDocument": {
                "Statement": {
                    "Effect": "Allow",
                    "Principal": {"AWS": "*"},
                    "Condition": {
                        "StringEquals": {"aws:PrincipalOrgID": "o-exampleorg"}
                    },
                }
            }
        },
    )


def test_invalid_region_checks_only_explicit_aws_regions(
    policy_runtime: SimpleNamespace,
) -> None:
    """Reject unsupported regions without crashing on non-AWS resources."""
    config = _custom_config(policy_runtime)
    empty_allowlist = _custom_config(policy_runtime, allowed_regions=())

    assert (
        policy_runtime.invalid_region(
            "pulumi:providers:aws",
            {"region": "us-east-1"},
            config,
        )
        == "us-east-1"
    )
    assert (
        policy_runtime.invalid_region(
            "pulumi:providers:aws",
            {"region": "eu-central-1"},
            config,
        )
        is None
    )
    assert (
        policy_runtime.invalid_region(
            "pulumi:providers:aws",
            {"region": "us-east-1"},
            empty_allowlist,
        )
        is None
    )
    assert (
        policy_runtime.invalid_region(
            "tests:s3/bucket:Bucket",
            {"region": "us-east-1"},
            config,
        )
        is None
    )
    assert (
        policy_runtime.invalid_region(
            "pulumi:providers:awsx",
            {"region": "us-east-1"},
            config,
        )
        is None
    )


def test_storage_encryption_and_logging_violations_cover_supported_resources(
    policy_runtime: SimpleNamespace,
) -> None:
    """Keep encryption and logging checks explicit for supported resource types."""
    assert policy_runtime.storage_encryption_violations("aws:s3/bucket:Bucket", {}) == [
        "S3 buckets must enable default server-side encryption."
    ]
    assert (
        policy_runtime.storage_encryption_violations(
            "aws:s3/bucket:Bucket",
            {
                "serverSideEncryptionConfiguration": {
                    "rule": {
                        "applyServerSideEncryptionByDefault": {"sseAlgorithm": "AES256"}
                    }
                }
            },
        )
        == []
    )
    assert policy_runtime.storage_encryption_violations(
        "aws:ec2/volume:Volume", {"encrypted": False}
    ) == ["EBS volumes must enable encryption at rest."]
    assert policy_runtime.storage_encryption_violations(
        "aws:efs/fileSystem:FileSystem", {"encrypted": "false"}
    ) == ["EFS file systems must enable encryption at rest."]
    assert policy_runtime.storage_encryption_violations(
        "aws:rds/instance:Instance", {"storageEncrypted": False}
    ) == ["RDS databases must enable storage encryption."]
    assert (
        policy_runtime.storage_encryption_violations(
            "aws:rds/cluster:Cluster", {"storageEncrypted": True}
        )
        == []
    )

    assert policy_runtime.logging_violations("aws:s3/bucket:Bucket", {}) == [
        "S3 buckets must send access logs to a target bucket."
    ]
    assert (
        policy_runtime.logging_violations(
            "aws:s3/bucket:Bucket",
            {"logging": {"targetBucket": "access-log-bucket"}},
        )
        == []
    )
    assert policy_runtime.logging_violations(
        "aws:s3/bucket:Bucket",
        {"tags": {"Purpose": "central-logging"}},
    ) == ["S3 buckets must send access logs to a target bucket."]
    assert (
        policy_runtime.logging_violations(
            "aws:s3/bucket:Bucket",
            {
                "tags": {
                    "LoggingExempt": "true",
                    "LoggingExemptReason": "Centralized S3 access log sink",
                }
            },
        )
        == []
    )
    assert policy_runtime.logging_violations(
        "aws:lb/loadBalancer:LoadBalancer",
        {"accessLogs": {"enabled": False}},
    ) == ["Load balancers must enable access logs."]
    assert (
        policy_runtime.logging_violations(
            "aws:lb/loadBalancer:LoadBalancer",
            {"accessLogs": {"enabled": True}},
        )
        == []
    )


def test_logging_stack_violations_support_split_s3_logging(
    policy_runtime: SimpleNamespace,
) -> None:
    """Allow S3 buckets covered by standalone logging resources."""
    bucket = _stack_resource(
        "aws:s3/bucket:Bucket",
        props={
            "bucket": "logs-bucket",
            "tags": {
                "Project": "demo",
                "Environment": "dev",
                "Owner": "platform",
                "CostCenter": "engineering",
            },
        },
        urn="urn:pulumi:dev::bootstrap::aws:s3/bucket:Bucket::logs-bucket",
    )
    logging = _stack_resource(
        "aws:s3/bucketLogging:BucketLogging",
        props={
            "bucket": "logs-bucket",
            "targetBucket": "audit-logs",
            "targetPrefix": "server-access/logs-bucket/",
        },
        urn="urn:pulumi:dev::bootstrap::aws:s3/bucketLogging:BucketLogging::logs-bucket-logging",
        dependencies=[bucket],
        property_dependencies={"bucket": [bucket]},
    )

    assert policy_runtime.logging_stack_violations([bucket, logging]) == []  # nosec B101
    assert (  # nosec B101
        _collect_stack_violations(
            policy_runtime.require_logging_stack,
            resources=[bucket, logging],
        )
        == []
    )


def test_storage_encryption_stack_violations_cover_missing_inline_and_name_only_paths(
    policy_runtime: SimpleNamespace,
) -> None:
    """Cover stack validation paths for missing and name-only S3 encryption."""
    missing_bucket = _stack_resource(
        "aws:s3/bucket:Bucket",
        props={"bucket": "unencrypted-bucket"},
        urn="urn:pulumi:dev::bootstrap::aws:s3/bucket:Bucket::unencrypted-bucket",
    )
    expected_violation = [
        (
            missing_bucket.urn,
            "S3 buckets must enable default server-side encryption.",
        )
    ]

    assert (  # nosec B101
        policy_runtime.storage_encryption_stack_violations([missing_bucket])
        == expected_violation
    )
    assert (  # nosec B101
        _collect_stack_violations(
            policy_runtime.require_storage_encryption_stack,
            resources=[missing_bucket],
        )
        == expected_violation
    )

    inline_bucket = _stack_resource(
        "aws:s3/bucket:Bucket",
        props={
            "bucket": "inline-encrypted-bucket",
            "serverSideEncryptionConfiguration": {
                "rule": {
                    "applyServerSideEncryptionByDefault": {"sseAlgorithm": "AES256"}
                }
            },
        },
        urn=(
            "urn:pulumi:dev::bootstrap::aws:s3/bucket:Bucket::inline-encrypted-bucket"
        ),
    )
    assert (
        policy_runtime.storage_encryption_stack_violations(  # nosec B101
            [inline_bucket]
        )
        == []
    )

    non_bucket_dependency = _stack_resource(
        "aws:iam/role:Role",
        props={},
        urn="urn:pulumi:dev::bootstrap::aws:iam/role:Role::not-a-bucket",
    )
    name_only_bucket = _stack_resource(
        "aws:s3/bucket:Bucket",
        props={"bucket": "name-only-encrypted-bucket"},
        urn=(
            "urn:pulumi:dev::bootstrap::aws:s3/bucket:Bucket::"
            "name-only-encrypted-bucket"
        ),
    )
    name_only_encryption = _stack_resource(
        "aws:s3/bucketServerSideEncryptionConfigurationV2:BucketServerSideEncryptionConfigurationV2",
        props={
            "bucket": "name-only-encrypted-bucket",
            "rule": {"applyServerSideEncryptionByDefault": {"sseAlgorithm": "AES256"}},
        },
        urn=(
            "urn:pulumi:dev::bootstrap::aws:s3/"
            "bucketServerSideEncryptionConfigurationV2:"
            "BucketServerSideEncryptionConfigurationV2::name-only-encryption"
        ),
        dependencies=[non_bucket_dependency],
    )
    assert (  # nosec B101
        policy_runtime.storage_encryption_stack_violations(
            [name_only_bucket, name_only_encryption]
        )
        == []
    )

    dependency_only_bucket = _stack_resource(
        "aws:s3/bucket:Bucket",
        props={"bucket": "dependency-only-encrypted-bucket"},
        urn=(
            "urn:pulumi:dev::bootstrap::aws:s3/bucket:Bucket::"
            "dependency-only-encrypted-bucket"
        ),
    )
    dependency_only_encryption = _stack_resource(
        "aws:s3/bucketServerSideEncryptionConfigurationV2:BucketServerSideEncryptionConfigurationV2",
        props={
            "rule": {"applyServerSideEncryptionByDefault": {"sseAlgorithm": "AES256"}},
        },
        urn=(
            "urn:pulumi:dev::bootstrap::aws:s3/"
            "bucketServerSideEncryptionConfigurationV2:"
            "BucketServerSideEncryptionConfigurationV2::dependency-only-encryption"
        ),
        dependencies=[dependency_only_bucket],
    )
    assert (  # nosec B101
        [
            urn
            for urn, _ in policy_runtime.storage_encryption_stack_violations(
                [dependency_only_bucket, dependency_only_encryption]
            )
        ]
        == [dependency_only_bucket.urn]
    )


def test_logging_stack_violations_cover_missing_inline_exempt_and_name_only_paths(
    policy_runtime: SimpleNamespace,
) -> None:
    """Cover stack validation paths for missing and split S3 logging."""
    missing_bucket = _stack_resource(
        "aws:s3/bucket:Bucket",
        props={"bucket": "missing-logs-bucket"},
        urn="urn:pulumi:dev::bootstrap::aws:s3/bucket:Bucket::missing-logs-bucket",
    )
    expected_violation = [
        (
            missing_bucket.urn,
            "S3 buckets must send access logs to a target bucket.",
        )
    ]

    assert (  # nosec B101
        policy_runtime.logging_stack_violations([missing_bucket]) == expected_violation
    )
    assert (  # nosec B101
        _collect_stack_violations(
            policy_runtime.require_logging_stack,
            resources=[missing_bucket],
        )
        == expected_violation
    )

    exempt_bucket = _stack_resource(
        "aws:s3/bucket:Bucket",
        props={
            "bucket": "exempt-logs-bucket",
            "tags": {
                "LoggingExempt": "true",
                "LoggingExemptReason": "Centralized S3 access log sink",
            },
        },
        urn="urn:pulumi:dev::bootstrap::aws:s3/bucket:Bucket::exempt-logs-bucket",
    )
    inline_bucket = _stack_resource(
        "aws:s3/bucket:Bucket",
        props={
            "bucket": "inline-logs-bucket",
            "logging": {"targetBucket": "audit-logs"},
        },
        urn="urn:pulumi:dev::bootstrap::aws:s3/bucket:Bucket::inline-logs-bucket",
    )
    assert policy_runtime.logging_stack_violations([exempt_bucket]) == []  # nosec B101
    assert policy_runtime.logging_stack_violations([inline_bucket]) == []  # nosec B101

    ignored_logging = _stack_resource(
        "aws:s3/bucketLogging:BucketLogging",
        props={"bucket": "missing-logs-bucket"},
        urn="urn:pulumi:dev::bootstrap::aws:s3/bucketLogging:BucketLogging::ignored",
        dependencies=[missing_bucket],
    )
    assert (  # nosec B101
        policy_runtime.logging_stack_violations([missing_bucket, ignored_logging])
        == expected_violation
    )

    non_bucket_dependency = _stack_resource(
        "aws:iam/role:Role",
        props={},
        urn="urn:pulumi:dev::bootstrap::aws:iam/role:Role::not-a-bucket",
    )
    name_only_bucket = _stack_resource(
        "aws:s3/bucket:Bucket",
        props={"bucket": "name-only-logs-bucket"},
        urn="urn:pulumi:dev::bootstrap::aws:s3/bucket:Bucket::name-only-logs-bucket",
    )
    name_only_logging = _stack_resource(
        "aws:s3/bucketLogging:BucketLogging",
        props={
            "bucket": "name-only-logs-bucket",
            "targetBucket": "audit-logs",
        },
        urn="urn:pulumi:dev::bootstrap::aws:s3/bucketLogging:BucketLogging::name-only",
        dependencies=[non_bucket_dependency],
    )
    assert (  # nosec B101
        policy_runtime.logging_stack_violations([name_only_bucket, name_only_logging])
        == []
    )

    dependency_only_bucket = _stack_resource(
        "aws:s3/bucket:Bucket",
        props={"bucket": "dependency-only-logs-bucket"},
        urn=(
            "urn:pulumi:dev::bootstrap::aws:s3/bucket:Bucket::"
            "dependency-only-logs-bucket"
        ),
    )
    dependency_only_logging = _stack_resource(
        "aws:s3/bucketLogging:BucketLogging",
        props={"targetBucket": "audit-logs"},
        urn=(
            "urn:pulumi:dev::bootstrap::aws:s3/bucketLogging:BucketLogging::"
            "dependency-only"
        ),
        dependencies=[dependency_only_bucket],
    )
    assert (  # nosec B101
        [
            urn
            for urn, _ in policy_runtime.logging_stack_violations(
                [dependency_only_bucket, dependency_only_logging]
            )
        ]
        == [dependency_only_bucket.urn]
    )


def test_storage_encryption_stack_violations_require_real_split_rules(
    policy_runtime: SimpleNamespace,
) -> None:
    """Split encryption resources should only count when they configure SSE."""
    invalid_bucket = _stack_resource(
        "aws:s3/bucket:Bucket",
        props={"bucket": "invalid-encryption-bucket"},
        urn=(
            "urn:pulumi:dev::bootstrap::aws:s3/bucket:Bucket::invalid-encryption-bucket"
        ),
    )
    invalid_encryption = _stack_resource(
        "aws:s3/bucketServerSideEncryptionConfigurationV2:BucketServerSideEncryptionConfigurationV2",
        props={"bucket": "invalid-encryption-bucket", "rules": []},
        urn=(
            "urn:pulumi:dev::bootstrap::aws:s3/"
            "bucketServerSideEncryptionConfigurationV2:"
            "BucketServerSideEncryptionConfigurationV2::invalid-encryption"
        ),
        dependencies=[invalid_bucket],
        property_dependencies={"bucket": [invalid_bucket]},
    )
    expected_violation = [
        (
            invalid_bucket.urn,
            "S3 buckets must enable default server-side encryption.",
        )
    ]

    assert (  # nosec B101
        policy_runtime.storage_encryption_stack_violations(
            [invalid_bucket, invalid_encryption]
        )
        == expected_violation
    )
    assert (  # nosec B101
        _collect_stack_violations(
            policy_runtime.require_storage_encryption_stack,
            resources=[invalid_bucket, invalid_encryption],
        )
        == expected_violation
    )

    valid_bucket = _stack_resource(
        "aws:s3/bucket:Bucket",
        props={"bucket": "valid-encryption-bucket"},
        urn=(
            "urn:pulumi:dev::bootstrap::aws:s3/bucket:Bucket::valid-encryption-bucket"
        ),
    )
    valid_encryption = _stack_resource(
        "aws:s3/bucketServerSideEncryptionConfigurationV2:BucketServerSideEncryptionConfigurationV2",
        props={
            "bucket": "valid-encryption-bucket",
            "rules": [
                {"applyServerSideEncryptionByDefault": {"sseAlgorithm": "AES256"}}
            ],
        },
        urn=(
            "urn:pulumi:dev::bootstrap::aws:s3/"
            "bucketServerSideEncryptionConfigurationV2:"
            "BucketServerSideEncryptionConfigurationV2::valid-encryption"
        ),
        dependencies=[valid_bucket],
        property_dependencies={"bucket": [valid_bucket]},
    )

    assert (  # nosec B101
        policy_runtime.storage_encryption_stack_violations(
            [valid_bucket, valid_encryption]
        )
        == []
    )


def test_storage_encryption_stack_violations_ignore_invalid_rules_before_valid_one(
    policy_runtime: SimpleNamespace,
) -> None:
    """Mixed split-rule payloads should only count concrete SSE defaults."""
    bucket = _stack_resource(
        "aws:s3/bucket:Bucket",
        props={"bucket": "mixed-encryption-bucket"},
        urn=(
            "urn:pulumi:dev::bootstrap::aws:s3/bucket:Bucket::mixed-encryption-bucket"
        ),
    )
    encryption = _stack_resource(
        "aws:s3/bucketServerSideEncryptionConfigurationV2:BucketServerSideEncryptionConfigurationV2",
        props={
            "bucket": "mixed-encryption-bucket",
            "rules": [
                {},
                {"applyServerSideEncryptionByDefault": "AES256"},
                {"applyServerSideEncryptionByDefault": {"sseAlgorithm": ""}},
                {"applyServerSideEncryptionByDefault": {"sseAlgorithm": "AES256"}},
            ],
        },
        urn=(
            "urn:pulumi:dev::bootstrap::aws:s3/"
            "bucketServerSideEncryptionConfigurationV2:"
            "BucketServerSideEncryptionConfigurationV2::mixed-encryption"
        ),
        dependencies=[bucket],
        property_dependencies={"bucket": [bucket]},
    )

    assert (  # nosec B101
        policy_runtime.storage_encryption_stack_violations([bucket, encryption]) == []
    )


@pytest.mark.parametrize("mode", ["inline", "split"])
@pytest.mark.parametrize("rule_key", ["rule", "rules"])
@pytest.mark.parametrize(
    ("algorithm", "accepted"),
    [
        ("AES256", True),
        ("aws:fsx", True),
        ("aws:kms", True),
        ("aws:kms:dsse", True),
        ("04da6b54-80e4-46f7-96ec-b56ff0331ba9", False),
        ("unverified-algorithm", False),
    ],
)
def test_s3_encryption_requires_a_supported_concrete_algorithm(
    policy_runtime: SimpleNamespace,
    mode: str,
    rule_key: str,
    algorithm: str,
    accepted: bool,
) -> None:
    """Unknown or invalid SSE values cannot satisfy either resource shape."""
    rule = {"applyServerSideEncryptionByDefault": {"sseAlgorithm": algorithm}}
    configuration = {rule_key: rule if rule_key == "rule" else [rule]}
    bucket = _stack_resource(
        "aws:s3/bucket:Bucket",
        props={"bucket": "concrete-encryption"},
        urn="urn:pulumi:test::policy::aws:s3/bucket:Bucket::concrete-encryption",
    )
    resources = [bucket]
    if mode == "inline":
        bucket.props["serverSideEncryptionConfiguration"] = configuration
    else:
        resources.append(
            _stack_resource(
                "aws:s3/bucketServerSideEncryptionConfigurationV2:"
                "BucketServerSideEncryptionConfigurationV2",
                props={"bucket": "concrete-encryption", **configuration},
                urn="urn:pulumi:test::policy::s3:encryption::concrete-encryption",
                property_dependencies={"bucket": [bucket]},
            )
        )
    message = "S3 buckets must enable default server-side encryption."
    expected = [] if accepted else [(bucket.urn, message)]
    assert policy_runtime.storage_encryption_stack_violations(resources) == expected
    if mode == "inline":
        assert policy_runtime.storage_encryption_violations(
            bucket.resource_type, bucket.props
        ) == ([] if accepted else [message])


@pytest.mark.parametrize("missing_urn", ["", None])
def test_logging_cannot_bind_buckets_by_an_empty_dependency_urn(
    policy_runtime: SimpleNamespace, missing_urn: str | None
) -> None:
    """Malformed dependency metadata cannot mark an unrelated bucket as logged."""
    bucket = _stack_resource("aws:s3/bucket:Bucket", props={}, urn="")
    dependency = _stack_resource("aws:s3/bucket:Bucket", props={}, urn="")
    bucket.urn = dependency.urn = missing_urn
    logging = _stack_resource(
        "aws:s3/bucketLogging:BucketLogging",
        props={"targetBucket": "audit-logs"},
        urn="urn:pulumi:test::policy::aws:s3/bucketLogging:BucketLogging::logging",
        property_dependencies={"bucket": [dependency]},
    )
    assert policy_runtime.logging_stack_violations([bucket, logging]) == [
        (missing_urn, "S3 buckets must send access logs to a target bucket.")
    ]


def test_wildcard_iam_violations_support_allowlists_and_inline_policies(
    policy_runtime: SimpleNamespace,
) -> None:
    """Reject wildcard IAM and allow narrowly justified exceptions."""
    wildcard_policy = _json(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
        }
    )
    config = _custom_config(policy_runtime)
    allowlisted = _custom_config(
        policy_runtime,
        reviewed_iam_documents={
            "aws:iam/policy:Policy|allowed-policy": (
                hashlib.sha256(
                    json.dumps(
                        json.loads(wildcard_policy),
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode()
                ).hexdigest(),
            )
        },
    )

    violations = policy_runtime.wildcard_iam_violations(
        "aws:iam/policy:Policy",
        {"policy": wildcard_policy, "name": "too-open"},
        config,
    )
    assert violations == [
        "policy must not use wildcard IAM permissions without an explicit allowlist."
    ]
    assert policy_runtime.iam_policy_identifier({"policyName": "named"}) == "named"
    assert policy_runtime.iam_policy_identifier({"name": "allowed-policy"}) == (
        "allowed-policy"
    )
    assert policy_runtime.iam_policy_identifier({}) is None
    assert (  # nosec B101
        policy_runtime.wildcard_iam_violations(
            "aws:iam/policy:Policy",
            {"policy": wildcard_policy, "name": "allowed-policy"},
            allowlisted,
        )
        == []
    )
    assert policy_runtime.wildcard_iam_violations(
        "aws:iam/role:Role",
        {
            "inlinePolicies": [{"policy": wildcard_policy}],
            "tags": {
                "AllowWildcardIam": "true",
                "AllowWildcardIamReason": "bootstrap role",
            },
        },
        config,
    ) == [
        "inlinePolicies[0].policy must not use wildcard IAM permissions "
        "without an explicit allowlist."
    ]
    assert policy_runtime.wildcard_iam_violations(
        "aws:iam/role:Role",
        {
            "inlinePolicies": [
                "invalid",
                {"policy": "{not-json}"},
                {"policy": wildcard_policy},
            ],
        },
        config,
    ) == [
        "inlinePolicies[2].policy must not use wildcard IAM permissions "
        "without an explicit allowlist."
    ]
    assert policy_runtime.wildcard_iam_violations(
        "aws:iam/role:Role",
        {"assumeRolePolicy": wildcard_policy},
        config,
    ) == [
        "assumeRolePolicy must not use wildcard IAM permissions without an "
        "explicit allowlist."
    ]
    assert policy_runtime.wildcard_iam_violations(
        "aws:iam/policy:Policy",
        {
            "policy": _json(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": ["s3:*"],
                            "Resource": [
                                "arn:aws:s3:::example",
                                "arn:aws:s3:::example/*",
                            ],
                        }
                    ],
                }
            )
        },
        config,
    ) == ["policy must not use wildcard IAM permissions without an explicit allowlist."]
    assert (  # nosec B101
        policy_runtime.wildcard_iam_violations(
            "aws:iam/policy:Policy",
            {
                "policy": _json(
                    {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": ["sts:GetCallerIdentity"],
                                "Resource": "*",
                            }
                        ],
                    }
                )
            },
            config,
        )
        == []
    )
    assert (  # nosec B101
        policy_runtime.wildcard_iam_violations(
            "aws:iam/policy:Policy",
            {
                "policy": _json(
                    {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": ["cloudtrail:DescribeTrails"],
                                "Resource": "*",
                            }
                        ],
                    }
                )
            },
            config,
        )
        == []
    )
    assert (  # nosec B101
        policy_runtime.wildcard_iam_violations(
            "aws:iam/policy:Policy",
            {
                "policy": _json(
                    {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": ["kms:CreateKey"],
                                "Resource": "*",
                                "Condition": {
                                    "StringEquals": {
                                        "aws:RequestTag/Environment": "test",
                                        "aws:RequestTag/Purpose": "pulumi-secrets",
                                    }
                                },
                            }
                        ],
                    }
                )
            },
            config,
        )
        == []
    )
    assert (  # nosec B101
        policy_runtime.wildcard_iam_violations(
            "aws:iam/policy:Policy",
            {
                "policy": _json(
                    {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": ["billing:GetBillingViewData"],
                                "Resource": "*",
                            }
                        ],
                    }
                )
            },
            config,
        )
        == []
    )
    assert (  # nosec B101
        policy_runtime.wildcard_iam_violations(
            "aws:iam/policy:Policy",
            {
                "policy": _json(
                    {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": [
                                    "ce:CreateAnomalyMonitor",
                                    "ce:CreateAnomalySubscription",
                                ],
                                "Resource": "*",
                                "Condition": {
                                    "StringEquals": {
                                        "aws:RequestTag/Environment": "test",
                                        "aws:RequestTag/Purpose": [
                                            "cost-anomaly-monitor",
                                            "cost-anomaly-subscription",
                                        ],
                                    }
                                },
                            }
                        ],
                    }
                )
            },
            config,
        )
        == []
    )
    assert (  # nosec B101
        policy_runtime.wildcard_iam_violations(
            "aws:iam/policy:Policy",
            {
                "policy": _json(
                    {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": ["guardduty:ListDetectors"],
                                "Resource": "*",
                            }
                        ],
                    }
                )
            },
            config,
        )
        == []
    )
    assert (  # nosec B101
        policy_runtime.wildcard_iam_violations(
            "aws:iam/policy:Policy",
            {
                "policy": _json(
                    {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": ["guardduty:CreateDetector"],
                                "Resource": "*",
                                "Condition": {
                                    "StringEquals": {
                                        "aws:RequestTag/Environment": "test",
                                        "aws:RequestTag/Purpose": "security-detection",
                                    }
                                },
                            }
                        ],
                    }
                )
            },
            config,
        )
        == []
    )
    assert (  # nosec B101
        policy_runtime.wildcard_iam_violations(
            "aws:iam/policy:Policy",
            {
                "policy": _json(
                    {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": [
                                    "config:DeleteDeliveryChannel",
                                    "config:DescribeDeliveryChannels",
                                    "config:PutDeliveryChannel",
                                ],
                                "Resource": "*",
                            }
                        ],
                    }
                )
            },
            config,
        )
        == []
    )
    assert (  # nosec B101
        policy_runtime.wildcard_iam_violations(
            "aws:iam/policy:Policy",
            {
                "policy": _json(
                    {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": [
                                    "sns:GetSubscriptionAttributes",
                                    "sns:Unsubscribe",
                                ],
                                "Resource": (
                                    "arn:aws:sns:eu-central-1:123456789012:example"
                                ),
                            }
                        ],
                    }
                )
            },
            config,
        )
        == []
    )
    assert policy_runtime.wildcard_iam_violations(  # nosec B101
        "aws:iam/policy:Policy",
        {
            "policy": _json(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": ["guardduty:CreateDetector"],
                            "Resource": "*",
                        }
                    ],
                }
            )
        },
        config,
    ) == ["policy must not use wildcard IAM permissions without an explicit allowlist."]
    assert policy_runtime.wildcard_iam_violations(  # nosec B101
        "aws:iam/policy:Policy",
        {
            "policy": _json(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": ["ce:CreateAnomalyMonitor"],
                            "Resource": "*",
                        }
                    ],
                }
            )
        },
        config,
    ) == ["policy must not use wildcard IAM permissions without an explicit allowlist."]
    assert (  # nosec B101
        policy_runtime.wildcard_iam_violations(
            "aws:iam/policy:Policy",
            {
                "policy": _json(
                    {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": ["ce:ListCostAllocationTags"],
                                "Resource": "*",
                            }
                        ],
                    }
                )
            },
            config,
        )
        == []
    )
    assert policy_runtime.wildcard_iam_violations(  # nosec B101
        "aws:iam/policy:Policy",
        {
            "policy": _json(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": ["kms:CreateKey"],
                            "Resource": "*",
                        }
                    ],
                }
            )
        },
        config,
    ) == ["policy must not use wildcard IAM permissions without an explicit allowlist."]
    assert policy_runtime.wildcard_iam_violations(  # nosec B101
        "aws:iam/policy:Policy",
        {
            "policy": _json(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": 123,
                            "Resource": "*",
                        }
                    ],
                }
            )
        },
        config,
    ) == ["policy must not use wildcard IAM permissions without an explicit allowlist."]
    assert policy_runtime.wildcard_iam_violations(  # nosec B101
        "aws:iam/policy:Policy",
        {
            "policy": _json(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": ["kms:CreateKey"],
                            "Resource": "*",
                            "Condition": {"StringEquals": "invalid"},
                        }
                    ],
                }
            )
        },
        config,
    ) == ["policy must not use wildcard IAM permissions without an explicit allowlist."]
    assert policy_runtime.wildcard_iam_violations(  # nosec B101
        "aws:iam/policy:Policy",
        {
            "policy": _json(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": ["kms:CreateKey"],
                            "Resource": "*",
                            "Condition": {
                                "StringEquals": {"aws:RequestTag/Other": "test"}
                            },
                        }
                    ],
                }
            )
        },
        config,
    ) == ["policy must not use wildcard IAM permissions without an explicit allowlist."]


def test_wildcard_iam_violations_limit_resource_policy_exceptions(
    policy_runtime: SimpleNamespace,
) -> None:
    """Allow self-resource scope only, retaining checks for other policy carriers."""
    wildcard_policy = _json(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}
            ],
        }
    )
    config = _custom_config(policy_runtime)

    assert (
        policy_runtime.wildcard_iam_violations(
            "aws:s3/bucketPolicy:BucketPolicy",
            {"policy": wildcard_policy, "bucket": "example"},
            config,
        )
        == []
    )
    assert (
        policy_runtime.wildcard_iam_violations(
            "aws:kms/key:Key",
            {"policy": wildcard_policy},
            config,
        )
        == []
    )
    assert policy_runtime.wildcard_iam_violations(
        "aws:custom/policyCarrier:Carrier",
        {"policy": wildcard_policy},
        config,
    ) == ["policy must not use wildcard IAM permissions without an explicit allowlist."]
    assert policy_runtime.wildcard_iam_violations(
        "aws:iam/policy:Policy",
        {
            "policy": _json(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "NotAction": "iam:PassRole",
                            "Resource": "arn:aws:iam::123456789012:role/example",
                        }
                    ],
                }
            )
        },
        config,
    ) == ["policy must not use wildcard IAM permissions without an explicit allowlist."]
    assert policy_runtime.wildcard_iam_violations(
        "aws:iam/policy:Policy",
        {
            "policy": _json(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "iam:PassRole",
                            "NotResource": ["arn:aws:iam::123456789012:role/example"],
                        }
                    ],
                }
            )
        },
        config,
    ) == ["policy must not use wildcard IAM permissions without an explicit allowlist."]
    assert policy_runtime.wildcard_iam_violations(
        "aws:iam/policy:Policy",
        {
            "policy": _json(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "s3:GetObject",
                            "Resource": "*",
                        }
                    ],
                }
            )
        },
        config,
    ) == ["policy must not use wildcard IAM permissions without an explicit allowlist."]


def test_production_database_violations_only_apply_to_production_like_stacks(
    policy_runtime: SimpleNamespace,
) -> None:
    """Avoid breaking lower environments while hardening production defaults."""
    config = _custom_config(policy_runtime)

    assert (
        policy_runtime.production_database_violations(
            "aws:s3/bucket:Bucket",
            {"tags": {"Environment": "prod"}},
            config,
        )
        == []
    )
    assert (
        policy_runtime.production_database_violations(
            "aws:rds/instance:Instance",
            {"tags": {"Environment": "dev"}},
            config,
        )
        == []
    )
    assert policy_runtime.production_database_violations(
        "aws:rds/instance:Instance",
        {
            "tags": {"Environment": "prod"},
            "deletionProtection": False,
            "skipFinalSnapshot": True,
            "publiclyAccessible": True,
        },
        config,
    ) == [
        "Production databases must enable deletion protection.",
        "Production databases must keep final snapshots enabled.",
        "Production databases must not be publicly accessible.",
    ]
    assert (
        policy_runtime.production_database_violations(
            "aws:rds/instance:Instance",
            {
                "tags": {"Environment": "production"},
                "deletionProtection": True,
                "skipFinalSnapshot": False,
                "publiclyAccessible": False,
            },
            config,
        )
        == []
    )


def test_open_admin_ports_covers_supported_security_group_shapes(
    policy_runtime: SimpleNamespace,
) -> None:
    """Catch public SSH and RDP exposure without false positives."""
    assert policy_runtime.open_admin_ports(
        "aws:ec2/securityGroupRule:SecurityGroupRule",
        {
            "type": "ingress",
            "protocol": "tcp",
            "fromPort": 22,
            "toPort": 22,
            "cidrBlocks": ["0.0.0.0/0"],
        },
    ) == [22]
    assert policy_runtime.open_admin_ports(
        "aws:vpc/securityGroupIngressRule:SecurityGroupIngressRule",
        {"cidrIpv6": "::/0", "ipProtocol": "-1"},
    ) == [22, 3389]
    assert policy_runtime.open_admin_ports(
        "aws:ec2/securityGroup:SecurityGroup",
        {
            "ingress": [
                "ignore-me",
                {
                    "protocol": "tcp",
                    "fromPort": 443,
                    "toPort": 443,
                    "cidrBlocks": ["0.0.0.0/0"],
                },
                {
                    "protocol": "tcp",
                    "fromPort": 3389,
                    "toPort": 3389,
                    "ipv6CidrBlocks": ["::/0"],
                },
            ]
        },
    ) == [3389]
    assert (
        policy_runtime.open_admin_ports(
            "aws:ec2/securityGroupRule:SecurityGroupRule",
            {"type": "egress", "protocol": "-1", "cidrBlocks": ["0.0.0.0/0"]},
        )
        == []
    )
    assert (
        policy_runtime.open_admin_ports(
            "aws:ec2/securityGroupRule:SecurityGroupRule",
            {"type": "ingress", "cidrBlocks": "0.0.0.0/0"},
        )
        == []
    )
    assert (
        policy_runtime.open_admin_ports(
            "aws:ec2/securityGroupRule:SecurityGroupRule",
            {
                "type": "ingress",
                "protocol": "icmp",
                "fromPort": 22,
                "toPort": 22,
                "cidrBlocks": ["0.0.0.0/0"],
            },
        )
        == []
    )
    assert (
        policy_runtime.open_admin_ports(
            "aws:ec2/securityGroupRule:SecurityGroupRule",
            {
                "type": "ingress",
                "protocol": "tcp",
                "fromPort": "22",
                "toPort": 22,
                "cidrBlocks": ["0.0.0.0/0"],
            },
        )
        == []
    )
    assert (
        policy_runtime.open_admin_ports(
            "aws:s3/bucket:Bucket",
            {"cidrBlocks": ["0.0.0.0/0"]},
        )
        == []
    )


def test_pack_validators_report_expected_messages(
    policy_runtime: SimpleNamespace,
) -> None:
    """Keep the policy-pack messages stable enough for operators and CI logs."""
    violations = _collect_violations(
        policy_runtime.require_default_tags,
        resource_type="tests:s3/bucket:Bucket",
        props={"tags": {"Project": "svc"}},
    )
    assert violations == []

    violations = _collect_violations(
        policy_runtime.require_default_tags,
        resource_type="aws:s3/bucket:Bucket",
        props={},
    )
    assert violations == []

    violations = _collect_violations(
        policy_runtime.require_default_tags,
        resource_type="aws:s3/bucket:Bucket",
        props={"tags": {"Project": "svc"}},
    )
    assert "Owner" in violations[0]
    assert (  # nosec B101
        _collect_violations(
            policy_runtime.require_default_tags,
            resource_type="aws:s3/bucket:Bucket",
            props={
                "tags": {
                    "Project": "svc",
                    "Environment": "dev",
                    "Owner": "platform",
                    "CostCenter": "eng",
                    "DataClassification": "internal",
                    "Criticality": "high",
                    "RetentionClass": "standard",
                }
            },
        )
        == []
    )

    violations = _collect_violations(
        policy_runtime.enforce_allowed_regions,
        resource_type="aws:providers:Provider",
        props={"region": "us-east-1"},
    )
    assert "allowlist" in violations[0]
    assert (
        _collect_violations(
            policy_runtime.enforce_allowed_regions,
            resource_type="aws:providers:Provider",
            props={"region": "eu-central-1"},
        )
        == []
    )

    violations = _collect_violations(
        policy_runtime.block_public_s3_exposure,
        resource_type="aws:s3/bucket:Bucket",
        props={"acl": "public-read"},
    )
    assert "public ACLs" in violations[0]

    violations = _collect_violations(
        policy_runtime.block_public_s3_exposure,
        resource_type="aws:s3/bucketPolicy:BucketPolicy",
        props={"tags": {"AllowPublicBucket": "true"}},
    )
    assert violations == []

    violations = _collect_violations(
        policy_runtime.block_public_s3_exposure,
        resource_type="aws:s3/bucketPolicy:BucketPolicy",
        props={"policy": _json({"Statement": {"Effect": "Allow", "Principal": "*"}})},
    )
    assert "bucket policies" in violations[0]

    violations = _collect_violations(
        policy_runtime.require_storage_encryption,
        resource_type="aws:ec2/volume:Volume",
        props={"encrypted": False},
    )
    assert violations == ["EBS volumes must enable encryption at rest."]

    bucket = _stack_resource(
        "aws:s3/bucket:Bucket",
        props={"bucket": "logs-bucket"},
        urn="urn:pulumi:dev::bootstrap::aws:s3/bucket:Bucket::logs",
    )
    encryption = _stack_resource(
        "aws:s3/bucketServerSideEncryptionConfigurationV2:BucketServerSideEncryptionConfigurationV2",
        props={
            "bucket": "logs-bucket",
            "rule": {"applyServerSideEncryptionByDefault": {"sseAlgorithm": "AES256"}},
        },
        urn="urn:pulumi:dev::bootstrap::aws:s3/bucketServerSideEncryptionConfigurationV2:BucketServerSideEncryptionConfigurationV2::logs-encryption",
        dependencies=[bucket],
        property_dependencies={"bucket": [bucket]},
    )
    assert (  # nosec B101
        policy_runtime.storage_encryption_stack_violations([bucket, encryption]) == []
    )
    assert (  # nosec B101
        _collect_stack_violations(
            policy_runtime.require_storage_encryption_stack,
            resources=[bucket, encryption],
        )
        == []
    )

    violations = _collect_violations(
        policy_runtime.require_logging,
        resource_type="aws:lb/loadBalancer:LoadBalancer",
        props={"accessLogs": {"enabled": False}},
    )
    assert violations == ["Load balancers must enable access logs."]  # nosec B101

    violations = _collect_violations(
        policy_runtime.block_wildcard_iam,
        resource_type="aws:iam/policy:Policy",
        props={
            "policy": _json(
                {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
            )
        },
    )
    assert "wildcard IAM permissions" in violations[0]

    violations = _collect_violations(
        policy_runtime.require_production_database_safety,
        resource_type="aws:rds/instance:Instance",
        props={"tags": {"Environment": "prod"}},
    )
    assert "deletion protection" in violations[0]

    violations = _collect_violations(
        policy_runtime.block_open_admin_ports,
        resource_type="aws:ec2/securityGroupRule:SecurityGroupRule",
        props={
            "type": "ingress",
            "protocol": "tcp",
            "fromPort": 22,
            "toPort": 22,
            "cidrBlocks": ["0.0.0.0/0"],
        },
    )
    assert "22" in violations[0]
    assert (
        _collect_violations(
            policy_runtime.block_open_admin_ports,
            resource_type="aws:ec2/securityGroupRule:SecurityGroupRule",
            props={
                "type": "egress",
                "protocol": "tcp",
                "fromPort": 22,
                "toPort": 22,
                "cidrBlocks": ["0.0.0.0/0"],
            },
        )
        == []
    )


def test_build_policies_exports_all_required_guardrails(
    policy_runtime: SimpleNamespace,
) -> None:
    """Keep the exported policy list aligned with the documented rules."""
    policies = policy_runtime.build_policies()
    policy_names = {policy.name for policy in policies}

    assert policy_runtime.POLICY_PACK_NAME == "vilnacrm-guardrails"
    assert len(policies) == 8
    assert all(
        policy.enforcement_level is EnforcementLevel.MANDATORY for policy in policies
    )
    assert policy_names == {
        "aws-resource-required-default-tags",
        "aws-region-allowlist",
        "s3-no-public-exposure",
        "critical-storage-encrypted",
        "supported-resources-logging-enabled",
        "iam-no-wildcards",
        "production-database-safety",
        "security-group-no-open-admin-ports",
    }


def test_guardrails_support_direct_script_import(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Keep direct policy-analyzer startup working when `policy` is not a package."""
    monkeypatch.syspath_prepend(str(POLICY_DIR))
    for module_name in (
        "config",
        "guardrails",
        "policy",
        "policy.config",
        "policy.guardrails",
    ):
        monkeypatch.delitem(sys.modules, module_name, raising=False)

    config_spec = importlib.util.spec_from_file_location(
        "config", POLICY_DIR / "config.py"
    )
    assert config_spec is not None
    assert config_spec.loader is not None
    config_module = importlib.util.module_from_spec(config_spec)
    monkeypatch.setitem(sys.modules, "config", config_module)
    config_spec.loader.exec_module(config_module)

    guardrails_spec = importlib.util.spec_from_file_location(
        "guardrails", POLICY_DIR / "guardrails.py"
    )
    assert guardrails_spec is not None
    assert guardrails_spec.loader is not None
    guardrails_module = importlib.util.module_from_spec(guardrails_spec)
    monkeypatch.setitem(sys.modules, "guardrails", guardrails_module)
    guardrails_spec.loader.exec_module(guardrails_module)

    assert guardrails_module.CONFIG.required_tags == (  # nosec B101
        "Project",
        "Environment",
        "Owner",
        "CostCenter",
        "DataClassification",
        "Criticality",
        "RetentionClass",
    )


def test_wildcard_policy_helpers_ignore_non_allow_statements(
    policy_runtime: SimpleNamespace,
) -> None:
    """Cover the helper branches that reject non-Allow statements and lists."""
    deny_policy = _json(
        {
            "Statement": [
                {
                    "Effect": "Deny",
                    "Action": ["*"],
                    "Resource": ["*"],
                }
            ]
        }
    )

    assert (
        policy_runtime.wildcard_iam_violations(
            "aws:iam/policy:Policy",
            {"policy": deny_policy},
            _custom_config(policy_runtime),
        )
        == []
    )
    assert (
        policy_runtime.wildcard_iam_violations(
            "aws:iam/policy:Policy",
            {
                "policy": _json(
                    {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": ["s3:GetObject"],
                                "Resource": ["arn:aws:s3:::example/*"],
                            }
                        ]
                    }
                )
            },
            _custom_config(policy_runtime),
        )
        == []
    )
    assert (
        policy_runtime.wildcard_iam_violations(
            "aws:iam/policy:Policy",
            {
                "policy": _json(
                    {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": 123,
                                "Resource": 456,
                            }
                        ]
                    }
                )
            },
            _custom_config(policy_runtime),
        )
        == []
    )
    assert policy_runtime.wildcard_iam_violations(
        "aws:iam/policy:Policy",
        {
            "policy": _json(
                {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": ["*"],
                            "Resource": ["*"],
                        }
                    ]
                }
            )
        },
        _custom_config(policy_runtime),
    ) == ["policy must not use wildcard IAM permissions without an explicit allowlist."]


def test_policy_main_registers_the_built_policy_pack(
    monkeypatch: pytest.MonkeyPatch, policy_runtime: SimpleNamespace
) -> None:
    """Exercise the policy entrypoint with a fake PolicyPack constructor."""
    recorded: dict[str, Any] = {}

    def fake_policy_pack(*, name: str, policies: list[Any]) -> None:
        recorded["name"] = name
        recorded["policies"] = policies

    monkeypatch.setattr("pulumi_policy.PolicyPack", fake_policy_pack)
    runpy.run_path(str(POLICY_MAIN), run_name="__main__")

    assert recorded["name"] == policy_runtime.POLICY_PACK_NAME
    assert len(recorded["policies"]) == 8


def test_policy_main_supports_direct_pack_startup_without_repo_root(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Keep direct Pulumi policy-pack startup working without the repo root package."""
    recorded: dict[str, Any] = {}
    policy_dir = str(POLICY_DIR)
    project_root = str(PROJECT_ROOT.resolve())

    def fake_policy_pack(*, name: str, policies: list[Any]) -> None:
        recorded["name"] = name
        recorded["policies"] = policies

    monkeypatch.setattr("pulumi_policy.PolicyPack", fake_policy_pack)
    for module_name in (
        "config",
        "guardrails",
        "pack",
        "policy",
        "policy.config",
        "policy.guardrails",
        "policy.pack",
    ):
        monkeypatch.delitem(sys.modules, module_name, raising=False)

    monkeypatch.setattr(
        sys,
        "path",
        [
            policy_dir,
            *[
                path
                for path in sys.path
                if str(Path(path or ".").resolve()) != project_root
            ],
        ],
    )

    runpy.run_path(str(POLICY_MAIN), run_name="__main__")

    assert recorded["name"] == "vilnacrm-guardrails"
    assert len(recorded["policies"]) == 8


@pytest.mark.parametrize("kind", ["encryption", "logging"])
@pytest.mark.parametrize("property_scoped", [False, True])
def test_split_s3_coverage_never_credits_an_unrelated_dependency(
    policy_runtime: SimpleNamespace, kind: str, property_scoped: bool
) -> None:
    """A log destination/general dependency cannot prove its own protection."""
    source = _stack_resource(
        "aws:s3/bucket:Bucket", props={"bucket": "source"}, urn="urn:source"
    )
    destination = _stack_resource(
        "aws:s3/bucket:Bucket", props={"bucket": "destination"}, urn="urn:destination"
    )
    if kind == "encryption":
        resource_type = (
            "aws:s3/bucketServerSideEncryptionConfigurationV2:"
            "BucketServerSideEncryptionConfigurationV2"
        )
        props = {
            "rule": {"applyServerSideEncryptionByDefault": {"sseAlgorithm": "AES256"}}
        }
        validate = policy_runtime.storage_encryption_stack_violations
    else:
        resource_type = "aws:s3/bucketLogging:BucketLogging"
        props = {"targetBucket": "destination"}
        validate = policy_runtime.logging_stack_violations
    if not property_scoped:
        props["bucket"] = "source"
    protection = _stack_resource(
        resource_type,
        props=props,
        urn="urn:protection",
        dependencies=[source, destination],
        property_dependencies={"bucket": [source]} if property_scoped else {},
    )
    violations = validate([source, destination, protection])
    assert [urn for urn, _ in violations] == [destination.urn]


@pytest.mark.parametrize(
    "operator",
    [
        "StringNotEquals",
        "ArnNotEquals",
        "StringEqualsIfExists",
        "ForAllValues:StringEquals",
        "ForAnyValue:StringEquals",
        "Bool",
        "UnknownOperator",
        7,
    ],
)
@pytest.mark.parametrize(
    "action",
    [
        "kms:CreateKey",
        "ce:CreateAnomalyMonitor",
        "ce:CreateAnomalySubscription",
        "guardduty:CreateDetector",
    ],
)
def test_required_request_tags_cannot_use_optional_negated_or_set_conditions(
    policy_runtime: SimpleNamespace, operator: str | int, action: str
) -> None:
    """Required single-valued tags need a positive, existence-requiring match."""
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": action,
                "Resource": "*",
                "Condition": {
                    operator: {
                        "aws:RequestTag/Environment": "test",
                        "aws:RequestTag/Purpose": "bootstrap",
                    }
                },
            }
        ]
    }
    assert policy_runtime.wildcard_iam_violations(
        "aws:iam/policy:Policy",
        {"policy": policy},
        _custom_config(policy_runtime),
    ) == ["policy must not use wildcard IAM permissions without an explicit allowlist."]


@pytest.mark.parametrize("kind", ["encryption", "logging"])
def test_split_s3_non_bucket_property_dependency_cannot_prove_protection(
    policy_runtime: SimpleNamespace, kind: str
) -> None:
    """Even a property dependency must identify the bucket resource itself."""
    bucket = _stack_resource(
        "aws:s3/bucket:Bucket", props={}, urn="urn:unprotected-bucket"
    )
    unrelated_role = _stack_resource(
        "aws:iam/role:Role", props={}, urn="urn:unrelated-role"
    )
    if kind == "encryption":
        resource_type = (
            "aws:s3/bucketServerSideEncryptionConfigurationV2:"
            "BucketServerSideEncryptionConfigurationV2"
        )
        props = {
            "rule": {"applyServerSideEncryptionByDefault": {"sseAlgorithm": "AES256"}}
        }
        validate = policy_runtime.storage_encryption_stack_violations
    else:
        resource_type = "aws:s3/bucketLogging:BucketLogging"
        props = {"targetBucket": "destination"}
        validate = policy_runtime.logging_stack_violations
    protection = _stack_resource(
        resource_type,
        props=props,
        urn="urn:protection",
        property_dependencies={"bucket": [unrelated_role]},
    )
    assert [urn for urn, _ in validate([bucket, protection])] == [bucket.urn]


@pytest.mark.parametrize(
    "encryption",
    [
        {},
        {"rule": "AES256"},
        {"rules": []},
        {"rules": [None, "AES256"]},
        {"rule": {}},
        {"rule": {"applyServerSideEncryptionByDefault": {}}},
        {"rule": {"applyServerSideEncryptionByDefault": {"sseAlgorithm": ""}}},
        {"rule": {"applyServerSideEncryptionByDefault": "AES256"}},
    ],
)
def test_inline_s3_encryption_requires_concrete_default(policy_runtime, encryption):
    """Malformed inline metadata must not bypass resource or stack encryption policy."""
    props = {
        "bucket": "unencrypted-inline",
        "serverSideEncryptionConfiguration": encryption,
    }
    resource_type = "aws:s3/bucket:Bucket"
    bucket = _stack_resource(resource_type, props=props, urn="urn:unencrypted-inline")
    message = "S3 buckets must enable default server-side encryption."
    assert policy_runtime.storage_encryption_violations(resource_type, props) == [
        message
    ]
    assert policy_runtime.storage_encryption_stack_violations([bucket]) == [
        (bucket.urn, message)
    ]


@pytest.mark.parametrize("container", ["rule", "rules"])
@pytest.mark.parametrize("algorithm", ["AES256", "aws:kms"])
def test_inline_s3_encryption_accepts_concrete_default(
    policy_runtime, container, algorithm
):
    """Real inline rule shapes satisfy both resource and stack encryption policy."""
    rule = {"applyServerSideEncryptionByDefault": {"sseAlgorithm": algorithm}}
    encryption = {container: rule if container == "rule" else [rule]}
    props = {
        "bucket": "encrypted-inline",
        "serverSideEncryptionConfiguration": encryption,
    }
    resource_type = "aws:s3/bucket:Bucket"
    bucket = _stack_resource(resource_type, props=props, urn="urn:encrypted-inline")
    assert policy_runtime.storage_encryption_violations(resource_type, props) == []
    assert policy_runtime.storage_encryption_stack_violations([bucket]) == []


@pytest.mark.parametrize(
    "resource_type", ["aws:s3/bucketPolicy:BucketPolicy", "aws:kms/key:Key"]
)
@pytest.mark.parametrize("field", ["policy", "policyDocument"])
@pytest.mark.parametrize(
    "scope",
    [
        {"Action": "*", "Resource": "*"},
        {"Action": "iam:*", "Resource": "*"},
        {"Action": ["ec2:*"], "Resource": "arn:aws:s3:::example/*"},
        {"NotAction": "kms:ScheduleKeyDeletion", "Resource": "*"},
        {"NotAction": ["s3:GetObject"], "Resource": "*"},
        {"Action": "kms:Decrypt", "NotResource": "*"},
        {
            "Action": "kms:Decrypt",
            "NotResource": ["arn:aws:kms:eu-central-1:123456789012:key/example"],
        },
    ],
)
def test_resource_policy_exemption_never_skips_action_or_negated_scope(
    policy_runtime: SimpleNamespace, resource_type: str, field: str, scope: dict
) -> None:
    """Resource policies cannot hide global/cross-service or negated grants."""
    document = {"Statement": [{"Effect": "Allow", **scope}]}
    assert policy_runtime.wildcard_iam_violations(
        resource_type, {field: _json(document)}, _custom_config(policy_runtime)
    ) == [
        f"{field} must not use wildcard IAM permissions without an explicit allowlist."
    ]


@pytest.mark.parametrize("action", ["sns:GetSubscriptionAttributes", "sns:Unsubscribe"])
@pytest.mark.parametrize("resource", ["*", ["*"]])
def test_sns_topic_scopable_actions_require_resource_scope(
    policy_runtime: SimpleNamespace, action: str, resource: object
) -> None:
    """SNS SAR lists topic scope for these actions; generic wildcards must fail."""
    assert policy_runtime.wildcard_iam_violations(
        "aws:iam/policy:Policy",
        {
            "policy": _json(
                {
                    "Statement": [
                        {"Effect": "Allow", "Action": action, "Resource": resource}
                    ]
                }
            )
        },
        _custom_config(policy_runtime),
    )


@pytest.mark.parametrize(
    "resource_type,action",
    [
        ("aws:kms/key:Key", "kms:Decrypt"),
        ("aws:s3/bucketPolicy:BucketPolicy", "s3:GetObject"),
    ],
)
@pytest.mark.parametrize("field", ["policy", "policyDocument"])
def test_resource_policy_preserves_explicit_actions_and_self_resource_scope(
    policy_runtime: SimpleNamespace, resource_type: str, action: str, field: str
) -> None:
    """The existing Resource-only exception retains concrete action grants."""
    document = {"Statement": [{"Effect": "Allow", "Action": action, "Resource": "*"}]}
    assert (
        policy_runtime.wildcard_iam_violations(
            resource_type, {field: _json(document)}, _custom_config(policy_runtime)
        )
        == []
    )


@pytest.mark.parametrize(
    "resource_type,action",
    [
        ("aws:kms/key:Key", "kms:*"),
        ("aws:s3/bucketPolicy:BucketPolicy", "s3:*"),
        ("aws:kms/key:Key", ["KMS:*", "kms:GenerateDataKey*"]),
        ("aws:s3/bucketPolicy:BucketPolicy", ["S3:*"]),
    ],
)
def test_resource_policy_retains_same_service_compatibility(
    policy_runtime: SimpleNamespace, resource_type: str, action: object
) -> None:
    """Keep existing same-service grants; this is not principal/condition approval."""
    assert (
        policy_runtime.wildcard_iam_violations(
            resource_type,
            {
                "policy": _json(
                    {
                        "Statement": [
                            {"Effect": "Allow", "Action": action, "Resource": "*"}
                        ]
                    }
                )
            },
            _custom_config(policy_runtime),
        )
        == []
    )


@pytest.mark.parametrize(
    "resource_type,action",
    [
        ("aws:kms/key:Key", "s3:*"),
        ("aws:s3/bucketPolicy:BucketPolicy", "kms:*"),
        ("aws:kms/key:Key", ["kms:*", "*"]),
        ("aws:s3/bucketPolicy:BucketPolicy", ["s3:*", "iam:*"]),
    ],
)
def test_resource_policy_rejects_global_and_cross_family_mixtures(
    policy_runtime: SimpleNamespace, resource_type: str, action: object
) -> None:
    """A permitted family action cannot mask an unrelated or global grant."""
    assert policy_runtime.wildcard_iam_violations(
        resource_type,
        {
            "policy": _json(
                {"Statement": [{"Effect": "Allow", "Action": action, "Resource": "*"}]}
            )
        },
        _custom_config(policy_runtime),
    )


def test_resource_policy_preserves_tls_deny_and_kms_account_admin_shape(
    policy_runtime: SimpleNamespace,
) -> None:
    """Real source patterns retain deny semantics and explicit key administration."""
    statements = [
        (
            "aws:s3/bucketPolicy:BucketPolicy",
            {
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:*",
                "Resource": "arn:aws:s3:::example/*",
                "Condition": {"Bool": {"aws:SecureTransport": "false"}},
            },
        ),
        (
            "aws:kms/key:Key",
            {
                "Sid": "EnableAccountPermissions",
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
                "Action": "kms:*",
                "Resource": "*",
            },
        ),
    ]
    for resource_type, statement in statements:
        assert (
            policy_runtime.wildcard_iam_violations(
                resource_type,
                {"policy": _json({"Statement": [statement]})},
                _custom_config(policy_runtime),
            )
            == []
        )


@pytest.mark.parametrize("kind", ["encryption", "logging"])
@pytest.mark.parametrize("property_scoped", [False, True])
def test_unknown_s3_names_never_match_unrelated_buckets(
    policy_runtime: SimpleNamespace, kind: str, property_scoped: bool
) -> None:
    """An unknown name proves no identity; a bucket-specific URN still does."""
    unknown = "04da6b54-80e4-46f7-96ec-b56ff0331ba9"
    source = _stack_resource(
        "aws:s3/bucket:Bucket", props={"bucket": unknown}, urn="urn:source"
    )
    unrelated = _stack_resource(
        "aws:s3/bucket:Bucket", props={"bucket": unknown}, urn="urn:unrelated"
    )
    if kind == "encryption":
        resource_type = (
            "aws:s3/bucketServerSideEncryptionConfigurationV2:"
            "BucketServerSideEncryptionConfigurationV2"
        )
        props = {
            "bucket": unknown,
            "rule": {"applyServerSideEncryptionByDefault": {"sseAlgorithm": "AES256"}},
        }
        validate = policy_runtime.storage_encryption_stack_violations
    else:
        resource_type = "aws:s3/bucketLogging:BucketLogging"
        props = {"bucket": unknown, "targetBucket": "audit-logs"}
        validate = policy_runtime.logging_stack_violations
    protection = _stack_resource(
        resource_type,
        props=props,
        urn="urn:protection",
        property_dependencies={"bucket": [source]} if property_scoped else {},
    )
    expected = [unrelated.urn] if property_scoped else [source.urn, unrelated.urn]
    assert [urn for urn, _ in validate([source, unrelated, protection])] == expected


@pytest.mark.parametrize("mode", ["inline", "split"])
@pytest.mark.parametrize(
    "target", ["04da6b54-80e4-46f7-96ec-b56ff0331ba9", "audit-logs"]
)
def test_s3_logging_requires_a_concrete_destination(
    policy_runtime: SimpleNamespace, mode: str, target: str
) -> None:
    """Even an exact source dependency cannot prove an unknown log destination."""
    bucket = _stack_resource(
        "aws:s3/bucket:Bucket", props={"bucket": "source"}, urn="urn:source"
    )
    resources = [bucket]
    if mode == "inline":
        bucket.props["logging"] = {"targetBucket": target}
    else:
        resources.append(
            _stack_resource(
                "aws:s3/bucketLogging:BucketLogging",
                props={"bucket": "source", "targetBucket": target},
                urn="urn:logging",
                property_dependencies={"bucket": [bucket]},
            )
        )
    expected = [] if target == "audit-logs" else [bucket.urn]
    assert [
        urn for urn, _ in policy_runtime.logging_stack_violations(resources)
    ] == expected
    if mode == "inline":
        assert bool(
            policy_runtime.logging_violations(bucket.resource_type, bucket.props)
        ) == bool(expected)
