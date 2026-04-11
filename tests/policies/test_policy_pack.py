"""Tests for the VilnaCRM Pulumi policy pack and reusable guardrail helpers."""

from __future__ import annotations

import importlib.util
import json
import runpy
import sys
from pathlib import Path
from types import MappingProxyType, SimpleNamespace
from typing import Any, cast

import pytest
from pulumi_policy import EnforcementLevel

PROJECT_ROOT = Path(__file__).resolve().parents[2]
POLICY_DIR = PROJECT_ROOT / "policy"
POLICY_MAIN = POLICY_DIR / "__main__.py"


@pytest.fixture
def policy_runtime(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    """Import the policy modules without leaking globals across tests."""
    module_names = (
        "config",
        "guardrails",
        "pack",
        "policy.config",
        "policy.guardrails",
        "policy.pack",
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
            logging_violations=guardrails.logging_violations,
            missing_required_tags=guardrails.missing_required_tags,
            open_admin_ports=guardrails.open_admin_ports,
            production_database_violations=guardrails.production_database_violations,
            storage_encryption_violations=guardrails.storage_encryption_violations,
            wildcard_iam_violations=guardrails.wildcard_iam_violations,
            POLICY_PACK_NAME=pack.POLICY_PACK_NAME,
            block_open_admin_ports=pack.block_open_admin_ports,
            block_public_s3_exposure=pack.block_public_s3_exposure,
            block_wildcard_iam=pack.block_wildcard_iam,
            build_policies=pack.build_policies,
            enforce_allowed_regions=pack.enforce_allowed_regions,
            require_default_tags=pack.require_default_tags,
            require_logging=pack.require_logging,
            require_production_database_safety=pack.require_production_database_safety,
            require_storage_encryption=pack.require_storage_encryption,
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
        "wildcard_iam_allowlist": frozenset(),
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


def _json(document: dict[str, Any]) -> str:
    """Serialize a policy document into stable JSON."""
    return json.dumps(document, sort_keys=True)


def test_repo_policy_config_declares_expected_defaults(
    policy_runtime: SimpleNamespace,
) -> None:
    """Keep the committed policy config aligned with the documented guardrails."""
    config = policy_runtime.load_policy_config()

    assert config.required_tags == ("Project", "Environment", "Owner", "CostCenter")
    assert config.allowed_regions == ("eu-central-1", "eu-west-1")
    assert config.production_environments == ("prod", "production", "live")
    assert config.annotations["public_s3_tag"] == "AllowPublicBucket"
    assert config.public_s3_bucket_allowlist == frozenset()
    assert config.wildcard_iam_allowlist == frozenset()


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
    assert config.wildcard_iam_allowlist == frozenset()


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
            {"serverSideEncryptionConfiguration": {"rule": "AES256"}},
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
        policy_runtime, wildcard_iam_allowlist=frozenset({"allowed-policy"})
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
    assert (
        policy_runtime.wildcard_iam_violations(
            "aws:iam/policy:Policy",
            {"policy": wildcard_policy, "name": "allowed-policy"},
            allowlisted,
        )
        == []
    )
    assert (
        policy_runtime.wildcard_iam_violations(
            "aws:iam/role:Role",
            {
                "inlinePolicies": [{"policy": wildcard_policy}],
                "tags": {
                    "AllowWildcardIam": "true",
                    "AllowWildcardIamReason": "bootstrap role",
                },
            },
            config,
        )
        == []
    )
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
            "cidrBlocks": ["0.0.0.0/00"],
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
    assert (
        _collect_violations(
            policy_runtime.require_default_tags,
            resource_type="aws:s3/bucket:Bucket",
            props={
                "tags": {
                    "Project": "svc",
                    "Environment": "dev",
                    "Owner": "platform",
                    "CostCenter": "eng",
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

    violations = _collect_violations(
        policy_runtime.require_logging,
        resource_type="aws:lb/loadBalancer:LoadBalancer",
        props={"accessLogs": {"enabled": False}},
    )
    assert violations == ["Load balancers must enable access logs."]

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

    assert guardrails_module.CONFIG.required_tags == (
        "Project",
        "Environment",
        "Owner",
        "CostCenter",
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
