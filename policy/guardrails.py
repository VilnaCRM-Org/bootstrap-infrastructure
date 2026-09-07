"""Reusable validators for the VilnaCRM Pulumi policy pack."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from ipaddress import ip_network
from typing import Any, cast

try:
    from policy.config import PolicyConfig, load_policy_config
    from policy.reviewed_iam import reviewed_iam_document_matches
except ModuleNotFoundError as exc:  # pragma: no cover - direct policy startup.
    if exc.name not in {"policy", "policy.config"}:
        raise
    from config import PolicyConfig, load_policy_config
    from reviewed_iam import reviewed_iam_document_matches

CONFIG = load_policy_config()
PUBLIC_S3_ACLS = {"public-read", "public-read-write"}
OPEN_CIDRS = ("0.0.0.0/0", "::/0")
SENSITIVE_PORTS = (22, 3389)
PUBLIC_ACCESS_NARROWING_KEYS = (
    "aws:PrincipalArn",
    "aws:PrincipalOrgID",
    "aws:SourceAccount",
    "aws:SourceArn",
    "aws:SourceIp",
    "aws:SourceVpc",
    "aws:SourceVpce",
)
POSITIVE_PUBLIC_ACCESS_OPERATORS = frozenset(
    {"ArnEquals", "ArnLike", "IpAddress", "StringEquals", "StringLike"}
)
AWS_PROVIDER_TYPE_SUFFIX = "pulumi:providers:aws"
S3_BUCKET_TYPE_SUFFIX = "s3/bucket:Bucket"
S3_BUCKET_ENCRYPTION_TYPE_SUFFIXES = (
    "s3/bucketServerSideEncryptionConfiguration:BucketServerSideEncryptionConfiguration",
    "s3/bucketServerSideEncryptionConfigurationV2:BucketServerSideEncryptionConfigurationV2",
)
S3_BUCKET_LOGGING_TYPE_SUFFIXES = ("s3/bucketLogging:BucketLogging",)
S3_BUCKET_ACL_TYPE_SUFFIX = "s3/bucketAcl:BucketAcl"
S3_BUCKET_ACL_V2_TYPE_SUFFIX = "s3/bucketAclV2:BucketAclV2"
S3_BUCKET_POLICY_TYPE_SUFFIX = "s3/bucketPolicy:BucketPolicy"
EBS_VOLUME_TYPE_SUFFIX = "ec2/volume:Volume"
EFS_FILE_SYSTEM_TYPE_SUFFIX = "efs/fileSystem:FileSystem"
RDS_CLUSTER_TYPE_SUFFIX = "rds/cluster:Cluster"
RDS_INSTANCE_TYPE_SUFFIX = "rds/instance:Instance"
LOAD_BALANCER_TYPE_SUFFIX = "lb/loadBalancer:LoadBalancer"
SECURITY_GROUP_RULE_TYPE_SUFFIX = "ec2/securityGroupRule:SecurityGroupRule"
SECURITY_GROUP_TYPE_SUFFIX = "ec2/securityGroup:SecurityGroup"
SECURITY_GROUP_INGRESS_RULE_TYPE_SUFFIX = (
    "vpc/securityGroupIngressRule:SecurityGroupIngressRule"
)
KMS_KEY_TYPE_SUFFIX = "kms/key:Key"
IAM_ROLE_TYPE_SUFFIX = "iam/role:Role"
IDENTITY_POLICY_TYPE_SUFFIXES = (
    "iam/policy:Policy",
    "iam/rolePolicy:RolePolicy",
    "iam/groupPolicy:GroupPolicy",
    "iam/userPolicy:UserPolicy",
)
LOGGING_EXEMPT_TAG = "LoggingExempt"
LOGGING_EXEMPT_REASON_TAG = "LoggingExemptReason"


def extract_tags(props: Mapping[str, Any]) -> Mapping[str, Any] | None:
    """Return the resource tag mapping when the provider exposes one."""
    tags_all = props.get("tagsAll")
    tags = props.get("tags")
    if isinstance(tags_all, Mapping) and isinstance(tags, Mapping):
        return {**tags_all, **tags}

    if isinstance(tags_all, Mapping):
        return tags_all

    if isinstance(tags, Mapping):
        return tags

    return None


def missing_required_tags(
    tags: Mapping[str, Any] | None, config: PolicyConfig = CONFIG
) -> list[str]:
    """Return required default tags that are absent or blank."""
    if tags is None:
        return list(config.required_tags)

    missing = []
    for key in config.required_tags:
        value = tags.get(key)
        if not isinstance(value, str) or not value.strip():
            missing.append(key)
    return missing


def has_public_s3_acl(resource_type: str, props: Mapping[str, Any]) -> bool:
    """Detect explicitly public S3 bucket ACLs."""
    return _matches_any_resource_type(
        resource_type,
        (
            S3_BUCKET_TYPE_SUFFIX,
            S3_BUCKET_ACL_TYPE_SUFFIX,
            S3_BUCKET_ACL_V2_TYPE_SUFFIX,
        ),
    ) and (props.get("acl") in PUBLIC_S3_ACLS)


def has_public_s3_bucket_policy(resource_type: str, props: Mapping[str, Any]) -> bool:
    """Detect bucket policies that allow public access."""
    if not _matches_any_resource_type(
        resource_type, (S3_BUCKET_POLICY_TYPE_SUFFIX, S3_BUCKET_TYPE_SUFFIX)
    ):
        return False

    for statement in _policy_statements(props):
        if _statement_allows_public_access(statement):
            return True
    return False


def is_public_bucket_allowlisted(
    props: Mapping[str, Any], config: PolicyConfig = CONFIG
) -> bool:
    """Allow explicit public buckets only through an allowlist or tag annotation."""
    bucket_name = _string_value(props.get("bucket"))
    if bucket_name and bucket_name in config.public_s3_bucket_allowlist:
        return True

    tags = extract_tags(props) or {}
    tag_name = config.annotations.get("public_s3_tag", "AllowPublicBucket")
    return _truthy(tags.get(tag_name))


def invalid_region(
    resource_type: str, props: Mapping[str, Any], config: PolicyConfig = CONFIG
) -> str | None:
    """Reject regions outside the repository allowlist when explicitly configured."""
    if not config.allowed_regions:
        return None

    if not (
        resource_type.startswith("aws:")
        or _matches_resource_type(resource_type, AWS_PROVIDER_TYPE_SUFFIX)
    ):
        return None

    region = _string_value(props.get("region"))
    if region is None or region in config.allowed_regions:
        return None
    return region


def storage_encryption_violations(
    resource_type: str, props: Mapping[str, Any]
) -> list[str]:
    """Return storage encryption issues for critical persistent resources."""
    violations: list[str] = []

    if _matches_resource_type(resource_type, S3_BUCKET_TYPE_SUFFIX):
        encryption = props.get("serverSideEncryptionConfiguration")
        if not isinstance(encryption, Mapping) or not _has_default_s3_encryption_rule(
            encryption
        ):
            violations.append("S3 buckets must enable default server-side encryption.")

    if _matches_resource_type(resource_type, EBS_VOLUME_TYPE_SUFFIX) and not _truthy(
        props.get("encrypted")
    ):
        violations.append("EBS volumes must enable encryption at rest.")

    if _matches_resource_type(
        resource_type, EFS_FILE_SYSTEM_TYPE_SUFFIX
    ) and not _truthy(props.get("encrypted")):
        violations.append("EFS file systems must enable encryption at rest.")

    if _matches_any_resource_type(
        resource_type, (RDS_CLUSTER_TYPE_SUFFIX, RDS_INSTANCE_TYPE_SUFFIX)
    ) and not _truthy(props.get("storageEncrypted")):
        violations.append("RDS databases must enable storage encryption.")

    return violations


def storage_encryption_stack_violations(
    resources: Sequence[Any],
) -> list[tuple[str | None, str]]:
    """Return stack-wide encryption issues, including split S3 resources."""
    encrypted_bucket_names, encrypted_bucket_urns = _s3_encryption_targets(resources)

    violations: list[tuple[str | None, str]] = []
    for resource in resources:
        resource_type = getattr(resource, "resource_type", "")
        props = cast(Mapping[str, Any], getattr(resource, "props", {}))
        urn = cast(str | None, getattr(resource, "urn", None))

        if _s3_bucket_is_covered(
            resource_type,
            props,
            urn,
            encrypted_bucket_names,
            encrypted_bucket_urns,
        ):
            continue

        for violation in storage_encryption_violations(resource_type, props):
            violations.append((urn, violation))

    return violations


def logging_violations(resource_type: str, props: Mapping[str, Any]) -> list[str]:
    """Return logging configuration issues for supported resource types."""
    violations: list[str] = []

    if _matches_resource_type(resource_type, S3_BUCKET_TYPE_SUFFIX):
        if _bucket_logging_exempt(props):
            return violations
        logging_config = props.get("logging")
        if not isinstance(logging_config, Mapping) or not _string_value(
            logging_config.get("targetBucket")
        ):
            violations.append("S3 buckets must send access logs to a target bucket.")

    if _matches_resource_type(resource_type, LOAD_BALANCER_TYPE_SUFFIX):
        access_logs = props.get("accessLogs")
        if not isinstance(access_logs, Mapping) or not _truthy(
            access_logs.get("enabled")
        ):
            violations.append("Load balancers must enable access logs.")

    return violations


def logging_stack_violations(resources: Sequence[Any]) -> list[tuple[str | None, str]]:
    """Return stack-wide logging issues, including split S3 logging resources."""
    logged_bucket_names, logged_bucket_urns = _s3_logging_targets(resources)

    violations: list[tuple[str | None, str]] = []
    for resource in resources:
        resource_type = getattr(resource, "resource_type", "")
        props = cast(Mapping[str, Any], getattr(resource, "props", {}))
        urn = cast(str | None, getattr(resource, "urn", None))

        if _s3_bucket_logging_is_covered(
            resource_type,
            props,
            urn,
            logged_bucket_names,
            logged_bucket_urns,
        ):
            continue

        for violation in logging_violations(resource_type, props):
            violations.append((urn, violation))

    return violations


def _resource_dependencies(resource: Any, property_name: str) -> Sequence[Any]:
    """Return only dependencies that affect the specific protected property."""
    property_dependencies = cast(
        Mapping[str, Sequence[Any]],
        getattr(resource, "property_dependencies", {}) or {},
    )
    return list(property_dependencies.get(property_name, []))


def _s3_encryption_rule_items(props: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    """Return concrete inline and split encryption rules from one resource."""
    rule_items: list[Mapping[str, Any]] = []
    rule = props.get("rule")
    if isinstance(rule, Mapping):
        rule_items.append(rule)

    rules = props.get("rules")
    if not isinstance(rules, Sequence):
        return rule_items

    rule_items.extend(
        candidate for candidate in rules if isinstance(candidate, Mapping)
    )
    return rule_items


def _has_default_s3_encryption_rule(props: Mapping[str, Any]) -> bool:
    """Require a supported concrete SSE algorithm, never an RPC unknown value."""
    for candidate in _s3_encryption_rule_items(props):
        default_encryption = candidate.get("applyServerSideEncryptionByDefault")
        if not isinstance(default_encryption, Mapping):
            continue
        if _string_value(default_encryption.get("sseAlgorithm")) in {
            "AES256",
            "aws:fsx",
            "aws:kms",
            "aws:kms:dsse",
        }:
            return True
    return False


def _s3_encryption_targets(resources: Sequence[Any]) -> tuple[set[str], set[str]]:
    """Collect bucket names and URNs protected by standalone S3 encryption resources."""
    encrypted_bucket_names: set[str] = set()
    encrypted_bucket_urns: set[str] = set()

    for resource in resources:
        resource_type = getattr(resource, "resource_type", "")
        if not _matches_any_resource_type(
            resource_type,
            S3_BUCKET_ENCRYPTION_TYPE_SUFFIXES,
        ):
            continue

        props = cast(Mapping[str, Any], getattr(resource, "props", {}))
        if not _has_default_s3_encryption_rule(props):
            continue

        bucket_name = _string_value(props.get("bucket"))
        if bucket_name:
            encrypted_bucket_names.add(bucket_name)

        for dependency in _resource_dependencies(resource, "bucket"):
            dependency_type = getattr(dependency, "resource_type", "")
            if _matches_resource_type(dependency_type, S3_BUCKET_TYPE_SUFFIX):
                dependency_urn = getattr(dependency, "urn", "")
                encrypted_bucket_urns.update(filter(None, (dependency_urn,)))

    return encrypted_bucket_names, encrypted_bucket_urns


def _s3_bucket_is_covered(
    resource_type: str,
    props: Mapping[str, Any],
    urn: str | None,
    encrypted_bucket_names: set[str],
    encrypted_bucket_urns: set[str],
) -> bool:
    """Return True when an S3 bucket is protected by inline or split encryption."""
    if not _matches_resource_type(resource_type, S3_BUCKET_TYPE_SUFFIX):
        return False

    encryption = props.get("serverSideEncryptionConfiguration")
    if isinstance(encryption, Mapping) and _has_default_s3_encryption_rule(encryption):
        return True

    bucket_name = _string_value(props.get("bucket"))
    if urn in encrypted_bucket_urns:
        return True
    return bool(bucket_name and bucket_name in encrypted_bucket_names)


def _s3_logging_targets(resources: Sequence[Any]) -> tuple[set[str], set[str]]:
    """Collect bucket names and URNs covered by standalone S3 logging resources."""
    logged_bucket_names: set[str] = set()
    logged_bucket_urns: set[str] = set()

    for resource in resources:
        resource_type = getattr(resource, "resource_type", "")
        if not _matches_any_resource_type(
            resource_type,
            S3_BUCKET_LOGGING_TYPE_SUFFIXES,
        ):
            continue

        props = cast(Mapping[str, Any], getattr(resource, "props", {}))
        if not _string_value(props.get("targetBucket")):
            continue

        bucket_name = _string_value(props.get("bucket"))
        if bucket_name:
            logged_bucket_names.add(bucket_name)

        for dependency in _resource_dependencies(resource, "bucket"):
            dependency_type = getattr(dependency, "resource_type", "")
            if _matches_resource_type(dependency_type, S3_BUCKET_TYPE_SUFFIX):
                dependency_urn = getattr(dependency, "urn", "")
                logged_bucket_urns.update(filter(None, (dependency_urn,)))

    return logged_bucket_names, logged_bucket_urns


def _s3_bucket_logging_is_covered(
    resource_type: str,
    props: Mapping[str, Any],
    urn: str | None,
    logged_bucket_names: set[str],
    logged_bucket_urns: set[str],
) -> bool:
    """Return True when an S3 bucket has inline or split access logging."""
    if not _matches_resource_type(resource_type, S3_BUCKET_TYPE_SUFFIX):
        return False

    if _bucket_logging_exempt(props):
        return True

    logging_config = props.get("logging")
    if isinstance(logging_config, Mapping) and _string_value(
        logging_config.get("targetBucket")
    ):
        return True

    bucket_name = _string_value(props.get("bucket"))
    if urn in logged_bucket_urns:
        return True
    return bool(bucket_name and bucket_name in logged_bucket_names)


def _bucket_logging_exempt(props: Mapping[str, Any]) -> bool:
    """Return True when the bucket is tagged as intentionally log-exempt."""
    tags = extract_tags(props) or {}
    return bool(
        _truthy(tags.get(LOGGING_EXEMPT_TAG))
        and _string_value(tags.get(LOGGING_EXEMPT_REASON_TAG))
    )


def wildcard_iam_violations(
    resource_type: str,
    props: Mapping[str, Any],
    config: PolicyConfig = CONFIG,
) -> list[str]:
    """Reject broad IAM grants; retain reviewed and resource-local exceptions."""
    if reviewed_iam_document_matches(
        resource_type, props, config.reviewed_iam_documents
    ):
        return []

    documents = list(_policy_documents(resource_type, props))
    violations: list[str] = []
    for field_name, statements in documents:
        resource_policy_service = _resource_policy_service(resource_type, field_name)
        for statement in statements:
            if _statement_contains_wildcard_permissions(
                statement, resource_policy_service=resource_policy_service
            ):
                violations.append(
                    f"{field_name} must not use wildcard IAM permissions "
                    "without an explicit allowlist."
                )
                break
    return violations


def iam_policy_identifier(props: Mapping[str, Any]) -> str | None:
    """Return a stable identifier for policy allowlists when one is available."""
    for key in ("name", "policyName", "bucket", "role", "group", "user"):
        value = _string_value(props.get(key))
        if value:
            return value
    return None


def production_database_violations(
    resource_type: str,
    props: Mapping[str, Any],
    config: PolicyConfig = CONFIG,
) -> list[str]:
    """Enforce safer database defaults for production-like environments."""
    if not _matches_any_resource_type(
        resource_type, (RDS_CLUSTER_TYPE_SUFFIX, RDS_INSTANCE_TYPE_SUFFIX)
    ):
        return []

    environment = _string_value((extract_tags(props) or {}).get("Environment"))
    if environment is None or environment.lower() not in config.production_environments:
        return []

    violations: list[str] = []
    if not _truthy(props.get("deletionProtection")):
        violations.append("Production databases must enable deletion protection.")
    if _truthy(props.get("skipFinalSnapshot")):
        violations.append("Production databases must keep final snapshots enabled.")
    if _truthy(props.get("publiclyAccessible")):
        violations.append("Production databases must not be publicly accessible.")
    return violations


def open_admin_ports(resource_type: str, props: Mapping[str, Any]) -> list[int]:
    """Return sensitive ports exposed to the public internet."""
    exposed_ports: set[int] = set()
    for rule in _open_admin_port_rules(resource_type, props):
        exposed_ports.update(_ports_in_range(rule))

    return sorted(exposed_ports)


def _open_admin_port_rules(
    resource_type: str, props: Mapping[str, Any]
) -> Sequence[Mapping[str, Any]]:
    """Yield ingress rules that are open to the public internet."""
    if _matches_resource_type(resource_type, SECURITY_GROUP_RULE_TYPE_SUFFIX):
        return [props] if _is_public_ingress_rule(props) else []

    if _matches_resource_type(resource_type, SECURITY_GROUP_INGRESS_RULE_TYPE_SUFFIX):
        return [props] if _is_open_to_world(props) else []

    if _matches_resource_type(resource_type, SECURITY_GROUP_TYPE_SUFFIX):
        return _public_ingress_rules(props.get("ingress", []) or [])

    return []


def _is_public_ingress_rule(props: Mapping[str, Any]) -> bool:
    """Return whether a classic security-group rule is public ingress."""
    return props.get("type") == "ingress" and _is_open_to_world(props)


def _public_ingress_rules(rules: Sequence[object]) -> list[Mapping[str, Any]]:
    """Filter nested ingress rules down to the public ones."""
    public_rules: list[Mapping[str, Any]] = []
    for rule in rules:
        if isinstance(rule, Mapping) and _is_open_to_world(rule):
            public_rules.append(cast(Mapping[str, Any], rule))
    return public_rules


def _policy_documents(
    resource_type: str, props: Mapping[str, Any]
) -> Sequence[tuple[str, Sequence[Mapping[str, Any]]]]:
    """Return every policy-like document embedded in a resource."""
    documents = list(_named_policy_documents(props))
    if _matches_resource_type(resource_type, IAM_ROLE_TYPE_SUFFIX):
        documents.extend(_role_policy_documents(props))
    return documents


def _named_policy_documents(
    props: Mapping[str, Any],
) -> Sequence[tuple[str, Sequence[Mapping[str, Any]]]]:
    """Return policy documents attached directly to a resource."""
    documents: list[tuple[str, Sequence[Mapping[str, Any]]]] = []
    for field_name in ("policy", "policyDocument"):
        statements = _policy_statements_from_value(props.get(field_name))
        if statements:
            documents.append((field_name, statements))
    return documents


def _role_policy_documents(
    props: Mapping[str, Any],
) -> Sequence[tuple[str, Sequence[Mapping[str, Any]]]]:
    """Return trust and inline policy documents embedded in IAM roles."""
    documents: list[tuple[str, Sequence[Mapping[str, Any]]]] = []

    assume_role_statements = _policy_statements_from_value(
        props.get("assumeRolePolicy")
    )
    if assume_role_statements:
        documents.append(("assumeRolePolicy", assume_role_statements))

    inline_policies = props.get("inlinePolicies")
    if not isinstance(inline_policies, Sequence) or isinstance(
        inline_policies, (str, bytes)
    ):
        return documents

    for index, policy in enumerate(inline_policies):
        if not isinstance(policy, Mapping):
            continue
        statements = _policy_statements_from_value(policy.get("policy"))
        if statements:
            documents.append((f"inlinePolicies[{index}].policy", statements))
    return documents


def _resource_policy_service(resource_type: str, field_name: str) -> str | None:
    """Retain self-resource and same-service scope, never global/negated grants.

    This compatibility rule is not principal/condition approval. Stronger exact
    resource-policy review is tracked separately; IAM document pins stay distinct.
    """
    if field_name not in {"policy", "policyDocument"}:
        return None
    for suffix, service in (
        (S3_BUCKET_POLICY_TYPE_SUFFIX, "s3"),
        (KMS_KEY_TYPE_SUFFIX, "kms"),
    ):
        if _matches_resource_type(resource_type, suffix):
            return service
    return None


_UNSCOPABLE_RESOURCE_WILDCARD_ACTIONS = frozenset(
    {
        "access-analyzer:validatepolicy",
        "billing:getbillingviewdata",
        "ce:createanomalymonitor",
        "ce:createanomalysubscription",
        "ce:listcostallocationtags",
        "ce:updatecostallocationtagsstatus",
        "cloudtrail:describetrails",
        "config:deletedeliverychannel",
        "config:describedeliverychannels",
        "config:putdeliverychannel",
        "guardduty:createdetector",
        "guardduty:listdetectors",
        "iam:createopenidconnectprovider",
        "iam:listopenidconnectproviders",
        "kms:createkey",
        "kms:listaliases",
        "sts:getcalleridentity",
    }
)
REQUEST_TAG_ENVIRONMENT_KEY = "aws:RequestTag/Environment"
REQUEST_TAG_PURPOSE_KEY = "aws:RequestTag/Purpose"
_RESOURCE_WILDCARD_ACTION_REQUIRED_CONDITION_KEYS = {
    "ce:createanomalymonitor": frozenset(
        {
            REQUEST_TAG_ENVIRONMENT_KEY,
            REQUEST_TAG_PURPOSE_KEY,
        }
    ),
    "ce:createanomalysubscription": frozenset(
        {
            REQUEST_TAG_ENVIRONMENT_KEY,
            REQUEST_TAG_PURPOSE_KEY,
        }
    ),
    "kms:createkey": frozenset(
        {
            REQUEST_TAG_ENVIRONMENT_KEY,
            REQUEST_TAG_PURPOSE_KEY,
        }
    ),
    "guardduty:createdetector": frozenset(
        {
            REQUEST_TAG_ENVIRONMENT_KEY,
            REQUEST_TAG_PURPOSE_KEY,
        }
    ),
}


def _policy_statements(props: Mapping[str, Any]) -> Sequence[Mapping[str, Any]]:
    """Extract policy statements from common Pulumi resource property shapes."""
    documents: list[Mapping[str, Any]] = []
    for field_name in ("policy", "policyDocument"):
        statements = _policy_statements_from_value(props.get(field_name))
        if statements:
            documents.extend(statements)
    return documents


def _policy_statements_from_value(value: object) -> Sequence[Mapping[str, Any]]:
    """Parse a policy document string or mapping and return statement objects."""
    document = _parse_json_document(value)
    if not isinstance(document, Mapping):
        return []

    statements = document.get("Statement")
    if isinstance(statements, Mapping):
        return [statements]
    if isinstance(statements, Sequence) and not isinstance(statements, (str, bytes)):
        return [statement for statement in statements if isinstance(statement, Mapping)]
    return []


def _parse_json_document(value: object) -> Mapping[str, Any] | None:
    """Parse a JSON document if one is present and valid."""
    if isinstance(value, Mapping):
        return cast(Mapping[str, Any], value)
    if not isinstance(value, str):
        return None
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, Mapping) else None


def _statement_allows_public_access(statement: Mapping[str, Any]) -> bool:
    """Detect allow statements that grant public access to everyone."""
    effect = _string_value(statement.get("Effect"))
    if effect != "Allow":
        return False
    if _has_public_access_narrowing_condition(statement.get("Condition")):
        return False

    principal = statement.get("Principal")
    if principal == "*":
        return True

    if isinstance(principal, Mapping):
        for value in principal.values():
            if value == "*":
                return True
            if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
                if "*" in value:
                    return True
    return False


def _has_public_access_narrowing_condition(condition: object) -> bool:
    """Treat well-known narrowing conditions as non-public access."""
    if not isinstance(condition, Mapping):
        return False

    for operator, value in condition.items():
        if not isinstance(operator, str) or not _is_positive_condition_operator(
            operator
        ):
            continue
        if not isinstance(value, Mapping):
            continue
        for key, nested_value in value.items():
            if key in PUBLIC_ACCESS_NARROWING_KEYS and _condition_values_are_concrete(
                nested_value
            ):
                return True
    return False


def _statement_contains_wildcard_permissions(
    statement: Mapping[str, Any], *, resource_policy_service: str | None = None
) -> bool:
    """Reject global/negated grants, with explicit resource-policy compatibility."""
    effect = _string_value(statement.get("Effect"))
    if effect != "Allow":
        return False

    if (
        _contains_action_wildcard(
            statement.get("Action"), allowed_service=resource_policy_service
        )
        or _contains_action_wildcard(statement.get("NotAction"))
        or _has_negated_policy_scope(statement.get("NotAction"))
        or _contains_resource_wildcard(statement.get("NotResource"))
        or _has_negated_policy_scope(statement.get("NotResource"))
    ):
        return True
    return (
        resource_policy_service is None
        and _contains_resource_wildcard(statement.get("Resource"))
        and not _resource_wildcard_allowed_for_unscopable_actions(statement)
    )


def _resource_wildcard_allowed_for_unscopable_actions(
    statement: Mapping[str, Any],
) -> bool:
    """Allow Resource='*' only for AWS actions that cannot be ARN-scoped."""
    actions = frozenset(_normalized_action_values(statement.get("Action")))
    if not actions or actions.difference(_UNSCOPABLE_RESOURCE_WILDCARD_ACTIONS):
        return False

    for action in actions:
        required_keys = _RESOURCE_WILDCARD_ACTION_REQUIRED_CONDITION_KEYS.get(action)
        if required_keys and not _condition_has_concrete_keys(
            statement.get("Condition"), required_keys
        ):
            return False
    return True


def _normalized_action_values(value: object) -> tuple[str, ...]:
    """Return normalized IAM action strings from scalar or list-shaped input."""
    if isinstance(value, str):
        return (value.lower(),)
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return tuple(item.lower() for item in value if isinstance(item, str))
    return ()


def _condition_has_concrete_keys(
    condition: object, required_keys: frozenset[str]
) -> bool:
    """Return True when a condition provides all required keys with real values."""
    if not isinstance(condition, Mapping):
        return False

    found: set[str] = set()
    for operator, condition_value in condition.items():
        # Required request-tag keys are single-valued. Set qualifiers can make
        # absent keys match, so only bare positive operators establish presence.
        if (
            not isinstance(operator, str)
            or operator not in POSITIVE_PUBLIC_ACCESS_OPERATORS
        ):
            continue
        if not isinstance(condition_value, Mapping):
            continue
        for key, value in condition_value.items():
            if key in required_keys and _condition_values_are_concrete(value):
                found.add(key)
    return required_keys <= found


def _contains_action_wildcard(
    value: object, *, allowed_service: str | None = None
) -> bool:
    """Reject global/service wildcards except the attached resource service."""
    if value == "*":
        return True
    if isinstance(value, str):
        return value.endswith(":*") and value.lower() != f"{allowed_service}:*"
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return any(
            item == "*"
            or (
                isinstance(item, str)
                and item.endswith(":*")
                and item.lower() != f"{allowed_service}:*"
            )
            for item in value
        )
    return False


def _contains_resource_wildcard(value: object) -> bool:
    """Detect only full-resource wildcards, not common ARN suffix patterns."""
    if value == "*":
        return True
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return any(item == "*" for item in value)
    return False


def _has_negated_policy_scope(value: object) -> bool:
    """Treat non-empty NotAction and NotResource clauses as inherently broad."""
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return any(isinstance(item, str) and item.strip() for item in value)
    return False


def _is_open_to_world(props: Mapping[str, Any]) -> bool:
    """Return whether a rule exposes traffic to all IPv4 or IPv6 addresses."""
    return any(
        _contains_open_cidr(props.get(key))
        for key in ("cidrBlocks", "ipv6CidrBlocks", "cidrIpv4", "cidrIpv6")
    )


def _matches_resource_type(resource_type: str, suffix: str) -> bool:
    """Allow equivalent package prefixes while keeping the module/type contract."""
    if suffix.startswith("pulumi:providers:"):
        return resource_type == suffix or resource_type.startswith(f"{suffix}:")
    return resource_type.endswith(suffix)


def _matches_any_resource_type(resource_type: str, suffixes: Sequence[str]) -> bool:
    """Check multiple equivalent provider suffixes without hardcoding package names."""
    return any(_matches_resource_type(resource_type, suffix) for suffix in suffixes)


def _contains_open_cidr(value: Any) -> bool:
    """Handle both provider scalar and list representations for CIDR blocks."""
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return any(_is_open_cidr(cidr) for cidr in value)
    return isinstance(value, str) and _is_open_cidr(value)


def _is_positive_condition_operator(operator: str) -> bool:
    """Accept only operators that narrow access rather than invert it."""
    return operator.split(":")[-1] in POSITIVE_PUBLIC_ACCESS_OPERATORS


def _condition_values_are_concrete(value: object) -> bool:
    """Require non-empty concrete values for public-access narrowing conditions."""
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return bool(value) and all(_condition_value_is_concrete(item) for item in value)
    return _condition_value_is_concrete(value)


def _condition_value_is_concrete(value: object) -> bool:
    """Reject wildcard, blank, and globally open condition values."""
    if not isinstance(value, str):
        return False

    stripped = value.strip()
    if not stripped or "*" in stripped or "?" in stripped:
        return False

    return not _is_open_cidr(stripped)


def _is_open_cidr(value: str) -> bool:
    """Treat explicit and syntactically equivalent /0 CIDRs as non-narrowing."""
    if value in OPEN_CIDRS:
        return True

    try:
        network = ip_network(value, strict=False)
    except ValueError:
        return False
    return network.prefixlen == 0


def _ports_in_range(props: Mapping[str, Any]) -> set[int]:
    """Return tracked sensitive ports within the rule's from/to range."""
    protocol = props.get("ipProtocol", props.get("protocol"))
    if isinstance(protocol, str):
        protocol = protocol.lower()
    if protocol in (-1, "-1", "all"):
        return set(SENSITIVE_PORTS)
    if protocol not in {"tcp", "udp", "6", "17", 6, 17}:
        return set()

    from_port = props.get("fromPort")
    to_port = props.get("toPort")
    if not isinstance(from_port, int) or not isinstance(to_port, int):
        return set()
    return {port for port in SENSITIVE_PORTS if from_port <= port <= to_port}


def _truthy(value: object) -> bool:
    """Normalize the common Pulumi representations of true-ish values."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return False


def _string_value(value: object) -> str | None:
    """Return a stripped string or None when no stable value is available."""
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped or None
