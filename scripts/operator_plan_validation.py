"""Pure validation of complete Pulumi 3.223.0 / AWS 7.23.0 operator plans.

Inputs are private JSON bytes, never logged. The caller authenticates their
provenance, obtains a coherent checkpoint, verifies active seed enrollment and
repeats validation before replay. Hashes returned here establish no authority.
Preview collection must show unchanged resources and replacement steps. Default
provider goals are checked directly because the CLI hides their internal events. A
refresh is accepted only when it leaves the supplied checkpoint unchanged.

Syntax follows the pinned Pulumi apitype/plan.go and pkg/display/json.go.
Physical targets come exclusively from the hash-pinned seed catalog.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
import re
from collections import Counter
from dataclasses import dataclass
from typing import Any, Mapping, cast

from seed.policy_registry import CATALOG_HASHES, document_hash

MAX_DOCUMENT_BYTES = 32 * 1024 * 1024
PROJECT = "github-ci-bootstrap"
ROLE = "aws:iam/role:Role"
POLICY = "aws:iam/policy:Policy"
INLINE = "aws:iam/rolePolicy:RolePolicy"
ATTACHMENT = "aws:iam/rolePolicyAttachment:RolePolicyAttachment"
EXCLUSIVE = "aws:iam/rolePolicyAttachmentsExclusive:RolePolicyAttachmentsExclusive"
# Public Pulumi resource type, not credential material.
SECRET = "aws:secretsmanager/secret:Secret"  # nosec B105
VERSION = "aws:secretsmanager/secretVersion:SecretVersion"
OIDC = "aws:iam/openIdConnectProvider:OpenIdConnectProvider"
PROVIDER = "pulumi:providers:aws"
STACK = "pulumi:pulumi:Stack"
SIGNATURE = "4dabf18193072939515e22adb298388d"
# Public Pulumi wire-format tag, not credential material.
WIRE_VALUE_TAG = "1b47061264138c4ac30d75fd1eb44270"
UNKNOWN = "04da6b54-80e4-46f7-96ec-b56ff0331ba9"
REPLACEMENTS = {
    ("create-replacement", "replace", "delete-replaced"),
    ("delete-replaced", "replace", "create-replacement"),
}
_STATE_FIELDS: set[str] = set(
    "urn type custom id inputs outputs parent protect external provider dependencies "
    "propertyDependencies additionalSecretOutputs aliases customTimeouts importID "
    "created modified sourcePosition stackTrace ignoreChanges hideDiff "
    "replaceOnChanges "
    "replacementTrigger refreshBeforeUpdate resourceHooks delete taint "
    "pendingReplacement "
    "initErrors retainOnDelete deletedWith replaceWith viewOf".split()
)
_GOAL_FIELDS: set[str] = set(
    "type name custom inputDiff outputDiff parent protect dependencies provider "
    "propertyDependencies deleteBeforeReplace ignoreChanges additionalSecretOutputs "
    "aliases structuredAliases id customTimeouts".split()
)


@dataclass(frozen=True)
class OperatorPlanValidation:
    """Metadata-only result; neither a credential nor an apply authorization."""

    plan_sha256: str
    preview_sha256: str
    checkpoint_sha256: str
    catalog_sha256: str
    changed_urns: tuple[str, ...]


def _require(condition: Any, category: str) -> None:
    if not condition:
        raise ValueError(category)


def _object(value: Any, required: set[str], allowed: set[str]) -> dict[str, Any]:
    _require(isinstance(value, dict), "object-required")
    _require(required <= value.keys() <= allowed, "object-fields")
    return value


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        _require(key not in result, "duplicate-json-key")
        result[key] = value
    return result


def _constant(_: str) -> None:
    raise ValueError("nonfinite-json")


def _number(value: str) -> float:
    number = float(value)
    _require(math.isfinite(number), "nonfinite-json")
    return number


def _decode(payload: bytes) -> dict[str, Any]:
    _require(
        type(payload) is bytes and 0 < len(payload) <= MAX_DOCUMENT_BYTES,
        "document-size",
    )
    try:
        result = json.loads(
            payload,
            object_pairs_hook=_pairs,
            parse_constant=_constant,
            parse_float=_number,
        )
    except (ValueError, RecursionError):
        raise ValueError("invalid-json-document") from None
    _require(isinstance(result, dict), "document-object")
    return result


def _strings(value: Any) -> list[str]:
    _require(isinstance(value, list), "string-list")
    _require(all(isinstance(item, str) and item for item in value), "string-list")
    _require(len(value) == len(set(value)), "duplicate-list-item")
    return value


def _text(value: Any) -> str:
    _require(
        isinstance(value, str) and bool(value) and value not in {UNKNOWN, "[secret]"},
        "concrete-identity",
    )
    return value


def _project(value: Any) -> Any:
    """Match the CLI's secret-redacted projection without returning secret values."""
    if isinstance(value, dict):
        if SIGNATURE in value:
            _require(
                value[SIGNATURE] == WIRE_VALUE_TAG, "unsupported-property-signature"
            )
            _require(
                set(value) in ({SIGNATURE, "ciphertext"}, {SIGNATURE, "plaintext"}),
                "secret-shape",
            )
            _require(
                all(
                    isinstance(item, str) and bool(item)
                    for key, item in value.items()
                    if key != SIGNATURE
                ),
                "secret-value-shape",
            )
            return "[secret]"
        return {key: _project(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_project(item) for item in value]
    _require(value != UNKNOWN, "unknown-input")
    return value


def _manifest(value: Any) -> None:
    row = _object(
        value, {"version", "time", "magic"}, {"version", "time", "magic", "plugins"}
    )
    _require(row["version"] == "v3.223.0", "pulumi-version")
    _text(row["time"])
    _require(row["magic"] == hashlib.sha256(b"v3.223.0").hexdigest(), "manifest-magic")
    _require(isinstance(row.get("plugins", []), list), "manifest-plugins")


def _urn(value: Any, catalog: Mapping[str, Any]) -> str:
    urn = _text(value)
    parts = urn.split("::")
    _require(
        len(parts) == 4
        and parts[:2] == [f"urn:pulumi:{catalog['environment']}", PROJECT],
        "foreign-urn",
    )
    _require(bool(parts[2]) and bool(parts[3]), "invalid-urn")
    return urn


def _state(
    value: Any,
    catalog: Mapping[str, Any],
    *,
    redacted_preview: bool = False,
    require_tags_all_output: bool = True,
) -> dict[str, Any]:
    row = _object(value, {"urn", "type", "custom"}, _STATE_FIELDS)
    urn = _urn(row["urn"], catalog)
    _require(urn.split("::")[2].split("$")[-1] == row["type"], "urn-type")
    for key in (
        "custom",
        "protect",
        "external",
        "delete",
        "taint",
        "pendingReplacement",
        "retainOnDelete",
        "refreshBeforeUpdate",
    ):
        _require(type(row.get(key, False)) is bool, "state-boolean")
    for key in (
        "delete",
        "taint",
        "pendingReplacement",
        "retainOnDelete",
        "refreshBeforeUpdate",
        "deletedWith",
        "replaceWith",
        "viewOf",
        "resourceHooks",
        "initErrors",
        "aliases",
        "hideDiff",
        "replacementTrigger",
    ):
        _require(not row.get(key), "unsupported-state-option")
    for key in ("inputs", "outputs", "propertyDependencies", "customTimeouts"):
        _require(isinstance(row.get(key, {}), dict), "state-map")
    for key in ("parent", "provider", "id", "importID"):
        _require(isinstance(row.get(key, ""), str), "state-string")
    for key in (
        "dependencies",
        "ignoreChanges",
        "additionalSecretOutputs",
        "replaceOnChanges",
    ):
        _strings(row.get(key, []))
    _project(row.get("inputs", {}))
    _input_shape(row, redacted_preview=redacted_preview)
    _computed_tags_all(row, require_output=require_tags_all_output)
    return row


_INPUT_FIELDS = {
    ROLE: set(
        "assumeRolePolicy description forceDetachPolicies inlinePolicies "
        "managedPolicyArns maxSessionDuration name namePrefix path "
        "permissionsBoundary tags tagsAll".split()
    ),
    POLICY: set(
        "delayAfterPolicyCreationInMs description name namePrefix path "
        "policy tags tagsAll".split()
    ),
    INLINE: {"name", "namePrefix", "role", "policy"},
    ATTACHMENT: {"role", "policyArn"},
    EXCLUSIVE: {"roleName", "policyArns"},
    SECRET: set(
        "description forceOverwriteReplicaSecret kmsKeyId name namePrefix "
        "policy recoveryWindowInDays region replicas tags tagsAll".split()
    ),
    VERSION: {"region", "secretBinary", "secretId", "secretString", "versionStages"},
    OIDC: {"url", "clientIdLists", "thumbprintLists", "tags", "tagsAll"},
}


def _input_fields(row: dict[str, Any]) -> None:
    kind, inputs = row["type"], row.get("inputs", {})
    if kind in _INPUT_FIELDS:
        _require(
            inputs.keys() <= _INPUT_FIELDS[kind] | {"__defaults"},
            "unsupported-provider-input",
        )
    for key in {"forceDetachPolicies", "forceOverwriteReplicaSecret"} & inputs.keys():
        _require(type(inputs[key]) is bool, "input-boolean")
    for key in {
        "maxSessionDuration",
        "delayAfterPolicyCreationInMs",
        "recoveryWindowInDays",
    } & inputs.keys():
        _require(type(inputs[key]) is int and inputs[key] >= 0, "input-integer")
    _require(not inputs.get("namePrefix"), "autonamed-target")
    if kind == VERSION and not row.get("external", False):
        _require(
            len({"secretString", "secretBinary"} & inputs.keys()) == 1,
            "secret-value-required",
        )
    if "replicas" in inputs:
        _require(isinstance(inputs["replicas"], list), "secret-replicas")
        for replica in inputs["replicas"]:
            _object(replica, {"region"}, {"region", "kmsKeyId"})
            _require(
                all(isinstance(value, str) for value in replica.values()),
                "secret-replica-fields",
            )


def _input_shape(row: dict[str, Any], *, redacted_preview: bool = False) -> None:
    kind, inputs = row["type"], row.get("inputs", {})
    _input_fields(row)
    string_keys = {
        ROLE: {
            "name",
            "path",
            "namePrefix",
            "permissionsBoundary",
            "description",
            "assumeRolePolicy",
        },
        POLICY: {"name", "path", "namePrefix", "description", "policy"},
        INLINE: {"name", "namePrefix", "role", "policy"},
        ATTACHMENT: {"role", "policyArn"},
        EXCLUSIVE: {"roleName"},
        SECRET: {"name", "namePrefix", "description", "region", "kmsKeyId", "policy"},
        VERSION: {"secretId", "region"},
        OIDC: {"url"},
    }.get(kind, set())
    for key in string_keys & inputs.keys():
        _require(
            isinstance(inputs[key], str) and inputs[key] != UNKNOWN, "input-string"
        )
    for key in {"tags"} & inputs.keys():
        _require(
            isinstance(inputs[key], dict)
            and all(isinstance(value, str) for value in inputs[key].values()),
            "tags-shape",
        )
    _tags_all_shape(inputs)
    for key in {
        "versionStages",
        "managedPolicyArns",
        "policyArns",
        "__defaults",
        "clientIdLists",
        "thumbprintLists",
    } & inputs.keys():
        _strings(inputs[key])
    _secret_inputs(inputs, redacted_preview=redacted_preview)


def _tags_all_shape(inputs: dict[str, Any]) -> None:
    if "tagsAll" not in inputs:
        return
    tags_all = inputs["tagsAll"]
    _require(
        isinstance(tags_all, dict)
        and all(
            isinstance(key, str)
            and isinstance(value, str)
            and value not in {UNKNOWN, "[secret]"}
            for key, value in tags_all.items()
        ),
        "tags-all-shape",
    )
    _require(inputs.get("tags") == tags_all, "tags-all-inputs")


def _computed_tags_all(row: dict[str, Any], *, require_output: bool) -> None:
    """Bind checkpoint aliases to outputs without trusting preview output freshness."""
    inputs = row.get("inputs", {})
    if "tagsAll" not in inputs:
        return
    tags_all = inputs["tagsAll"]
    if require_output:
        _require(row.get("outputs", {}).get("tagsAll") == tags_all, "tags-all-output")


def _secret_inputs(inputs: dict[str, Any], *, redacted_preview: bool) -> None:
    """Distinguish secret-bearing saved inputs from the CLI preview projection."""
    for key in {"secretString", "secretBinary"} & inputs.keys():
        # The CLI preview has a public redacted projection. Only that surface
        # may use its exact placeholder; checkpoint and saved-plan inputs must
        # retain Pulumi's secret wrapper.
        if redacted_preview and inputs[key] == "[secret]":
            continue
        _require(
            isinstance(inputs[key], dict)
            and inputs[key].get(SIGNATURE) == WIRE_VALUE_TAG,
            "secret-input-shape",
        )
        _require(isinstance(_project(inputs[key]), str), "secret-input-shape")


def _ownership(row: dict[str, Any]) -> tuple[Any, ...]:
    return tuple(
        row.get(key, default)
        for key, default in (
            ("type", ""),
            ("custom", False),
            ("parent", ""),
            ("provider", ""),
            ("protect", False),
            ("external", False),
        )
    )


def _diff(value: Any, old: dict[str, Any]) -> dict[str, Any]:
    row = _object(value, set(), {"adds", "updates", "deletes"})
    adds = row.get("adds", {})
    updates = row.get("updates", {})
    _require(isinstance(adds, dict) and isinstance(updates, dict), "diff-map")
    deletes = set(_strings(row.get("deletes", [])))
    _require(
        not (adds.keys() & old.keys())
        and updates.keys() <= old.keys()
        and deletes <= old.keys(),
        "diff-origin",
    )
    _require(
        not (
            adds.keys() & updates.keys()
            or adds.keys() & deletes
            or updates.keys() & deletes
        ),
        "diff-overlap",
    )
    return {
        **{key: value for key, value in old.items() if key not in deletes},
        **adds,
        **updates,
    }


def _iam_target(row: dict[str, Any], catalog: Mapping[str, Any]) -> str:
    kind, inputs = row["type"], row.get("inputs", {})
    prefix = f"arn:aws:iam::{catalog['account_id']}:"
    if row.get("external", False):
        identifier = _text(row.get("id"))
        arn = prefix + "role/" + identifier if kind == ROLE else identifier
    else:
        name = _text(inputs.get("name"))
        path = inputs.get("path", "/")
        _require(
            isinstance(path, str) and path.startswith("/") and path.endswith("/"),
            "iam-path",
        )
        arn = f"{prefix}{'role' if kind == ROLE else 'policy'}{path}{name}"
    _require(
        arn
        in catalog["operator_bindings"]["role_read" if kind == ROLE else "policy_read"],
        "foreign-iam-target",
    )
    return arn


def _secret_target(row: dict[str, Any], catalog: Mapping[str, Any]) -> str:
    kind, inputs = row["type"], row.get("inputs", {})
    bindings = catalog["operator_bindings"]
    identifier = _text(row.get("id") if kind == SECRET else inputs.get("secretId"))
    arn = (
        identifier
        if kind == SECRET
        else _secret_version_target(identifier, bindings["secrets"])
    )
    _require(
        isinstance(arn, str) and arn in bindings["secrets"], "foreign-secret-target"
    )
    _require(
        inputs.get("region", catalog["region"]) == catalog["region"],
        "secret-region",
    )
    if kind == SECRET and not row.get("external", False):
        _require(
            inputs.get("name") == _secret_name(arn),
            "secret-name-identity",
        )
    return arn


def _exclusive_target(row: dict[str, Any], catalog: Mapping[str, Any]) -> str:
    """Accept only the recorded non-guard or full guard-retaining inventory."""
    inputs = row.get("inputs", {})
    role_name = _text(inputs.get("roleName"))
    policy_arns = _strings(inputs.get("policyArns"))
    role_arn = f"arn:aws:iam::{catalog['account_id']}:role/{role_name}"
    principals = [
        principal for principal in catalog["principals"] if principal["arn"] == role_arn
    ]
    _require(
        role_name
        == f"PulumiAutomation-bootstrap-infrastructure-{catalog['environment']}"
        and role_arn in catalog["operator_bindings"]["role_write"]
        and len(principals) == 1,
        "foreign-exclusive-role",
    )
    principal = principals[0]
    expected = set(principal["attachment_arns"]) - set(principal["guard_arns"])
    full_inventory = set(principal["attachment_arns"])
    _require(
        frozenset(policy_arns) in {frozenset(expected), frozenset(full_inventory)}
        and (set(policy_arns) - set(principal["guard_arns"]))
        <= set(catalog["operator_bindings"]["policy_write"]),
        "exclusive-policy-inventory",
    )
    _require(
        row["urn"].split("::")[-1]
        == "github-automation-managed-policy-attachments-exclusive",
        "exclusive-resource-name",
    )
    _require(
        row["custom"] is True
        and row.get("protect") is True
        and row.get("external", False) is False,
        "exclusive-ownership",
    )
    return role_arn


def _secret_version_target(identifier: str, secrets: list[str]) -> str:
    if identifier in secrets:
        return identifier
    matches = [arn for arn in secrets if _secret_name(arn) == identifier]
    _require(len(matches) == 1, "foreign-secret-target")
    return matches[0]


def _secret_name(arn: str) -> str:
    name, separator, suffix = arn.partition(":secret:")[2].rpartition("-")
    _require(
        bool(name)
        and separator == "-"
        and re.fullmatch(r"[A-Za-z0-9]{6}", suffix) is not None,
        "foreign-secret-target",
    )
    return name


def _target(row: dict[str, Any], catalog: Mapping[str, Any]) -> tuple[str, ...]:
    """Resolve exact physical targets, including attachment and inline role pairs."""
    kind, inputs = row["type"], row.get("inputs", {})
    bindings = catalog["operator_bindings"]
    prefix = f"arn:aws:iam::{catalog['account_id']}:"
    if kind in {ROLE, POLICY}:
        return (_iam_target(row, catalog),)
    if kind in {INLINE, ATTACHMENT}:
        role = prefix + "role/" + _text(inputs.get("role"))
        _require(role in bindings["role_read"], "foreign-role-target")
        other = _text(inputs.get("policyArn" if kind == ATTACHMENT else "name"))
        if kind == ATTACHMENT:
            _require(other in bindings["policy_read"], "foreign-policy-target")
        return role, other
    if kind == EXCLUSIVE:
        return (_exclusive_target(row, catalog),)
    if kind in {SECRET, VERSION}:
        return (_secret_target(row, catalog),)
    if kind == OIDC:
        _require(row.get("id") == bindings["oidc"], "foreign-oidc-target")
        return (bindings["oidc"],)
    _require(kind == PROVIDER or row["custom"] is False, "unsupported-resource-type")
    return (row["urn"],)


def _physical_id(row: dict[str, Any], target: tuple[str, ...]) -> None:
    kind, identifier = row["type"], _text(row.get("id"))
    if kind in {ROLE, POLICY, SECRET, VERSION, OIDC}:
        _require(row.get("outputs", {}).get("arn") == target[0], "checkpoint-arn")
    if kind == ROLE:
        _require(identifier == target[0].rsplit("/", 1)[1], "role-id")
    elif kind in {POLICY, SECRET, OIDC}:
        _require(identifier == target[0], "resource-id")
    elif kind == INLINE:
        _require(
            identifier == f"{target[0].rsplit('/', 1)[1]}:{target[1]}", "inline-id"
        )
    elif kind == VERSION:
        selector = _text(row.get("inputs", {}).get("secretId"))
        _require(
            identifier.count("|") == 1
            and identifier.split("|", 1)[0] == selector
            and bool(identifier.rsplit("|", 1)[1]),
            "version-id",
        )
        _require(
            row.get("outputs", {}).get("secretId") == selector,
            "version-secret-id",
        )
    elif kind == EXCLUSIVE:
        _require(identifier == row["inputs"].get("roleName"), "exclusive-id")
        _require(
            row.get("outputs", {}).get("roleName") == row["inputs"].get("roleName")
            and set(_strings(row.get("outputs", {}).get("policyArns")))
            == set(row["inputs"]["policyArns"]),
            "exclusive-output-binding",
        )


_PROVIDER_VALIDATION_FLAGS = (
    "skipCredentialsValidation",
    "skipRegionValidation",
    "skipRequestingAccountId",
)


def _provider_inputs(inputs: dict[str, Any], catalog: Mapping[str, Any]) -> None:
    _require(
        inputs.keys()
        <= {
            "version",
            "region",
            "allowedAccountIds",
            "defaultTags",
            "skipMetadataApiCheck",
            "skipCredentialsValidation",
            "skipRegionValidation",
            "skipRequestingAccountId",
            "maxRetries",
            "__defaults",
        },
        "provider-credential-or-endpoint-option",
    )
    for key in _PROVIDER_VALIDATION_FLAGS:
        value = inputs.get(key)
        _require(value is False or value == "false", "provider-validation-disabled")
    _require(
        inputs.get("version") == "7.23.0" and inputs.get("region") == catalog["region"],
        "aws-provider-version-region",
    )
    _require(
        inputs.get("allowedAccountIds")
        in ([catalog["account_id"]], json.dumps([catalog["account_id"]])),
        "aws-provider-account",
    )


def _legacy_provider_inputs(inputs: dict[str, Any], catalog: Mapping[str, Any]) -> bool:
    """Recognize only the complete recorded provider shape before hardening."""
    return inputs == {
        "__internal": {},
        "region": catalog["region"],
        "skipCredentialsValidation": "false",
        "skipRegionValidation": "true",
        "version": "7.23.0",
    }


def _provider_state_inputs(
    row: dict[str, Any], catalog: Mapping[str, Any], *, allow_legacy: bool = False
) -> None:
    inputs = row.get("inputs", {})
    if allow_legacy and _legacy_provider_inputs(inputs, catalog):
        _require(row["urn"].split("::")[-1] == "default_7_23_0", "legacy-provider-name")
        return
    if "__internal" in inputs:
        _require(inputs["__internal"] == {}, "provider-internal-metadata")
    _provider_inputs(
        {key: value for key, value in inputs.items() if key != "__internal"}, catalog
    )


def _provider_hardening(
    prior: dict[str, Any] | None,
    desired: dict[str, Any] | None,
    ops: tuple[str, ...],
    catalog: Mapping[str, Any],
) -> None:
    if prior is None or desired is None:
        raise ValueError("provider-hardening-inventory")
    _require(
        ops == ("update",)
        and prior["urn"] == desired["urn"]
        and prior["urn"].split("::")[-1] == "default_7_23_0"
        and prior.get("id") == desired.get("id"),
        "provider-hardening-identity",
    )
    _require(
        _legacy_provider_inputs(prior.get("inputs", {}), catalog),
        "provider-hardening-origin",
    )
    _provider_state_inputs(desired, catalog)
    _require(
        desired["inputs"].keys()
        <= {
            "version",
            "region",
            "__internal",
            "allowedAccountIds",
            *_PROVIDER_VALIDATION_FLAGS,
        },
        "provider-hardening-inputs",
    )


def validate_operator_configuration(
    value: Any, *, account_id: str, region: str
) -> None:
    """Reject CLI/provider credential sources and redirects before PR execution.

    Pulumi 3.223 serializes plan config with the same value shapes as stack YAML.
    Accept its legacy namespace:config:key spelling, but reject aliases that
    collide. Project settings remain program data; only closed AWS settings may
    influence the CLI's default provider. The caller authenticates account/region.
    """
    _require(type(value) is dict, "operator-config")
    inputs: dict[str, Any] = {
        "version": "7.23.0",
        "region": region,
        "allowedAccountIds": [account_id],
        **dict.fromkeys(_PROVIDER_VALIDATION_FLAGS, False),
    }
    seen = set()
    for key, item in value.items():
        match = (
            re.fullmatch(r"(aws|github-ci-bootstrap):(?:config:)?([^:\s]+)", key)
            if type(key) is str
            else None
        )
        _require(match is not None, "operator-config-key")
        namespace, name = cast(re.Match[str], match).groups()
        identity = (namespace, name)
        _require(identity not in seen, "duplicate-operator-config-key")
        seen.add(identity)
        if namespace == "aws":
            _require(name not in {"version", "__defaults"}, "operator-config-key")
            inputs[name] = item
    _provider_inputs(inputs, {"account_id": account_id, "region": region})


def harden_operator_configuration(
    value: Any, *, account_id: str, region: str
) -> dict[str, Any]:
    """Validate requested settings, then materialize actual provider safety pins."""
    validate_operator_configuration(value, account_id=account_id, region=region)
    pinned = {
        "region": region,
        "allowedAccountIds": [account_id],
        **dict.fromkeys(_PROVIDER_VALIDATION_FLAGS, False),
    }
    result = {
        key: item
        for key, item in value.items()
        if not (key.startswith("aws:") and key.rsplit(":", 1)[-1] in pinned)
    }
    result.update({"aws:" + key: item for key, item in pinned.items()})
    return result


def _parent(
    row: dict[str, Any], resources: dict[str, Any], catalog: Mapping[str, Any]
) -> None:
    parent = row.get("parent", "")
    _require(not parent or parent in resources, "missing-parent")
    qualified = row["type"]
    if parent and resources[parent]["type"] != STACK:
        qualified = parent.split("::")[2] + "$" + qualified
    _require(row["urn"].split("::")[2] == qualified, "parent-qualified-type")
    if row["type"] == STACK:
        _require(
            not parent
            and row["urn"].split("::")[3] == f"{PROJECT}-{catalog['environment']}",
            "root-stack-identity",
        )


def _references(
    row: dict[str, Any],
    resources: dict[str, Any],
    catalog: Mapping[str, Any],
    *,
    allow_legacy_provider: bool = False,
) -> None:
    _parent(row, resources, catalog)
    if row["custom"] and row["type"] != PROVIDER:
        reference = _text(row.get("provider"))
        provider_urn, _, provider_id = reference.rpartition("::")
        provider = resources.get(provider_urn, {})
        _require(
            provider.get("type") == PROVIDER and provider.get("id") == provider_id,
            "provider-owner",
        )
    dependencies = list(_strings(row.get("dependencies", [])))
    for values in row.get("propertyDependencies", {}).values():
        dependencies += _strings(values)
    _require(all(value in resources for value in dependencies), "foreign-dependency")
    if row["type"] == PROVIDER:
        _provider_state_inputs(row, catalog, allow_legacy=allow_legacy_provider)


def _physical_owner(
    row: dict[str, Any],
    target: tuple[str, ...],
    identities: dict[tuple[Any, ...], tuple[bool, tuple[str, ...]]],
    catalog: Mapping[str, Any],
) -> None:
    identity: tuple[Any, ...] = (row["type"], row["id"])
    if row["type"] == VERSION:
        identity = (row["type"], target[0], row["id"].rsplit("|", 1)[1])
    external = row.get("external", False)
    only_references, previous_target = identities.get(identity, (True, target))
    existing_role_reference = (
        row["type"] == ROLE
        and target[0] in catalog["operator_bindings"]["role_write"]
        and (external or only_references)
    )
    _require(previous_target == target, "physical-alias-target")
    _require(
        identity not in identities
        or (external and only_references)
        or existing_role_reference,
        "duplicate-physical-owner",
    )
    identities[identity] = (external and only_references, target)


def _checkpoint(
    payload: bytes, catalog: Mapping[str, Any]
) -> dict[str, dict[str, Any]]:
    document = _object(
        _decode(payload), {"version", "deployment"}, {"version", "deployment"}
    )
    _require(
        type(document["version"]) is int and document["version"] == 3,
        "checkpoint-version",
    )
    deployment = _object(
        document["deployment"],
        {"manifest", "resources", "secrets_providers"},
        {
            "manifest",
            "resources",
            "secrets_providers",
            "pending_operations",
            "metadata",
        },
    )
    _manifest(deployment["manifest"])
    secret_provider = _object(
        deployment["secrets_providers"], {"type", "state"}, {"type", "state"}
    )
    _require(
        secret_provider["type"] == "cloud"
        and isinstance(secret_provider["state"], dict),
        "checkpoint-secrets-provider",
    )
    _object(deployment.get("metadata", {}), set(), {"integrity_error"})
    _require(
        isinstance(deployment.get("pending_operations", []), list),
        "checkpoint-pending-shape",
    )
    _require(
        not deployment.get("pending_operations")
        and not deployment.get("metadata", {}).get("integrity_error"),
        "checkpoint-pending-or-corrupt",
    )
    _require(
        isinstance(deployment["resources"], list) and bool(deployment["resources"]),
        "checkpoint-resources",
    )
    resources: dict[str, dict[str, Any]] = {}
    identities: dict[tuple[Any, ...], tuple[bool, tuple[str, ...]]] = {}
    for value in deployment["resources"]:
        row = _state(value, catalog)
        urn = row["urn"]
        _require(urn not in resources, "duplicate-checkpoint-urn")
        target = _target(row, catalog)
        if row["custom"]:
            _physical_id(row, target)
            _physical_owner(row, target, identities, catalog)
        resources[urn] = row
    _require(
        sum(row["type"] == STACK for row in resources.values()) == 1, "stack-owner"
    )
    for row in resources.values():
        _references(row, resources, catalog, allow_legacy_provider=True)
    return resources


def _mutable(kind: str, target: tuple[str, ...], catalog: Mapping[str, Any]) -> bool:
    bindings = catalog["operator_bindings"]
    if kind in {ROLE, INLINE}:
        return target[0] in bindings["role_write"]
    if kind == POLICY:
        return target[0] in bindings["policy_write"]
    if kind == ATTACHMENT:
        return (
            target[0] in bindings["role_write"]
            and target[1] in bindings["policy_write"]
        )
    return kind in {SECRET, VERSION}


def _frozen_config(row: dict[str, Any], catalog: Mapping[str, Any]) -> None:
    target = _target(row, catalog)[0]
    principal = next(item for item in catalog["principals"] if item["arn"] == target)
    frozen = principal["frozen_config"]
    if frozen is None:
        return
    inputs = row.get("inputs", {})
    if row["type"] == ROLE:
        _require(
            json.loads(inputs["assumeRolePolicy"]) == frozen["trust"],
            "frozen-config-trust",
        )
        for item in inputs.get("inlinePolicies", []):
            _require(
                json.loads(item["policy"])
                == frozen["inline_policies"].get(item["name"]),
                "frozen-config-inline",
            )
    else:
        _require(
            json.loads(inputs["policy"])
            == frozen["inline_policies"].get(inputs["name"]),
            "frozen-config-inline",
        )


def _role_guards(row: dict[str, Any], catalog: Mapping[str, Any]) -> None:
    target = _target(row, catalog)[0]
    principal = next(item for item in catalog["principals"] if item["arn"] == target)
    inputs = row.get("inputs", {})
    _require(
        inputs.get("permissionsBoundary") == principal["boundary_arn"], "role-boundary"
    )
    if "managedPolicyArns" in inputs:
        arns = _strings(inputs["managedPolicyArns"])
        _require(set(principal["guard_arns"]) <= set(arns), "role-guard-removal")
        _require(
            set(arns)
            <= set(principal["attachment_arns"])
            | set(catalog["operator_bindings"]["policy_write"]),
            "role-attachment-ceiling",
        )


def _lifecycle(
    kind: str,
    prior: dict[str, Any] | None,
    desired: dict[str, Any] | None,
    ops: tuple[str, ...],
) -> None:
    allowed: set[tuple[str, ...]] = {("update",)}
    if kind in {INLINE, ATTACHMENT, VERSION, POLICY}:
        allowed |= {("create",), ("delete",)}
    if kind in {INLINE, ATTACHMENT, VERSION}:
        allowed |= REPLACEMENTS
    _require(ops in allowed, "forbidden-lifecycle")
    if ops == ("delete",) or ops in REPLACEMENTS:
        _require(
            prior is not None and prior.get("protect", False) is False,
            "protected-resource-deletion",
        )
    _require(
        (prior is None) == (ops == ("create",))
        and (desired is None) == (ops == ("delete",)),
        "lifecycle-inventory",
    )


def _changed_inputs(prior: dict[str, Any], desired: dict[str, Any]) -> None:
    # Pinned provider field semantics: no secret policy/KMS/replication writes,
    # principal replacement, boundary rebinding, or hidden provider controls.
    allowed = {
        ROLE: {
            "assumeRolePolicy",
            "description",
            "inlinePolicies",
            "managedPolicyArns",
            "maxSessionDuration",
            "tags",
        },
        POLICY: {"policy", "tags"},
        INLINE: {"policy", "name"},
        ATTACHMENT: {"role", "policyArn"},
        SECRET: {"description", "tags"},
        VERSION: {"secretString", "secretBinary", "versionStages"},
    }[desired["type"]]
    old, new = prior.get("inputs", {}), desired.get("inputs", {})
    changed = {key for key in old.keys() | new.keys() if old.get(key) != new.get(key)}
    if "tagsAll" in changed:
        changed.remove("tagsAll")
    _require(changed <= allowed, "unsupported-input-change")
    if desired["type"] == ROLE and "managedPolicyArns" in old:
        _require("managedPolicyArns" in new, "role-guard-management-removal")


def _policy_document(value: Any) -> None:
    _require(isinstance(value, str), "policy-document")
    policy = _decode(value.encode())
    statements = policy.get("Statement")
    _require(isinstance(statements, (list, dict)), "policy-statements")
    if isinstance(statements, list):
        _require(all(isinstance(item, dict) for item in statements), "policy-statement")


def _iam_documents(row: dict[str, Any]) -> None:
    inputs, kind = row.get("inputs", {}), row["type"]
    if kind in {POLICY, INLINE}:
        _policy_document(inputs.get("policy"))
    if kind == ROLE:
        _policy_document(inputs.get("assumeRolePolicy"))
        _require(inputs.get("forceDetachPolicies", False) is False, "role-force-detach")
        _require(isinstance(inputs.get("inlinePolicies", []), list), "inline-policies")
        names = []
        for value in inputs.get("inlinePolicies", []):
            item = _object(value, {"name", "policy"}, {"name", "policy"})
            names.append(_text(item["name"]))
            _policy_document(item["policy"])
        _strings(names)


def _preserve_ownership(
    prior: dict[str, Any] | None,
    desired: dict[str, Any] | None,
    target: tuple[str, ...],
    kind: str,
    catalog: Mapping[str, Any],
) -> None:
    if prior is not None and desired is not None:
        _require(_ownership(prior) == _ownership(desired), "ownership-change")
        _require(
            set(prior.get("additionalSecretOutputs", []))
            <= set(desired.get("additionalSecretOutputs", [])),
            "secret-output-declassification",
        )
        _require(
            _target(prior, catalog) == target
            or kind == ATTACHMENT
            or (kind == INLINE and _target(prior, catalog)[0] == target[0]),
            "physical-target-change",
        )


def _control_invariants(desired: dict[str, Any], catalog: Mapping[str, Any]) -> None:
    kind = desired["type"]
    if kind in {ROLE, POLICY, INLINE}:
        _iam_documents(desired)
    if kind in {ROLE, INLINE}:
        _frozen_config(desired, catalog)
    if kind == ROLE:
        _role_guards(desired, catalog)
    if kind == EXCLUSIVE:
        role_arn = _exclusive_target(desired, catalog)
        principal = next(
            item for item in catalog["principals"] if item["arn"] == role_arn
        )
        _require(
            set(desired["inputs"]["policyArns"]) == set(principal["attachment_arns"]),
            "exclusive-guard-retention",
        )
    if kind in {ROLE, POLICY, SECRET}:
        _require(desired.get("protect") is True, "unprotected-control-resource")


def _changed_operation(
    row: dict[str, Any],
    prior: dict[str, Any] | None,
    desired: dict[str, Any] | None,
    ops: tuple[str, ...],
    catalog: Mapping[str, Any],
) -> None:
    kind, target = row["type"], _target(row, catalog)
    if kind == PROVIDER:
        _provider_hardening(prior, desired, ops, catalog)
        return
    if kind == EXCLUSIVE:
        _exclusive_guard_transition(prior, desired, ops, catalog)
        return
    _require(_mutable(kind, target, catalog), "frozen-resource-change")
    if prior is not None:
        _require(
            _mutable(kind, _target(prior, catalog), catalog), "frozen-prior-change"
        )
    _lifecycle(kind, prior, desired, ops)
    if prior is not None and desired is not None:
        _changed_inputs(prior, desired)


def _exclusive_guard_transition(
    prior: dict[str, Any] | None,
    desired: dict[str, Any] | None,
    ops: tuple[str, ...],
    catalog: Mapping[str, Any],
) -> None:
    """Permit only migration from the recorded non-guard set to full inventory."""
    if prior is None or desired is None or ops != ("update",):
        raise ValueError("exclusive-transition")
    role_arn = _exclusive_target(prior, catalog)
    _require(_exclusive_target(desired, catalog) == role_arn, "exclusive-transition")
    principal = next(item for item in catalog["principals"] if item["arn"] == role_arn)
    _require(
        set(prior["inputs"]["policyArns"])
        == set(principal["attachment_arns"]) - set(principal["guard_arns"]),
        "exclusive-transition",
    )
    changed = {
        key
        for key in prior["inputs"].keys() | desired["inputs"].keys()
        if prior["inputs"].get(key) != desired["inputs"].get(key)
    }
    _require(changed == {"policyArns"}, "exclusive-transition")


def _property_semantics(
    value: dict[str, Any], kind: str, *, inputs: bool
) -> dict[str, Any]:
    """Compare only proved bridge metadata and the exclusive attachment set."""
    result = dict(value)
    if inputs and kind in {INLINE, ATTACHMENT, VERSION}:
        if result.get("__defaults") == []:
            del result["__defaults"]
    if kind == EXCLUSIVE and "policyArns" in result:
        # State/target validation separately requires the exact catalog inventory.
        result["policyArns"] = sorted(_strings(result["policyArns"]))
    return result


def _operation(
    prior: dict[str, Any] | None,
    desired: dict[str, Any] | None,
    ops: tuple[str, ...],
    catalog: Mapping[str, Any],
) -> None:
    row = desired if desired is not None else prior
    if row is None:
        raise ValueError("missing-operation-resource")
    target = _target(row, catalog)
    kind = row["type"]
    _preserve_ownership(prior, desired, target, kind, catalog)
    if ops == ("same",):
        _require(
            prior is not None
            and desired is not None
            and _property_semantics(prior.get("inputs", {}), kind, inputs=True)
            == _property_semantics(desired.get("inputs", {}), kind, inputs=True),
            "same-input-change",
        )
    else:
        _changed_operation(row, prior, desired, ops, catalog)
    if desired is not None:
        _control_invariants(desired, catalog)


def _goal_options(urn: str, row: dict[str, Any]) -> dict[str, Any]:
    goal = _object(row.get("goal"), {"type", "name", "custom", "protect"}, _GOAL_FIELDS)
    _require(goal["name"] == urn.split("::")[3], "goal-name")
    for key in ("aliases", "structuredAliases", "ignoreChanges", "id"):
        _require(not goal.get(key), "unsupported-goal-option")
    _require(
        type(goal.get("deleteBeforeReplace", False)) is bool, "goal-replacement-option"
    )
    return goal


def _seed(value: Any) -> None:
    try:
        _require(len(base64.b64decode(value, validate=True)) == 32, "plan-seed")
    except (ValueError, TypeError, binascii.Error):
        raise ValueError("plan-seed") from None


def _same_input_diff(value: Any, old_inputs: dict[str, Any], kind: str) -> Any:
    """Remove only the bridge's redundant empty-default add after validation."""
    if kind not in {INLINE, ATTACHMENT, VERSION} or old_inputs.get("__defaults") != []:
        return value
    row = _object(value, set(), {"adds", "updates", "deletes"})
    adds = row.get("adds", {})
    if not isinstance(adds, dict) or adds.get("__defaults") != []:
        return row
    # Validate the complete original diff against its pre-refresh metadata origin.
    # Overlapping updates/deletes of __defaults still fail; none are discarded.
    _diff(row, {key: item for key, item in old_inputs.items() if key != "__defaults"})
    return {
        **row,
        "adds": {key: item for key, item in adds.items() if key != "__defaults"},
    }


def _goal_inputs(
    goal: dict[str, Any],
    prior: dict[str, Any] | None,
    ops: tuple[str, ...],
) -> dict[str, Any]:
    old_inputs = (
        prior.get("inputs", {})
        if prior is not None and ops[0] != "delete-replaced"
        else {}
    )
    input_diff = goal.get("inputDiff", {})
    if prior is not None and ops == ("same",):
        input_diff = _same_input_diff(input_diff, old_inputs, goal["type"])
    inputs = _diff(input_diff, old_inputs)
    if ops == ("same",):
        # Compare unredacted values: redaction would hide changed secret inputs.
        _require(
            _property_semantics(old_inputs, goal["type"], inputs=True)
            == _property_semantics(inputs, goal["type"], inputs=True),
            "same-input-diff",
        )
    _diff(goal.get("outputDiff", {}), prior.get("outputs", {}) if prior else {})
    return inputs


def _goal(
    urn: str,
    row: dict[str, Any],
    prior: dict[str, Any] | None,
    catalog: Mapping[str, Any],
) -> dict[str, Any] | None:
    ops = tuple(_strings(row.get("steps")))
    _require(bool(ops), "plan-steps")
    if ops == ("delete",):
        _require(prior is not None and "goal" not in row, "delete-goal")
        return None
    goal = _goal_options(urn, row)
    inputs = _goal_inputs(goal, prior, ops)
    desired = {key: value for key, value in goal.items() if key in _STATE_FIELDS}
    desired.update(urn=urn, inputs=inputs)
    if prior is not None:
        desired["id"] = prior.get("id", "")
    _state(desired, catalog, require_tags_all_output=False)
    # Validate references once every desired resource is present; a dependency
    # may be created by this same plan and therefore absent from the checkpoint.
    _seed(row.get("seed", ""))
    return desired


def _preview_step(
    value: Any, catalog: Mapping[str, Any]
) -> tuple[dict[str, Any], str, str]:
    row = _object(
        value,
        {"op", "urn", "detailedDiff"},
        {
            "op",
            "urn",
            "provider",
            "oldState",
            "newState",
            "diffReasons",
            "replaceReasons",
            "detailedDiff",
        },
    )
    urn = _urn(row["urn"], catalog)
    op = _text(row["op"])
    _require(
        op
        in {
            "same",
            "update",
            "create",
            "delete",
            "replace",
            "create-replacement",
            "delete-replaced",
            "read",
            "refresh",
        },
        "preview-operation",
    )
    for key in ("diffReasons", "replaceReasons"):
        _strings(row.get(key, []))
    if row["detailedDiff"] is not None:
        _require(isinstance(row["detailedDiff"], dict), "preview-diff")
        for detail in row["detailedDiff"].values():
            _object(detail, {"kind", "inputDiff"}, {"kind", "inputDiff"})
            _require(
                detail["kind"]
                in {
                    "add",
                    "delete",
                    "update",
                    "add-replace",
                    "delete-replace",
                    "update-replace",
                }
                and type(detail["inputDiff"]) is bool,
                "preview-diff-kind",
            )
    return row, urn, op


def _preview_metadata(preview: dict[str, Any]) -> None:
    _require(isinstance(preview.get("config", {}), dict), "preview-config")
    _require(preview.get("maybeCorrupt", False) is False, "corrupt-preview")
    _require(
        type(preview.get("duration", 0)) is int and preview.get("duration", 0) >= 0,
        "preview-duration",
    )
    _require(isinstance(preview.get("diagnostics", []), list), "preview-diagnostics")
    for value in preview.get("diagnostics", []):
        diagnostic = _object(
            value, {"severity"}, {"urn", "prefix", "message", "severity"}
        )
        _require(
            diagnostic["severity"] in {"info", "info#err", "warning"}, "preview-error"
        )
    _require(
        isinstance(preview["steps"], list) and bool(preview["steps"]), "preview-steps"
    )


def _default_provider(urn: str) -> bool:
    parts = urn.split("::")
    return parts[2].split("$")[-1] == PROVIDER and parts[3].startswith("default")


def _preview_counts(summary: Any, counts: Counter[str], reads: int) -> None:
    _require(
        isinstance(summary, dict)
        and all(type(value) is int and value >= 0 for value in summary.values()),
        "preview-summary",
    )
    _require(0 <= summary.get("read", 0) <= reads, "preview-read-count")
    _require(
        {key: value for key, value in summary.items() if value and key != "read"}
        == dict(counts),
        "preview-summary-counts",
    )


def _preview_steps(
    payload: bytes, catalog: Mapping[str, Any]
) -> dict[str, list[dict[str, Any]]]:
    preview = _object(
        _decode(payload),
        {"steps", "changeSummary"},
        {"steps", "changeSummary", "config", "diagnostics", "duration", "maybeCorrupt"},
    )
    _preview_metadata(preview)
    result: dict[str, list[dict[str, Any]]] = {}
    counts: Counter[str] = Counter()
    reads = 0
    for value in preview["steps"]:
        row, urn, op = _preview_step(value, catalog)
        _require(
            op not in [item["op"] for item in result.get(urn, [])],
            "duplicate-preview-step",
        )
        _require(not _default_provider(urn), "internal-provider-preview-step")
        if op == "read":
            reads += 1
        elif op not in {"create-replacement", "delete-replaced", "refresh"}:
            counts[op] += 1
        result.setdefault(urn, []).append(row)
    _preview_counts(preview["changeSummary"], counts, reads)
    return result


def _preview_state(
    value: Any, expected: dict[str, Any], *, new: bool, catalog: Mapping[str, Any]
) -> None:
    row = _state(
        value,
        catalog,
        redacted_preview=True,
        require_tags_all_output=False,
    )
    _require(
        row["urn"] == expected["urn"] and _ownership(row) == _ownership(expected),
        "preview-ownership",
    )
    _require(
        _project(_property_semantics(row.get("inputs", {}), row["type"], inputs=True))
        == _project(
            _property_semantics(expected.get("inputs", {}), row["type"], inputs=True)
        ),
        "preview-inputs",
    )
    if not new:
        _require(row.get("id", "") == expected.get("id", ""), "preview-old-id")
        _require(
            _project(
                _property_semantics(row.get("outputs", {}), row["type"], inputs=False)
            )
            == _project(
                _property_semantics(
                    expected.get("outputs", {}), row["type"], inputs=False
                )
            ),
            "preview-old-outputs",
        )
    if new and row.get("id") and row.get("id") != UNKNOWN:
        _require(row["id"] == expected.get("id"), "preview-new-id")
    if expected.get("external", False):
        _require(row.get("id") == expected.get("id"), "external-id-change")


def _preview_resource(
    rows: list[dict[str, Any]],
    prior: dict[str, Any] | None,
    desired: dict[str, Any] | None,
    ops: tuple[str, ...],
    catalog: Mapping[str, Any],
) -> None:
    actual = tuple(row["op"] for row in rows if row["op"] != "refresh")
    _require(actual == ops, "plan-preview-operations")
    for row in rows:
        if row["op"] == "refresh":
            if prior is None:
                raise ValueError("refresh-absent-resource")
            _require(
                _project(
                    _property_semantics(
                        row.get("newState", {}).get("outputs", {}),
                        prior["type"],
                        inputs=False,
                    )
                )
                == _project(
                    _property_semantics(
                        prior.get("outputs", {}), prior["type"], inputs=False
                    )
                ),
                "refresh-drift",
            )
            _preview_states(row, prior, prior, catalog)
        else:
            new = None if row["op"] in {"delete", "delete-replaced"} else desired
            _preview_states(row, prior, new, catalog)


def _preview_states(
    row: dict[str, Any],
    old: dict[str, Any] | None,
    new: dict[str, Any] | None,
    catalog: Mapping[str, Any],
) -> None:
    if old is not None:
        observed_old = row.get("oldState")
        if row["op"] in {"replace", "delete-replaced"} and isinstance(
            observed_old, dict
        ):
            _require(
                type(observed_old.get("delete", False)) is bool,
                "replacement-delete-marker",
            )
            observed_old = {**observed_old, "delete": False}
        _preview_state(observed_old, old, new=False, catalog=catalog)
    else:
        _require("oldState" not in row, "unexpected-old-state")
    if new is not None:
        _preview_state(row.get("newState"), new, new=True, catalog=catalog)
    else:
        _require("newState" not in row, "unexpected-new-state")
    _require(
        row.get("provider", "") == (new or old or {}).get("provider", ""),
        "preview-provider",
    )


def _retained_role_owner(
    urn: str,
    target: tuple[str, ...],
    resources: dict[str, Any],
    catalog: Mapping[str, Any],
) -> bool:
    prior = resources.get(urn)
    if target[0] != ROLE or prior is None:
        return False
    if prior["type"] != ROLE or prior["urn"] != urn:
        return False
    if prior["custom"] is not True or prior.get("external", False) is not False:
        return False
    return (ROLE, *_target(prior, catalog)) == target and target[1] in catalog[
        "operator_bindings"
    ]["role_write"]


def _target_ownership(
    resources: dict[str, Any],
    desired: dict[str, dict[str, Any] | None],
    catalog: Mapping[str, Any],
) -> None:
    targets = [
        (row["type"], *_target(row, catalog))
        for row in desired.values()
        if row is not None and row["custom"]
    ]
    _require(len(targets) == len(set(targets)), "duplicate-desired-target")
    external_targets = {
        (row["type"], *_target(row, catalog))
        for row in resources.values()
        if row.get("external")
    }
    for urn, row in desired.items():
        if row is None or not row["custom"]:
            continue
        target = (row["type"], *_target(row, catalog))
        if target in external_targets:
            _require(
                _retained_role_owner(urn, target, resources, catalog),
                "external-target-ownership",
            )


def _desired_inventory(
    resources: dict[str, Any],
    desired: dict[str, dict[str, Any] | None],
    catalog: Mapping[str, Any],
) -> None:
    _target_ownership(resources, desired, catalog)
    remaining = {
        **{urn: row for urn, row in resources.items() if row.get("external")},
        **{urn: row for urn, row in desired.items() if row is not None},
    }
    for row in remaining.values():
        _references(row, remaining, catalog)


def _validate_resources(
    resources: dict[str, Any],
    goals: dict[str, Any],
    preview: dict[str, list[dict[str, Any]]],
    catalog: Mapping[str, Any],
) -> None:
    desired: dict[str, dict[str, Any] | None] = {}
    for urn, value in goals.items():
        _urn(urn, catalog)
        row = _object(value, {"steps", "state"}, {"steps", "state", "goal", "seed"})
        _require(row["state"] is None or isinstance(row["state"], dict), "plan-state")
        prior = resources.get(urn)
        _require(
            prior is None or not prior.get("external", False), "external-plan-goal"
        )
        desired[urn] = _goal(urn, row, prior, catalog)
        ops = tuple(row["steps"])
        _operation(prior, desired[urn], ops, catalog)
        if not _default_provider(urn):
            _preview_resource(preview[urn], prior, desired[urn], ops, catalog)
    for urn in resources.keys() - goals.keys():
        _require(resources[urn].get("external") is True, "missing-owned-goal")
        _preview_resource(
            preview[urn], resources[urn], resources[urn], ("read",), catalog
        )
    _desired_inventory(resources, desired, catalog)


def _validate_operator_plan(
    plan_payload: bytes,
    preview_payload: bytes,
    checkpoint_payload: bytes,
    *,
    catalog: Mapping[str, Any],
) -> OperatorPlanValidation:
    """Validate a complete saved plan against authenticated caller-supplied facts.

    ``catalog`` must be the unchanged result of ``seed.policy_registry.load_catalog``.
    Checkpoint bytes use the ``pulumi stack export`` version-3 deployment shape.
    This function never reads files, executes PR source, or establishes provenance.
    """
    _require(
        isinstance(catalog, dict) and catalog.get("environment") in CATALOG_HASHES,
        "catalog-environment",
    )
    _require(
        document_hash(catalog) == CATALOG_HASHES[catalog["environment"]], "catalog-hash"
    )
    resources = _checkpoint(checkpoint_payload, catalog)
    plan = _object(
        _decode(plan_payload),
        {"manifest", "resourcePlans"},
        {"manifest", "resourcePlans", "config"},
    )
    _manifest(plan["manifest"])
    validate_operator_configuration(
        plan.get("config", {}),
        account_id=catalog["account_id"],
        region=catalog["region"],
    )
    goals = plan["resourcePlans"]
    _require(isinstance(goals, dict) and bool(goals), "plan-goals")
    preview = _preview_steps(preview_payload, catalog)
    owned = {urn for urn, row in resources.items() if not row.get("external", False)}
    _require(
        owned <= goals.keys()
        and set(preview)
        == {urn for urn in set(resources) | set(goals) if not _default_provider(urn)},
        "complete-inventory",
    )
    _validate_resources(resources, goals, preview, catalog)
    return OperatorPlanValidation(
        hashlib.sha256(plan_payload).hexdigest(),
        hashlib.sha256(preview_payload).hexdigest(),
        hashlib.sha256(checkpoint_payload).hexdigest(),
        document_hash(catalog),
        tuple(sorted(urn for urn, row in goals.items() if row["steps"] != ["same"])),
    )


def validate_operator_plan(
    plan_payload: bytes,
    preview_payload: bytes,
    checkpoint_payload: bytes,
    *,
    catalog: Mapping[str, Any],
) -> OperatorPlanValidation:
    """Validate private plan/preview and version-3 stack-export checkpoint bytes.

    Catalog input is the unchanged ``seed.policy_registry.load_catalog`` result.
    The caller must authenticate inputs and source, check active seed enrollment,
    and bind the current backend version and secrets-provider identity before
    each replay. This pure function establishes none of that provenance.
    """
    try:
        return _validate_operator_plan(
            plan_payload, preview_payload, checkpoint_payload, catalog=catalog
        )
    except (TypeError, KeyError, AttributeError, RecursionError, OverflowError):
        raise ValueError("malformed-plan-evidence") from None
