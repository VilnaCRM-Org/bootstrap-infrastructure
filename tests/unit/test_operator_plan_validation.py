"""Pure, synthetic full-plan ownership and immutable-target boundary tests."""

import base64
import copy
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path
from typing import cast

import pytest
from seed.policy_registry import load_catalog

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))

import operator_plan_validation as validation  # noqa: E402


def encoded(value):
    return json.dumps(value).encode()


def manifest():
    return {
        "version": "v3.223.0",
        "time": "2026-09-07T00:00:00Z",
        "magic": hashlib.sha256(b"v3.223.0").hexdigest(),
    }


def fixture(environment="test"):
    catalog = load_catalog(environment)
    binding = catalog["operator_bindings"]
    prefix = f"urn:pulumi:{environment}::github-ci-bootstrap::"
    root = prefix + validation.STACK + "::github-ci-bootstrap-" + environment
    provider = prefix + validation.PROVIDER + "::default_7_23_0"
    reference = provider + "::provider-id"
    resources = []

    def add(kind, name, identifier, inputs, *, custom=True, **kwargs):
        row = {
            "urn": prefix + kind + "::" + name,
            "type": kind,
            "custom": custom,
            "inputs": inputs,
            "outputs": {},
            "protect": custom and kind != validation.PROVIDER,
            **kwargs,
        }
        if identifier:
            row["id"] = identifier
        if row["urn"] != root:
            row["parent"] = root
        if custom and kind != validation.PROVIDER:
            row["provider"] = reference
        if kind in {
            validation.ROLE,
            validation.POLICY,
            validation.SECRET,
            validation.OIDC,
        }:
            row["outputs"]["arn"] = (
                f"arn:aws:iam::{catalog['account_id']}:role/{identifier}"
                if kind == validation.ROLE
                else identifier
            )
        resources.append(row)
        return row

    add(validation.STACK, "github-ci-bootstrap-" + environment, "", {}, custom=False)
    add(
        validation.PROVIDER,
        "default_7_23_0",
        "provider-id",
        {
            "version": "7.23.0",
            "region": catalog["region"],
            "allowedAccountIds": json.dumps([catalog["account_id"]]),
            "skipCredentialsValidation": "false",
            "skipRegionValidation": "false",
            "skipRequestingAccountId": "false",
        },
    )
    arn = binding["role_write"][0]
    name = arn.rsplit("/", 1)[1]
    principal = next(p for p in catalog["principals"] if p["arn"] == arn)
    role = add(
        validation.ROLE,
        "role",
        name,
        {
            "name": name,
            "path": "/",
            "permissionsBoundary": principal["boundary_arn"],
            "assumeRolePolicy": '{"Version":"2012-10-17","Statement":[]}',
        },
    )
    policy_arn = binding["policy_write"][0]
    add(
        validation.POLICY,
        "policy",
        policy_arn,
        {
            "name": policy_arn.rsplit("/", 1)[1],
            "path": "/",
            "policy": '{"Statement":[]}',
        },
    )
    add(
        validation.INLINE,
        "inline",
        name + ":inline",
        {
            "name": "inline",
            "role": name,
            "policy": '{"Statement":[]}',
        },
        protect=False,
    )
    add(
        validation.ATTACHMENT,
        "attachment",
        name + "-synthetic",
        {
            "role": name,
            "policyArn": policy_arn,
        },
        protect=False,
    )
    add(
        validation.SECRET,
        "secret",
        binding["secrets"][0],
        {
            "name": "/bootstrap-infrastructure/ci/" + environment,
            "description": "Synthetic configuration container",
        },
    )
    version = add(
        validation.VERSION,
        "version",
        binding["secrets"][0] + "|synthetic-version",
        {
            "secretId": binding["secrets"][0],
            "secretString": {
                validation.SIGNATURE: validation.WIRE_VALUE_TAG,
                "ciphertext": "synthetic-test-only",
            },
            "versionStages": ["AWSCURRENT"],
        },
        protect=False,
    )
    version["outputs"]["arn"] = binding["secrets"][0]
    version["outputs"]["secretId"] = binding["secrets"][0]
    add(
        validation.OIDC,
        "oidc",
        binding["oidc"],
        {"url": "https://token.actions.githubusercontent.com"},
    )
    # ReadResource entries have preview read steps, but no saved-plan goal.
    add(
        validation.POLICY,
        "boundary-reference",
        principal["boundary_arn"],
        {
            "name": principal["boundary_arn"].rsplit("/", 1)[1],
            "path": "/",
        },
        external=True,
        protect=False,
    )
    checkpoint = {
        "version": 3,
        "deployment": {
            "manifest": manifest(),
            "resources": resources,
            "secrets_providers": {
                "type": "cloud",
                "state": {"url": "synthetic-provider"},
            },
        },
    }
    plan = {"manifest": manifest(), "resourcePlans": {}}
    preview = {"steps": [], "changeSummary": {}}
    for row in resources:
        if not row.get("external"):
            goal = {
                key: copy.deepcopy(row[key])
                for key in ("type", "custom", "protect", "parent", "provider")
                if key in row
            }
            goal.update(name=row["urn"].split("::")[-1], inputDiff={}, outputDiff={})
            plan["resourcePlans"][row["urn"]] = {
                "steps": ["same"],
                "goal": goal,
                "state": None,
                "seed": base64.b64encode(bytes(range(32))).decode(),
            }
        if row["type"] != validation.PROVIDER:
            append_preview(preview, row, row, "read" if row.get("external") else "same")
    return {
        "catalog": catalog,
        "checkpoint": checkpoint,
        "plan": plan,
        "preview": preview,
        "role": role["urn"],
    }


def redact(value):
    if isinstance(value, dict):
        if validation.SIGNATURE in value:
            return "[secret]"
        return {key: redact(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value


def append_preview(preview, old, new, op):
    row = new or old
    step = {"urn": row["urn"], "op": op, "detailedDiff": None}
    if "provider" in row:
        step["provider"] = row["provider"]
    if old is not None:
        step["oldState"] = redact(copy.deepcopy(old))
    if new is not None:
        step["newState"] = redact(copy.deepcopy(new))
    preview["steps"].append(step)
    recount(preview)


def recount(preview):
    preview["changeSummary"] = dict(
        Counter(
            step["op"]
            for step in preview["steps"]
            if step["op"]
            not in {"create-replacement", "delete-replaced", "refresh", "read"}
        )
    )


def resource(data, kind):
    return next(
        row
        for row in data["checkpoint"]["deployment"]["resources"]
        if row["type"] == kind
    )


def exclusive(data, *, full_inventory=False):
    catalog = data["catalog"]
    bindings = catalog["operator_bindings"]
    candidates = [
        principal
        for principal in catalog["principals"]
        if principal["arn"] in bindings["role_write"]
        and len(principal["attachment_arns"]) == 6
        and len(principal["guard_arns"]) == 1
        and len(set(principal["attachment_arns"]) - set(principal["guard_arns"])) == 5
    ]
    assert len(candidates) == 1
    principal = candidates[0]
    role_name = principal["arn"].rsplit("/", 1)[1]
    policy_arns = sorted(
        principal["attachment_arns"]
        if full_inventory
        else set(principal["attachment_arns"]) - set(principal["guard_arns"])
    )
    root = resource(data, validation.STACK)
    provider = resource(data, validation.PROVIDER)
    row = {
        "urn": "::".join(root["urn"].split("::")[:2])
        + "::"
        + validation.EXCLUSIVE
        + "::github-automation-managed-policy-attachments-exclusive",
        "type": validation.EXCLUSIVE,
        "custom": True,
        "id": role_name,
        "inputs": {"roleName": role_name, "policyArns": policy_arns},
        "outputs": {"roleName": role_name, "policyArns": policy_arns},
        "parent": root["urn"],
        "provider": provider["urn"] + "::" + provider["id"],
        "protect": True,
    }
    data["checkpoint"]["deployment"]["resources"].append(row)
    reset_noop(data)
    return row, principal


def change(data, kind, updates, ops=("update",)):
    old = resource(data, kind)
    new = copy.deepcopy(old)
    new["inputs"].update(updates)
    goal = data["plan"]["resourcePlans"][old["urn"]]
    goal["steps"] = list(ops)
    goal["goal"]["inputDiff"] = {
        "adds": {key: val for key, val in updates.items() if key not in old["inputs"]},
        "updates": {key: val for key, val in updates.items() if key in old["inputs"]},
    }
    data["preview"]["steps"] = [
        step for step in data["preview"]["steps"] if step["urn"] != old["urn"]
    ]
    for op in ops:
        append_preview(
            data["preview"], old, None if op == "delete-replaced" else new, op
        )
    return new


def validate(data):
    return validation.validate_operator_plan(
        encoded(data["plan"]),
        encoded(data["preview"]),
        encoded(data["checkpoint"]),
        catalog=data["catalog"],
    )


def computed_tags(data):
    tags = {"Project": "bootstrap", "Environment": "test"}
    for kind in (
        validation.ROLE,
        validation.POLICY,
        validation.SECRET,
        validation.OIDC,
    ):
        row = resource(data, kind)
        row["inputs"].update(tags=tags, tagsAll=tags)
        row["outputs"]["tagsAll"] = tags
    reset_noop(data)
    return tags


@pytest.mark.parametrize("environment", ["test", "prod"])
def test_complete_noop(environment):
    data = fixture(environment)
    before = copy.deepcopy(data)
    result = validate(data)
    assert result.changed_urns == ()
    assert result.plan_sha256 == hashlib.sha256(encoded(data["plan"])).hexdigest()
    assert data == before


def test_checkpoint_computed_tags_all_are_accepted_for_supported_resources():
    data = fixture()
    computed_tags(data)

    assert validate(data).changed_urns == ()


def test_computed_tags_all_requires_matching_explicit_tags():
    data = fixture()
    computed_tags(data)
    resource(data, validation.ROLE)["inputs"]["tagsAll"] = {"Project": "other"}
    reset_noop(data)

    with pytest.raises(ValueError, match="tags-all-inputs"):
        validate(data)


def test_checkpoint_computed_tags_all_requires_matching_output():
    data = fixture()
    computed_tags(data)
    resource(data, validation.ROLE)["outputs"]["tagsAll"] = {"Project": "other"}
    reset_noop(data)

    with pytest.raises(ValueError, match="tags-all-output"):
        validate(data)


@pytest.mark.parametrize(
    "kind", [validation.ROLE, validation.POLICY, validation.SECRET]
)
def test_computed_tags_all_tracks_allowed_explicit_tag_changes(kind):
    data = fixture()
    tags = computed_tags(data)
    changed_tags = {**tags, "CostCenter": "reviewed"}
    change(data, kind, {"tags": changed_tags, "tagsAll": changed_tags})

    assert validate(data).changed_urns == (resource(data, kind)["urn"],)


def test_computed_tags_all_does_not_unfreeze_oidc():
    data = fixture()
    tags = computed_tags(data)
    changed_tags = {**tags, "CostCenter": "reviewed"}
    change(data, validation.OIDC, {"tags": changed_tags, "tagsAll": changed_tags})

    with pytest.raises(ValueError, match="frozen-resource-change"):
        validate(data)


def test_computed_tags_all_deletion_without_explicit_tags_is_accepted():
    data = fixture()
    computed_tags(data)
    old = resource(data, validation.ROLE)
    new = copy.deepcopy(old)
    del new["inputs"]["tagsAll"]
    goal = data["plan"]["resourcePlans"][old["urn"]]
    goal["steps"] = ["update"]
    goal["goal"]["inputDiff"] = {"adds": {}, "updates": {}, "deletes": ["tagsAll"]}
    data["preview"]["steps"] = [
        step for step in data["preview"]["steps"] if step["urn"] != old["urn"]
    ]
    append_preview(data["preview"], old, new, "update")

    assert validate(data).changed_urns == (old["urn"],)


def test_computed_tags_all_addition_without_explicit_tags_is_accepted():
    data = fixture()
    old = resource(data, validation.ROLE)
    tags = {"Project": "bootstrap", "Environment": "test"}
    old["inputs"]["tags"] = tags
    reset_noop(data)
    change(data, validation.ROLE, {"tagsAll": tags})

    assert validate(data).changed_urns == (old["urn"],)


def test_preview_new_state_keeps_input_alias_binding_but_allows_stale_output():
    data = fixture()
    tags = computed_tags(data)
    changed_tags = {**tags, "CostCenter": "reviewed"}
    role = resource(data, validation.ROLE)
    change(data, validation.ROLE, {"tags": changed_tags, "tagsAll": changed_tags})
    step = next(item for item in data["preview"]["steps"] if item["urn"] == role["urn"])
    step["newState"]["outputs"]["tagsAll"] = validation.UNKNOWN

    assert validate(data).changed_urns == (role["urn"],)


def test_preview_new_state_cannot_substitute_computed_tags_all_input():
    data = fixture()
    tags = computed_tags(data)
    changed_tags = {**tags, "CostCenter": "reviewed"}
    role = resource(data, validation.ROLE)
    change(data, validation.ROLE, {"tags": changed_tags, "tagsAll": changed_tags})
    step = next(item for item in data["preview"]["steps"] if item["urn"] == role["urn"])
    del step["newState"]["inputs"]["tagsAll"]

    with pytest.raises(ValueError, match="preview-inputs"):
        validate(data)


def test_computed_tags_all_is_limited_to_provider_tagged_resources():
    data = fixture()
    change(data, validation.INLINE, {"tags": {}, "tagsAll": {}})

    with pytest.raises(ValueError, match="unsupported-provider-input"):
        validate(data)


@pytest.mark.parametrize(
    ("tags", "tags_all", "message"),
    [
        ({"Project": "ok"}, {"Project": validation.UNKNOWN}, "unknown-input"),
        ({"Project": "ok"}, {"Project": []}, "tags-all-shape"),
        (
            {"Project": "ok"},
            {
                "Project": {
                    validation.SIGNATURE: validation.WIRE_VALUE_TAG,
                    "ciphertext": "synthetic-test-only",
                }
            },
            "tags-all-shape",
        ),
    ],
)
def test_computed_tags_all_requires_concrete_string_map(tags, tags_all, message):
    data = fixture()
    change(data, validation.ROLE, {"tags": tags, "tagsAll": tags_all})

    with pytest.raises(ValueError, match=message):
        validate(data)


@pytest.mark.parametrize("use_friendly_name", [False, True])
def test_secret_version_accepts_exact_owned_arn_or_friendly_name(use_friendly_name):
    data = fixture()
    secret = resource(data, validation.SECRET)
    version = resource(data, validation.VERSION)
    if use_friendly_name:
        name = validation._secret_name(secret["id"])
        version["inputs"]["secretId"] = name
        version["outputs"]["secretId"] = name
        version["id"] = name + "|synthetic-version"
        reset_noop(data)

    assert validate(data).changed_urns == ()


def test_secret_version_friendly_name_is_unique_and_exact():
    data = fixture()
    secret = resource(data, validation.SECRET)["id"]
    name = validation._secret_name(secret)
    secrets = data["catalog"]["operator_bindings"]["secrets"]
    suffix = "abcdef" if not secret.endswith("-abcdef") else "ghijkl"
    secrets.append(secret.rsplit("-", 1)[0] + "-" + suffix)

    with pytest.raises(ValueError, match="foreign-secret-target"):
        validation._secret_version_target(name, secrets)

    with pytest.raises(ValueError, match="foreign-secret-target"):
        validation._secret_version_target(secret[:-1], secrets)


def test_secret_version_friendly_name_keeps_region_and_output_binding():
    data = fixture()
    secret = resource(data, validation.SECRET)
    version = resource(data, validation.VERSION)
    name = validation._secret_name(secret["id"])
    version["inputs"].update(secretId=name, region="us-east-1")
    version["outputs"]["secretId"] = name
    version["id"] = name + "|synthetic-version"
    reset_noop(data)

    with pytest.raises(ValueError, match="secret-region"):
        validate(data)

    version["inputs"].pop("region")
    version["outputs"]["arn"] = "foreign-secret-target"
    reset_noop(data)
    with pytest.raises(ValueError, match="checkpoint-arn"):
        validate(data)


def test_secret_version_output_secret_id_binds_to_its_input_selector():
    data = fixture()
    secret = resource(data, validation.SECRET)
    version = resource(data, validation.VERSION)
    name = validation._secret_name(secret["id"])
    version["inputs"]["secretId"] = name
    version["outputs"]["secretId"] = secret["id"]
    version["id"] = name + "|synthetic-version"
    reset_noop(data)

    with pytest.raises(ValueError, match="version-secret-id"):
        validate(data)


def test_secret_version_physical_owner_normalizes_exact_friendly_name_alias():
    data = fixture()
    secret = resource(data, validation.SECRET)
    version = resource(data, validation.VERSION)
    alias = copy.deepcopy(version)
    name = validation._secret_name(secret["id"])
    alias["urn"] += "-friendly"
    alias["inputs"]["secretId"] = name
    alias["outputs"]["secretId"] = name
    alias["id"] = name + "|synthetic-version"
    data["checkpoint"]["deployment"]["resources"].append(alias)
    reset_noop(data)

    with pytest.raises(ValueError, match="duplicate-physical-owner"):
        validate(data)


def test_secret_version_selector_change_is_not_normalized_in_input_diff():
    data = fixture()
    name = validation._secret_name(resource(data, validation.SECRET)["id"])
    change(data, validation.VERSION, {"secretId": name})

    with pytest.raises(ValueError, match="unsupported-input-change"):
        validate(data)


def test_exclusive_attachments_accept_full_catalog_inventory_without_mutation():
    data = fixture()
    _, principal = exclusive(data, full_inventory=True)
    assert not set(principal["guard_arns"]) & set(
        data["catalog"]["operator_bindings"]["policy_write"]
    )

    assert validate(data).changed_urns == ()


def test_exclusive_attachments_reject_legacy_same_or_partial_inventory():
    data = fixture()
    row, _ = exclusive(data)

    with pytest.raises(ValueError, match="exclusive-guard-retention"):
        validate(data)

    row["inputs"]["policyArns"] = row["inputs"]["policyArns"][:-1]
    row["outputs"]["policyArns"] = row["inputs"]["policyArns"]
    reset_noop(data)

    with pytest.raises(ValueError, match="exclusive-policy-inventory"):
        validate(data)


def test_exclusive_attachments_bind_fixed_identity_and_outputs():
    data = fixture()
    row, _ = exclusive(data, full_inventory=True)
    row["id"] = "other-role"
    reset_noop(data)

    with pytest.raises(ValueError, match="exclusive-id"):
        validate(data)

    row["id"] = row["inputs"]["roleName"]
    row["outputs"]["policyArns"] = []
    reset_noop(data)

    with pytest.raises(ValueError, match="exclusive-output-binding"):
        validate(data)


def test_exclusive_checkpoint_output_order_does_not_change_policy_set():
    data = fixture()
    row, _ = exclusive(data, full_inventory=True)
    row["outputs"]["policyArns"] = list(reversed(row["inputs"]["policyArns"]))
    reset_noop(data)

    assert validate(data).changed_urns == ()


@pytest.mark.parametrize("invalid", [None, [False], ["duplicate", "duplicate"]])
def test_exclusive_checkpoint_outputs_require_unique_concrete_policy_arns(invalid):
    data = fixture()
    row, _ = exclusive(data, full_inventory=True)
    row["outputs"]["policyArns"] = invalid
    reset_noop(data)

    with pytest.raises(ValueError):
        validate(data)


def test_exclusive_attachments_only_transition_from_legacy_to_full_inventory():
    data = fixture()
    _, principal = exclusive(data)
    change(data, validation.EXCLUSIVE, {"policyArns": principal["attachment_arns"]})

    assert validate(data).changed_urns


def test_exclusive_attachments_reject_general_full_inventory_updates():
    data = fixture()
    row, _ = exclusive(data, full_inventory=True)
    change(
        data,
        validation.EXCLUSIVE,
        {"policyArns": list(reversed(row["inputs"]["policyArns"]))},
    )

    with pytest.raises(ValueError, match="exclusive-transition"):
        validate(data)


def test_exclusive_attachments_reject_full_inventory_rollback():
    data = fixture()
    _, principal = exclusive(data, full_inventory=True)
    non_guard = sorted(set(principal["attachment_arns"]) - set(principal["guard_arns"]))
    change(data, validation.EXCLUSIVE, {"policyArns": non_guard})

    with pytest.raises(ValueError, match="exclusive-transition"):
        validate(data)


@pytest.mark.parametrize(
    ("prior", "desired", "ops"),
    [
        (False, True, ("update",)),
        (True, False, ("update",)),
        (True, True, ("create",)),
        (True, True, ("delete",)),
        (True, True, ("create-replacement", "replace", "delete-replaced")),
    ],
)
def test_exclusive_attachments_reject_missing_or_non_update_transitions(
    prior, desired, ops
):
    data = fixture()
    row, _ = exclusive(data)

    with pytest.raises(ValueError, match="exclusive-transition"):
        validation._exclusive_guard_transition(
            row if prior else None,
            row if desired else None,
            ops,
            data["catalog"],
        )


def test_exclusive_attachments_reject_foreign_principal():
    data = fixture()
    exclusive(data, full_inventory=True)
    change(data, validation.EXCLUSIVE, {"roleName": "foreign-automation-role"})

    with pytest.raises(ValueError, match="foreign-exclusive-role"):
        validate(data)


def test_computed_tags_all_cannot_bypass_secret_kms_policy_or_role_boundary():
    data = fixture()
    tags = computed_tags(data)
    change(
        data,
        validation.SECRET,
        {
            "kmsKeyId": "foreign-key",
            "policy": '{"Statement":[]}',
            "tagsAll": tags,
        },
    )
    change(
        data,
        validation.ROLE,
        {
            "permissionsBoundary": "arn:aws:iam::891377212104:policy/other",
            "tagsAll": tags,
        },
    )

    with pytest.raises(ValueError):
        validate(data)


@pytest.mark.parametrize(
    ("kind", "updates"),
    [
        (validation.ROLE, {"description": "Reviewed update"}),
        (validation.ROLE, {"assumeRolePolicy": '{"Statement":[]}'}),
        (
            validation.POLICY,
            {"policy": '{"Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}'},
        ),
        (
            validation.INLINE,
            {"policy": '{"Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}'},
        ),
        (validation.SECRET, {"description": "Reviewed description"}),
        (validation.VERSION, {"versionStages": ["AWSPREVIOUS"]}),
    ],
)
def test_permitted_existing_updates(kind, updates):
    data = fixture()
    change(data, kind, updates)
    assert validate(data).changed_urns == (resource(data, kind)["urn"],)


def test_secret_replacement_uses_pinned_aws_lifecycle():
    data = fixture()
    change(
        data,
        validation.VERSION,
        {
            "secretString": {
                validation.SIGNATURE: validation.WIRE_VALUE_TAG,
                "ciphertext": "different-synthetic-ciphertext",
            }
        },
        ("create-replacement", "replace", "delete-replaced"),
    )
    assert validate(data).changed_urns == (resource(data, validation.VERSION)["urn"],)


def test_attachment_replacement_stays_within_exact_ceiling():
    data = fixture()
    change(
        data,
        validation.ATTACHMENT,
        {"policyArn": data["catalog"]["operator_bindings"]["policy_write"][1]},
        ("create-replacement", "replace", "delete-replaced"),
    )
    assert validate(data).changed_urns


@pytest.mark.parametrize(
    "kind", [validation.ATTACHMENT, validation.INLINE, validation.VERSION]
)
def test_remove_permitted_grant_or_value_version(kind):
    data = fixture()
    old = resource(data, kind)
    data["plan"]["resourcePlans"][old["urn"]] = {"steps": ["delete"], "state": None}
    data["preview"]["steps"] = [
        step for step in data["preview"]["steps"] if step["urn"] != old["urn"]
    ]
    append_preview(data["preview"], old, None, "delete")
    assert validate(data).changed_urns


@pytest.mark.parametrize(
    "kind",
    [validation.ATTACHMENT, validation.INLINE, validation.VERSION, validation.POLICY],
)
def test_create_known_target_lifecycle(kind):
    data = fixture()
    prior = resource(data, kind)
    data["checkpoint"]["deployment"]["resources"].remove(prior)
    goal = data["plan"]["resourcePlans"][prior["urn"]]
    goal["steps"] = ["create"]
    goal["goal"]["inputDiff"] = {"adds": prior["inputs"]}
    data["preview"]["steps"] = [
        step for step in data["preview"]["steps"] if step["urn"] != prior["urn"]
    ]
    new = copy.deepcopy(prior)
    new.pop("id", None)
    append_preview(data["preview"], None, new, "create")
    assert validate(data).changed_urns


def new_policy_and_attachment():
    data = fixture()
    rows = [resource(data, kind) for kind in (validation.POLICY, validation.ATTACHMENT)]
    for row in rows:
        data["checkpoint"]["deployment"]["resources"].remove(row)
        goal = data["plan"]["resourcePlans"][row["urn"]]
        goal["steps"] = ["create"]
        goal["goal"]["inputDiff"] = {"adds": row["inputs"]}
        data["preview"]["steps"] = [
            step for step in data["preview"]["steps"] if step["urn"] != row["urn"]
        ]
        row.pop("id", None)
    policy, attachment = rows
    attachment["dependencies"] = [policy["urn"]]
    attachment["propertyDependencies"] = {"policyArn": [policy["urn"]]}
    data["plan"]["resourcePlans"][attachment["urn"]]["goal"].update(
        dependencies=attachment["dependencies"],
        propertyDependencies=attachment["propertyDependencies"],
    )
    for row in rows:
        append_preview(data["preview"], None, row, "create")
    return data, policy, attachment


@pytest.mark.parametrize("reverse", [False, True])
def test_new_resources_can_depend_on_each_other(reverse):
    data, policy, attachment = new_policy_and_attachment()
    if reverse:
        data["plan"]["resourcePlans"] = dict(
            reversed(list(data["plan"]["resourcePlans"].items()))
        )
    assert validate(data).changed_urns == tuple(
        sorted([policy["urn"], attachment["urn"]])
    )


def test_new_goal_dependency_must_exist():
    data, _, attachment = new_policy_and_attachment()
    goal = data["plan"]["resourcePlans"][attachment["urn"]]["goal"]
    foreign = attachment["urn"] + "-absent"
    goal["dependencies"][:] = [foreign]
    for step in data["preview"]["steps"]:
        if step["urn"] == attachment["urn"]:
            step["newState"]["dependencies"] = [foreign]
    with pytest.raises(ValueError, match="foreign-dependency"):
        validate(data)


def test_deleted_dependency_is_unavailable():
    data = fixture()
    policy = resource(data, validation.INLINE)
    attachment = resource(data, validation.ATTACHMENT)
    attachment["dependencies"] = [policy["urn"]]
    reset_noop(data)
    data["plan"]["resourcePlans"][attachment["urn"]]["goal"]["dependencies"] = [
        policy["urn"]
    ]
    data["plan"]["resourcePlans"][policy["urn"]] = {"steps": ["delete"], "state": None}
    data["preview"]["steps"] = [
        step for step in data["preview"]["steps"] if step["urn"] != policy["urn"]
    ]
    append_preview(data["preview"], policy, None, "delete")
    with pytest.raises(ValueError, match="foreign-dependency"):
        validate(data)


@pytest.mark.parametrize(
    ("kind", "updates", "error"),
    [
        (
            validation.ROLE,
            {"permissionsBoundary": "arn:aws:iam::891377212104:policy/other"},
            "unsupported-input-change",
        ),
        (validation.ROLE, {"name": "new-role"}, "foreign-iam-target"),
        (
            validation.ATTACHMENT,
            {"policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"},
            "foreign-policy-target",
        ),
        (validation.VERSION, {"secretId": "foreign-secret"}, "foreign-secret-target"),
        (validation.POLICY, {"name": "outside-ceiling"}, "foreign-iam-target"),
        (
            validation.OIDC,
            {"url": "https://attacker.example"},
            "frozen-resource-change",
        ),
    ],
)
def test_reviewed_plan_cannot_widen_targets(kind, updates, error):
    data = fixture()
    change(data, kind, updates)
    with pytest.raises(ValueError, match=error):
        validate(data)


@pytest.mark.parametrize("path", ["plan", "preview", "checkpoint"])
@pytest.mark.parametrize(
    "payload",
    [
        b"{}",
        b"[]",
        b'{"x":1,"x":2}',
        b'{"x":NaN}',
        b'{"x":Infinity}',
        b"\xff",
        b"not-json",
    ],
)
def test_reject_malformed_documents(path, payload):
    data = fixture()
    values = {key: encoded(data[key]) for key in ("plan", "preview", "checkpoint")}
    values[path] = payload
    with pytest.raises(ValueError):
        validation.validate_operator_plan(
            values["plan"],
            values["preview"],
            values["checkpoint"],
            catalog=data["catalog"],
        )


@pytest.mark.parametrize(
    "mutation",
    [
        lambda d: d["plan"]["resourcePlans"].pop(d["role"]),
        lambda d: d["preview"]["steps"].pop(),
        lambda d: d["preview"]["steps"].append(copy.deepcopy(d["preview"]["steps"][0])),
        lambda d: d["checkpoint"]["deployment"]["resources"].append(
            copy.deepcopy(resource(d, validation.ROLE))
        ),
        lambda d: d["plan"]["resourcePlans"][d["role"]]["goal"].update(protect=False),
        lambda d: d["plan"]["resourcePlans"][d["role"]]["goal"].update(
            provider="foreign-provider"
        ),
        lambda d: d["plan"]["resourcePlans"][d["role"]]["goal"].update(
            parent="foreign-parent"
        ),
        lambda d: d["plan"]["resourcePlans"][d["role"]]["goal"].update(
            name="substituted"
        ),
        lambda d: d["plan"]["resourcePlans"][d["role"]]["goal"].update(custom=1),
        lambda d: d["plan"]["resourcePlans"][d["role"]].update(steps=["import"]),
        lambda d: d["plan"]["resourcePlans"][d["role"]].update(seed="bad-base64"),
        lambda d: d["preview"].update(maybeCorrupt=True),
        lambda d: d["preview"].update(diagnostics=[{"severity": "error"}]),
        lambda d: d["preview"]["changeSummary"].update(same=True),
        lambda d: d["checkpoint"]["deployment"].update(pending_operations=[{}]),
        lambda d: resource(d, validation.PROVIDER)["inputs"].update(version="7.24.0"),
        lambda d: resource(d, validation.PROVIDER)["inputs"].update(
            allowedAccountIds='["933245420672"]'
        ),
        lambda d: d["catalog"]["operator_bindings"]["role_write"].append("attacker"),
    ],
)
def test_missing_duplicate_or_substituted_evidence(mutation):
    data = fixture()
    mutation(data)
    with pytest.raises(ValueError):
        validate(data)


def reset_noop(data):
    """Rebuild coherent synthetic observations after changing the trusted baseline."""
    data["plan"]["resourcePlans"] = {}
    data["preview"] = {"steps": [], "changeSummary": {}}
    for row in data["checkpoint"]["deployment"]["resources"]:
        if not row.get("external"):
            goal = {
                key: copy.deepcopy(row[key])
                for key in ("type", "custom", "protect", "parent", "provider")
                if key in row
            }
            goal.update(name=row["urn"].split("::")[-1], inputDiff={}, outputDiff={})
            data["plan"]["resourcePlans"][row["urn"]] = {
                "goal": goal,
                "steps": ["same"],
                "state": {},
                "seed": base64.b64encode(bytes(range(32))).decode(),
            }
        if row["type"] != validation.PROVIDER or not row["urn"].split("::")[
            -1
        ].startswith("default"):
            append_preview(
                data["preview"], row, row, "read" if row.get("external") else "same"
            )


def config_baseline():
    data = fixture()
    principal = next(
        item for item in data["catalog"]["principals"] if item["frozen_config"]
    )
    row = resource(data, validation.ROLE)
    row["id"] = principal["arn"].rsplit("/", 1)[1]
    row["outputs"]["arn"] = principal["arn"]
    row["inputs"] = {
        "name": row["id"],
        "path": "/",
        "assumeRolePolicy": json.dumps(principal["frozen_config"]["trust"]),
        "managedPolicyArns": principal["attachment_arns"],
    }
    inline = resource(data, validation.INLINE)
    name, policy = next(iter(principal["frozen_config"]["inline_policies"].items()))
    inline["id"] = row["id"] + ":" + name
    inline["inputs"] = {"name": name, "role": row["id"], "policy": json.dumps(policy)}
    reset_noop(data)
    return data


def test_frozen_config_exact_existing_noop():
    data = config_baseline()
    assert validate(data).changed_urns == ()


@pytest.mark.parametrize("kind", [validation.ROLE, validation.INLINE])
def test_frozen_config_cannot_change_even_inside_catalog(kind):
    data = config_baseline()
    field = "assumeRolePolicy" if kind == validation.ROLE else "policy"
    change(data, kind, {field: '{"Statement":[]}'})
    with pytest.raises(ValueError, match="frozen-resource-change"):
        validate(data)


@pytest.mark.parametrize("kind", [validation.ROLE, validation.INLINE])
def test_frozen_config_does_not_accept_wrong_baseline_as_noop(kind):
    data = config_baseline()
    row = resource(data, kind)
    row["inputs"]["assumeRolePolicy" if kind == validation.ROLE else "policy"] = (
        '{"Statement":[]}'
    )
    reset_noop(data)
    with pytest.raises(ValueError, match="frozen-config"):
        validate(data)


def test_config_embedded_inline_policy_matches_seed():
    data = config_baseline()
    principal = next(
        item for item in data["catalog"]["principals"] if item["frozen_config"]
    )
    resource(data, validation.ROLE)["inputs"]["inlinePolicies"] = [
        {"name": name, "policy": json.dumps(policy)}
        for name, policy in principal["frozen_config"]["inline_policies"].items()
    ]
    reset_noop(data)
    assert validate(data).changed_urns == ()


def test_role_updates_keep_seed_guard_and_reviewed_policies():
    data = fixture()
    principal = next(
        item
        for item in data["catalog"]["principals"]
        if item["arn"] == resource(data, validation.ROLE)["outputs"]["arn"]
    )
    resource(data, validation.ROLE)["inputs"]["managedPolicyArns"] = principal[
        "attachment_arns"
    ]
    reset_noop(data)
    change(
        data,
        validation.ROLE,
        {
            "managedPolicyArns": principal["guard_arns"]
            + data["catalog"]["operator_bindings"]["policy_write"][:1],
            "inlinePolicies": [{"name": "reviewed", "policy": '{"Statement":[]}'}],
            "tags": {"review": "yes"},
            "description": "",
        },
    )
    assert validate(data).changed_urns


@pytest.mark.parametrize("arns", [[], ["arn:aws:iam::aws:policy/AdministratorAccess"]])
def test_guard_attachment_removal_or_foreign_attachment_rejected(arns):
    data = fixture()
    change(data, validation.ROLE, {"managedPolicyArns": arns})
    with pytest.raises(ValueError, match="role-guard-removal"):
        validate(data)


def test_guard_attachment_has_no_mutable_lifecycle():
    data = fixture()
    role = resource(data, validation.ROLE)
    principal = next(
        item
        for item in data["catalog"]["principals"]
        if item["arn"] == role["outputs"]["arn"]
    )
    row = resource(data, validation.ATTACHMENT)
    row["inputs"]["policyArn"] = principal["guard_arns"][0]
    reset_noop(data)
    assert validate(data).changed_urns == ()
    change(
        data,
        validation.ATTACHMENT,
        {"policyArn": data["catalog"]["operator_bindings"]["policy_write"][0]},
        ("create-replacement", "replace", "delete-replaced"),
    )
    with pytest.raises(ValueError, match="frozen-prior-change"):
        validate(data)


@pytest.mark.parametrize(
    ("kind", "updates"),
    [
        (validation.ROLE, {"forceDetachPolicies": True}),
        (validation.SECRET, {"kmsKeyId": "foreign-key"}),
        (validation.SECRET, {"policy": '{"Statement":[]}'}),
        (validation.SECRET, {"name": "/other"}),
        (validation.VERSION, {"secretStringWo": "synthetic-write-only"}),
        (validation.VERSION, {"secretString": "synthetic-unwrapped-value"}),
        (validation.VERSION, {"secretString": "[secret]"}),
        (validation.VERSION, {"secretString": {"plaintext": "synthetic-no-marker"}}),
        (validation.ROLE, {"maxSessionDuration": True}),
        (validation.ROLE, {"tags": []}),
        (validation.ROLE, {"assumeRolePolicy": []}),
        (validation.INLINE, {"policy": '{"Statement":[null]}'}),
        (validation.POLICY, {"policy": '{"Statement":true}'}),
        (validation.POLICY, {"policy": '{"Statement":[],"Statement":[{}]}'}),
        (
            validation.VERSION,
            {
                "secretString": {
                    validation.SIGNATURE: validation.WIRE_VALUE_TAG,
                    "ciphertext": [],
                }
            },
        ),
    ],
)
def test_no_hidden_credential_policy_or_malformed_input(kind, updates):
    data = fixture()
    change(data, kind, updates)
    with pytest.raises(ValueError):
        validate(data)


def test_external_read_identity_is_not_an_unchecked_goal_exception():
    data = fixture()
    row = next(
        item
        for item in data["checkpoint"]["deployment"]["resources"]
        if item.get("external")
    )
    row["inputs"] = {}
    reset_noop(data)
    assert validate(data).changed_urns == ()
    step = next(item for item in data["preview"]["steps"] if item["urn"] == row["urn"])
    step["newState"]["id"] = data["catalog"]["operator_bindings"]["policy_read"][0]
    with pytest.raises(ValueError, match="preview-new-id"):
        validate(data)


def oidc_alias_fixture(environment="test"):
    """Use both existing OIDC component paths and the provider's .get inputs."""
    data = fixture(environment)
    rows = data["checkpoint"]["deployment"]["resources"]
    original = resource(data, validation.OIDC)
    rows.remove(original)
    root = resource(data, validation.STACK)["urn"]
    prefix = f"urn:pulumi:{environment}::github-ci-bootstrap::"
    for parent_type, parent_name, component_name in (
        (
            "bootstrap:ci:GitHubCiBootstrap",
            "github-ci-bootstrap",
            "github-ci-bootstrap-oidc",
        ),
        ("bootstrap:iam:PlatformControlIam", "platform-control-iam", "github-oidc"),
    ):
        parent = prefix + parent_type + "::" + parent_name
        qualified = parent_type + "$bootstrap:iam:GitHubOidcRoles"
        component = prefix + qualified + "::" + component_name
        for urn, kind, owner in (
            (parent, parent_type, root),
            (component, "bootstrap:iam:GitHubOidcRoles", parent),
        ):
            rows.append(
                {
                    "urn": urn,
                    "type": kind,
                    "custom": False,
                    "parent": owner,
                    "protect": False,
                }
            )
        alias = copy.deepcopy(original)
        alias.update(
            urn=prefix
            + qualified
            + "$"
            + validation.OIDC
            + "::"
            + component_name
            + "-provider",
            parent=component,
            external=True,
            protect=False,
            inputs={},
        )
        rows.append(alias)
    reset_noop(data)
    return data


@pytest.mark.parametrize("environment", ["test", "prod"])
def test_existing_oidc_read_aliases_remain_unchanged(environment):
    data = oidc_alias_fixture(environment)
    assert validate(data).changed_urns == ()


@pytest.mark.parametrize(
    "external_flags", [(False, False), (False, True), (True, False)]
)
def test_oidc_alias_cannot_duplicate_or_mix_ownership(external_flags):
    data = oidc_alias_fixture()
    aliases = [
        row
        for row in data["checkpoint"]["deployment"]["resources"]
        if row["type"] == validation.OIDC
    ]
    for row, external in zip(aliases, external_flags, strict=True):
        row.update(external=external, protect=not external)
    reset_noop(data)
    with pytest.raises(ValueError, match="duplicate-physical-owner"):
        validate(data)


def test_new_oidc_read_alias_is_not_admitted_from_preview():
    data = oidc_alias_fixture()
    data["checkpoint"]["deployment"]["resources"].remove(
        resource(data, validation.OIDC)
    )
    with pytest.raises(ValueError, match="complete-inventory"):
        validate(data)


@pytest.mark.parametrize(
    "field,value", [("id", "foreign-id"), ("parent", ""), ("external", False)]
)
def test_existing_oidc_alias_cannot_change_read_identity(field, value):
    data = oidc_alias_fixture()
    urn = resource(data, validation.OIDC)["urn"]
    step = next(row for row in data["preview"]["steps"] if row["urn"] == urn)
    step["newState"][field] = value
    with pytest.raises(ValueError):
        validate(data)


def role_read_aliases(data, external_flags):
    owner = resource(data, validation.ROLE)
    rows = data["checkpoint"]["deployment"]["resources"]
    position = rows.index(owner)
    rows.remove(owner)
    aliases = []
    managed_count = 0
    for index, external in enumerate(external_flags):
        row = copy.deepcopy(owner)
        if external:
            row.update(
                urn=owner["urn"] + f"-read-{index}",
                inputs={},
                external=True,
                protect=False,
            )
        else:
            if managed_count:
                row["urn"] += f"-second-owner-{index}"
            managed_count += 1
        aliases.append(row)
    rows[position:position] = aliases
    reset_noop(data)
    return aliases


@pytest.mark.parametrize("environment", ["test", "prod"])
@pytest.mark.parametrize("flags", [(False, True), (True, False), (True, False, True)])
def test_existing_role_owner_and_read_aliases_are_order_independent(environment, flags):
    data = fixture(environment)
    role_read_aliases(data, flags)
    before = copy.deepcopy(data)

    assert validate(data).changed_urns == ()
    assert data == before


@pytest.mark.parametrize(
    "flags", [(False, False), (False, True, False), (True, False, True, False)]
)
def test_role_reads_cannot_hide_a_second_managed_owner(flags):
    data = fixture()
    role_read_aliases(data, flags)
    with pytest.raises(ValueError, match="duplicate-physical-owner"):
        validate(data)


@pytest.mark.parametrize("field,value", [("id", "foreign-role"), ("external", False)])
def test_role_read_alias_preview_cannot_retarget_or_become_managed(field, value):
    data = fixture()
    _, alias = role_read_aliases(data, (False, True))
    preview = next(
        row for row in data["preview"]["steps"] if row["urn"] == alias["urn"]
    )
    preview["newState"][field] = value
    with pytest.raises(ValueError):
        validate(data)


def test_existing_role_read_alias_cannot_gain_a_saved_plan_goal():
    data = fixture()
    owner, alias = role_read_aliases(data, (False, True))
    data["plan"]["resourcePlans"][alias["urn"]] = copy.deepcopy(
        data["plan"]["resourcePlans"][owner["urn"]]
    )
    with pytest.raises(ValueError, match="external-plan-goal"):
        validate(data)


def test_existing_managed_role_cannot_reclassify_itself_as_read_only():
    data = fixture()
    owner, _ = role_read_aliases(data, (False, True))
    data["plan"]["resourcePlans"][owner["urn"]]["goal"]["external"] = True
    with pytest.raises(ValueError):
        validate(data)


@pytest.mark.parametrize("retain_old_owner", [False, True])
def test_role_reference_cannot_be_claimed_by_a_new_managed_urn(retain_old_owner):
    data = fixture()
    owner, alias = role_read_aliases(data, (False, True))
    resources = {alias["urn"]: alias}
    if retain_old_owner:
        resources[owner["urn"]] = owner
    new = copy.deepcopy(owner)
    new["urn"] += "-new-owner"
    with pytest.raises(ValueError, match="external-target-ownership"):
        validation._target_ownership(resources, {new["urn"]: new}, data["catalog"])


def test_existing_role_reference_is_not_itself_a_prior_managed_owner():
    data = fixture()
    owner, alias = role_read_aliases(data, (False, True))
    new = copy.deepcopy(owner)
    new["urn"] = alias["urn"]
    with pytest.raises(ValueError, match="external-target-ownership"):
        validation._target_ownership(
            {alias["urn"]: alias}, {alias["urn"]: new}, data["catalog"]
        )


def test_role_physical_alias_must_keep_canonical_target():
    data = fixture()
    owner, alias = role_read_aliases(data, (False, True))
    identities = {}
    target = validation._target(owner, data["catalog"])
    validation._physical_owner(owner, target, identities, data["catalog"])
    with pytest.raises(ValueError, match="physical-alias-target"):
        validation._physical_owner(
            alias, (target[0] + "-other",), identities, data["catalog"]
        )


def test_role_alias_compatibility_does_not_include_read_only_catalog_principals():
    data = fixture()
    owner, alias = role_read_aliases(data, (False, True))
    read_only = next(
        arn
        for arn in data["catalog"]["operator_bindings"]["role_read"]
        if arn not in data["catalog"]["operator_bindings"]["role_write"]
    )
    identities = {}
    validation._physical_owner(owner, (read_only,), identities, data["catalog"])
    with pytest.raises(ValueError, match="duplicate-physical-owner"):
        validation._physical_owner(alias, (read_only,), identities, data["catalog"])


def test_existing_role_owner_target_cannot_change_under_read_alias():
    data = fixture()
    owner, alias = role_read_aliases(data, (False, True))
    other = next(
        arn
        for arn in data["catalog"]["operator_bindings"]["role_write"]
        if arn != validation._target(owner, data["catalog"])[0]
    )
    assert not validation._retained_role_owner(
        owner["urn"], (validation.ROLE, other), {owner["urn"]: owner}, data["catalog"]
    )


def test_new_owned_policy_cannot_capture_existing_external_target():
    data = fixture()
    prior = resource(data, validation.POLICY)
    rows = data["checkpoint"]["deployment"]["resources"]
    rows.remove(prior)
    alias = copy.deepcopy(prior)
    alias.update(urn=prior["urn"] + "-read", external=True, protect=False, inputs={})
    rows.append(alias)
    goal = data["plan"]["resourcePlans"][prior["urn"]]
    goal["steps"] = ["create"]
    goal["goal"]["inputDiff"] = {"adds": prior["inputs"]}
    data["preview"]["steps"] = [
        row for row in data["preview"]["steps"] if row["urn"] != prior["urn"]
    ]
    new = copy.deepcopy(prior)
    new.pop("id")
    append_preview(data["preview"], None, new, "create")
    append_preview(data["preview"], alias, alias, "read")
    with pytest.raises(ValueError, match="external-target-ownership"):
        validate(data)


def test_external_role_provider():
    data = fixture()
    row = resource(data, validation.ROLE)
    row.update(external=True, protect=False, inputs={})
    provider = resource(data, validation.PROVIDER)
    old_urn = provider["urn"]
    provider["urn"] = old_urn.replace("default_7_23_0", "fixed-provider")
    for item in data["checkpoint"]["deployment"]["resources"]:
        if item.get("provider"):
            item["provider"] = item["provider"].replace(old_urn, provider["urn"])
    reset_noop(data)
    assert validate(data).changed_urns == ()


def test_harmless_refresh_is_bound_to_supplied_checkpoint():
    data = fixture()
    old = resource(data, validation.ROLE)
    append_preview(data["preview"], old, old, "refresh")
    assert validate(data).changed_urns == ()
    data["preview"]["steps"][-1]["newState"]["outputs"]["description"] = (
        "unobserved-drift"
    )
    with pytest.raises(ValueError, match="refresh-drift"):
        validate(data)


def test_pinned_delete_before_create_plan_and_replacement_markers():
    data = fixture()
    ops = ("delete-replaced", "replace", "create-replacement")
    new = change(
        data,
        validation.VERSION,
        {
            "secretString": {
                validation.SIGNATURE: validation.WIRE_VALUE_TAG,
                "plaintext": '"synthetic"',
            }
        },
        ops,
    )
    goal = data["plan"]["resourcePlans"][new["urn"]]["goal"]
    goal["inputDiff"] = {"adds": new["inputs"]}
    goal["deleteBeforeReplace"] = True
    for step in data["preview"]["steps"]:
        if step["urn"] == new["urn"] and step["op"] in {"delete-replaced", "replace"}:
            step["oldState"]["delete"] = True
    assert validate(data).changed_urns == (new["urn"],)


@pytest.mark.parametrize("environment", ["test", "prod"])
@pytest.mark.parametrize("legacy", [False, True])
def test_plan_keeps_safe_config_and_project_secret_values(environment, legacy):
    data = fixture(environment)
    prefix = "aws:config:" if legacy else "aws:"
    data["plan"]["config"] = {
        prefix + "region": data["catalog"]["region"],
        prefix + "allowedAccountIds": [data["catalog"]["account_id"]],
        "github-ci-bootstrap:writeSecretValues": True,
        "github-ci-bootstrap:ciConfig": {"secure": "synthetic-encrypted-setting"},
    }
    assert validate(data).changed_urns == ()


@pytest.mark.parametrize("legacy", [False, True])
@pytest.mark.parametrize(
    "option",
    [
        "accessKey",
        "secretKey",
        "token",
        "profile",
        "assumeRole",
        "assumeRoles",
        "assumeRoleWithWebIdentity",
        "endpoints",
        "sharedCredentialsFiles",
        "sharedConfigFiles",
        "httpProxy",
        "insecure",
        "s3UsePathStyle",
    ],
)
def test_plan_config_cannot_redirect_provider_or_credentials(option, legacy):
    data = fixture()
    prefix = "aws:config:" if legacy else "aws:"
    data["plan"]["config"] = {prefix + option: "synthetic-denied-setting"}
    with pytest.raises(ValueError, match="credential-or-endpoint"):
        validate(data)


@pytest.mark.parametrize(
    "config",
    [
        None,
        [],
        {1: "value"},
        {"aws": {}},
        {"aws:config:region:extra": "value"},
        {"aws:version": "other"},
        {"aws:__defaults": []},
        {"other:profile": "value"},
        {"aws:region": "eu-central-1", "aws:config:region": "eu-central-1"},
        {"aws:region": "us-east-1"},
        {"aws:region": {"secure": "hidden"}},
        {"aws:allowedAccountIds": ["933245420672"]},
        {"aws:skipCredentialsValidation": True},
        {"aws:skipRegionValidation": "true"},
        {"aws:skipRequestingAccountId": True},
    ],
)
def test_ambiguous_config_and_account_overrides_fail(config):
    data = fixture()
    data["plan"]["config"] = config
    with pytest.raises(ValueError):
        validate(data)


def test_config_key_type_is_checked_before_regex():
    with pytest.raises(ValueError, match="operator-config-key"):
        validation.validate_operator_configuration(
            {1: "value"}, account_id="891377212104", region="eu-central-1"
        )


def test_full_new_values_and_precise_diff_diagnostics():
    data = fixture()
    change(
        data,
        validation.POLICY,
        {"policy": '{"Statement":{"Effect":"Deny","Action":"*","Resource":"*"}}'},
    )
    step = data["preview"]["steps"][-1]
    step.update(
        diffReasons=["policy"],
        replaceReasons=[],
        detailedDiff={"policy": {"kind": "update", "inputDiff": True}},
    )
    data["preview"].update(
        duration=1,
        diagnostics=[{"severity": "warning", "message": "synthetic warning"}],
    )
    data["plan"]["manifest"]["plugins"] = []
    assert validate(data).changed_urns


@pytest.mark.parametrize("payload", [b'{"x":1e10000}', b"[" * 2000 + b"]" * 2000])
def test_numeric_and_deep_json_are_bounded(payload):
    data = fixture()
    with pytest.raises(ValueError):
        validation.validate_operator_plan(
            payload,
            encoded(data["preview"]),
            encoded(data["checkpoint"]),
            catalog=data["catalog"],
        )


def test_json_decoder_preserves_finite_fractional_values():
    assert validation._decode(b'{"value":0.125}') == {"value": 0.125}


@pytest.mark.parametrize(
    ("field", "value"),
    [
        (field, value)
        for field in ("goal", "steps", "state")
        for value in (None, True, 4, "bad")
        if (field, value) != ("state", None)
    ],
)
def test_wrong_nested_plan_types_are_categorical(field, value):
    data = fixture()
    data["plan"]["resourcePlans"][data["role"]][field] = value
    with pytest.raises(ValueError):
        validate(data)


def test_private_error_redaction(capsys):
    data = fixture()
    change(data, validation.POLICY, {"policy": "synthetic-sensitive-marker"})
    with pytest.raises(ValueError) as error:
        validate(data)
    assert "synthetic-sensitive-marker" not in str(error.value)
    assert capsys.readouterr().out == ""


def test_validation_performs_no_file_reads(monkeypatch):
    data = fixture()

    def forbidden(*args, **kwargs):
        raise AssertionError("unexpected IO")

    monkeypatch.setattr("builtins.open", forbidden)
    assert validate(data).changed_urns == ()


def test_component_parent_and_property_dependencies_remain_closed():
    data = fixture()
    root = resource(data, validation.STACK)["urn"]
    component_type = "bootstrap:infra:ControlComponent"
    component_urn = (
        root.replace(validation.STACK, component_type).rsplit("::", 1)[0] + "::controls"
    )
    data["checkpoint"]["deployment"]["resources"].append(
        {
            "urn": component_urn,
            "type": component_type,
            "custom": False,
            "parent": root,
            "inputs": {},
            "outputs": {},
            "protect": False,
        }
    )
    row = resource(data, validation.ROLE)
    row["urn"] = row["urn"].replace(
        validation.ROLE, component_type + "$" + validation.ROLE
    )
    row["parent"] = component_urn
    row["dependencies"] = [component_urn]
    row["propertyDependencies"] = {"name": [resource(data, validation.PROVIDER)["urn"]]}
    reset_noop(data)
    assert validate(data).changed_urns == ()
    row["propertyDependencies"]["name"] = [
        "urn:pulumi:prod::foreign::aws:iam/role:Role::foreign"
    ]
    reset_noop(data)
    with pytest.raises(ValueError, match="foreign-dependency"):
        validate(data)


@pytest.mark.parametrize("value", [None, True, [], 1])
def test_malformed_input_diff_is_normalized_without_source_data(value):
    data = fixture()
    data["plan"]["resourcePlans"][data["role"]]["goal"]["inputDiff"] = value
    with pytest.raises(ValueError):
        validate(data)


@pytest.mark.parametrize("option", ["endpoints", "accessKey", "assumeRoles", "profile"])
def test_provider_cannot_redirect_credentials_or_api(option):
    data = fixture()
    resource(data, validation.PROVIDER)["inputs"][option] = "synthetic-redirect"
    reset_noop(data)
    with pytest.raises(ValueError, match="provider-credential-or-endpoint-option"):
        validate(data)


def test_default_provider_goal_cannot_be_missing_or_changed():
    data = fixture()
    urn = resource(data, validation.PROVIDER)["urn"]
    assert all(step["urn"] != urn for step in data["preview"]["steps"])
    data["plan"]["resourcePlans"].pop(urn)
    with pytest.raises(ValueError, match="complete-inventory"):
        validate(data)


def test_plan_plaintext_secret_cannot_be_disguised_as_same():
    data = fixture()
    change(
        data,
        validation.VERSION,
        {
            "secretString": {
                validation.SIGNATURE: validation.WIRE_VALUE_TAG,
                "plaintext": '"different-synthetic"',
            }
        },
        ("same",),
    )
    with pytest.raises(ValueError, match="same-input-diff"):
        validate(data)


def test_guard_management_field_cannot_disappear():
    data = fixture()
    row = resource(data, validation.ROLE)
    principal = next(
        item
        for item in data["catalog"]["principals"]
        if item["arn"] == row["outputs"]["arn"]
    )
    row["inputs"]["managedPolicyArns"] = principal["attachment_arns"]
    reset_noop(data)
    new = change(data, validation.ROLE, {})
    new["inputs"].pop("managedPolicyArns")
    goal = data["plan"]["resourcePlans"][row["urn"]]["goal"]
    goal["inputDiff"] = {"deletes": ["managedPolicyArns"]}
    data["preview"]["steps"][-1]["newState"] = redact(new)
    with pytest.raises(ValueError, match="role-guard-management-removal"):
        validate(data)


def test_protected_attachment_cannot_be_replaced():
    data = fixture()
    resource(data, validation.ATTACHMENT)["protect"] = True
    reset_noop(data)
    change(
        data,
        validation.ATTACHMENT,
        {"policyArn": data["catalog"]["operator_bindings"]["policy_write"][1]},
        ("create-replacement", "replace", "delete-replaced"),
    )
    with pytest.raises(ValueError, match="protected-resource-deletion"):
        validate(data)


def test_payload_size_limit_and_wrong_payload_types(monkeypatch):
    data = fixture()
    monkeypatch.setattr(validation, "MAX_DOCUMENT_BYTES", 1)
    with pytest.raises(ValueError, match="document-size"):
        validate(data)
    with pytest.raises(ValueError, match="document-size"):
        validation.validate_operator_plan(
            cast(bytes, "synthetic"), b"{}", b"{}", catalog=data["catalog"]
        )


def test_empty_steps_and_secret_declassification_are_rejected():
    data = fixture()
    data["plan"]["resourcePlans"][data["role"]]["steps"] = []
    with pytest.raises(ValueError, match="plan-steps"):
        validate(data)
    data = fixture()
    resource(data, validation.ROLE)["additionalSecretOutputs"] = ["sensitiveMetadata"]
    with pytest.raises(ValueError, match="secret-output-declassification"):
        validate(data)


def test_existing_secret_replica_shape_is_validated_without_widening_writes():
    data = fixture()
    resource(data, validation.SECRET)["inputs"]["replicas"] = [
        {"region": "eu-west-1", "kmsKeyId": "synthetic-key-reference"}
    ]
    reset_noop(data)
    assert validate(data).changed_urns == ()
    change(data, validation.SECRET, {"replicas": [{"region": "eu-west-2"}]})
    with pytest.raises(ValueError, match="unsupported-input-change"):
        validate(data)


def test_operation_needs_resource():
    with pytest.raises(ValueError, match="missing-operation-resource"):
        validation._operation(None, None, ("delete",), {})


def test_refresh_needs_checkpoint():
    with pytest.raises(ValueError, match="refresh-absent-resource"):
        validation._preview_resource([{"op": "refresh"}], None, None, (), {})
