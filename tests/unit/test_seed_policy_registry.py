"""Independent seed enrollment rejects incomplete or widened policy inventories."""

import copy
import json
from dataclasses import replace
from fnmatch import fnmatchcase
from typing import cast

import pytest
from seed import policy_registry as registry

# Synthetic unit-test metadata only; never a proposed or installed seed key.
TEST_KEY_ID = "9f610284-127a-4abc-a612-8d638bec729a"


def key_for(environment="test"):
    """Return explicitly synthetic public metadata for pure offline tests."""
    account = registry.ACCOUNTS[environment]
    return registry.SeedKeyBinding(
        f"arn:aws:kms:{registry.REGION}:{account}:key/{TEST_KEY_ID}",
        TEST_KEY_ID,
        account,
        "CUSTOMER",
        "Enabled",
        "ENCRYPT_DECRYPT",
    )


def build(environment="test", **kwargs):
    """Build a complete registry without AWS, Pulumi or credential dependencies."""
    return registry.build_registry(
        environment,
        account_id=registry.ACCOUNTS[environment],
        seed_key=key_for(environment),
        **kwargs,
    )


def observation_for(expected):
    """Model a complete initial metadata observation with disabled executor trust."""
    policies = tuple(
        registry.ObservedPolicy(p.arn, "v1", p.document_json) for p in expected.policies
    )
    roles = tuple(
        registry.ObservedPrincipal(
            p.arn,
            p.boundary_arn,
            p.attachment_arns,
            p.frozen_config.trust_json
            if p.frozen_config
            else registry.canonical_json(registry.DISABLED_TRUST),
            p.frozen_config.inline_policies if p.frozen_config else (),
        )
        for p in expected.principals
    )
    frozen = next(p.frozen_config for p in expected.principals if p.frozen_config)
    aws_policy = registry.ObservedAwsManagedPolicy(
        frozen.aws_policy_arn,
        frozen.aws_policy_version,
        frozen.aws_policy_sha256,
    )
    return registry.EnrollmentObservation(
        expected.account_id,
        expected.seed_key,
        policies,
        roles,
        (aws_policy,),
    )


@pytest.mark.parametrize("environment", ["test", "prod"])
def test_complete_deterministic_inventory_and_disabled_enrollment(environment):
    expected = build(environment)
    assert expected == build(environment)
    assert expected.sha256 == build(environment).sha256
    assert len(expected.principals) == 24
    assert sum(p.existing for p in expected.principals) == 21
    assert len(expected.policies) == 55
    assert sum(p.kind == "purpose_capability_boundary" for p in expected.policies) == 8
    old = [p for p in expected.policies if p.installed_arn]
    assert len(old) == 6
    assert all(p.ownership == "existing_operator_policy_transfer_to_seed" for p in old)
    assert all(len(p.document_json) <= 6144 for p in expected.policies)
    assert max(len(p.attachment_arns) for p in expected.principals) == 10
    assert all('"Ref"' not in p.document_json for p in expected.policies)
    assert all(
        p.sha256 == registry.document_hash(json.loads(p.document_json))
        for p in expected.policies
    )
    result = registry.verify_enrollment(expected, observation_for(expected))
    assert (
        result.policies_verified,
        result.principals_verified,
        result.disabled_executors_verified,
    ) == (55, 24, 3)
    assert result.registry_sha256 == expected.sha256
    assert result.activation_authorized is False


@pytest.mark.parametrize("environment", ["test", "prod"])
def test_executor_and_config_envelopes_remain_exact(environment):
    expected = build(environment)
    executors = [p for p in expected.principals if not p.existing]
    assert sorted(len(p.attachment_arns) for p in executors) == [5, 5, 7]
    assert all(p.owner_project == "independent_seed" for p in executors)
    config = next(p for p in expected.principals if p.frozen_config)
    assert config.boundary_arn is None
    assert config.owner_project == "github-ci-bootstrap"
    assert len(config.attachment_arns) == 2
    assert len(config.frozen_config.inline_policies) == 1
    assert "s3:PutObject" in config.frozen_config.inline_policies[0][1]
    assert config.frozen_config.aws_policy_version == "v72"
    assert all(set(p.guard_arns) <= set(p.attachment_arns) for p in expected.principals)


def matches_action(statement, action):
    """Match only IAM action selectors; unrelated actions cannot trigger a guard."""
    values = statement.get("Action", statement.get("NotAction"))
    patterns = [values] if isinstance(values, str) else values
    matched = any(fnmatchcase(action.lower(), pattern.lower()) for pattern in patterns)
    return not matched if "NotAction" in statement else matched


@pytest.mark.parametrize("environment", ["test", "prod"])
@pytest.mark.parametrize("purpose", ["Preview", "Apply", "Drift"])
def test_policy_gate_permission_respects_executor_purpose(environment, purpose):
    expected = build(environment)
    policies = {p.arn: json.loads(p.document_json) for p in expected.policies}
    executor = next(
        p
        for p in expected.principals
        if p.arn.endswith(f"/GitHubOperator{purpose}-{environment}")
    )
    identity = next(arn for arn in executor.attachment_arns if "/identity/" in arn)
    action = "access-analyzer:ValidatePolicy"
    for arn in (executor.boundary_arn, identity):
        grants = [s for s in policies[arn]["Statement"] if matches_action(s, action)]
        assert grants == (
            []
            if purpose == "Drift"
            else [
                {
                    "Effect": "Allow",
                    "Resource": "*",
                    "Action": ["sts:GetCallerIdentity", "kms:ListAliases", action],
                }
            ]
        )
    blockers = [
        s
        for arn in executor.guard_arns
        for s in policies[arn]["Statement"]
        if matches_action(s, action)
    ]
    if purpose == "Drift":
        assert len(blockers) == 1
        assert set(blockers[0]) == {"Effect", "NotAction", "Resource"}
        assert blockers[0]["Effect"] == "Deny" and blockers[0]["Resource"] == "*"
    else:
        # No guard's action selector matches, independent of resource or context.
        assert blockers == []
    closed = policies[
        next(a for a in executor.guard_arns if a.endswith("-closed-actions"))
    ]["Statement"][0]
    for unrelated in (
        "access-analyzer:CreateAnalyzer",
        "access-analyzer:StartPolicyGeneration",
        "access-analyzer:CheckNoNewAccess",
    ):
        assert matches_action(closed, unrelated)
        assert not any(
            matches_action(s, unrelated)
            for arn in (executor.boundary_arn, identity)
            for s in policies[arn]["Statement"]
        )


@pytest.mark.parametrize("environment", ["test", "prod"])
def test_catalog_amendment_is_exactly_policy_gate_permission(environment):
    """Removing the documented delta reproduces the entire prior pinned catalog."""
    catalog = registry.load_catalog(environment)
    action = "access-analyzer:ValidatePolicy"
    changed = []
    for arn, policy in catalog["policies"].items():
        if not any(f"GitHubOperator{p}" in arn for p in ("Preview", "Apply")):
            continue
        if policy["kind"] not in {
            "executor_boundary",
            "executor_identity",
        } and not arn.endswith("-closed-actions"):
            continue
        statements = [
            copy.deepcopy(catalog["statements"][k]) for k in policy["statement_ids"]
        ]
        for statement in statements:
            selector = "NotAction" if "NotAction" in statement else "Action"
            if action in statement[selector]:
                statement[selector].remove(action)
                changed.append(arn)
        policy["statement_ids"] = [registry.document_hash(s) for s in statements]
        catalog["statements"].update(
            zip(policy["statement_ids"], statements, strict=True)
        )
        policy["template_sha256"] = registry.document_hash(
            {"Version": "2012-10-17", "Statement": statements}
        )
    assert len(changed) == len(set(changed)) == 6
    used = {s for p in catalog["policies"].values() for s in p["statement_ids"]}
    catalog["statements"] = {
        k: v for k, v in catalog["statements"].items() if k in used
    }
    amendment = catalog["provenance"].pop("executor_amendments")
    assert amendment[0]["action"] == action
    assert amendment[0]["purposes"] == ["preview", "apply"]
    baseline = {
        "test": "9cba41674f977e36c6e1793f7480effecd8c98577da03a7f404e7e001c22e6f7",
        "prod": "6ba8eb8430269ce57bc31f22c2654b06788209bc23879ce7a962096b52d5c0d9",
    }
    assert registry.document_hash(catalog) == baseline[environment]


@pytest.mark.parametrize("environment", ["other", "../test", "TEST"])
def test_unknown_environment_never_selects_arbitrary_catalog(environment):
    with pytest.raises(registry.RegistryError, match="Unknown seed environment"):
        registry.load_catalog(environment)
    with pytest.raises(registry.RegistryError, match="Unknown seed environment"):
        registry.build_registry(
            environment, account_id="891377212104", seed_key=key_for()
        )


def test_account_mismatch_and_absent_binding_rejected():
    with pytest.raises(registry.RegistryError, match="account/environment"):
        registry.build_registry(
            "test", account_id=registry.ACCOUNTS["prod"], seed_key=key_for()
        )
    with pytest.raises(registry.RegistryError, match="Explicit seed KMS"):
        registry.build_registry(
            "test",
            account_id=registry.ACCOUNTS["test"],
            seed_key=cast(registry.SeedKeyBinding, None),
        )


@pytest.mark.parametrize(
    "change,message",
    [
        (
            {"arn": "arn:aws:kms:eu-west-1:891377212104:key/" + TEST_KEY_ID},
            "ARN/account",
        ),
        ({"aws_account_id": "933245420672"}, "metadata account"),
        ({"key_manager": "AWS"}, "enabled customer"),
        ({"key_state": "Disabled"}, "enabled customer"),
        ({"key_usage": "SIGN_VERIFY"}, "enabled customer"),
    ],
)
def test_invalid_key_metadata_fails(change, message):
    with pytest.raises(registry.RegistryError, match=message):
        registry.build_registry(
            "test",
            account_id=registry.ACCOUNTS["test"],
            seed_key=replace(key_for(), **change),
        )


@pytest.mark.parametrize(
    "key_id,message",
    [
        ("PLACEHOLDER", "exact key ID"),
        ("alias/seed", "exact key ID"),
        ("00000000-0000-4000-8000-000000000001", "Placeholder"),
        ("12345678-1234-4321-8234-123456789abc", "Placeholder"),
        ("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "Placeholder"),
    ],
)
def test_placeholder_and_alias_bindings_rejected(key_id, message):
    key = replace(
        key_for(),
        key_id=key_id,
        arn=f"arn:aws:kms:eu-central-1:891377212104:key/{key_id}",
    )
    with pytest.raises(registry.RegistryError, match=message):
        registry.build_registry(
            "test", account_id=registry.ACCOUNTS["test"], seed_key=key
        )


def test_routine_key_cannot_be_reused_and_real_shape_mrk_supported():
    catalog = registry.load_catalog("test")
    arn = catalog["operator_bindings"]["backend_key"]
    key = replace(key_for(), arn=arn, key_id=arn.rsplit("/", 1)[1])
    with pytest.raises(registry.RegistryError, match="reuse a routine key"):
        registry.build_registry(
            "test", account_id=registry.ACCOUNTS["test"], seed_key=key
        )
    key_id = "mrk-9f610284127a4abca6128d638bec729a"
    key = replace(
        key_for(),
        key_id=key_id,
        arn=f"arn:aws:kms:eu-central-1:891377212104:key/{key_id}",
    )
    assert (
        registry.build_registry(
            "test", account_id=registry.ACCOUNTS["test"], seed_key=key
        ).seed_key
        == key
    )


@pytest.mark.parametrize("change", ["role", "guard", "boundary", "policy", "account"])
def test_catalog_changes_require_separate_review(change):
    catalog = registry.load_catalog("test")
    if change == "role":
        catalog["principals"].pop()
    elif change == "guard":
        catalog["principals"][0]["guard_arns"] = []
    elif change == "boundary":
        catalog["principals"][0]["boundary_arn"] = None
    elif change == "policy":
        catalog["policies"].pop(next(iter(catalog["policies"])))
    else:
        catalog["account_id"] = registry.ACCOUNTS["prod"]
    with pytest.raises(registry.RegistryError, match="Catalog changed"):
        build(catalog=catalog)


def test_unknown_reference_and_oversized_policy_fail_even_in_builder():
    with pytest.raises(registry.RegistryError, match="Unknown seed policy binding"):
        registry._bind({"Ref": "UnreviewedKey"}, key_for().arn)
    catalog = registry.load_catalog("test")
    arn, policy = next(iter(catalog["policies"].items()))
    bad_hash = copy.deepcopy(policy)
    bad_hash["template_sha256"] = "0" * 64
    with pytest.raises(registry.RegistryError, match="Policy template hash"):
        registry._policy(arn, bad_hash, catalog, key_for().arn)
    statement = {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "x" * 6200}
    catalog["statements"]["large"] = statement
    large = dict(
        policy,
        statement_ids=["large"],
        template_sha256=registry.document_hash(
            {"Version": "2012-10-17", "Statement": [statement]}
        ),
    )
    with pytest.raises(registry.RegistryError, match="exceeds 6144"):
        registry._policy(arn, large, catalog, key_for().arn)


@pytest.mark.parametrize(
    "change,message",
    [
        ({"guard_arns": ()}, "Missing required guard"),
        ({"attachment_arns": ()}, "Missing required guard"),
        ({"boundary_arn": None}, "Unbounded non-Config"),
    ],
)
def test_invalid_principal_closure_is_rejected(change, message):
    expected = build()
    policies = {p.arn: p for p in expected.policies}
    with pytest.raises(registry.RegistryError, match=message):
        registry._validate_principal(
            replace(expected.principals[0], **change), policies
        )


def test_guard_kind_boundary_kind_duplicate_and_attachment_quota():
    expected = build()
    policies = {p.arn: p for p in expected.policies}
    role = expected.principals[0]
    guard = role.guard_arns[0]
    with pytest.raises(registry.RegistryError, match="Attachment quota"):
        registry._validate_principal(
            replace(
                role,
                attachment_arns=role.attachment_arns
                + ("arn:aws:iam::891377212104:policy/extra",),
            ),
            policies,
        )
    with pytest.raises(registry.RegistryError, match="Duplicate guard"):
        registry._validate_principal(replace(role, guard_arns=(guard, guard)), policies)
    changed = dict(
        policies, **{guard: replace(policies[guard], kind="executor_identity")}
    )
    with pytest.raises(registry.RegistryError, match="not a managed deny"):
        registry._validate_principal(role, changed)
    with pytest.raises(registry.RegistryError, match="Boundary kind"):
        registry._validate_principal(replace(role, boundary_arn=guard), policies)


@pytest.mark.parametrize(
    "field,message",
    [
        ("policies", "Observed policy inventory"),
        ("principals", "Observed role inventory"),
        ("aws_managed_policies", "Observed Config AWS policy set"),
    ],
)
def test_missing_observed_inventory_fails(field, message):
    expected = build()
    observed = observation_for(expected)
    with pytest.raises(registry.RegistryError, match=message):
        registry.verify_enrollment(expected, replace(observed, **{field: ()}))


@pytest.mark.parametrize("field", ["policies", "principals", "aws_managed_policies"])
def test_duplicate_observed_inventory_fails(field):
    expected = build()
    observed = observation_for(expected)
    values = getattr(observed, field)
    with pytest.raises(registry.RegistryError, match="Duplicate observed"):
        registry.verify_enrollment(
            expected, replace(observed, **{field: values + values})
        )


def test_observation_account_key_and_registry_substitution_fail():
    expected = build()
    observed = observation_for(expected)
    with pytest.raises(registry.RegistryError, match="Observation account"):
        registry.verify_enrollment(
            expected, replace(observed, account_id="933245420672")
        )
    with pytest.raises(registry.RegistryError, match="KMS binding changed"):
        registry.verify_enrollment(
            expected, replace(observed, seed_key=key_for("prod"))
        )
    with pytest.raises(registry.RegistryError, match="Rendered registry changed"):
        registry.verify_enrollment(replace(expected, principals=()), observed)


@pytest.mark.parametrize(
    "change,message",
    [
        ({"document_json": '{"Version":"2012-10-17","Statement":[]}'}, "document hash"),
        ({"default_version_id": "default"}, "Invalid observed default"),
    ],
)
def test_guard_document_or_default_version_is_verified(change, message):
    expected = build()
    observed = observation_for(expected)
    policy = next(p for p in observed.policies if "/guard/" in p.arn)
    changed = tuple(
        replace(p, **change) if p.arn == policy.arn else p for p in observed.policies
    )
    with pytest.raises(registry.RegistryError, match=message):
        registry.verify_enrollment(expected, replace(observed, policies=changed))


@pytest.mark.parametrize(
    "change,message",
    [
        ({"boundary_arn": None}, "boundary mismatch"),
        ({"attachment_arns": ()}, "required guard is missing"),
        (
            {"trust_json": '{"Version":"2012-10-17","Statement":[]}'},
            "trust is not disabled",
        ),
        ({"inline_policies": (("admin", "{}"),)}, "Unexpected new executor inline"),
    ],
)
def test_executor_cannot_be_enrolled_with_partial_guards_or_enabled_trust(
    change, message
):
    expected = build()
    observed = observation_for(expected)
    arn = next(p.arn for p in expected.principals if not p.existing)
    roles = tuple(
        replace(p, **change) if p.arn == arn else p for p in observed.principals
    )
    with pytest.raises(registry.RegistryError, match=message):
        registry.verify_enrollment(expected, replace(observed, principals=roles))


def test_duplicate_role_attachment_rejected():
    expected = build()
    observed = observation_for(expected)
    role = observed.principals[0]
    roles = (
        replace(role, attachment_arns=role.attachment_arns * 2),
    ) + observed.principals[1:]
    with pytest.raises(registry.RegistryError, match="Duplicate observed attachment"):
        registry.verify_enrollment(expected, replace(observed, principals=roles))


@pytest.mark.parametrize(
    "change,message",
    [
        ({"trust_json": "{}"}, "Config trust changed"),
        ({"inline_policies": ()}, "complete inline grants"),
    ],
)
def test_config_full_trust_and_inline_grants_frozen(change, message):
    expected = build()
    observed = observation_for(expected)
    arn = next(p.arn for p in expected.principals if p.frozen_config)
    roles = tuple(
        replace(p, **change) if p.arn == arn else p for p in observed.principals
    )
    with pytest.raises(registry.RegistryError, match=message):
        registry.verify_enrollment(expected, replace(observed, principals=roles))


@pytest.mark.parametrize(
    "change,message",
    [
        ({"default_version_id": "v73"}, "version requires enrollment review"),
        ({"document_sha256": "0" * 64}, "AWS-managed policy document changed"),
    ],
)
def test_config_complete_aws_managed_grant_checked_by_observed_digest(change, message):
    expected = build()
    observed = observation_for(expected)
    changed = replace(observed.aws_managed_policies[0], **change)
    with pytest.raises(registry.RegistryError, match=message):
        registry.verify_enrollment(
            expected, replace(observed, aws_managed_policies=(changed,))
        )


def active_observation_for(expected):
    """Supply exact active trust while preserving complete observed IAM metadata."""
    observed = observation_for(expected)
    principals = {p.arn: p for p in expected.principals}
    roles = tuple(
        replace(
            p, trust_json=registry._active_executor_trust(expected, principals[p.arn])
        )
        if not principals[p.arn].existing
        else p
        for p in observed.principals
    )
    return replace(observed, principals=roles)


@pytest.mark.parametrize("environment", ["test", "prod"])
def test_initial_and_active_verifiers_have_distinct_trust_contracts(environment):
    expected = build(environment)
    initial, active = observation_for(expected), active_observation_for(expected)
    assert (
        registry.verify_enrollment(expected, initial).disabled_executors_verified == 3
    )
    result = registry.verify_active_enrollment(expected, active)
    assert (
        result.policies_verified,
        result.principals_verified,
        result.active_executors_verified,
    ) == (55, 24, 3)
    assert result.registry_sha256 == expected.sha256
    assert result.activation_authorized is False
    with pytest.raises(registry.RegistryError, match="Active executor trust changed"):
        registry.verify_active_enrollment(expected, initial)
    with pytest.raises(registry.RegistryError, match="trust is not disabled"):
        registry.verify_enrollment(expected, active)


@pytest.mark.parametrize("environment", ["test", "prod"])
def test_current_mutable_grants_can_change_only_inside_each_project_catalog(
    environment,
):
    expected = build(environment)
    observed = active_observation_for(expected)
    permitted = registry._mutable_attachment_sets(expected)
    assert len(permitted) == 14
    by_arn = {p.arn: p for p in expected.principals}
    for arn, allowed in permitted.items():
        role = by_arn[arn]
        assert len(allowed) == (2 if role.owner_project == "governance" else 26)
        for policy in allowed:
            roles = tuple(
                replace(p, attachment_arns=role.guard_arns + (policy,))
                if p.arn == arn
                else p
                for p in observed.principals
            )
            assert (
                registry.verify_active_enrollment(
                    expected, replace(observed, principals=roles)
                ).active_executors_verified
                == 3
            )
    # Removal of mutable grants is allowed without removing the immutable guard.
    arn = expected.principals[0].arn
    roles = tuple(
        replace(p, attachment_arns=by_arn[arn].guard_arns) if p.arn == arn else p
        for p in observed.principals
    )
    assert registry.verify_active_enrollment(
        expected, replace(observed, principals=roles)
    )
    with pytest.raises(registry.RegistryError, match="attachment set changed"):
        registry.verify_enrollment(expected, replace(observed, principals=roles))


@pytest.mark.parametrize(
    "owner,foreign",
    [
        ("github-ci-bootstrap", "service"),
        ("governance", "operator"),
        ("governance", "foreign-account"),
        ("github-ci-bootstrap", "administrator"),
        ("governance", "unlisted-policy"),
    ],
)
def test_cross_project_or_unknown_mutable_attachments_are_rejected(owner, foreign):
    expected = build()
    observed = active_observation_for(expected)
    permitted = registry._mutable_attachment_sets(expected)
    role = next(
        p
        for p in expected.principals
        if p.owner_project == owner and p.arn in permitted
    )
    operator = next(
        p
        for p in expected.principals
        if p.owner_project == "github-ci-bootstrap" and p.arn in permitted
    )
    service = next(
        p
        for p in expected.principals
        if p.owner_project == "governance" and p.arn in permitted
    )
    candidates = {
        "service": next(iter(permitted[service.arn])),
        "operator": next(iter(permitted[operator.arn])),
        "foreign-account": next(iter(permitted[service.arn])).replace(
            expected.account_id, "111122223333"
        ),
        "administrator": "arn:aws:iam::aws:policy/AdministratorAccess",
        "unlisted-policy": (
            f"arn:aws:iam::{expected.account_id}:policy/new-service-policy"
        ),
    }
    roles = tuple(
        replace(p, attachment_arns=role.guard_arns + (candidates[foreign],))
        if p.arn == role.arn
        else p
        for p in observed.principals
    )
    with pytest.raises(registry.RegistryError, match="permitted policy identities"):
        registry.verify_active_enrollment(expected, replace(observed, principals=roles))


@pytest.mark.parametrize("environment", ["test", "prod"])
def test_service_apply_grants_cannot_be_attached_to_other_service_roles(environment):
    expected = build(environment)
    observed = active_observation_for(expected)
    permitted = registry._mutable_attachment_sets(expected)
    service = [p for p in expected.principals if p.owner_project == "governance"]
    apply = next(p for p in service if p.arn in permitted)
    assert apply.arn.endswith(
        f"/GitHubCiApply-user-service-infrastructure-{environment}"
    )
    others = [p for p in service if p != apply]
    assert len(others) == 5
    for role in others:
        assert role.arn not in permitted
        for policy in permitted[apply.arn]:
            roles = tuple(
                replace(p, attachment_arns=p.attachment_arns + (policy,))
                if p.arn == role.arn
                else p
                for p in observed.principals
            )
            with pytest.raises(registry.RegistryError, match="attachment set changed"):
                registry.verify_active_enrollment(
                    expected, replace(observed, principals=roles)
                )


@pytest.mark.parametrize("index", range(24))
def test_active_verifier_requires_every_principals_guard_and_boundary(index):
    expected = build()
    observed = active_observation_for(expected)
    role = observed.principals[index]
    guards = expected.principals[index].guard_arns
    missing = replace(
        role, attachment_arns=tuple(a for a in role.attachment_arns if a not in guards)
    )
    for changed in [
        missing,
        replace(role, boundary_arn="arn:aws:iam::891377212104:policy/other"),
    ]:
        roles = (
            observed.principals[:index] + (changed,) + observed.principals[index + 1 :]
        )
        with pytest.raises(registry.RegistryError):
            registry.verify_active_enrollment(
                expected, replace(observed, principals=roles)
            )


@pytest.mark.parametrize("kind", ["duplicate", "over-quota"])
def test_active_mutable_attachment_duplicates_and_quota_fail(kind):
    expected = build()
    observed = active_observation_for(expected)
    role = observed.principals[0]
    policies = sorted(registry._mutable_attachment_sets(expected)[role.arn])
    attachments = (
        role.attachment_arns * 2
        if kind == "duplicate"
        else (expected.principals[0].guard_arns + tuple(policies[:10]))
    )
    roles = (replace(role, attachment_arns=attachments),) + observed.principals[1:]
    with pytest.raises(registry.RegistryError, match="duplicate or quota"):
        registry.verify_active_enrollment(expected, replace(observed, principals=roles))


@pytest.mark.parametrize(
    "claim",
    [
        "aud",
        "sub",
        "repository",
        "repository_id",
        "repository_owner_id",
        "ref",
        "job_workflow_ref",
        "environment",
    ],
)
def test_active_executor_trust_cannot_drop_or_change_any_condition(claim):
    expected = build()
    observed = active_observation_for(expected)
    arn = next(p.arn for p in expected.principals if not p.existing)
    role = next(p for p in observed.principals if p.arn == arn)
    policy = json.loads(role.trust_json)
    condition = policy["Statement"][0]["Condition"]["StringEquals"]
    del condition[f"token.actions.githubusercontent.com:{claim}"]
    roles = tuple(
        replace(p, trust_json=json.dumps(policy)) if p.arn == arn else p
        for p in observed.principals
    )
    with pytest.raises(registry.RegistryError, match="Active executor trust changed"):
        registry.verify_active_enrollment(expected, replace(observed, principals=roles))


def test_active_executor_inline_grant_and_backup_attachment_drift_fail():
    expected = build()
    observed = active_observation_for(expected)
    executor = next(p.arn for p in expected.principals if not p.existing)
    roles = tuple(
        replace(p, inline_policies=(("extra", "{}"),)) if p.arn == executor else p
        for p in observed.principals
    )
    with pytest.raises(registry.RegistryError, match="active executor inline grant"):
        registry.verify_active_enrollment(expected, replace(observed, principals=roles))
    backup = next(
        p for p in expected.principals if p.owner_project == "bootstrap-infrastructure"
    )
    roles = tuple(
        replace(p, attachment_arns=backup.guard_arns) if p.arn == backup.arn else p
        for p in observed.principals
    )
    with pytest.raises(registry.RegistryError, match="attachment set changed"):
        registry.verify_active_enrollment(expected, replace(observed, principals=roles))


@pytest.mark.parametrize(
    "kind",
    [
        "account",
        "key",
        "guard-policy",
        "config-trust",
        "config-inline",
        "config-aws-policy",
        "config-aws-version",
        "missing-policy",
        "missing-role",
    ],
)
def test_active_verifier_reuses_complete_inventory_and_config_freeze(kind):
    expected = build()
    observed = active_observation_for(expected)
    config = next(p.arn for p in expected.principals if p.frozen_config)
    if kind == "account":
        observed = replace(observed, account_id="111122223333")
    elif kind == "key":
        observed = replace(observed, seed_key=key_for("prod"))
    elif kind == "guard-policy":
        policies = list(observed.policies)
        index = next(i for i, p in enumerate(policies) if "/guard/" in p.arn)
        policies[index] = replace(policies[index], document_json="{}")
        observed = replace(observed, policies=tuple(policies))
    elif kind in {"config-trust", "config-inline"}:
        changes = (
            {"trust_json": "{}"} if kind == "config-trust" else {"inline_policies": ()}
        )
        roles = tuple(
            replace(p, **changes) if p.arn == config else p for p in observed.principals
        )
        observed = replace(observed, principals=roles)
    elif kind in {"config-aws-policy", "config-aws-version"}:
        changes = (
            {"document_sha256": "0" * 64}
            if kind == "config-aws-policy"
            else {"default_version_id": "v73"}
        )
        observed = replace(
            observed,
            aws_managed_policies=(
                replace(observed.aws_managed_policies[0], **changes),
            ),
        )
    elif kind == "missing-policy":
        observed = replace(observed, policies=observed.policies[1:])
    else:
        observed = replace(observed, principals=observed.principals[1:])
    with pytest.raises(registry.RegistryError):
        registry.verify_active_enrollment(expected, observed)


@pytest.mark.parametrize("environment", ["test", "prod"])
@pytest.mark.parametrize("executor_index", [0, 1, 2])
def test_duplicate_executor_rejected(environment, executor_index):
    expected = build(environment)
    executor = [p for p in expected.principals if not p.existing][executor_index]
    with pytest.raises(ValueError, match="Expected 24 principals"):
        registry._validate_closure(expected.policies, expected.principals + (executor,))
