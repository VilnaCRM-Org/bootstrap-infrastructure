"""Post-create publisher stack comparison; fixtures are not AWS evidence."""

from __future__ import annotations

import json
from dataclasses import replace

import pytest
from seed import poc_publisher_stack_verification as verification
from seed import poc_runtime as runtime
from seed import poc_runtime_fence_stack as fences
from seed.policy_registry import ObservedPolicy, RegistryError

PUBLISHER = runtime.runtime_identities()[2]
BOUNDARY = PUBLISHER.policy_arn("boundary")
GUARD = PUBLISHER.policy_arn("guard")
ECS_BOUNDARY = runtime.runtime_identities()[0].policy_arn("boundary")
POLICY = "AWS::IAM::ManagedPolicy"
ADMIN = "arn:aws:iam::aws:policy/AdministratorAccess"
EMPTY = '{"Statement":[]}'
DENY_UPDATE = {
    "Statement": [
        {"Effect": "Deny", "Action": "Update:*", "Principal": "*", "Resource": "*"}
    ]
}
TAGS = (
    ("OwnerProject", "independent-seed"),
    ("Environment", "test"),
    ("Repository", runtime.APPLICATION_REPOSITORY),
    ("Purpose", "publisher"),
)


def _document(arn):
    policies, _ = runtime.enrollment_records()
    return next(row.document_json for row in policies if row.arn == arn)


ECS_ROW = (fences._logical_id(ECS_BOUNDARY), POLICY, ECS_BOUNDARY)
ECS_POLICY = ObservedPolicy(ECS_BOUNDARY, "v1", _document(ECS_BOUNDARY))


def observed_stack():
    """Synthetic complete post-create metadata for only the publisher stack."""
    template = fences.build_fence_stack_packet().template_json
    return verification.ObservedPublisherStack(
        account_id=runtime.ACCOUNT_ID,
        region=runtime.REGION,
        stack_name="issue219-runtime-fences-test",
        stack_status="CREATE_COMPLETE",
        template_json=json.dumps(json.loads(template), indent=2),
        termination_protection=True,
        stack_policy_json=json.dumps(DENY_UPDATE),
        stack_resources=(
            (fences._logical_id(BOUNDARY), POLICY, BOUNDARY),
            (fences._logical_id(GUARD), POLICY, GUARD),
            (
                fences._logical_id(PUBLISHER.arn),
                "AWS::IAM::Role",
                runtime.PUBLISHER_NAME,
            ),
        ),
        policies=(
            ObservedPolicy(BOUNDARY, "v1", _document(BOUNDARY)),
            ObservedPolicy(GUARD, "v1", _document(GUARD)),
        ),
        role=verification.ObservedPublisherRole(
            arn=PUBLISHER.arn,
            path="/",
            boundary_arn=BOUNDARY,
            attachment_arns=(GUARD,),
            inline_policies=(("Issue219TestImagePush", runtime.publisher_policy()),),
            max_session_duration=3600,
            tags=TAGS,
            trust_json=runtime.publisher_trust(runtime.PUBLISHER_SUBJECT),
        ),
    )


def _stack(**changes):
    return lambda stack: replace(stack, **changes)


def _role(**changes):
    return lambda stack: replace(stack, role=replace(stack.role, **changes))


def _first_policy(**changes):
    return lambda stack: replace(
        stack, policies=(replace(stack.policies[0], **changes), *stack.policies[1:])
    )


def _drop_first(field):
    return lambda stack: replace(stack, **{field: getattr(stack, field)[1:]})


def _duplicate_first(field):
    return lambda stack: replace(
        stack, **{field: (*getattr(stack, field), getattr(stack, field)[0])}
    )


def _append(field, row):
    return lambda stack: replace(stack, **{field: (*getattr(stack, field), row)})


def _append_role(field, row):
    return lambda stack: replace(
        stack, role=replace(stack.role, **{field: (*getattr(stack.role, field), row)})
    )


EDITS = {
    "account_id": (_stack(account_id="933245420672"), "target"),
    "region": (_stack(region="us-east-1"), "target"),
    "stack_name": (_stack(stack_name="issue219-other-test"), "name"),
    "stack_status": (_stack(stack_status="UPDATE_COMPLETE"), "CREATE_COMPLETE"),
    "template_json": (_stack(template_json='{"Resources":{}}'), "template"),
    "termination_protection": (_stack(termination_protection=False), "termination"),
    "stack_policy_json": (_stack(stack_policy_json=EMPTY), "deny-update"),
    "stack_resources_missing": (_drop_first("stack_resources"), "resource inventory"),
    "stack_resources_duplicate": (
        _duplicate_first("stack_resources"),
        "resource inventory",
    ),
    "stack_resources_ecs_fence": (
        _append("stack_resources", ECS_ROW),
        "resource inventory",
    ),
    "policies_missing": (_drop_first("policies"), "policy inventory"),
    "policies_duplicate": (_duplicate_first("policies"), "policy inventory"),
    "policies_ecs_fence": (_append("policies", ECS_POLICY), "policy inventory"),
    "policy_version": (_first_policy(default_version_id="v2"), "default version"),
    "policy_document": (_first_policy(document_json=EMPTY), "fence document"),
    "role_arn": (
        _role(arn=PUBLISHER.arn.replace(":role/", ":role/other/")),
        "identity",
    ),
    "role_path": (_role(path="/issue219/"), "path"),
    "boundary": (_role(boundary_arn=None), "boundary"),
    "guard_missing": (_role(attachment_arns=()), "single guard"),
    "guard_extra": (_role(attachment_arns=(GUARD, ADMIN)), "single guard"),
    "inline_missing": (_role(inline_policies=()), "inline"),
    "inline_changed": (
        _role(inline_policies=(("Issue219TestImagePush", EMPTY),)),
        "inline",
    ),
    "inline_extra": (_append_role("inline_policies", ("extra", EMPTY)), "inline"),
    "max_session_duration": (_role(max_session_duration=43200), "session"),
    "tags_changed": (_role(tags=(*TAGS[:-1], ("Purpose", "execution"))), "tags"),
    "tags_duplicate": (_append_role("tags", TAGS[0]), "tags"),
    "trust": (_role(trust_json=runtime.disabled_trust()), "trust"),
}


def test_complete_publisher_stack_verified_without_ecs_roles():
    observed = observed_stack()
    result = verification.verify_publisher_stack(observed)
    digest = fences.build_fence_stack_packet().template_sha256
    assert result == verification.PublisherStackVerification(digest)
    assert (result.policies_verified, result.roles_verified) == (2, 1)
    assert result.activation_authorized is False
    reordered = replace(
        observed,
        stack_resources=tuple(reversed(observed.stack_resources)),
        policies=tuple(reversed(observed.policies)),
        role=replace(observed.role, tags=tuple(reversed(observed.role.tags))),
    )
    assert verification.verify_publisher_stack(reordered) == result


@pytest.mark.parametrize("field", sorted(EDITS))
def test_each_post_create_field_fails_closed(field):
    edit, message = EDITS[field]
    with pytest.raises(RegistryError, match=message):
        verification.verify_publisher_stack(edit(observed_stack()))


@pytest.mark.parametrize("broken", ["missing", "role"])
def test_malformed_observation_rejected(broken):
    observed = None if broken == "missing" else replace(observed_stack(), role=None)
    with pytest.raises(RegistryError, match="Complete publisher stack observation"):
        verification.verify_publisher_stack(observed)
