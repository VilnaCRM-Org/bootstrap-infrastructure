"""Complete independent runtime observation checks; fixtures are not AWS evidence."""

from dataclasses import replace

import pytest
from seed import poc_runtime as runtime
from seed import poc_runtime_verification as verification
from seed.policy_registry import ObservedPolicy, ObservedPrincipal, RegistryError
from test_poc_runtime import subject


def observation(publisher_subject):
    """Construct complete synthetic metadata, with task grants kept empty."""
    policies, principals = runtime.enrollment_records()
    roles = []
    for identity, principal in zip(runtime.runtime_identities(), principals):
        if identity.purpose == "execution":
            trust = runtime.execution_trust()
            inline = (("Issue219TestImagePull", runtime.execution_policy()),)
        elif identity.purpose == "publisher":
            trust = (
                runtime.publisher_trust(publisher_subject)
                if publisher_subject is not None
                else runtime.disabled_trust()
            )
            inline = (("Issue219TestImagePush", runtime.publisher_policy()),)
        else:
            trust, inline = runtime.disabled_trust(), ()
        roles.append(
            ObservedPrincipal(
                principal.arn,
                principal.boundary_arn,
                principal.attachment_arns,
                trust,
                inline,
            )
        )
    return {
        "account_id": runtime.ACCOUNT_ID,
        "region": runtime.REGION,
        "policies": tuple(
            ObservedPolicy(row.arn, "v1", row.document_json) for row in policies
        ),
        "principals": tuple(roles),
        "publisher_subject": publisher_subject,
    }


@pytest.mark.parametrize("publisher_subject", [None, subject()])
def test_complete_enrollment_does_not_authorize_activation(publisher_subject):
    inputs = observation(publisher_subject)
    result = verification.verify_runtime_enrollment(**inputs)
    assert result.policies_verified == 6
    assert result.principals_verified == 3
    assert result.activation_authorized is False
    assert len(result.enrollment_sha256) == 64
    inputs["policies"] = tuple(reversed(inputs["policies"]))
    inputs["principals"] = tuple(reversed(inputs["principals"]))
    assert verification.verify_runtime_enrollment(**inputs) == result
    assert result != verification.verify_runtime_enrollment(
        **observation(subject() if publisher_subject is None else None)
    )


@pytest.mark.parametrize(
    "field,value", [("account_id", "933245420672"), ("region", "us-east-1")]
)
def test_wrong_target_rejected(field, value):
    with pytest.raises(RegistryError, match="target"):
        verification.verify_runtime_enrollment(**(observation(None) | {field: value}))


@pytest.mark.parametrize("field", ["policies", "principals"])
@pytest.mark.parametrize("change", ["missing", "duplicate", "foreign"])
def test_incomplete_or_foreign_inventory_rejected(field, change):
    inputs = observation(subject())
    rows = inputs[field]
    if change == "missing":
        rows = rows[1:]
    elif change == "duplicate":
        rows = (*rows, rows[0])
    else:
        rows = (replace(rows[0], arn=rows[0].arn + "Foreign"), *rows[1:])
    inputs[field] = rows
    with pytest.raises(RegistryError, match="inventory"):
        verification.verify_runtime_enrollment(**inputs)


@pytest.mark.parametrize(
    "changes", [{"default_version_id": "v0"}, {"document_json": '{"Statement":[]}'}]
)
def test_changed_default_policy_rejected(changes):
    inputs = observation(None)
    inputs["policies"] = (
        replace(inputs["policies"][0], **changes),
        *inputs["policies"][1:],
    )
    with pytest.raises(RegistryError, match="fence"):
        verification.verify_runtime_enrollment(**inputs)


@pytest.mark.parametrize("index", [0, 1, 2])
@pytest.mark.parametrize(
    "change",
    [
        "boundary",
        "missing_guard",
        "extra_attachment",
        "trust",
        "inline",
        "duplicate_inline",
    ],
)
def test_changed_role_grants_or_fences_rejected(index, change):
    inputs = observation(subject())
    roles = list(inputs["principals"])
    role = roles[index]
    changes = {
        "boundary": {"boundary_arn": None},
        "missing_guard": {"attachment_arns": ()},
        "extra_attachment": {"attachment_arns": (*role.attachment_arns, "foreign")},
        "trust": {"trust_json": '{"Statement":[]}'},
        "inline": {"inline_policies": (("extra", '{"Statement":[]}'),)},
        "duplicate_inline": {
            "inline_policies": (*role.inline_policies, ("extra", '{"Statement":[]}'))
        },
    }[change]
    roles[index] = replace(role, **changes)
    inputs["principals"] = tuple(roles)
    with pytest.raises(RegistryError, match="Runtime"):
        verification.verify_runtime_enrollment(**inputs)


def test_default_subject_denied():
    inputs = observation(None) | {
        "publisher_subject": (
            "repo:VilnaCRM-Org/user-service:environment:poc-test-images"
        )
    }
    with pytest.raises(RegistryError, match="Publisher"):
        verification.verify_runtime_enrollment(**inputs)
