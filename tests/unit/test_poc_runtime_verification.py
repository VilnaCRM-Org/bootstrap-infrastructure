"""Complete independent runtime observation checks; fixtures are not AWS evidence."""

from dataclasses import replace

import pytest
from seed import poc_runtime as runtime
from seed import poc_runtime_verification as verification
from seed.policy_registry import ObservedPolicy, ObservedPrincipal, RegistryError
from test_poc_runtime import subject


def observation(publisher_subject=runtime.PUBLISHER_SUBJECT):
    """Construct complete synthetic metadata, with task grants kept empty."""
    policies, principals = runtime.enrollment_records()
    roles = []
    for identity, principal in zip(runtime.runtime_identities(), principals):
        if identity.purpose == "execution":
            trust = runtime.execution_trust()
            inline = (("Issue219TestImagePull", runtime.execution_policy()),)
        elif identity.purpose == "publisher":
            trust = runtime.publisher_trust(runtime.PUBLISHER_SUBJECT)
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


def test_complete_enrollment_does_not_authorize_activation():
    inputs = observation()
    result = verification.verify_runtime_enrollment(**inputs)
    assert result.policies_verified == 6
    assert result.principals_verified == 3
    assert result.activation_authorized is False
    assert len(result.enrollment_sha256) == 64
    inputs["policies"] = tuple(reversed(inputs["policies"]))
    inputs["principals"] = tuple(reversed(inputs["principals"]))
    assert verification.verify_runtime_enrollment(**inputs) == result


def test_enrollment_digest_binds_publisher_trust(monkeypatch):
    baseline = verification.verify_runtime_enrollment(**observation())
    monkeypatch.setattr(runtime, "publisher_trust", lambda _: runtime.disabled_trust())
    changed = verification.verify_runtime_enrollment(**observation())
    assert changed.enrollment_sha256 != baseline.enrollment_sha256


@pytest.mark.parametrize(
    "publisher_subject",
    [
        None,
        "",
        subject(repository_id="1"),
        subject(environment="prod"),
        subject() + ":actor:someone",
    ],
)
def test_publisher_subject_must_equal_reviewed_subject(publisher_subject):
    with pytest.raises(RegistryError, match="reviewed TEST subject"):
        verification.verify_runtime_enrollment(**observation(publisher_subject))


def test_publisher_subject_is_required():
    inputs = observation()
    del inputs["publisher_subject"]
    with pytest.raises(TypeError, match="publisher_subject"):
        verification.verify_runtime_enrollment(**inputs)


@pytest.mark.parametrize(
    "field,value", [("account_id", "933245420672"), ("region", "us-east-1")]
)
def test_wrong_target_rejected(field, value):
    with pytest.raises(RegistryError, match="target"):
        verification.verify_runtime_enrollment(**(observation() | {field: value}))


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
    inputs = observation()
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
    inputs = observation() | {
        "publisher_subject": (
            "repo:VilnaCRM-Org/user-service:environment:poc-test-images"
        )
    }
    with pytest.raises(RegistryError, match="Publisher"):
        verification.verify_runtime_enrollment(**inputs)
