"""Completed operator imports disappear without changing reads or resource options."""

from types import SimpleNamespace

import pulumi.resource as resource_runtime
import pulumi_aws as aws
import pytest
from infra.operator_resource_options import without_completed_import
from pulumi.runtime.stack import wait_for_rpcs
from pulumi.runtime.sync_await import _sync_await

import pulumi

OPERATOR_TYPES = [
    "aws:iam/role:Role",
    "aws:iam/policy:Policy",
    "aws:iam/rolePolicy:RolePolicy",
    "aws:iam/rolePolicyAttachment:RolePolicyAttachment",
    "aws:iam/rolePolicyAttachmentsExclusive:RolePolicyAttachmentsExclusive",
    "aws:secretsmanager/secret:Secret",
]


def transformation_args(options, *, type_=OPERATOR_TYPES[0], props=None):
    return pulumi.ResourceTransformationArgs(
        resource=SimpleNamespace(),
        type_=type_,
        name="owned-resource",
        props={} if props is None else props,
        opts=options,
    )


@pytest.mark.parametrize("type_", OPERATOR_TYPES)
def test_clears_only_import_on_a_copy_of_real_sdk_options(pulumi_mocks, type_):
    """Preserve even option references; cloning must not resolve Pulumi Outputs."""
    sentinel = pulumi.ComponentResource("test:component:Parent", "copy-parent")
    provider = pulumi.ProviderResource("aws", "copy-provider", {})
    options = pulumi.ResourceOptions(
        import_="existing-physical-id",
        parent=sentinel,
        depends_on=[sentinel],
        protect=True,
        provider=provider,
        aliases=["existing-alias"],
        additional_secret_outputs=["payload"],
        ignore_changes=["unchanged"],
        retain_on_delete=True,
        delete_before_replace=False,
        custom_timeouts=pulumi.CustomTimeouts(create="5m"),
    )
    previous = vars(options).copy()
    properties = {"name": "owned", "value": pulumi.Output.from_input("synthetic")}
    result = without_completed_import(
        transformation_args(options, type_=type_, props=properties)
    )
    assert result is not None
    assert result.props is properties
    assert result.opts is not options
    assert result.opts.import_ is None
    assert vars(options) == previous
    assert vars(result.opts).keys() == previous.keys()
    for key, value in previous.items():
        if key != "import_":
            assert vars(result.opts)[key] is value
    # The SDK merge contract intentionally ignores None; this is why we copy.
    assert (
        pulumi.ResourceOptions.merge(
            options, pulumi.ResourceOptions(import_=None)
        ).import_
        == "existing-physical-id"
    )
    _sync_await(wait_for_rpcs())


@pytest.mark.parametrize(
    "options",
    [
        pulumi.ResourceOptions(),
        pulumi.ResourceOptions(import_=""),
        pulumi.ResourceOptions(import_="existing", id="provider-read"),
        pulumi.ResourceOptions(import_="existing", id=""),
        pulumi.ResourceOptions(import_="existing", urn="engine-read"),
        pulumi.ResourceOptions(import_="existing", urn=""),
    ],
)
def test_absent_import_and_provider_or_engine_reads_are_untouched(options):
    before = vars(options).copy()
    assert without_completed_import(transformation_args(options)) is None
    assert vars(options) == before


@pytest.mark.parametrize(
    "type_",
    [
        "pulumi:providers:aws",
        "pulumi:pulumi:Stack",
        "bootstrap:component:Root",
        "aws:s3/bucket:Bucket",
    ],
)
def test_unrelated_resource_types_keep_import_hints(type_):
    options = pulumi.ResourceOptions(import_="outside-reviewed-operator-types")
    assert without_completed_import(transformation_args(options, type_=type_)) is None
    assert options.import_ == "outside-reviewed-operator-types"


def test_real_sdk_inherits_transform_before_registration_and_preserves_reads(
    pulumi_mocks, monkeypatch
):
    """Exercise Resource constructors and stack inheritance before SDK RPC dispatch."""
    registrations = []
    reads = []
    engine_reads = []
    original_register = resource_runtime.register_resource
    original_read = resource_runtime.read_resource

    def register(*args, **kwargs):
        registrations.append((args[2], args[7]))
        return original_register(*args, **kwargs)

    def read(*args, **kwargs):
        reads.append((args[2], args[4]))
        return original_read(*args, **kwargs)

    monkeypatch.setattr(resource_runtime, "register_resource", register)
    monkeypatch.setattr(resource_runtime, "read_resource", read)
    monkeypatch.setattr(
        resource_runtime, "get_resource", lambda *args: engine_reads.append(args)
    )
    outside = pulumi.ComponentResource("test:component:Root", "outside-operator")
    pulumi.CustomResource(
        OPERATOR_TYPES[0],
        "first-adoption",
        {},
        pulumi.ResourceOptions(parent=outside, import_="adoption-id"),
    )
    pulumi.runtime.register_stack_transformation(without_completed_import)
    operator = pulumi.ComponentResource("test:component:Root", "operator")
    for index, type_ in enumerate(OPERATOR_TYPES):
        options = pulumi.ResourceOptions(
            parent=operator, import_=f"owned-{index}", protect=True
        )
        pulumi.CustomResource(type_, f"owned-{index}", {}, options)
        assert options.import_ == f"owned-{index}"
    aws.iam.Role.get(
        "provider-reference",
        "read-id",
        opts=pulumi.ResourceOptions(parent=operator, import_="read-hint"),
    )
    pulumi.CustomResource(
        OPERATOR_TYPES[0],
        "engine-reference",
        {},
        pulumi.ResourceOptions(
            parent=operator, urn="engine-urn", import_="engine-hint"
        ),
    )
    _sync_await(wait_for_rpcs())
    by_name = dict(registrations)
    assert by_name["first-adoption"].import_ == "adoption-id"
    for index in range(len(OPERATOR_TYPES)):
        options = by_name[f"owned-{index}"]
        assert options.import_ is None and options.protect is True
        assert options.parent is operator
    assert len(reads) == 1
    assert reads[0][0] == "provider-reference"
    assert reads[0][1].id == "read-id" and reads[0][1].import_ == "read-hint"
    assert len(engine_reads) == 1 and engine_reads[0][3] == "engine-urn"
