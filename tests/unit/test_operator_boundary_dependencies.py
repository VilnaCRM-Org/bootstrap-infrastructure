"""Role ceilings must depend directly on the policies they reference."""

from dataclasses import replace
from types import SimpleNamespace

from controller_fixtures import ACCOUNT, PROVIDER, REPO, inputs
from infra import automation, platform_iam
from infra.ci_bootstrap import GitHubCiBootstrap, GitHubCiBootstrapArgs
from infra.iam import adoption
from infra.platform_control_iam import PlatformControlIam
from pulumi.runtime import settings as runtime_settings
from pulumi.runtime.stack import wait_for_rpcs
from pulumi.runtime.sync_await import _sync_await


def test_all_five_bounded_operator_roles_have_policy_property_dependencies(
    pulumi_mocks, monkeypatch
):
    """Check serialized SDK edges without relying on component parent ordering."""
    settings = replace(inputs().settings, org="VilnaCRM-Org")
    repo = replace(REPO, name="bootstrap-infrastructure", project="bootstrap")
    monkeypatch.setattr(automation, "_aws_lookup_exists", lambda *args, **kwargs: True)
    monkeypatch.setattr(adoption, "inline_policy_name", lambda role, prefix: prefix)
    monkeypatch.setattr(adoption, "attachment_exists", lambda role, arn: True)
    monkeypatch.setattr(
        platform_iam.aws.kms,
        "get_alias",
        lambda **kwargs: SimpleNamespace(
            target_key_arn=f"arn:aws:kms:eu-central-1:{ACCOUNT}:key/current"
        ),
    )
    monitor = runtime_settings.get_monitor()
    original = monitor.RegisterResource
    registrations = {}
    urn_requests = {}
    resource_ids = {}

    def capture(request):
        registrations[request.name] = request
        response = original(request)
        resource_ids[request.name] = response.id
        urn_requests[response.urn] = request
        return response

    monkeypatch.setattr(monitor, "RegisterResource", capture)
    boundaries = platform_iam.PlatformIamBoundaries(
        "boundaries",
        settings=settings,
        repositories=[repo],
        account_id=ACCOUNT,
        region="eu-central-1",
    )
    arns = {key: policy.arn for key, policy in boundaries.policies.items()}
    bootstrap = GitHubCiBootstrap(
        "ci",
        args=GitHubCiBootstrapArgs(
            settings=settings,
            control_permissions_boundary=arns["control"],
            write_secret_values=False,
        ),
    )
    controls = PlatformControlIam(
        "controls",
        settings=settings,
        repositories=[repo],
        account_id=ACCOUNT,
        partition="aws",
        region="eu-central-1",
        provider_arn=PROVIDER,
        boundary_arns=arns,
    )
    _sync_await(wait_for_rpcs())
    assert bootstrap.roles["apply"]
    expected = {
        "ci-apply-role": "control",
        "github-automation-role": "control",
        "github-oidc-role-bootstrap-infrastructure": "control",
        "platform-replication-bootstrap-infrastructure-role": "state-replication",
        "platform-replication-logs-role": "log-replication",
    }
    for name, purpose in expected.items():
        request = registrations[name]
        policy_urn = _sync_await(boundaries.policies[purpose].urn.future())
        assert policy_urn in request.dependencies
        assert policy_urn in request.propertyDependencies["permissionsBoundary"].urns
        assert request.object.fields["permissionsBoundary"].string_value == (
            _sync_await(boundaries.policies[purpose].arn.future())
        )
    guards = {
        "ci-apply-role": bootstrap.state_guards["apply"],
        "github-automation-role": controls.state_guards[("automation", "")],
        "github-oidc-role-bootstrap-infrastructure": controls.state_guards[
            ("deploy", "bootstrap-infrastructure")
        ],
    }
    _assert_guard_order(registrations, urn_requests, resource_ids, guards)


def _assert_guard_order(registrations, urn_requests, resource_ids, guards):
    role_guards = {}
    for logical_name, guard in guards.items():
        role_request = registrations[logical_name]
        role_name = role_request.object.fields["name"].string_value
        guard_urn = _sync_await(guard.urn.future())
        role_guards[role_name] = guard_urn
        role_guards[resource_ids[logical_name]] = guard_urn
        guard_request = urn_requests[guard_urn]
        role_urn = next(
            urn for urn, request in urn_requests.items() if request is role_request
        )
        assert role_urn in guard_request.propertyDependencies["role"].urns

    grant_counts = dict.fromkeys(role_guards.values(), 0)
    for urn, request in urn_requests.items():
        role_name = request.object.fields["role"].string_value
        if role_name in role_guards and urn != role_guards[role_name]:
            assert role_guards[role_name] in _ancestors(request, urn_requests)
            grant_counts[role_guards[role_name]] += 1
        if request.type == "aws:iam/policy:Policy":
            for prefix, role_key in (
                ("ci-apply-", "ci-apply-role"),
                ("github-automation-", "github-automation-role"),
            ):
                if request.name.startswith(prefix):
                    guard_urn = _sync_await(guards[role_key].urn.future())
                    assert guard_urn in request.dependencies
        assert urn not in _ancestors(request, urn_requests), (
            "Activation graph must be acyclic"
        )
    assert all(count > 0 for count in grant_counts.values())


def _ancestors(request, urn_requests, seen=None):
    seen = set() if seen is None else seen
    for dependency in request.dependencies:
        if dependency not in seen:
            seen.add(dependency)
            if dependency in urn_requests:
                _ancestors(urn_requests[dependency], urn_requests, seen)
    return seen
