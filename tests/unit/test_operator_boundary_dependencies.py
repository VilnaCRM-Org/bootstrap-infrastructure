"""Role ceilings must depend directly on the policies they reference."""

from dataclasses import replace
from types import SimpleNamespace

from infra import automation, platform_iam
from infra.ci_bootstrap import GitHubCiBootstrap, GitHubCiBootstrapArgs
from infra.iam import adoption
from infra.platform_control_iam import PlatformControlIam
from pulumi.runtime import settings as runtime_settings
from pulumi.runtime.stack import wait_for_rpcs
from pulumi.runtime.sync_await import _sync_await
from test_governance_automation import ACCOUNT, PROVIDER, REPO, inputs


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

    def capture(request):
        registrations[request.name] = request
        return original(request)

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
    PlatformControlIam(
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
