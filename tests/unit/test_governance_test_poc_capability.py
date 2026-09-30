"""TEST prerequisite capability grants are enabled only for the exact installed seed."""

import dataclasses
import json
from fnmatch import fnmatchcase
from pathlib import Path

import pytest
from infra.governance import (
    _governance_role_specs,
    _test_poc_capability_statements,
    _TestPocTarget,
)
from infra.governance_automation import (
    governance_repo_iam_policy,
    service_boundary_policy,
)
from seed.policy_registry import _mutable_attachment_sets, load_catalog
from test_governance_automation import REPO, inputs
from test_seed_policy_registry import build

ACCOUNT = "891377212104"
REPOSITORY = "user-service-infrastructure"
ZONE = "arn:aws:route53:::hostedzone/Z04999481RZ4UQK2NANVH"
NAME = "a" * 32 + "._domainkey.user.vilnacrmtest.com"
PREFIX = "route53:ChangeResourceRecordSets"
POLICY = (
    f"arn:aws:iam::{ACCOUNT}:policy/GitHubCiApply-{REPOSITORY}-test-poc-prerequisites"
)
REAL_READ_TEXT = Path.read_text


@pytest.mark.parametrize("write", [False, True])
def test_packaged_capability_matches_installed_test_seed(write):
    assert capability(write=write)
    args = arguments()
    boundary = json.loads(service_boundary_policy(args, REPO))["Statement"]
    catalog = load_catalog("test")
    pin = catalog["policies"][
        f"arn:aws:iam::{ACCOUNT}:policy/GovernanceBoundary-{REPOSITORY}-test"
    ]
    assert [catalog["statements"][s] for s in pin["statement_ids"]] == boundary
    specs = _governance_role_specs(
        account_id=ACCOUNT,
        partition="aws",
        settings=args.settings,
        region="eu-central-1",
        repo=REPOSITORY,
        project=REPOSITORY,
    )
    assert all("poc-prerequisites" in dict(spec.policy_documents) for spec in specs)


def lifecycle(monkeypatch, state):
    """Serve the packaged identity with one reviewed lifecycle state."""

    def staged(path, *args, **kwargs):
        content = REAL_READ_TEXT(path, *args, **kwargs)
        if path.name == "test-poc-identity.json":
            identity = json.loads(content)
            if state is None:
                identity.pop("state")
            else:
                identity["state"] = state
            return json.dumps(identity)
        return content

    monkeypatch.setattr(Path, "read_text", staged)


def rendered(args):
    """Render the three consumers exactly as the operator and governance stacks do."""
    boundary = json.loads(service_boundary_policy(args, REPO))["Statement"]
    governors = [
        json.loads(governance_repo_iam_policy(args, REPO, apply=apply))["Statement"]
        for apply in (False, True)
    ]
    specs = _governance_role_specs(
        account_id=ACCOUNT,
        partition="aws",
        settings=args.settings,
        region="eu-central-1",
        repo=REPOSITORY,
        project=REPOSITORY,
    )
    return boundary, governors, specs


def installed_boundary():
    """Return the active TEST seed boundary pin's rendered statements."""
    catalog = load_catalog("test")
    pin = catalog["policies"][
        f"arn:aws:iam::{ACCOUNT}:policy/GovernanceBoundary-{REPOSITORY}-test"
    ]
    return [catalog["statements"][s] for s in pin["statement_ids"]]


def governs_policy(statements, actions):
    """Report whether the governor may perform every action on the exact ARN."""
    return all(
        any(POLICY in s["Resource"] and action in s["Action"] for s in statements)
        for action in actions
    )


def test_explicitly_disabled_identity_still_emits_no_capability(monkeypatch):
    lifecycle(monkeypatch, "disabled")
    assert capability() == []
    assert capability(write=False) == []
    boundary, governors, specs = rendered(arguments())
    assert boundary == installed_boundary()[:5]
    assert not any(POLICY in json.dumps(governor) for governor in governors)
    assert all("poc-prerequisites" not in dict(s.policy_documents) for s in specs)


GOVERNOR_READ = [
    "iam:GetPolicy",
    "iam:GetPolicyVersion",
    "iam:ListPolicyVersions",
    "iam:ListEntitiesForPolicy",
]
GOVERNOR_UPDATE = ["iam:CreatePolicyVersion", "iam:DeletePolicyVersion"]


def test_withdrawn_state_denies_capability_in_place_and_keeps_governor(
    monkeypatch,
):
    enabled = {
        spec.purpose: dict(spec.policy_documents) for spec in rendered(arguments())[2]
    }
    lifecycle(monkeypatch, "withdrawn")
    assert capability() == []
    assert capability(write=False) == []
    boundary, (preview, apply), specs = rendered(arguments())
    for spec in specs:
        documents = dict(spec.policy_documents)
        # Same policy identities: the governance plan updates in place and has
        # no IAM delete for the destructive-diff gate or protect to reject.
        assert documents.keys() == enabled[spec.purpose].keys()
        withdrawn = json.loads(documents["poc-prerequisites"])["Statement"]
        granted = json.loads(enabled[spec.purpose]["poc-prerequisites"])["Statement"]
        assert {s["Effect"] for s in withdrawn} == {"Deny"}
        # Statement for statement: same actions, resources and exact Conditions,
        # so the Deny blocks precisely what the replaced Allow granted.
        assert [
            (s["Sid"], s["Action"], s["Resource"], s.get("Condition"))
            for s in withdrawn
        ] == [
            (f"{s['Sid']}Withdrawn", s["Action"], s["Resource"], s.get("Condition"))
            for s in granted
        ]
        conditioned = [s for s in withdrawn if "Condition" in s]
        assert [s["Sid"] for s in conditioned] == (
            ["PocDkimRecordsWithdrawn"] if spec.purpose == "apply" else []
        )
        assert len(documents["poc-prerequisites"].replace(" ", "")) < 6144
    # The operator stack runs first and must keep managing the exact policy.
    assert governs_policy(preview, GOVERNOR_READ)
    assert governs_policy(apply, GOVERNOR_READ + GOVERNOR_UPDATE)
    assert boundary == installed_boundary()


@pytest.mark.parametrize("state", [None, "", "Enabled", True, "active", "withdrawing"])
def test_unknown_lifecycle_state_fails_closed_for_every_consumer(monkeypatch, state):
    lifecycle(monkeypatch, state)
    for use in ("grant", "tombstone", "governor", "ceiling"):
        with pytest.raises(ValueError, match="lifecycle state"):
            capability(use=use)
    with pytest.raises(ValueError, match="lifecycle state"):
        rendered(arguments())


def test_installed_catalog_rejects_replaying_seed_amendment():
    from seed.test_poc_prerequisite_amendment import build_catalog

    with pytest.raises(ValueError, match="reviewed TEST baseline"):
        build_catalog()


def arguments():
    """Use real public identity bindings without contacting AWS."""
    args = inputs(account_id=ACCOUNT)
    settings = dataclasses.replace(
        args.settings,
        org="VilnaCRM-Org",
        github_repository_id="911736693",
        github_repository_owner_id="114362548",
    )
    return dataclasses.replace(args, settings=settings)


def capability(*, write=True, **changes):
    """Render the reviewed slice and allow negative identity substitutions."""
    args = arguments()
    values = dict(
        account_id=args.account_id,
        partition=args.partition,
        settings=args.settings,
        repo=REPOSITORY,
        region=args.region,
        project=REPOSITORY,
        write=write,
        use="grant",
    )
    values.update(changes)
    settings = values.pop("settings")
    write = values.pop("write")
    use = values.pop("use")
    return _test_poc_capability_statements(
        _TestPocTarget(**values), settings, write=write, use=use
    )


def dns_condition_matches(operator, actual, expected):
    """Evaluate one supported condition without broadening the test oracle."""
    if operator == "Null":
        return (actual is None) == (expected == "true")
    if operator == "ForAllValues:StringEquals":
        return all(value in expected for value in actual or [])
    if operator == "ForAllValues:StringLike":
        return all(
            any(fnmatchcase(value, pattern) for pattern in expected)
            for value in actual or []
        )
    raise AssertionError(f"Unimplemented condition: {operator}")


def dns_allowed(statement, zone=ZONE, **changes):
    """Evaluate only this policy's explicit Route53 condition subset offline."""
    context = {
        PREFIX + "NormalizedRecordNames": [NAME],
        PREFIX + "RecordTypes": ["CNAME"],
        PREFIX + "Actions": ["CREATE"],
    }
    context.update(changes)
    if zone not in statement["Resource"]:
        return False
    return all(
        dns_condition_matches(operator, context.get(key), expected)
        for operator, entries in statement["Condition"].items()
        for key, expected in entries.items()
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("account_id", "933245420672"),
        ("account_id", "123456789012"),
        ("partition", "aws-cn"),
        ("repo", "website-infrastructure"),
        ("region", "us-east-1"),
        ("project", "bootstrap-infrastructure"),
    ],
)
def test_other_resources_receive_no_capability(field, value):
    assert capability(**{field: value}) == []


@pytest.mark.parametrize(
    "field,value",
    [
        ("environment", "prod"),
        ("org", "foreign-org"),
        ("github_repository_id", "911736694"),
        ("github_repository_owner_id", "1"),
    ],
)
def test_other_identities_receive_no_capability(field, value):
    settings = dataclasses.replace(arguments().settings, **{field: value})
    assert capability(settings=settings) == []


def test_packaged_identity_does_not_depend_on_working_directory(monkeypatch, tmp_path):
    expected = capability()
    monkeypatch.chdir(tmp_path)
    assert capability() == expected


@pytest.mark.parametrize("payload,error", [("{", ValueError), ("{}", KeyError)])
def test_invalid_packaged_identity_fails_closed(monkeypatch, payload, error):
    monkeypatch.setattr(Path, "read_text", lambda *_args, **_kwargs: payload)
    with pytest.raises(error):
        capability()


def test_missing_packaged_identity_fails_closed(monkeypatch):
    def missing(*_args, **_kwargs):
        raise FileNotFoundError("Missing reviewed identity")

    monkeypatch.setattr(Path, "read_text", missing)
    with pytest.raises(FileNotFoundError, match="Missing reviewed identity"):
        capability()


def test_enabled_identity_boundary_governor_and_attachment_allowlist_match():
    args = arguments()
    full = capability()
    boundary = json.loads(service_boundary_policy(args, REPO))["Statement"]
    assert boundary[-len(full) :] == full
    catalog = load_catalog("test")
    pin = catalog["policies"][
        f"arn:aws:iam::{ACCOUNT}:policy/GovernanceBoundary-{REPOSITORY}-test"
    ]
    assert [catalog["statements"][s] for s in pin["statement_ids"]] == boundary
    specs = _governance_role_specs(
        account_id=ACCOUNT,
        partition="aws",
        settings=args.settings,
        region="eu-central-1",
        repo=REPOSITORY,
        project=REPOSITORY,
    )
    for spec in specs:
        doc = dict(spec.policy_documents)["poc-prerequisites"]
        assert len(doc.replace(" ", "")) < 6144
        assert json.loads(doc)["Statement"] == capability(write=spec.purpose == "apply")
    governor = json.loads(governance_repo_iam_policy(args, REPO, apply=True))
    assert any(POLICY in s["Resource"] for s in governor["Statement"])
    assert governs_policy(governor["Statement"], GOVERNOR_READ + GOVERNOR_UPDATE)
    permitted = _mutable_attachment_sets(build("test"))
    role = f"arn:aws:iam::{ACCOUNT}:role/GitHubCiApply-{REPOSITORY}-test"
    assert permitted[role] == {
        POLICY,
        POLICY.removesuffix("poc-prerequisites") + "pulumi-backend",
        POLICY.removesuffix("poc-prerequisites") + "secret-read-deny",
    }
    assert all(
        POLICY not in policies
        for principal, policies in permitted.items()
        if principal != role
    )
    assert all(
        "poc-prerequisites" not in arn
        for policies in _mutable_attachment_sets(build("prod")).values()
        for arn in policies
    )


def test_only_initial_prerequisite_actions_and_exact_resources():
    statements = capability()
    actions = {a for s in statements for a in s["Action"]}
    assert actions == {
        "ecr:DescribeRepositories",
        "ecr:ListTagsForResource",
        "ecr:CreateRepository",
        "ecr:TagResource",
        "ecr:UntagResource",
        "ses:GetEmailIdentity",
        "ses:ListTagsForResource",
        "ses:CreateEmailIdentity",
        "ses:TagResource",
        "ses:UntagResource",
        "route53:GetHostedZone",
        "route53:ListResourceRecordSets",
        "route53:GetChange",
        "route53:ChangeResourceRecordSets",
        "s3:GetBucketVersioning",
    }
    assert statements[0]["Resource"] == [
        f"arn:aws:ecr:eu-central-1:{ACCOUNT}:repository/user-service-test-{kind}"
        for kind in ("web", "worker")
    ]
    assert statements[1]["Resource"] == [
        f"arn:aws:ses:eu-central-1:{ACCOUNT}:identity/user.vilnacrmtest.com"
    ]
    reads = {a for s in capability(write=False) for a in s["Action"]}
    assert reads == {
        "ecr:DescribeRepositories",
        "ecr:ListTagsForResource",
        "ses:GetEmailIdentity",
        "ses:ListTagsForResource",
        "route53:GetHostedZone",
        "route53:ListResourceRecordSets",
        "s3:GetBucketVersioning",
    }


@pytest.mark.parametrize(
    "field,values",
    [
        ("NormalizedRecordNames", [NAME, "outside.vilnacrmtest.com"]),
        ("NormalizedRecordNames", ["_domainkey.user.vilnacrmtest.com"]),
        ("NormalizedRecordNames", [NAME + ".evil.example"]),
        ("NormalizedRecordNames", [NAME.replace("user.", "other.")]),
        ("NormalizedRecordNames", None),
        ("RecordTypes", ["CNAME", "TXT"]),
        ("RecordTypes", None),
        ("Actions", ["CREATE", "UPSERT"]),
        ("Actions", ["DELETE"]),
        ("Actions", None),
    ],
)
def test_dns_denies_mixed_batches_foreign_scope_and_absent_keys(field, values):
    statement = capability()[-1]
    assert dns_allowed(statement)
    assert not dns_allowed(statement, **{PREFIX + field: values})


@pytest.mark.parametrize("write", [False, True])
def test_backend_observer_only_reads_versioning_on_exact_test_bucket(write):
    statements = [
        statement
        for statement in capability(write=write)
        if any(action.startswith("s3:") for action in statement["Action"])
    ]
    assert statements == [
        {
            "Sid": "PocBackendVersioning",
            "Effect": "Allow",
            "Action": ["s3:GetBucketVersioning"],
            "Resource": ["arn:aws:s3:::pulumi-user-service-infrastructure-test-state"],
        }
    ]


def test_dns_denies_other_zone_and_permits_multiple_valid_tokens():
    statement = capability()[-1]
    assert not dns_allowed(statement, zone=ZONE + "OTHER")
    assert dns_allowed(
        statement, **{PREFIX + "NormalizedRecordNames": [NAME, "b" + NAME[1:]]}
    )


@pytest.mark.parametrize(
    "action,resource",
    [
        (
            "ecr:CreateRepository",
            "arn:aws:ecr:eu-central-1:891377212104:repository/user-service-test-web",
        ),
        (
            "ecr:CreateRepository",
            "arn:aws:ecr:eu-central-1:891377212104:repository/user-service-test-worker",
        ),
        (
            "ses:CreateEmailIdentity",
            "arn:aws:ses:eu-central-1:891377212104:identity/user.vilnacrmtest.com",
        ),
    ],
)
def test_initial_creation_allows_exact_resources_and_rejects_neighbors(
    action, resource
):
    statements = capability()

    def matches(candidate):
        return any(
            action in statement["Action"] and candidate in statement["Resource"]
            for statement in statements
        )

    assert matches(resource)
    for foreign in (
        resource + "-foreign",
        resource.replace("891377212104", "933245420672"),
        resource.replace("eu-central-1", "us-east-1"),
    ):
        assert not matches(foreign)


def test_missing_identity_pair_and_prod_have_no_role_capability():
    args = arguments()
    for overrides in (
        {"github_repository_id": None, "github_repository_owner_id": None},
        {"environment": "prod"},
    ):
        settings = dataclasses.replace(args.settings, **overrides)
        assert capability(settings=settings) == []
        specs = _governance_role_specs(
            account_id=ACCOUNT,
            partition="aws",
            settings=settings,
            region="eu-central-1",
            repo=REPOSITORY,
            project=REPOSITORY,
        )
        assert all(
            "poc-prerequisites" not in dict(spec.policy_documents) for spec in specs
        )


def test_active_seed_guard_admits_only_exact_prerequisite_policy():
    catalog = load_catalog("test")
    pin = catalog["policies"][
        f"arn:aws:iam::{ACCOUNT}:policy/issue215-seed/test/guard/G-GitHubGovernanceApply"
    ]
    statements = [catalog["statements"][sid] for sid in pin["statement_ids"]]
    not_resources = [
        s["NotResource"]
        for s in statements
        if "NotResource" in s
        and any(
            fnmatchcase("iam:CreatePolicy", action)
            for action in (
                [s["Action"]] if isinstance(s["Action"], str) else s["Action"]
            )
        )
    ]
    assert len(not_resources) == 2
    assert all(POLICY in resources for resources in not_resources)
    for candidate in (
        POLICY + "-foreign",
        POLICY.replace("891377212104", "933245420672").replace("-test-", "-prod-"),
        "arn:aws:iam::891377212104:policy/AdministratorAccess",
    ):
        assert all(candidate not in resources for resources in not_resources)
