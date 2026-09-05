"""Golden parity gate for the single-repo GitHub CI bootstrap render (NFR6).

This module captures a reviewed golden snapshot of the single-repo
``bootstrap-infrastructure`` render (role names, trust JSON, backend/read-only/
apply policy JSON, ``Repository`` tag) and asserts the lifted per-repo helpers in
``ci_bootstrap`` reproduce it **byte-for-byte**. The fixture
(``fixtures/github_ci_bootstrap_parity.json``) was captured BEFORE the
``_BootstrapBuildContext`` repo/project refactor (E1.S2, FEASIBILITY-4) and is the
gating artifact for E1.S2-E1.S4b: any drift in the single-repo output fails here.
The September 2026 security amendment changes trust and preview-state baselines:
apply requires its environment; preview/drift accept separate preview environments.
Branch and pull-request tokens must never authorize an apply. Resource names and
apply policies now deny operator-owned IAM/config mutations and permit only
bounded Backup IAM changes. Preview/drift can
write backend locks only, protecting checkpoint integrity.

It also pins the negative case (a second repo renders that repo's resources, never
the first repo's) and the edge subject sets (apply+prod yields only
``environment:prod``; non-prod yields branch-ref + ``environment:test``).
"""

import json
from pathlib import Path
from typing import cast

from infra import ci_bootstrap, config
from infra.automation import _operations_alert_triage_role_name
from infra.ci_config import (
    _ci_config_project,
    _ci_config_read_role_name,
    _ci_secret_suffixes,
)

import pulumi

_FIXTURE_PATH = Path(__file__).parent / "fixtures" / "github_ci_bootstrap_parity.json"
_GOLDEN = json.loads(_FIXTURE_PATH.read_text())


def _golden_settings(environment: str) -> config.BootstrapSettings:
    """Return settings matching the golden fixture's single-repo capture."""
    return config.BootstrapSettings(
        org=_GOLDEN["org"],
        repo=_GOLDEN["repo"],
        environment=environment,
        owner="platform",
        cost_center="core",
        data_classification="internal",
        criticality="high",
        retention_class="standard",
        github_branch=_GOLDEN["github_branch"],
        logging_prefix="company",
        replication_region=None,
        github_token=None,
        github_oidc_provider_arn=None,
        manage_cost_allocation_tags=environment == "test",
    )


def _render_environment(environment: str) -> dict[str, object]:
    """Re-render the single-repo CI bootstrap surface via the lifted helpers."""
    settings = _golden_settings(environment)
    account_id = _GOLDEN["account_id"]
    partition = _GOLDEN["partition"]
    provider_arn = _GOLDEN["provider_arn"]
    purposes = ("preview", "apply", "drift")

    rendered: dict[str, object] = {
        "repository_tag": _ci_config_project(settings),
        "deploy_role_names": {
            purpose: ci_bootstrap._ci_role_name(settings, purpose)
            for purpose in purposes
        },
        "deploy_role_subjects": {
            purpose: ci_bootstrap._deployment_role_subjects(settings, purpose)
            for purpose in purposes
        },
        "deploy_trust_json": {
            purpose: ci_bootstrap._deployment_assume_role_policy(
                provider_arn,
                f"{settings.org}/{settings.repo}",
                ci_bootstrap._deployment_role_subjects(settings, purpose),
            )
            for purpose in purposes
        },
        "deploy_policy_json": {
            purpose: ci_bootstrap._role_policy_documents(
                account_id, partition, settings, purpose
            )
            for purpose in purposes
        },
        "state_bucket_resources": ci_bootstrap._state_bucket_resources(settings),
        "backend_policy_json": ci_bootstrap._pulumi_backend_policy_document(
            account_id, partition, settings
        ),
        "read_only_policy_json": ci_bootstrap._read_only_policy_document(
            account_id, partition, settings
        ),
        "config_read_role_names": {
            suffix: _ci_config_read_role_name(settings, suffix)
            for suffix in _ci_secret_suffixes(settings.environment)
        },
    }
    if environment == "test":
        rendered["operations_alert_triage_role_name"] = (
            _operations_alert_triage_role_name(settings, settings.repo or "")
        )
        rendered["operations_alert_triage_trust_json"] = (
            ci_bootstrap._deployment_assume_role_policy(
                provider_arn,
                f"{settings.org}/{settings.repo}",
                [
                    ci_bootstrap._repo_subject(
                        settings, f"ref:{ci_bootstrap._branch_ref(settings)}"
                    )
                ],
            )
        )
    return rendered


def _to_jsonable(value: object) -> object:
    """Normalize tuples to lists so renders compare byte-equal to JSON fixtures."""
    return json.loads(json.dumps(value))


def test_single_repo_render_is_byte_identical_to_golden_fixture():
    """The lifted helpers reproduce the captured single-repo render byte-for-byte."""
    for environment, golden_env in _GOLDEN["environments"].items():
        rendered = _to_jsonable(_render_environment(environment))
        assert rendered == golden_env, f"parity drift in {environment} stack"  # nosec B101


def test_golden_fixture_covers_apply_automation_branch_and_repository_tag():
    """The fixture pins the apply automation documents and the Repository tag."""
    test_apply = _GOLDEN["environments"]["test"]["deploy_policy_json"]["apply"]
    suffixes = {suffix for suffix, _doc in test_apply}
    # The apply branch threads _automation_policy_documents(account_id, settings, repo)
    # which contributes the per-domain managed-policy documents alongside the backend
    # and iam-managed-policies documents.
    assert {"pulumi-backend", "iam-managed-policies"} <= suffixes  # nosec B101
    assert "policy" in suffixes  # nosec B101
    repo_arn = (
        "arn:aws:secretsmanager:*:123456789012:secret:/bootstrap-infrastructure/ci"
    )
    iam_doc = next(doc for suffix, doc in test_apply if suffix == "iam-policy")
    assert repo_arn in iam_doc  # nosec B101
    assert _GOLDEN["environments"]["test"]["repository_tag"] == (  # nosec B101
        "bootstrap-infrastructure"
    )


def test_other_repo_render_is_scoped_to_that_repo_not_the_first():
    """A second repo renders its own bucket/alias/roles, never the golden repo's."""
    settings = _golden_settings("test")
    other = "user-service-infrastructure"

    bucket_arn, object_arns = ci_bootstrap._state_bucket_resources(settings, other)
    assert bucket_arn == "arn:aws:s3:::pulumi-user-service-infrastructure-test-state"  # nosec B101
    assert all(_GOLDEN["repo"] not in arn for arn in (bucket_arn, *object_arns))  # nosec B101

    backend = json.loads(
        ci_bootstrap._pulumi_backend_policy_document(
            _GOLDEN["account_id"], _GOLDEN["partition"], settings, other
        )
    )
    statements = {statement["Sid"]: statement for statement in backend["Statement"]}
    assert statements["UsePulumiStateBucket"]["Resource"] == [  # nosec B101
        "arn:aws:s3:::pulumi-user-service-infrastructure-test-state",
        "arn:aws:s3:::pulumi-user-service-infrastructure-test-state/state/test/*",
    ]
    aliases = statements["UsePulumiSecretsProviderKey"]["Condition"][
        "ForAnyValue:StringLike"
    ]["kms:ResourceAliases"]
    assert "alias/pulumi-user-service-infrastructure-test-secrets" in aliases  # nosec B101
    assert not any(_GOLDEN["repo"] in alias for alias in aliases)  # nosec B101

    assert (  # nosec B101
        ci_bootstrap._ci_role_name(settings, "preview", _ci_config_project_for(other))
        == "GitHubCiPreview-user-service-infrastructure-test"
    )
    subjects = ci_bootstrap._deployment_role_subjects(settings, "preview", other)
    assert subjects == [  # nosec B101
        "repo:VilnaCRM-Org/user-service-infrastructure:ref:refs/heads/main",
        "repo:VilnaCRM-Org/user-service-infrastructure:pull_request",
        "repo:VilnaCRM-Org/user-service-infrastructure:environment:test",
        "repo:VilnaCRM-Org/user-service-infrastructure:environment:test-preview",
    ]
    assert not any(_GOLDEN["repo"] in subject for subject in subjects)  # nosec B101


def _ci_config_project_for(repo: str) -> str:
    """Return the canonical project slug (full sanitized repo slug) for a repo."""
    settings = _golden_settings("test")
    return settings.sanitize_bucket_component(repo, "repoSlug").replace(".", "-")


def test_apply_prod_subject_set_is_environment_prod_only():
    """apply + prod yields only the environment:prod subject (edge case)."""
    settings = _golden_settings("prod")

    subjects = ci_bootstrap._deployment_role_subjects(
        settings, "apply", _GOLDEN["repo"]
    )
    assert subjects == [  # nosec B101
        "repo:VilnaCRM-Org/bootstrap-infrastructure:environment:prod"
    ]


def test_non_prod_subject_set_is_branch_ref_and_environment_test():
    """Non-prod preview yields branch-ref + environment:test (edge case)."""
    settings = _golden_settings("test")

    subjects = ci_bootstrap._deployment_role_subjects(
        settings, "preview", _GOLDEN["repo"]
    )
    assert subjects == [  # nosec B101
        "repo:VilnaCRM-Org/bootstrap-infrastructure:ref:refs/heads/main",
        "repo:VilnaCRM-Org/bootstrap-infrastructure:pull_request",
        "repo:VilnaCRM-Org/bootstrap-infrastructure:environment:test",
        "repo:VilnaCRM-Org/bootstrap-infrastructure:environment:test-preview",
    ]


def test_context_derives_repo_and_project_from_settings_when_omitted():
    """Constructing the context without repo/project derives them from settings."""
    settings = _golden_settings("test")

    context = ci_bootstrap._BootstrapBuildContext(
        parent=cast(pulumi.Resource, object()),
        name="github-ci-bootstrap-test",
        account_id=_GOLDEN["account_id"],
        partition=_GOLDEN["partition"],
        region="eu-central-1",
        settings=settings,
        provider_arn=_GOLDEN["provider_arn"],
        pulumi_dir="pulumi",
        protect_resources=True,
    )

    assert context.repo == _GOLDEN["repo"]  # nosec B101
    assert context.project == "bootstrap-infrastructure"  # nosec B101
    assert context.project == _ci_config_project(settings)  # nosec B101


def test_context_accepts_explicit_repo_and_project_override():
    """An explicit repo/project is honored over the settings-derived default."""
    settings = _golden_settings("test")

    context = ci_bootstrap._BootstrapBuildContext(
        parent=cast(pulumi.Resource, object()),
        name="github-ci-bootstrap-test",
        account_id=_GOLDEN["account_id"],
        partition=_GOLDEN["partition"],
        region="eu-central-1",
        settings=settings,
        provider_arn=_GOLDEN["provider_arn"],
        pulumi_dir="pulumi",
        protect_resources=True,
        repo="user-service-infrastructure",
        project="user-service-infrastructure",
    )

    assert context.repo == "user-service-infrastructure"  # nosec B101
    assert context.project == "user-service-infrastructure"  # nosec B101
