"""Immutable GitHub identity validation and exact subject migration checks."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from infra.bootstrap_settings import BootstrapSettings
from infra.github_identity import (
    expand_subjects,
    identity_conditions,
    normalize_identity,
)
from infra.governance import RepoGovernance
from infra.managed_repository import ManagedRepository
from infra.repository_catalog import ManagedRepositoryCatalog
from jsonschema import Draft202012Validator

REPOSITORY = "VilnaCRM-Org/user-service-infrastructure"
REPOSITORY_ID = "911736693"
OWNER_ID = "114362548"


def settings(**values):
    """Load real settings using an explicit nonsecret config double."""
    values = {"githubOrg": "VilnaCRM-Org", "environment": "test", **values}
    return BootstrapSettings.from_pulumi_config(
        SimpleNamespace(
            get=values.get,
            get_secret=lambda key: None,
            get_object=lambda key: None,
        )
    )


@pytest.mark.parametrize(
    "value",
    [
        True,
        False,
        0,
        -1,
        1.5,
        "",
        "01",
        "0",
        "-1",
        "+1",
        " 1",
        "1 ",
        "１",
        "١",
        "*",
        "1?",
        "1\n",
        {},
        [],
    ],
)
def test_identity_rejects_noncanonical_ids(value):
    """Neither token IDs nor catalog data may introduce wildcard identity matches."""
    with pytest.raises(ValueError, match="canonical positive ASCII"):
        normalize_identity(value, OWNER_ID)
    with pytest.raises(ValueError, match="canonical positive ASCII"):
        normalize_identity(REPOSITORY_ID, value)


@pytest.mark.parametrize("pair", [(None, OWNER_ID), (REPOSITORY_ID, None)])
def test_identity_rejects_partial_pairs(pair):
    """An owner-only or repository-only pin is never accepted."""
    with pytest.raises(ValueError, match="must both"):
        identity_conditions(*pair)


def test_identity_normalizes_numeric_catalog_ids():
    """GitHub's JSON integer IDs become canonical JWT claim strings."""
    assert normalize_identity(911736693, 114362548) == (REPOSITORY_ID, OWNER_ID)
    assert identity_conditions(REPOSITORY_ID, OWNER_ID) == {
        "token.actions.githubusercontent.com:repository_id": REPOSITORY_ID,
        "token.actions.githubusercontent.com:repository_owner_id": OWNER_ID,
    }


def test_legacy_library_compatibility_keeps_subjects_without_claim_pins():
    """Absent pairs are supported for library callers; live entrypoints require pins."""
    subject = f"repo:{REPOSITORY}:environment:test"
    assert normalize_identity(None, None) == (None, None)
    assert identity_conditions(None, None) == {}
    assert expand_subjects([subject], REPOSITORY, None, None) == [subject]


@pytest.mark.parametrize(
    "suffix",
    [
        "environment:test",
        "environment:prod-preview",
        "ref:refs/heads/main",
        "pull_request",
    ],
)
def test_subject_expansion_preserves_only_authorized_context(suffix):
    """Both formats name the same repository, immutable identity, and exact context."""
    legacy = f"repo:{REPOSITORY}:{suffix}"
    immutable = (
        f"repo:VilnaCRM-Org@{OWNER_ID}/"
        f"user-service-infrastructure@{REPOSITORY_ID}:{suffix}"
    )
    assert expand_subjects([legacy, legacy], REPOSITORY, REPOSITORY_ID, OWNER_ID) == [
        legacy,
        immutable,
    ]


@pytest.mark.parametrize(
    "repository",
    [
        "*/*",
        "org/repo@*",
        "org/repo:environment:prod",
        "org",
        "org/repo/extra",
        " org/repo",
    ],
)
def test_subject_expansion_rejects_nonexact_repository(repository):
    """Repository segments cannot smuggle IAM patterns or subject components."""
    with pytest.raises(ValueError, match="exact owner/repository"):
        expand_subjects([], repository, REPOSITORY_ID, OWNER_ID)


@pytest.mark.parametrize(
    "subject",
    [
        "repo:attacker/repo:environment:test",
        f"repo:{REPOSITORY}:",
        "repo:VilnaCRM-Org@*/user-service-infrastructure@*:environment:test",
    ],
)
def test_subject_expansion_rejects_foreign_or_unpinned_prefix(subject):
    """Expansion never converts an unrelated subject into a trusted identity."""
    with pytest.raises(ValueError, match="pinned repository"):
        expand_subjects([subject], REPOSITORY, REPOSITORY_ID, OWNER_ID)


def test_empty_subject_list_cannot_gain_access():
    assert expand_subjects([], REPOSITORY, REPOSITORY_ID, OWNER_ID) == []


def test_settings_and_catalog_preserve_pinned_ids():
    """Config, fallback catalog and object catalog retain explicit identity metadata."""
    config = settings(
        repoSlug="user-service-infrastructure",
        githubRepositoryId=REPOSITORY_ID,
        githubRepositoryOwnerId=OWNER_ID,
    )
    assert config.github_repository_id == REPOSITORY_ID
    assert config.github_repository_owner_id == OWNER_ID
    fallback = ManagedRepositoryCatalog.from_settings(
        config, SimpleNamespace(get_object=lambda key: None)
    ).repositories[0]
    assert (fallback.repository_id, fallback.repository_owner_id) == (
        REPOSITORY_ID,
        OWNER_ID,
    )
    mapped = ManagedRepositoryCatalog.repository_from_item(
        {
            "name": "user-service-infrastructure",
            "repositoryId": 911736693,
            "repositoryOwnerId": 114362548,
        }
    )
    assert mapped.repository_id == REPOSITORY_ID
    assert mapped.repository_owner_id == OWNER_ID


def test_catalog_and_settings_reject_partial_metadata():
    with pytest.raises(ValueError, match="must both"):
        settings(githubRepositoryId=REPOSITORY_ID)
    with pytest.raises(ValueError, match="invalid metadata"):
        ManagedRepositoryCatalog.repository_from_item(
            {"name": "service", "repositoryId": REPOSITORY_ID}
        )


def test_repo_rescope_never_inherits_bootstrap_identity():
    """Service roles must use catalog IDs, never the platform repository's IDs."""
    bootstrap = settings(
        repoSlug="bootstrap-infrastructure",
        githubRepositoryId="1098568429",
        githubRepositoryOwnerId=OWNER_ID,
    )
    service = ManagedRepository(
        "user-service-infrastructure",
        "main",
        repository_id=REPOSITORY_ID,
        repository_owner_id=OWNER_ID,
    )
    scoped = RepoGovernance._repo_settings(bootstrap, service)
    assert (
        scoped.repo,
        scoped.github_repository_id,
        scoped.github_repository_owner_id,
    ) == (service.name, REPOSITORY_ID, OWNER_ID)
    legacy = RepoGovernance._repo_settings(
        bootstrap, ManagedRepository("legacy-infrastructure", "main")
    )
    assert legacy.github_repository_id is None
    assert legacy.github_repository_owner_id is None
    same = RepoGovernance._repo_settings(
        bootstrap, ManagedRepository("bootstrap-infrastructure", "main")
    )
    assert same.github_branch == "main"
    assert same.github_repository_id == bootstrap.github_repository_id
    assert same.github_repository_owner_id == bootstrap.github_repository_owner_id
    override = RepoGovernance._repo_settings(scoped, service)
    assert override.github_repository_id == REPOSITORY_ID


@pytest.mark.parametrize(
    "metadata, valid",
    [
        ({}, True),
        ({"repositoryId": REPOSITORY_ID}, False),
        ({"repositoryOwnerId": OWNER_ID}, False),
        ({"repositoryId": "*", "repositoryOwnerId": OWNER_ID}, False),
        ({"repositoryId": "01", "repositoryOwnerId": OWNER_ID}, False),
        ({"repositoryId": True, "repositoryOwnerId": OWNER_ID}, False),
        ({"repositoryId": REPOSITORY_ID, "repositoryOwnerId": OWNER_ID}, True),
        ({"repositoryId": 911736693, "repositoryOwnerId": 114362548}, True),
    ],
)
def test_catalog_schema_enforces_identity_pair(metadata, valid):
    schema = json.loads(
        (Path(__file__).parents[2] / "pulumi/repositories.schema.json").read_text()
    )
    payload = {"repositories": [{"name": "service", **metadata}]}
    assert Draft202012Validator(schema).is_valid(payload) is valid


def test_committed_catalogs_pin_verified_public_repository_ids():
    root = Path(__file__).parents[2] / "pulumi"
    for filename, expected in [
        ("repositories.bootstrap.json", "1098568429"),
        ("repositories.governance.json", REPOSITORY_ID),
    ]:
        repo = ManagedRepositoryCatalog.load_from_json_file(str(root / filename))[0]
        assert (repo.repository_id, repo.repository_owner_id) == (expected, OWNER_ID)
