"""Regression cases for pure, fail-closed central validation selection."""

from __future__ import annotations

import ast
import importlib
import sys
from collections.abc import Mapping
from pathlib import Path

import pytest

SCRIPTS_DIR = Path(__file__).resolve().parents[2] / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

deployment_scopes = importlib.import_module("deployment_scopes")
governance_paths = importlib.import_module("governance_paths")
SCAFFOLD_RUNTIME_FILES = deployment_scopes.SCAFFOLD_RUNTIME_FILES
STACK_ORDER = deployment_scopes.STACK_ORDER
DeploymentScopes = deployment_scopes.DeploymentScopes
select_deployment_scopes = deployment_scopes.select_deployment_scopes
paths_touch_governance = governance_paths.paths_touch_governance

BASE = "a" * 40
HEAD = "b" * 40
ALL = ("operator", "governance", "platform")


def select(*paths: str) -> DeploymentScopes:
    """Select a complete synthetic snapshot without touching runtime files."""
    return select_records([{"filename": path, "status": "modified"} for path in paths])


def select_records(records: list[Mapping[str, object]]) -> DeploymentScopes:
    """Supply independently fixed revision identities for table-driven cases."""
    return select_deployment_scopes(
        records,
        base_sha=BASE,
        head_sha=HEAD,
        expected_file_count=len(records),
        complete=True,
    )


@pytest.mark.parametrize(
    ("path", "stacks", "scaffold", "execution", "catalog"),
    [
        ("pulumi/__main__.py", ("platform",), False, False, False),
        ("pulumi/app/guardrails.py", ("platform",), False, False, False),
        ("pulumi/governance/__main__.py", ("governance",), False, False, False),
        ("pulumi/github-ci-bootstrap/__main__.py", ("operator",), False, False, False),
        ("pulumi/infra/governance_automation.py", ALL, False, False, False),
        ("pulumi/infra/platform_control_iam.py", ALL, False, False, False),
        ("pulumi/infra/iam/account.py", ALL, False, False, False),
        ("pulumi/infra/governance.py", ALL, False, False, False),
        ("pulumi/infra/logging_bucket.py", ALL, False, False, False),
        ("pulumi/infra/bootstrap_settings.py", ALL, False, False, False),
        ("pulumi/infra/utils/tags.py", ALL, False, False, False),
        ("pulumi/infra/__init__.py", ALL, False, False, False),
        ("pulumi/infra/new_helper.py", ALL, False, False, False),
        ("pulumi/infra/new_runtime_data.json", ALL, False, False, False),
        ("pulumi/infra/new_runtime_data.md", ALL, False, False, False),
        ("pulumi/repositories.governance.json", ALL, False, False, True),
        (
            "pulumi/repositories.bootstrap.json",
            ("operator", "platform"),
            False,
            False,
            True,
        ),
        ("pulumi/repositories.schema.json", (), False, False, True),
        ("pulumi/repositories.example.json", (), False, False, True),
        ("pulumi/governance/Pulumi.test.yaml", ("governance",), False, False, False),
        (
            "pulumi/github-ci-bootstrap/Pulumi.prod.yaml",
            ("operator",),
            False,
            False,
            False,
        ),
        ("pulumi/Pulumi.prod.yaml", ("platform",), False, False, False),
        ("pulumi/Pulumi.yaml", ("platform",), False, False, False),
        ("pulumi/Pulumi.example.yaml", ("platform",), False, False, False),
        ("pulumi/requirements.txt", ALL, False, False, False),
        ("pulumi/governance/requirements.txt", ("governance",), False, False, False),
        ("pulumi/sitecustomize.py", ALL, False, True, False),
        (
            "pulumi/user-service-infrastructure/pulumi/__main__.py",
            (),
            True,
            False,
            False,
        ),
        ("pulumi/user-service-infrastructure/README.md", (), True, False, False),
        (
            "pulumi/user-service-infrastructure/.github/workflows/self-deploy.yml",
            (),
            True,
            False,
            False,
        ),
        ("scripts/scaffold_infrastructure_repository.py", (), True, False, False),
        ("scripts/run_pulumi_command.py", ALL, True, True, False),
        ("scripts/_pulumi_stack_config.py", ALL, True, True, False),
        ("scripts/prepare_docker_context.py", ALL, False, True, False),
        ("scripts/run_pulumi_preview.py", ALL, False, True, False),
        ("scripts/run_pulumi_drift_check.py", ALL, False, True, False),
        ("scripts/pulumi_pr_comment.py", ALL, True, True, False),
        ("policy/vilnacrm_guardrails.yaml", ALL, True, True, False),
        ("policy/README.md", (), True, False, False),
        ("uv.lock", ALL, True, True, False),
        ("pyproject.toml", ALL, True, True, False),
        ("Dockerfile", ALL, True, True, False),
        (".dockerignore", ALL, True, True, False),
        ("Makefile", ALL, False, True, False),
        ("docker-compose.yml", ALL, False, True, False),
        ("docker-compose.prod.yml", ALL, False, True, False),
        ("scripts/record_dependabot_exception.py", (), False, True, False),
        (".github/workflows/security-scans.yml", (), False, True, False),
        (".github/CODEOWNERS", (), False, True, False),
        ("docs/governance-stack.md", (), False, False, False),
        ("docs/example.py", (), False, False, False),
        ("tests/unit/test_governance_paths.py", (), False, False, False),
        ("specs/issue215/architecture.md", (), False, False, False),
        ("README.md", (), False, False, False),
        ("CHANGELOG.rst", (), False, False, False),
        ("pulumi/governance/README.md", (), False, False, False),
    ],
)
def test_dependency_inventory(path, stacks, scaffold, execution, catalog) -> None:
    result = select(path)
    assert result.stacks == stacks
    assert result.scaffold_validation is scaffold
    assert result.execution_validation is execution
    assert result.catalog_validation is catalog
    assert result.base_sha == BASE and result.head_sha == HEAD
    assert result.reasons[0].path == path
    assert result.reasons[0].reason


@pytest.mark.parametrize("status", ["renamed", "copied"])
@pytest.mark.parametrize(
    ("source", "destination", "stacks"),
    [
        ("pulumi/infra/logging_bucket.py", "docs/archived.py", ALL),
        ("docs/design.md", "pulumi/infra/new_helper.py", ALL),
        (
            "pulumi/governance/Pulumi.test.yaml",
            "pulumi/Pulumi.test.yaml",
            ("governance", "platform"),
        ),
        (
            "pulumi/user-service-infrastructure/README.md",
            "docs/service.md",
            (),
        ),
    ],
)
def test_moved_files_union_both_paths(status, source, destination, stacks) -> None:
    result = select_records(
        [
            {"filename": destination, "previous_filename": source, "status": status},
        ]
    )
    assert result.stacks == stacks
    assert tuple(impact.path for impact in result.reasons) == tuple(
        sorted((source, destination))
    )
    assert result.scaffold_validation is source.startswith(
        "pulumi/user-service-infrastructure/"
    )


@pytest.mark.parametrize("status", ["added", "modified", "removed"])
@pytest.mark.parametrize(
    "path",
    ["scripts/_pulumi_stack_config.py", "pulumi/repositories.governance.json"],
)
def test_absent_inputs_remain_dependencies(monkeypatch, status, path) -> None:
    def forbidden(*args, **kwargs):
        raise AssertionError("Selector must not inspect repository paths")

    monkeypatch.setattr(Path, "exists", forbidden)
    monkeypatch.setattr(Path, "read_text", forbidden)
    assert select_records([{"filename": path, "status": status}]).stacks == ALL


def test_union_is_deterministic_and_dependency_ordered() -> None:
    paths = [
        "pulumi/infra/utils/tags.py",
        "pulumi/user-service-infrastructure/pulumi/__main__.py",
        "README.md",
        "pulumi/governance/__main__.py",
    ]
    result = select(*paths)
    assert result == select(*reversed(paths))
    assert result.stacks == STACK_ORDER == ALL
    assert result.scaffold_validation
    assert tuple(impact.path for impact in result.reasons) == tuple(sorted(paths))


def test_shared_rename_source_is_deduplicated_without_losing_destination() -> None:
    result = select_records(
        [
            {
                "filename": "docs/first.md",
                "status": "copied",
                "previous_filename": "README.md",
            },
            {
                "filename": "docs/second.md",
                "status": "copied",
                "previous_filename": "README.md",
            },
        ]
    )
    assert len(result.reasons) == 3


@pytest.mark.parametrize(
    "path",
    [
        "main.py",
        "catalog.json",
        "scripts/new_runner.py",
        ".github/workflows/new.yml",
        "pulumi/governance-extra/main.py",
        "pulumi/governance-notes.md",
        "pulumi/app-extra/main.py",
        "pulumi/user-service-infrastructure-extra/main.py",
        "pulumi/new_shared.py",
        "pulumi/PulumiBad.yaml",
        "pulumi/other/Pulumi.prod.yaml",
        "docker-compose.extra/nested.yml",
        "nested/docker-compose.yml",
    ],
)
def test_unknown_inputs_cannot_become_successful_empty_scopes(path) -> None:
    with pytest.raises(ValueError, match="Unclassified"):
        select(path)


@pytest.mark.parametrize(
    "path",
    [
        None,
        12,
        "",
        " ",
        "/README.md",
        "./README.md",
        "docs/../README.md",
        "docs//README.md",
        "docs/",
        "docs\\README.md",
        "README.md\n",
        "\tREADME.md",
        "docs/a\x00.md",
        "docs/a\x7f.md",
        "docs/a\n.md",
        " README.md",
        "README.md ",
    ],
)
def test_malformed_paths_fail_closed(path) -> None:
    with pytest.raises(ValueError, match="paths"):
        select_records([{"filename": path, "status": "modified"}])


@pytest.mark.parametrize(
    "record",
    [
        {},
        None,
        [],
        {"filename": "README.md"},
        {"filename": "README.md", "status": "unchanged"},
        {"filename": "README.md", "status": []},
        {"filename": "README.md", "status": "renamed"},
        {"filename": "README.md", "status": "copied", "previous_filename": None},
        {
            "filename": "README.md",
            "status": "renamed",
            "previous_filename": "README.md",
        },
        {"filename": "README.md", "status": "modified", "previous_filename": "old.md"},
    ],
)
def test_malformed_records_fail_closed(record) -> None:
    with pytest.raises(ValueError):
        select_records([record])


@pytest.mark.parametrize(
    "override",
    [
        {"base_sha": ""},
        {"head_sha": "b" * 39},
        {"base_sha": "A" * 40},
        {"base_sha": "z" * 40},
        {"head_sha": None},
        {"head_sha": BASE},
        {"complete": False},
        {"complete": 1},
        {"complete": None},
        {"expected_file_count": 0},
        {"expected_file_count": -1},
        {"expected_file_count": True},
        {"expected_file_count": "1"},
        {"expected_file_count": 2},
        {"records": []},
        {"records": "README.md"},
        {"records": None},
        {"records": {"filename": "README.md", "status": "modified"}},
    ],
)
def test_incomplete_or_unpinned_snapshots_fail_closed(override) -> None:
    arguments = {
        "records": [{"filename": "README.md", "status": "modified"}],
        "base_sha": BASE,
        "head_sha": HEAD,
        "expected_file_count": 1,
        "complete": True,
    }
    arguments.update(override)
    with pytest.raises(ValueError):
        select_deployment_scopes(**arguments)


def test_duplicate_records_cannot_satisfy_expected_total() -> None:
    record = {"filename": "README.md", "status": "modified"}
    with pytest.raises(ValueError, match="Duplicate"):
        select_records([record, record])


def test_snapshot_supports_immutable_record_sequence_and_ignores_api_metadata() -> None:
    result = select_deployment_scopes(
        ({"filename": "README.md", "status": "modified", "additions": 4},),
        base_sha=BASE,
        head_sha=HEAD,
        expected_file_count=1,
        complete=True,
    )
    assert result.stacks == ()


def test_security_classification_is_independent() -> None:
    for path in ("scripts/record_dependabot_exception.py", ".github/CODEOWNERS"):
        assert paths_touch_governance([path])
        assert select(path).stacks == ()
    # Shared runtime can affect governance even outside the security globs.
    assert not paths_touch_governance(["pulumi/infra/utils/tags.py"])
    assert select("pulumi/infra/utils/tags.py").stacks == ALL


@pytest.mark.parametrize(
    ("path", "scaffold"),
    [
        ("scripts/deployment_scopes.py", False),
        ("scripts/deployment_schedule.py", False),
        ("scripts/deployment_controller.py", False),
        ("scripts/deployment_controller_runtime.py", False),
        ("scripts/deployment_contract_io.py", False),
        ("scripts/deployment_worker_recheck.py", False),
        ("scripts/deployment_worker_runtime.py", False),
        ("scripts/deployment_worker_receipt.py", False),
        ("scripts/deployment_receipt_runtime.py", False),
        ("scripts/deployment_account_barrier.py", False),
        ("scripts/deployment_input_validation.py", False),
        ("scripts/deployment_promotion_proof.py", False),
        ("scripts/deployment_promotion_publication.py", False),
        ("scripts/deployment_promotion_emitter.py", False),
        ("scripts/deployment_promotion_scope.py", False),
        ("scripts/operator_enrollment_runtime.py", False),
        ("scripts/operator_aws_read.py", False),
        ("scripts/operator_execution_runtime.py", False),
        ("scripts/operator_execution_transport.py", False),
        (".github/workflows/pulumi-operator-account.yml", False),
        ("scripts/operator_plan_envelope.py", False),
        ("scripts/operator_plan_validation.py", False),
        ("scripts/pulumi_command_preflight.py", True),
        ("scripts/pulumi_pr_comment.py", True),
        ("scripts/governance_promotion.py", True),
        ("scripts/_github_environment_controls.py", True),
        ("scripts/_github_evidence_environment.py", True),
        ("scripts/_github_repository_controls.py", True),
        ("scripts/pulumi_ci_guardrails.py", True),
        ("scripts/validate_ci_environment.py", True),
        ("scripts/governance_paths.py", True),
        (".github/actions/load-aws-ci-env/action.yml", True),
        (".github/workflows/pulumi-pr-commands.yml", False),
        (".github/workflows/pulumi-pr-command-runner.yml", False),
        (".github/workflows/pulumi-platform-account.yml", False),
        (".github/workflows/pulumi-governance-account.yml", False),
        (".github/workflows/pulumi-governance.yml", False),
        (".github/workflows/governance-promotion.yml", False),
    ],
)
def test_coordinator_execution_inputs_select_conservative_validation(
    path, scaffold
) -> None:
    result = select(path)
    assert result.stacks == ALL
    assert result.execution_validation
    assert result.scaffold_validation is scaffold


def test_scaffold_copy_inventory_has_not_drifted() -> None:
    # Read Python syntax as data; never import/execute the generator to classify a PR.
    source = Path(__file__).resolve().parents[2] / (
        "scripts/scaffold_infrastructure_repository.py"
    )
    tree = ast.parse(source.read_text())
    copied = next(
        node.value
        for node in tree.body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "RUNTIME_FILES"
            for target in node.targets
        )
    )
    assert set(ast.literal_eval(copied)) == SCAFFOLD_RUNTIME_FILES
    for path in SCAFFOLD_RUNTIME_FILES:
        assert select(path).scaffold_validation
