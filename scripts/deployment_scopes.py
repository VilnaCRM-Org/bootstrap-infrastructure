"""Pure, conservative impact selection for a future trusted deployment coordinator.

Call this from trusted code with a complete, SHA-bound changed-file snapshot.
The caller must fetch and pin both revisions, exhaust pagination and verify the
reported file count. This module cannot attest provenance or completeness itself.
Selections request validation; they never authorize an apply or service rollout.
Security review remains the independent ``governance_paths`` classification.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import Literal

Stack = Literal["operator", "governance", "platform"]
STACK_ORDER: tuple[Stack, ...] = ("operator", "governance", "platform")
SCAFFOLD_ROOT = "pulumi/user-service-infrastructure/"

# Reviewed generator closure, kept explicit: do not import or execute PR code.
SCAFFOLD_RUNTIME_FILES = frozenset(
    {
        "Dockerfile",
        ".dockerignore",
        "pyproject.toml",
        "uv.lock",
        ".github/actions/load-aws-ci-env/action.yml",
        "scripts/_script_support.py",
        "scripts/_pulumi_command_support.py",
        "scripts/_pulumi_stack_config.py",
        "scripts/_github_environment_controls.py",
        "scripts/_github_evidence_environment.py",
        "scripts/_github_repository_controls.py",
        "scripts/configure_github_repository_controls.py",
        "scripts/run_pulumi_command.py",
        "scripts/prepare_policy_pack.py",
        "scripts/pulumi_ci_guardrails.py",
        "scripts/pulumi_command_preflight.py",
        "scripts/pulumi_pr_comment.py",
        "scripts/governance_paths.py",
        "scripts/governance_promotion.py",
        "scripts/validate_ci_environment.py",
        "scripts/initialize_service_stack.py",
    }
)
CENTRAL_EXECUTION_FILES = frozenset(
    {
        "Makefile",
        "Dockerfile",
        ".dockerignore",
        "pyproject.toml",
        "uv.lock",
        "pulumi/sitecustomize.py",
        "scripts/_script_support.py",
        "scripts/_pulumi_command_support.py",
        "scripts/_pulumi_stack_config.py",
        "scripts/run_pulumi_command.py",
        "scripts/prepare_docker_context.py",
        "scripts/prepare_policy_pack.py",
        "scripts/run_pulumi_preview.py",
        "scripts/run_pulumi_drift_check.py",
        "scripts/deployment_scopes.py",
        "scripts/deployment_schedule.py",
        "scripts/deployment_controller.py",
        "scripts/deployment_controller_runtime.py",
        "scripts/deployment_contract_io.py",
        "scripts/deployment_worker_recheck.py",
        "scripts/deployment_worker_runtime.py",
        "scripts/deployment_worker_receipt.py",
        "scripts/deployment_receipt_runtime.py",
        "scripts/deployment_account_barrier.py",
        "scripts/deployment_input_validation.py",
        "scripts/operator_plan_envelope.py",
        "scripts/pulumi_command_preflight.py",
        "scripts/pulumi_pr_comment.py",
        "scripts/governance_promotion.py",
        "scripts/_github_environment_controls.py",
        "scripts/_github_evidence_environment.py",
        "scripts/_github_repository_controls.py",
        "scripts/pulumi_ci_guardrails.py",
        "scripts/validate_ci_environment.py",
        "scripts/governance_paths.py",
        ".github/actions/load-aws-ci-env/action.yml",
        ".github/workflows/pulumi-pr-commands.yml",
        ".github/workflows/pulumi-pr-command-runner.yml",
        ".github/workflows/pulumi-platform-account.yml",
        ".github/workflows/pulumi-governance-account.yml",
        ".github/workflows/pulumi-governance.yml",
        ".github/workflows/governance-promotion.yml",
    }
)
# These known non-runtime inputs still need their own checks/security review.
VALIDATION_ONLY_FILES = frozenset(
    {
        ".github/CODEOWNERS",
        ".github/workflows/security-scans.yml",
        "scripts/record_dependabot_exception.py",
    }
)
PROJECT_READMES = frozenset(
    {
        "pulumi/README.md",
        "pulumi/governance/README.md",
        "pulumi/github-ci-bootstrap/README.md",
        "policy/README.md",
    }
)


@dataclass(frozen=True)
class PathImpact:
    """Explain one path's independent validation requirements."""

    path: str
    stacks: tuple[Stack, ...] = ()
    scaffold_validation: bool = False
    execution_validation: bool = False
    catalog_validation: bool = False
    reason: str = "Known documentation or tests; no central runtime dependency"


@dataclass(frozen=True)
class DeploymentScopes:
    """Deterministic validation selection, with immutable revision identities."""

    base_sha: str
    head_sha: str
    stacks: tuple[Stack, ...]
    scaffold_validation: bool
    execution_validation: bool
    catalog_validation: bool
    reasons: tuple[PathImpact, ...]


def _validate_path(value: object) -> str:
    """Reject ambiguous/noncanonical API paths instead of normalizing them."""
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError("Changed-file paths must be nonempty canonical strings")
    if (
        "\\" in value
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
        or any(part in {"", ".", ".."} for part in value.split("/"))
    ):
        raise ValueError("Changed-file paths must be canonical repository paths")
    return value


def _record_paths(record: Mapping[str, object]) -> tuple[str, ...]:
    """Preserve removed dependencies, including every rename/copy source."""
    if not isinstance(record, Mapping):
        raise ValueError("Each changed-file record must be a mapping")
    path = _validate_path(record.get("filename"))
    status = record.get("status")
    if status in ("renamed", "copied"):
        previous = _validate_path(record.get("previous_filename"))
        if previous == path:
            raise ValueError("Rename/copy source must differ from its destination")
        return (path, previous)
    if status not in ("added", "modified", "removed"):
        raise ValueError("Unsupported or missing changed-file status")
    if "previous_filename" in record:
        raise ValueError("Only rename/copy records may contain previous_filename")
    return (path,)


def _validate_snapshot_revisions(base_sha: str, head_sha: str) -> None:
    """Require distinct immutable revisions before evaluating snapshot contents."""
    for revision in (base_sha, head_sha):
        if not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{40}", revision):
            raise ValueError("Both revisions must be full lowercase Git commit SHAs")
    if base_sha == head_sha:
        raise ValueError("A changed-file snapshot must compare distinct revisions")


def _snapshot_paths(
    records: Sequence[Mapping[str, object]],
    base_sha: str,
    head_sha: str,
    expected_file_count: int,
    complete: bool,
) -> tuple[str, ...]:
    """Validate the caller's complete snapshot contract before selecting anything."""
    _validate_snapshot_revisions(base_sha, head_sha)
    if (
        complete is not True
        or type(expected_file_count) is not int
        or expected_file_count <= 0
        or not isinstance(records, (list, tuple))
        or len(records) != expected_file_count
    ):
        raise ValueError("A complete, nonempty changed-file snapshot is required")
    paths: set[str] = set()
    destinations: set[str] = set()
    for record in records:
        record_paths = _record_paths(record)
        if record_paths[0] in destinations:
            raise ValueError("Duplicate changed-file destination in snapshot")
        destinations.add(record_paths[0])
        paths.update(record_paths)
    return tuple(sorted(paths))


def _central_impact(path: str) -> PathImpact | None:
    """Classify central runtime inputs with specific project roots first."""
    for prefix, stack in (
        ("pulumi/github-ci-bootstrap/", "operator"),
        ("pulumi/governance/", "governance"),
        ("pulumi/app/", "platform"),
    ):
        if path.startswith(prefix):
            return PathImpact(path, (stack,), reason="Project runtime/configuration")
    if path.startswith("pulumi/infra/") or path == "pulumi/requirements.txt":
        return PathImpact(
            path, STACK_ORDER, reason="Conservative shared runtime impact"
        )
    if path == "pulumi/repositories.governance.json":
        return PathImpact(
            path,
            STACK_ORDER,
            catalog_validation=True,
            reason="Operator boundaries, governance resources, platform log inventory",
        )
    if path == "pulumi/repositories.bootstrap.json":
        return PathImpact(
            path,
            ("operator", "platform"),
            catalog_validation=True,
            reason="Operator catalog; conservative platform delegation revalidation",
        )
    if path in {"pulumi/repositories.schema.json", "pulumi/repositories.example.json"}:
        return PathImpact(
            path, catalog_validation=True, reason="Catalog validator input"
        )
    if _is_platform_project_input(path):
        return PathImpact(path, ("platform",), reason="Platform project runtime/input")
    return None


def _is_platform_project_input(path: str) -> bool:
    """Identify only the root platform entrypoint and project manifests/config."""
    return path == "pulumi/__main__.py" or (
        path.count("/") == 1
        and path.startswith("pulumi/Pulumi")
        and (path == "pulumi/Pulumi.yaml" or fnmatchcase(path, "pulumi/Pulumi.*.yaml"))
    )


def _is_central_execution_input(path: str) -> bool:
    """Match reviewed runner inputs, root Compose files, and shared policy."""
    compose = "/" not in path and fnmatchcase(path, "docker-compose*.yml")
    return path in CENTRAL_EXECUTION_FILES or compose or path.startswith("policy/")


def _path_impact(path: str) -> PathImpact:
    """Classify without inspecting filesystem state or importing changed programs."""
    if path.startswith(SCAFFOLD_ROOT) or path == (
        "scripts/scaffold_infrastructure_repository.py"
    ):
        return PathImpact(
            path, scaffold_validation=True, reason="Generated scaffold input"
        )
    scaffold = path in SCAFFOLD_RUNTIME_FILES or path.startswith("policy/")
    if _is_documentation_or_test(path):
        return PathImpact(path, scaffold_validation=scaffold)
    if _is_central_execution_input(path):
        return PathImpact(
            path,
            STACK_ORDER,
            scaffold,
            execution_validation=True,
            reason="Conservative shared execution/policy validation",
        )
    if scaffold:
        return PathImpact(
            path,
            scaffold_validation=True,
            execution_validation=True,
            reason="Copied scaffold execution/control input",
        )
    if path in VALIDATION_ONLY_FILES:
        return PathImpact(
            path,
            execution_validation=True,
            reason="Known workflow/security validation input; no central runtime edge",
        )
    central = _central_impact(path)
    if central is not None:
        return central
    raise ValueError(
        f"Unclassified changed path requires reviewed scope mapping: {path}"
    )


def _is_documentation_or_test(path: str) -> bool:
    """Limit no-runtime classifications to known documentation/test namespaces."""
    return (
        path.startswith(("docs/", "tests/", "specs/"))
        or path in PROJECT_READMES
        or ("/" not in path and path.endswith((".md", ".rst")))
    )


def select_deployment_scopes(
    records: Sequence[Mapping[str, object]],
    *,
    base_sha: str,
    head_sha: str,
    expected_file_count: int,
    complete: bool,
) -> DeploymentScopes:
    """Union validated old/new paths into ordered scopes; fail closed on uncertainty.

    ``records`` are GitHub-style file mappings containing ``filename``, ``status``
    and ``previous_filename`` for renames/copies. Additional API metadata is ignored.
    ``expected_file_count`` is the independently fetched PR total, not ``len(files)``.
    ``complete`` must attest exhausted pagination and a fresh revision/count check.
    Empty snapshots intentionally require caller review rather than a docs-only pass.
    """
    paths = _snapshot_paths(records, base_sha, head_sha, expected_file_count, complete)
    reasons = tuple(_path_impact(path) for path in paths)
    selected = {stack for impact in reasons for stack in impact.stacks}
    return DeploymentScopes(
        base_sha=base_sha,
        head_sha=head_sha,
        stacks=tuple(stack for stack in STACK_ORDER if stack in selected),
        scaffold_validation=any(impact.scaffold_validation for impact in reasons),
        execution_validation=any(impact.execution_validation for impact in reasons),
        catalog_validation=any(impact.catalog_validation for impact in reasons),
        reasons=reasons,
    )
