#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

from _script_support import repo_root
from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError, ValidationError

ROOT_DIR = repo_root(__file__)
DEFAULT_EXPECTED_ENVIRONMENTS = 2
PER_ENVIRONMENT_FANOUT = {
    "s3Buckets": 2,
    "kmsKeys": 1,
    "iamRoles": 2,
    "backupSelections": 1,
}
CENTRAL_STACK_FANOUT = {
    "s3Buckets": 3,
    "kmsKeys": 1,
    "backupVaults": 1,
    "backupPlans": 1,
    "iamRoles": 2,
    "oidcProviders": 1,
    "ecrRepositories": 1,
    "snsTopics": 1,
    "snsSubscriptions": 1,
    "sqsQueues": 1,
    "eventRules": 4,
    "cloudTrailTrails": 1,
    "budgets": 1,
    "costAnomalyMonitors": 1,
    "costAnomalySubscriptions": 1,
    # Cost allocation tags are optional and config-driven; keep the category
    # visible without assuming the optional controls are enabled by default.
    "costAllocationTags": 0,
}
LAST_REVIEWED_PATTERN = re.compile(r"\d{4}-\d{2}-\d{2}")


def repository_catalog_paths(root_dir: Path) -> list[Path]:
    """Return committed repository catalog JSON files, excluding the schema."""
    return sorted(
        path
        for path in (root_dir / "pulumi").glob("repositories*.json")
        if path.name != "repositories.schema.json"
    )


def _load_json(path: Path) -> Any:
    """Load a JSON document for schema validation."""
    return json.loads(path.read_text(encoding="utf-8"))


def _json_pointer(path_parts: Sequence[object]) -> str:
    """Render a readable JSON path for a validation error."""
    pointer = "$"
    for part in path_parts:
        if isinstance(part, int):
            pointer = f"{pointer}[{part}]"
        else:
            pointer = f"{pointer}.{part}"
    return pointer


def _format_schema_error(error: ValidationError) -> str:
    """Format the most specific schema validation failure."""
    return f"{_json_pointer(error.absolute_path)}: {error.message}"


def _required_non_blank_string(value: object, label: str) -> str:
    """Return a stripped string or raise the loader-compatible validation error."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError(label)
    return value.strip()


def _repository_name(item: object) -> str:
    """Normalize one repository catalog entry name."""
    if isinstance(item, str):
        return _required_non_blank_string(
            item,
            "Each managedRepositories entry must be a non-empty string.",
        )
    if isinstance(item, Mapping):
        return _required_non_blank_string(
            item.get("name"),
            "Each managedRepositories entry must include a non-empty 'name'.",
        )
    raise ValueError(
        "Each managedRepositories entry must be a string or an object with 'name'."
    )


def _validate_repository_mapping(item: Mapping[str, object]) -> None:
    """Validate optional repository mapping fields that default in the loader."""
    raw_default_branch = item.get("defaultBranch")
    if raw_default_branch is not None:
        _required_non_blank_string(
            raw_default_branch,
            "managedRepositories defaultBranch values must be non-empty strings.",
        )

    raw_project = item.get("project")
    if raw_project is not None:
        _required_non_blank_string(
            raw_project,
            "Each managedRepositories entry must include a non-empty 'project'.",
        )

    _validate_repository_metadata(item)


def _validate_repository_metadata(item: Mapping[str, object]) -> None:
    """Validate optional ownership and lifecycle metadata fields."""
    _validate_owner_metadata(item)
    _validate_lifecycle_state_metadata(item)
    _validate_last_reviewed_metadata(item)
    _validate_expected_environments_metadata(item)


def _validate_owner_metadata(item: Mapping[str, object]) -> None:
    """Validate optional repository owner metadata."""
    raw_owner = item.get("owner")
    if raw_owner is not None:
        _required_non_blank_string(
            raw_owner,
            "managedRepositories owner values must be non-empty strings.",
        )


def _validate_lifecycle_state_metadata(item: Mapping[str, object]) -> None:
    """Validate optional repository lifecycle metadata."""
    raw_lifecycle_state = item.get("lifecycleState")
    if raw_lifecycle_state is not None:
        lifecycle_state = _required_non_blank_string(
            raw_lifecycle_state,
            "managedRepositories lifecycleState values must be non-empty strings.",
        )
        if lifecycle_state not in {"active", "planned", "deprecated", "archived"}:
            raise ValueError(
                "managedRepositories lifecycleState values must be one of: "
                "active, planned, deprecated, archived."
            )


def _validate_last_reviewed_metadata(item: Mapping[str, object]) -> None:
    """Validate optional repository review-date metadata."""
    raw_last_reviewed = item.get("lastReviewed")
    if raw_last_reviewed is not None:
        last_reviewed = _required_non_blank_string(
            raw_last_reviewed,
            "managedRepositories lastReviewed values must be non-empty strings.",
        )
        if not LAST_REVIEWED_PATTERN.fullmatch(last_reviewed):
            raise ValueError(
                "managedRepositories lastReviewed values must use YYYY-MM-DD format."
            )
        try:
            dt.date.fromisoformat(last_reviewed)
        except ValueError as exc:
            raise ValueError(
                "managedRepositories lastReviewed values must use YYYY-MM-DD format."
            ) from exc


def _validate_expected_environments_metadata(item: Mapping[str, object]) -> None:
    """Validate optional repository environment fanout metadata."""
    raw_expected_environments = item.get("expectedEnvironments")
    if raw_expected_environments is not None and (
        isinstance(raw_expected_environments, bool)
        or not isinstance(raw_expected_environments, int)
        or raw_expected_environments < 1
    ):
        raise ValueError(
            "managedRepositories expectedEnvironments values must be positive integers."
        )


def _validate_loader_semantics(payload: Mapping[str, object]) -> None:
    """Validate catalog rules that the JSON Schema cannot fully express."""
    repositories = payload["repositories"]
    if not isinstance(repositories, list):
        raise ValueError("managedRepositories config must be a list.")

    seen: dict[str, str] = {}
    duplicates: set[str] = set()
    for item in repositories:
        name = _repository_name(item)
        if isinstance(item, Mapping):
            _validate_repository_mapping(item)
        normalized_name = name.casefold()
        if normalized_name in seen:
            duplicates.add(seen[normalized_name])
            duplicates.add(name)
        else:
            seen[normalized_name] = name

    if duplicates:
        duplicate_names = ", ".join(sorted(duplicates, key=str.casefold))
        raise ValueError(f"Managed repository names must be unique: {duplicate_names}.")


def validate_catalog(catalog_path: Path, schema_path: Path) -> Path:
    """Validate one repository catalog against JSON Schema and loader semantics."""
    schema = _load_json(schema_path)
    payload = _load_json(catalog_path)
    try:
        Draft202012Validator.check_schema(schema)
    except SchemaError as exc:
        raise ValueError(
            f"{schema_path}: invalid repository catalog schema: {exc.message}"
        ) from exc
    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(payload), key=lambda item: item.json_path)
    if errors:
        raise ValueError(f"{catalog_path}: {_format_schema_error(errors[0])}")

    _validate_loader_semantics(payload)
    return catalog_path


def validate_catalogs(catalog_paths: Sequence[Path], schema_path: Path) -> list[Path]:
    """Validate all repository catalog files."""
    return [
        validate_catalog(catalog_path, schema_path) for catalog_path in catalog_paths
    ]


def _expected_environments(item: object) -> int:
    """Return the projected environment count for one catalog entry."""
    if isinstance(item, Mapping):
        raw_value = item.get("expectedEnvironments")
        if isinstance(raw_value, int) and not isinstance(raw_value, bool):
            return raw_value
    return DEFAULT_EXPECTED_ENVIRONMENTS


def estimate_fanout(payload: Mapping[str, object]) -> dict[str, int]:
    """Estimate cost and quota-driving resources from repository catalog metadata."""
    repositories = payload.get("repositories")
    if not isinstance(repositories, list):
        raise ValueError("managedRepositories config must be a list.")
    environment_instances = sum(_expected_environments(item) for item in repositories)
    fanout = dict(CENTRAL_STACK_FANOUT)
    fanout["repositories"] = len(repositories)
    fanout["environmentInstances"] = environment_instances

    for key, count in PER_ENVIRONMENT_FANOUT.items():
        fanout[key] = fanout.get(key, 0) + count * environment_instances
    return fanout


def catalog_fanout_report(catalog_path: Path, schema_path: Path) -> dict[str, int]:
    """Validate a catalog and return its projected resource fanout."""
    validate_catalog(catalog_path, schema_path)
    payload = _load_json(catalog_path)
    if not isinstance(payload, Mapping):
        raise ValueError("Repository catalog JSON must be an object.")
    return estimate_fanout(payload)


def _fanout_thresholds(args: argparse.Namespace) -> dict[str, int]:
    """Return configured fanout thresholds."""
    return {
        "s3Buckets": args.max_s3_buckets,
        "kmsKeys": args.max_kms_keys,
        "iamRoles": args.max_iam_roles,
        "backupSelections": args.max_backup_selections,
        "ecrRepositories": args.max_ecr_repositories,
        "budgets": args.max_budgets,
        "snsSubscriptions": args.max_sns_subscriptions,
        "sqsQueues": args.max_sqs_queues,
        "cloudTrailTrails": args.max_cloudtrail_trails,
        "costAnomalyMonitors": args.max_cost_anomaly_monitors,
        "costAnomalySubscriptions": args.max_cost_anomaly_subscriptions,
        "costAllocationTags": args.max_cost_allocation_tags,
    }


def _fanout_failures(
    catalog_path: Path, report: Mapping[str, int], thresholds: Mapping[str, int]
) -> list[str]:
    """Return threshold violations for one fanout report."""
    failures = []
    for key, threshold in thresholds.items():
        value = report.get(key, 0)
        if value > threshold:
            failures.append(f"{catalog_path}: {key} fanout {value} exceeds {threshold}")
    return failures


def _fanout_threshold_report(
    report: Mapping[str, int], thresholds: Mapping[str, int]
) -> dict[str, dict[str, int | str]]:
    """Return current fanout counts with threshold headroom for reporting."""
    threshold_report: dict[str, dict[str, int | str]] = {}
    for key, threshold in thresholds.items():
        current = report.get(key, 0)
        threshold_report[key] = {
            "current": current,
            "max": threshold,
            "remaining": max(threshold - current, 0),
            "overBy": max(current - threshold, 0),
            "status": "exceeded" if current > threshold else "ok",
        }
    return threshold_report


def main(argv: Sequence[str] | None = None) -> int:
    """Validate committed repository catalog JSON files."""
    parser = argparse.ArgumentParser(
        description="Validate repository catalog JSON files.",
    )
    parser.add_argument(
        "catalogs",
        nargs="*",
        type=Path,
        help="Repository catalog JSON files. Defaults to pulumi/repositories*.json.",
    )
    parser.add_argument(
        "--schema",
        type=Path,
        default=ROOT_DIR / "pulumi" / "repositories.schema.json",
        help="JSON Schema file used for repository catalogs.",
    )
    parser.add_argument(
        "--fanout-report",
        action="store_true",
        help="Print static resource fanout estimates for each catalog.",
    )
    parser.add_argument("--max-s3-buckets", type=int, default=200)
    parser.add_argument("--max-kms-keys", type=int, default=100)
    parser.add_argument("--max-iam-roles", type=int, default=300)
    parser.add_argument("--max-backup-selections", type=int, default=500)
    parser.add_argument("--max-ecr-repositories", type=int, default=50)
    parser.add_argument("--max-budgets", type=int, default=20)
    parser.add_argument("--max-sns-subscriptions", type=int, default=50)
    parser.add_argument("--max-sqs-queues", type=int, default=50)
    parser.add_argument("--max-cloudtrail-trails", type=int, default=20)
    parser.add_argument("--max-cost-anomaly-monitors", type=int, default=20)
    parser.add_argument("--max-cost-anomaly-subscriptions", type=int, default=20)
    parser.add_argument("--max-cost-allocation-tags", type=int, default=100)
    args = parser.parse_args(argv)

    catalog_paths = list(args.catalogs) or repository_catalog_paths(ROOT_DIR)
    if not catalog_paths:
        print("error: no repository catalog JSON files found.", file=sys.stderr)
        return 1

    try:
        validated_paths = validate_catalogs(catalog_paths, args.schema)
        reports = (
            [
                (path, catalog_fanout_report(path, args.schema))
                for path in validated_paths
            ]
            if args.fanout_report
            else []
        )
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    for path in validated_paths:
        print(f"validated repository catalog: {path}")
    failures: list[str] = []
    thresholds = _fanout_thresholds(args)
    for path, report in reports:
        print(
            f"repository fanout estimate for {path}: "
            f"{json.dumps(report, sort_keys=True)}"
        )
        threshold_report_json = json.dumps(
            _fanout_threshold_report(report, thresholds),
            sort_keys=True,
        )
        print(f"repository fanout thresholds for {path}: {threshold_report_json}")
        failures.extend(_fanout_failures(path, report, thresholds))
    if failures:
        for failure in failures:
            print(f"error: {failure}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
