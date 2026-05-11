from __future__ import annotations

import argparse
from pathlib import Path

from _well_architected_evidence_common import _check
from validate_repository_catalogs import (
    _fanout_failures,
    _fanout_threshold_report,
    _fanout_thresholds,
    catalog_fanout_report,
    repository_catalog_paths,
)

EXAMPLE_CATALOG_NAMES = frozenset({"repositories.example.json"})


def repository_fanout_evidence(
    root_dir: Path, args: argparse.Namespace
) -> dict[str, object]:
    """Collect static repository fanout evidence from committed catalogs."""
    schema_path = root_dir / "pulumi" / "repositories.schema.json"
    catalog_paths = _evidence_repository_catalog_paths(root_dir)
    if not catalog_paths:
        return _check(
            "repository_fanout",
            status="missing",
            blockers=[
                "No non-example repository catalog JSON files were found for "
                "fanout evidence."
            ],
        )
    thresholds = _fanout_thresholds(args)
    reports = []
    failures: list[str] = []
    for catalog_path in catalog_paths:
        catalog_name = str(catalog_path.relative_to(root_dir))
        try:
            report = catalog_fanout_report(catalog_path, schema_path)
        except ValueError as exc:
            failures.append(f"{catalog_name}: {exc}")
            reports.append({"catalog": catalog_name, "error": str(exc)})
            continue
        reports.append(
            {
                "catalog": catalog_name,
                "fanout": report,
                "thresholds": _fanout_threshold_report(report, thresholds),
            }
        )
        failures.extend(_fanout_failures(catalog_path, report, thresholds))
    return _check(
        "repository_fanout",
        status="passed" if not failures else "failed",
        evidence={"catalogCount": len(catalog_paths), "reports": reports},
        blockers=failures,
    )


def _evidence_repository_catalog_paths(root_dir: Path) -> list[Path]:
    """Return non-example repository catalogs that can support evidence claims."""
    return [
        path
        for path in repository_catalog_paths(root_dir)
        if path.name not in EXAMPLE_CATALOG_NAMES
    ]
