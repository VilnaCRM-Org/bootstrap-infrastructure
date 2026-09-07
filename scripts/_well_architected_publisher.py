"""Trusted WA host primitives; PR checkout and approved artifacts are data only."""

from __future__ import annotations

import datetime as dt
import hashlib
import importlib
import json
import os
import re
import subprocess  # nosec B404
from pathlib import Path
from typing import Any
from urllib.parse import quote

import _github_evidence_environment as boundary
from _well_architected_trusted_evidence import (
    Target,
    _json,
    _require,
    parse_timestamp,
    status_payload,
    verify_bundle,
)

REPOSITORY = "VilnaCRM-Org/bootstrap-infrastructure"
ACCOUNT = "891377212104"
REGION = "eu-central-1"
APP_ID = 4840884
APP_SLUG = "vilnacrm-infrastructure-evidence"
WORKFLOW = ".github/workflows/trusted-well-architected.yml"
COLLECT_JOB = "Collect trusted Well-Architected evidence"
SELECTORS = {
    "question_matrix": "question_matrix_evidence",
    "external_controls": "external_control_evidence",
    "security_account": "security_account_attestation_evidence",
    "alert_route": "alert_route_observation_evidence",
    "restore_drill": "restore_drill_evidence",
    "production_dr": "production_dr_owner_evidence",
}


def command(argv: list[str], *, cwd: Path | None = None) -> str:
    result = subprocess.run(
        argv, cwd=cwd, check=False, capture_output=True, text=True, timeout=120
    )  # nosec B603
    _require(result.returncode == 0, "Trusted metadata command failed")
    _require(len(result.stdout) <= 16_000_000, "Metadata output exceeds bound")
    return result.stdout


def gh(path: str) -> Any:
    return _json(command(["gh", "api", path]).encode())


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def read_json(path: Path) -> dict[str, Any]:
    _require(not path.is_symlink() and path.is_file(), "Required host input missing")
    with path.open("rb") as stream:
        return _json(stream.read(2_000_001))


def approval(raw: bytes) -> dict[str, Any]:
    value = _json(raw)
    _require(
        value.get("schema") == "wa-publisher-approval-v1", "Unknown protected approval"
    )
    for field, size in (
        ("source_sha", 40),
        ("head_sha", 40),
        ("runtime_sha256", 64),
        ("manifest_sha256", 64),
    ):
        _require(
            isinstance(value.get(field), str)
            and re.fullmatch(f"[0-9a-f]{{{size}}}", value[field]) is not None,
            "Invalid protected source binding",
        )
    for field in ("repository_id", "pr"):
        _require(
            type(value.get(field)) is int and value[field] > 0,
            "Invalid protected numeric identity",
        )
    approved_transport(value)
    _require(value.get("repository") == REPOSITORY, "Foreign protected repository")
    _require(
        value.get("account") == ACCOUNT and value.get("region") == REGION,
        "Foreign evidence account or region",
    )
    _require(
        value.get("app_id") == APP_ID and value.get("app_slug") == APP_SLUG,
        "Foreign status issuer",
    )
    _require(
        re.fullmatch(
            f"arn:aws:iam::{ACCOUNT}:role/GitHubCiPreview-[A-Za-z0-9+=,.@_-]+-test",
            str(value.get("read_role_arn", "")),
        )
        is not None,
        "Invalid read-only role",
    )
    _require(
        str(value.get("topic_arn", "")).startswith(f"arn:aws:sns:{REGION}:{ACCOUNT}:"),
        "Foreign topic",
    )
    _require(
        re.fullmatch(r"[A-Za-z0-9._-]{3,128}", str(value.get("trail", ""))) is not None,
        "Invalid trail",
    )
    issued = parse_timestamp(value["issued_at"])
    expires = parse_timestamp(value["expires_at"])
    now = dt.datetime.now(dt.timezone.utc)
    _require(
        issued <= now < expires and expires - issued <= dt.timedelta(hours=24),
        "Protected approval is stale or excessive",
    )
    return value


def approved_transport(value: dict[str, Any]) -> None:
    """Local first installation has no invented remote artifact locator."""
    transport = value.get("transport")
    _require(
        transport in {"github-artifact", "local-reviewed-bundle"},
        "Unknown approved transport",
    )
    artifact_id = value.get("artifact_id")
    _require(
        (
            transport == "github-artifact"
            and type(artifact_id) is int
            and artifact_id > 0
        )
        or (transport == "local-reviewed-bundle" and artifact_id is None),
        "Invalid approved artifact identity",
    )


def target(value: dict[str, Any]) -> Target:
    return Target(
        value["repository"],
        value["repository_id"],
        value["pr"],
        value["head_sha"],
        value["runtime_sha256"],
    )


def runtime(root: Path, value: dict[str, Any], source_sha: str) -> None:
    _require(source_sha == value["source_sha"], "Operator source pin differs")
    _require(
        command(["git", "rev-parse", "HEAD"], cwd=root).strip() == source_sha,
        "Trusted source HEAD differs",
    )
    command(["git", "diff", "--exit-code", "HEAD", "--"], cwd=root)
    names = command(["git", "ls-files", "-z"], cwd=root).rstrip("\0").split("\0")
    files = {}
    for name in names:
        path = root / name
        _require(
            path.is_file() and not path.is_symlink(), "Unsafe trusted runtime file"
        )
        files[name] = sha(path.read_bytes())
    _require(
        sha(json.dumps(files, sort_keys=True, separators=(",", ":")).encode())
        == value["runtime_sha256"],
        "Trusted runtime closure differs",
    )
    tracked_python = {
        name for name in names if name.startswith("scripts/") and name.endswith(".py")
    }
    _require(
        {str(p.relative_to(root)) for p in (root / "scripts").rglob("*.py")}
        == tracked_python,
        "Untracked Python in trusted import root",
    )


def verify_environment() -> None:
    env = gh(f"repos/{REPOSITORY}/environments/governance-evidence")
    policies = gh(
        f"repos/{REPOSITORY}/environments/governance-evidence/deployment-branch-policies"
    )
    _require(
        not boundary.verification_blockers(env, policies),
        "App environment boundary differs",
    )


def pr_context(value: dict[str, Any]) -> dict[str, Any]:
    repo = gh(f"repos/{REPOSITORY}")
    _require(
        repo.get("id") == value["repository_id"]
        and repo.get("default_branch") == "main",
        "Repository identity or default branch differs",
    )
    pr = gh(f"repos/{REPOSITORY}/pulls/{value['pr']}")
    _require(
        pr.get("state") == "open" and pr.get("draft") is False,
        "PR is not open and ready",
    )
    for key in ("head", "base"):
        item = pr.get(key, {})
        _require(
            item.get("repo", {}).get("id") == value["repository_id"]
            and item.get("repo", {}).get("full_name") == REPOSITORY,
            "Fork or foreign PR repository",
        )
    _require(
        pr["base"].get("ref") == "main" and pr["head"].get("sha") == value["head_sha"],
        "PR head or base differs",
    )
    return pr


def workflow_context(value: dict[str, Any]) -> dict[str, Any]:
    _require(
        os.environ.get("GITHUB_REF") == "refs/heads/main"
        and os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch",
        "Publisher must run on main dispatch",
    )
    _require(
        os.environ.get("GITHUB_REPOSITORY") == REPOSITORY
        and os.environ.get("GITHUB_RUN_ATTEMPT") == "1",
        "Foreign or rerun publisher",
    )
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    _require(run_id.isascii() and run_id.isdigit(), "Invalid publisher run")
    run = gh(f"repos/{REPOSITORY}/actions/runs/{run_id}")
    _require(
        run.get("head_sha") == value["source_sha"]
        and run.get("head_branch") == "main"
        and run.get("event") == "workflow_dispatch"
        and run.get("run_attempt") == 1
        and run.get("path") == WORKFLOW,
        "Publisher run provenance differs",
    )
    return run


def bundle(value: dict[str, Any], root: Path) -> dict[str, Any]:
    with (root / "manifest.json").open("rb") as stream:
        raw = stream.read(2_000_001)
    result = verify_bundle(
        raw,
        approved_sha256=value["manifest_sha256"],
        target=target(value),
        bundle_root=root,
        now=dt.datetime.now(dt.timezone.utc),
    )
    _require(
        result.get("source_sha") == value["source_sha"],
        "Manifest observed runtime source differs",
    )
    _require(
        all(result.get(key) == value[key] for key in ("issued_at", "expires_at")),
        "Manifest approval times differ",
    )
    verify_observed_sources(result, root)
    return result


def data_checkout(root: Path, value: dict[str, Any], manifest: dict[str, Any]) -> None:
    _require(
        command(["git", "-C", str(root), "rev-parse", "HEAD"]).strip()
        == value["head_sha"],
        "Data checkout HEAD differs",
    )
    _require(
        not command(
            [
                "git",
                "-C",
                str(root),
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
            ]
        ).strip(),
        "Data checkout is dirty",
    )
    _require(not (root / "pulumi").is_symlink(), "Unsafe PR catalog directory")
    expected = manifest.get("pr_data")
    paths = sorted((root / "pulumi").glob("repositories*.json"))
    _require(
        isinstance(expected, dict) and 0 < len(paths) <= 20,
        "Bounded PR catalog approval missing",
    )
    actual = {}
    for path in paths:
        _require(
            not path.is_symlink() and path.stat().st_size <= 2_000_000,
            "Unsafe PR catalog",
        )
        actual[str(path.relative_to(root))] = sha(path.read_bytes())
    _require(actual == expected, "PR catalog/schema bytes not independently approved")


def collector(
    value: dict[str, Any], manifest: dict[str, Any], bundle_root: Path, data_root: Path
) -> dict[str, Any]:
    # Called only after trusted runtime and data/bundle validation. No PR imports.
    module = importlib.import_module("collect_well_architected_evidence")
    args = module.build_parser().parse_args(
        [
            "--repo",
            REPOSITORY,
            "--pr",
            str(value["pr"]),
            "--root-dir",
            str(data_root),
            "--aws-account-id",
            ACCOUNT,
            "--operations-topic-arn",
            value["topic_arn"],
            "--operations-cloudtrail-name",
            value["trail"],
        ]
    )
    for key, attribute in SELECTORS.items():
        setattr(args, attribute, bundle_root / manifest["evidence"][key])
    # Intentionally do not load evidence paths or exception switches from environment.
    os.environ["WELL_ARCHITECTED_CURRENT_CHECK_NAME"] = ""
    runner, receipts = self_status_runner(module.run, value)
    report = module.collect_evidence(args, runner=runner)
    report["reevaluatedEvidenceProducers"] = receipts
    status_payload(report, target=target(value), current_head=value["head_sha"])
    return report


def result(
    value: dict[str, Any], report: dict[str, Any], run_id: str
) -> dict[str, Any]:
    return {
        "schema": "wa-trusted-result-v1",
        "approval_sha256": sha(json.dumps(value, sort_keys=True).encode()),
        "run_id": run_id,
        "collected_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "report": report,
    }


def verify_result(
    value: dict[str, Any], record: dict[str, Any], run_id: str
) -> dict[str, Any]:
    _require(
        record.get("schema") == "wa-trusted-result-v1"
        and record.get("approval_sha256")
        == sha(json.dumps(value, sort_keys=True).encode())
        and record.get("run_id") == run_id,
        "Collector result provenance differs",
    )
    when = parse_timestamp(record["collected_at"])
    age = dt.datetime.now(dt.timezone.utc) - when
    _require(
        dt.timedelta(0) <= age <= dt.timedelta(minutes=10), "Collector result is stale"
    )
    report = record["report"]
    status_payload(report, target=target(value), current_head=value["head_sha"])
    return report


def fresh_github(report: dict[str, Any], value: dict[str, Any]) -> dict[str, Any]:
    module = importlib.import_module("collect_well_architected_evidence")
    os.environ["WELL_ARCHITECTED_CURRENT_CHECK_NAME"] = ""
    runner, _receipts = self_status_runner(module.run, value)
    checks = [
        module.github_pr_checks(REPOSITORY, value["pr"], runner=runner),
        module.github_review_threads(REPOSITORY, value["pr"]),
        module.github_branch_protection(REPOSITORY, "main"),
        module.github_production_environment(REPOSITORY, "prod", "Kravalg"),
    ]
    checks.append(
        module.github_dependabot_alerts(
            module.DependabotAlertRequest(
                repo=REPOSITORY,
                dependency=module.DEFAULT_DEPENDABOT_DEPENDENCY,
                manifest_path=module.DEFAULT_DEPENDABOT_MANIFEST,
            )
        )
    )
    return refresh_github_rows(module, report, checks)


def refresh_github_rows(module, report: dict[str, Any], checks: list) -> dict[str, Any]:
    """Refresh actual App-readable controls; preserve AWS/owner and extra blockers."""
    by_name = {check["name"]: check for check in checks}
    combined = [by_name.get(check["name"], check) for check in report["checks"]]
    old = module._all_blockers(report["checks"]) + module.score_blockers(
        report["checks"]
    )
    extra = [blocker for blocker in report["blockers"] if blocker not in old]
    proxy = module.pillar_scores(combined)
    scores = module.well_architected_scores(proxy, combined)
    score_blockers = module.score_blockers(combined)
    return {
        **report,
        "checks": combined,
        "proxyPillarScores": proxy,
        "pillarScores": scores,
        "scoreBlockers": score_blockers,
        "githubRefreshedAt": dt.datetime.now(dt.timezone.utc).isoformat(),
        "previousGitHubChecks": [
            check for check in report["checks"] if check["name"] in by_name
        ],
        "blockers": extra + module._all_blockers(combined) + score_blockers,
    }


def post(value: dict[str, Any], report: dict[str, Any], url: str) -> dict[str, Any]:
    verify_environment()
    report = fresh_github(report, value)
    approval(json.dumps(value).encode())
    pr_context(value)
    payload = {
        **status_payload(report, target=target(value), current_head=value["head_sha"]),
        "target_url": url,
    }
    response = subprocess.run(
        [
            "gh",
            "api",
            f"repos/{REPOSITORY}/statuses/{value['head_sha']}",
            "--method",
            "POST",
            "--input",
            "-",
        ],
        input=json.dumps(payload),
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )  # nosec B603 B607
    _require(response.returncode == 0, "Exact-head status publication failed")
    written = _json(response.stdout.encode())
    _require(
        written.get("creator", {}).get("login") == APP_SLUG + "[bot]"
        and written.get("context") == payload["context"]
        and written.get("state") == payload["state"],
        "Status issuer/readback differs",
    )
    return {**payload, "evidence_report": report}


def verify_issuer() -> None:
    # A same-name PR-controlled Actions result must not satisfy the required gate.
    raw = command(["gh", "api", f"repos/{REPOSITORY}/rulesets?per_page=100"])
    rulesets = json.loads(raw)
    _require(
        isinstance(rulesets, list) and len(rulesets) < 100,
        "Ruleset inventory incomplete",
    )
    found = False
    for summary in rulesets:
        ruleset = gh(f"repos/{REPOSITORY}/rulesets/{summary['id']}")
        refs = ruleset.get("conditions", {}).get("ref_name", {})
        if ruleset.get("enforcement") != "active" or ruleset.get("target") != "branch":
            continue
        if not set(refs.get("include", [])).intersection(
            {"~ALL", "~DEFAULT_BRANCH", "refs/heads/main"}
        ):
            continue
        _require(not refs.get("exclude"), "Ambiguous required-check exclusions")
        for rule in ruleset.get("rules", []):
            if rule.get("type") != "required_status_checks":
                continue
            for check in rule.get("parameters", {}).get("required_status_checks", []):
                if check.get("context") == "Test Account Evidence":
                    _require(
                        check.get("integration_id") == APP_ID,
                        "Required evidence issuer is not pinned to the App",
                    )
                    found = True
    _require(found, "Required App evidence context is not installed")


def self_status_runner(runner, value: dict[str, Any]):
    """Exclude only the preceding verified App status from its own reevaluation."""
    verify_issuer()
    status = gh(f"repos/{REPOSITORY}/commits/{value['head_sha']}/status?per_page=100")
    rows = status.get("statuses", [])
    _require(
        status.get("total_count") == len(rows) and len(rows) < 100,
        "Incomplete current status inventory",
    )
    own = [item for item in rows if item.get("context") == "Test Account Evidence"]
    _require(len(own) <= 1, "Ambiguous evidence status")
    if own:
        _require(
            own[0].get("creator", {}).get("login") == APP_SLUG + "[bot]",
            "Foreign evidence status issuer",
        )

    legacy = legacy_evidence_checks(value)

    def bounded_runner(argv, **kwargs):
        result = runner(argv, **kwargs)
        if (
            argv[:3] != ["gh", "pr", "view"]
            or result.returncode != 0
            or not (own or legacy)
        ):
            return result
        payload = json.loads(result.stdout)
        entries = payload.get("statusCheckRollup")
        if not isinstance(entries, list):
            return result
        previous = own[0] if own else {}
        payload["statusCheckRollup"] = [
            entry
            for entry in entries
            if not (
                bool(own)
                and entry.get("__typename") == "StatusContext"
                and entry.get("context") == "Test Account Evidence"
                and str(entry.get("state", "")).lower() == previous.get("state")
                and entry.get("targetUrl") == previous.get("target_url")
            )
            and not (
                entry.get("__typename") == "CheckRun"
                and entry.get("name") == "Test Account Evidence"
                and entry.get("detailsUrl") in legacy
            )
        ]
        return subprocess.CompletedProcess(
            result.args, result.returncode, json.dumps(payload), result.stderr
        )

    receipts = {
        "previousAppStatus": own,
        "legacyActionsChecks": legacy,
    }
    return bounded_runner, receipts


def legacy_evidence_checks(value: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Identify the exact replaced producer; the new collector reruns every gate."""
    payload = gh(
        f"repos/{REPOSITORY}/commits/{value['head_sha']}/check-runs?check_name=Test%20Account%20Evidence&per_page=100"
    )
    checks = payload.get("check_runs", [])
    _require(
        payload.get("total_count") == len(checks) and len(checks) < 100,
        "Incomplete legacy producer inventory",
    )
    known = {}
    for check in checks:
        url = check.get("details_url", "")
        match = re.fullmatch(
            r"https://github.com/"
            + re.escape(REPOSITORY)
            + r"/actions/runs/([0-9]+)/job/[0-9]+",
            url,
        )
        if (
            check.get("name") != "Test Account Evidence"
            or check.get("app", {}).get("id") != 15368
            or match is None
        ):
            continue
        run = gh(f"repos/{REPOSITORY}/actions/runs/{match[1]}")
        if (
            run.get("head_sha") == value["head_sha"]
            and run.get("path") == ".github/workflows/well-architected-evidence.yml"
            and run.get("event") == "pull_request"
        ):
            known[url] = {
                "check_id": check["id"],
                "run_id": run["id"],
                "conclusion": check.get("conclusion"),
                "reason": (
                    "Previous producer only; all underlying evidence requirements "
                    "reexecuted by trusted collector"
                ),
            }
    return known


def verify_observed_sources(manifest: dict[str, Any], root: Path) -> None:
    """Check historical source snapshots against their declared immutable commit."""
    checked = set()
    for name in manifest["files"]:
        if not name.endswith(".json") or name.startswith("sources/"):
            continue
        payload = read_json(root / name)
        commit = payload.get("sourceCommit")
        for path, expected in payload.get("sourceBindings", {}).items():
            key = (commit, path)
            if key in checked:
                continue
            remote = command(
                [
                    "gh",
                    "api",
                    f"repos/{REPOSITORY}/contents/{quote(path, safe='/')}?ref={commit}",
                    "-H",
                    "Accept: application/vnd.github.raw+json",
                ]
            )
            _require(
                sha(remote.encode()) == expected,
                "Declared historical source differs from GitHub commit",
            )
            checked.add(key)
