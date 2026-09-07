#!/usr/bin/env python3
"""Main-only trusted publisher and explicitly pinned local operator bootstrap."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sys
from pathlib import Path

# The entrypoint itself must be invoked from independently pinned trusted source.
# Isolated Python ignores cwd/PYTHONPATH; only this verified checkout is imported.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _well_architected_publisher as host  # noqa: E402
import _well_architected_publisher_artifacts as artifacts  # noqa: E402
from _well_architected_trusted_evidence import _require  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


def save(path: Path, value: dict) -> None:
    _require(not path.exists(), "Host output must be new")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
    path.chmod(0o600)


def context(args: argparse.Namespace) -> dict:
    with args.approval.open("rb") as stream:
        raw = stream.read(2_000_001)
    _require(host.sha(raw) == args.approval_sha256, "Protected approval digest differs")
    value = host.approval(raw)
    _require(
        value["transport"] == "github-artifact" or args.mode == "bootstrap",
        "Local approval cannot authorize workflow execution",
    )
    host.runtime(ROOT, value, args.source_sha)
    host.pr_context(value)
    if args.mode != "bootstrap":
        host.workflow_context(value)
    return value


def fetch(value: dict, destination: Path) -> None:
    info = host.gh(f"repos/{host.REPOSITORY}/actions/artifacts/{value['artifact_id']}")
    _require(
        info.get("id") == value["artifact_id"]
        and info.get("expired") is False
        and type(info.get("size_in_bytes")) is int
        and 0 < info["size_in_bytes"] <= 16_000_000,
        "Approved artifact absent, expired or oversized",
    )
    artifacts.extract(
        artifacts.download(host.REPOSITORY, value["artifact_id"]), destination
    )
    host.bundle(value, destination)


def collect(args: argparse.Namespace, value: dict, manifest: dict) -> dict:
    host.data_checkout(args.data_root, value, manifest)
    identity = host._json(
        host.command(["aws", "sts", "get-caller-identity", "--output", "json"]).encode()
    )
    _require(identity.get("Account") == host.ACCOUNT, "AWS evidence caller is foreign")
    os.environ["AWS_REGION"] = host.REGION
    os.environ["AWS_DEFAULT_REGION"] = host.REGION
    report = host.collector(value, manifest, args.bundle, args.data_root)
    return host.result(
        value, report, os.environ.get("GITHUB_RUN_ID", "local-bootstrap")
    )


def publication(value: dict, record: dict, *, bootstrap: bool) -> dict:
    run_id = "local-bootstrap" if bootstrap else os.environ["GITHUB_RUN_ID"]
    report = host.verify_result(value, record, run_id)
    if bootstrap:
        url = f"https://github.com/{host.REPOSITORY}/pull/{value['pr']}"
    else:
        run = host.workflow_context(value)
        jobs = host.gh(
            f"repos/{host.REPOSITORY}/actions/runs/{run_id}/jobs?per_page=100"
        )
        _require(
            jobs.get("total_count") == len(jobs.get("jobs", []))
            and jobs["total_count"] < 100,
            "Incomplete publisher job inventory",
        )
        collectors = [
            job for job in jobs["jobs"] if job.get("name") == host.COLLECT_JOB
        ]
        _require(
            len(collectors) == 1
            and collectors[0].get("status") == "completed"
            and collectors[0].get("conclusion") == "success",
            "Trusted collector job did not succeed",
        )
        url = run["html_url"]
    host.verify_issuer()
    return host.post(value, report, url)


def execute(args: argparse.Namespace) -> int:
    value = context(args)
    if args.mode in {"prepare", "publish", "bootstrap"}:
        host.verify_environment()
    if args.mode == "prepare":
        return prepare(args, value)
    manifest = host.bundle(value, args.bundle)
    if args.mode == "verify":
        host.verify_environment()
        host.verify_issuer()
        if args.data_root is not None:
            host.data_checkout(args.data_root, value, manifest)
        return 0
    if args.mode == "collect":
        save(args.output, collect(args, value, manifest))
        return (
            0  # Logical failure is retained in the report, never turned into success.
        )
    if args.mode == "bootstrap":
        _require(
            args.app_key is not None and args.installation_id is not None,
            "Local App issuance inputs missing",
        )
        record = collect(args, value, manifest)
        save(args.output, record)
        from _well_architected_publisher_app import installation_token

        with installation_token(args.app_key, args.installation_id):
            payload = publication(value, record, bootstrap=True)
    else:
        payload = publication(value, host.read_json(args.result), bootstrap=False)
    save(
        args.receipt,
        {
            "published_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "source_sha": value["source_sha"],
            "head_sha": value["head_sha"],
            "manifest_sha256": value["manifest_sha256"],
            **payload,
        },
    )
    return 0 if payload["state"] == "success" else 1


def prepare(args: argparse.Namespace, value: dict) -> int:
    fetch(value, args.bundle)
    output = {
        key: str(value[key])
        for key in ("pr", "head_sha", "source_sha", "read_role_arn")
    }
    output.update(approval_sha256=args.approval_sha256)
    if os.environ.get("GITHUB_OUTPUT"):
        with Path(os.environ["GITHUB_OUTPUT"]).open("a") as stream:
            for key, val in output.items():
                stream.write(f"{key}={val}\n")
    save(args.output, value)
    return 0


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument(
        "mode", choices=("prepare", "verify", "collect", "publish", "bootstrap")
    )
    result.add_argument("--approval", type=Path, required=True)
    result.add_argument("--approval-sha256", required=True)
    result.add_argument("--source-sha", required=True)
    result.add_argument("--bundle", type=Path, required=True)
    result.add_argument("--data-root", type=Path)
    result.add_argument("--output", type=Path)
    result.add_argument("--result", type=Path)
    result.add_argument("--receipt", type=Path)
    result.add_argument("--app-key", type=Path)
    result.add_argument("--installation-id", type=int)
    return result


def main(argv: list[str] | None = None) -> int:
    try:
        return execute(parser().parse_args(argv))
    except (ValueError, KeyError, TypeError, OSError) as error:
        # No remote payload, credential, secret or PR content in exception output.
        print(
            f"Trusted evidence publisher stopped ({type(error).__name__}).",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
