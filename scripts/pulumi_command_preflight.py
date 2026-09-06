#!/usr/bin/env python3
"""Authenticate a comment command against its immutable trusted intake artifact."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess  # nosec B404
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from _github_repository_controls import protected_environment_verification_blockers
from governance_paths import paths_touch_governance
from pulumi_pr_comment import parse_command, write_outputs

INTAKE_PATH = ".github/workflows/pulumi-pr-commands.yml"


def require(condition: bool, message: str) -> None:
    """Reject incomplete or contradictory evidence."""
    if not condition:
        raise ValueError(message)


def gh(*args: str) -> Any:
    """Read GitHub JSON without interpreting response text as commands."""
    result = subprocess.run(  # nosec B603 B607
        ["gh", "api", *args], check=True, capture_output=True, text=True
    )
    return json.loads(result.stdout)


def authenticate_intake(request: dict, evidence: dict):
    """Bind feedback to the original trusted run, artifact, repository and comment."""
    repository = evidence["repository"]
    pr, comment, run = (evidence[key] for key in ("pr", "comment", "run"))
    require(run["event"] == "issue_comment", "Source must be an issue_comment run")
    require(run["path"] == INTAKE_PATH, "Source must be the trusted intake workflow")
    require(run["head_repository"]["full_name"] == repository, "Foreign intake run")
    require(run["run_attempt"] == 1, "Re-run intake requests are not accepted")
    require(str(run["id"]) == request["source_run_id"], "Source run mismatch")
    require(evidence["artifact"] == request, "Dispatch differs from intake artifact")
    require(pr["head"]["repo"]["full_name"] == repository, "Fork PR rejected")
    require(pr["base"]["repo"]["full_name"] == repository, "Foreign base repository")
    issue_url = (
        f"{evidence['api_url']}/repos/{repository}/issues/"
        f"{request['pull_request_number']}"
    )
    require(comment["issue_url"] == issue_url, "Comment belongs to another PR")
    require(str(comment["id"]) == request["comment_id"], "Comment ID mismatch")
    require(comment["updated_at"] == comment["created_at"], "Edited comment rejected")
    created = datetime.fromisoformat(comment["created_at"].replace("Z", "+00:00"))
    started = datetime.fromisoformat(run["created_at"].replace("Z", "+00:00"))
    require(0 <= (started - created).total_seconds() <= 300, "Stale intake comment")
    require(run["actor"]["id"] == comment["user"]["id"], "Intake actor mismatch")
    command = parse_command(comment["body"])
    if command is None:
        raise ValueError("Comment is not a Pulumi command")
    require(
        command.action == request["command"]
        and command.target_environment == request["target_environment"],
        "Comment command or environment differs from dispatch",
    )
    return command


def validate_request(
    request: dict, evidence: dict, *, governance: bool, service: bool = False
) -> dict:
    """Require authenticated origin and all current execution authorization checks."""
    command = authenticate_intake(request, evidence)
    pr, comment = evidence["pr"], evidence["comment"]
    require(pr["state"] == "open" and pr["merged"] is False, "PR closed or merged")
    require(pr["head"]["sha"] == request["head_sha"], "PR head moved")
    require(pr["base"]["ref"] == "main", "PR must target main")
    require(pr["base"]["sha"] == evidence["scope_base_sha"], "PR base moved")
    created = datetime.fromisoformat(comment["created_at"].replace("Z", "+00:00"))
    require(0 <= (evidence["now"] - created).total_seconds() <= 900, "Expired command")
    require(
        evidence["permission"] in {"write", "maintain", "admin"},
        "Write access required",
    )
    if command.action == "up":
        require(
            comment["user"]["login"].lower() != "kravalg",
            "Apply requester must differ from sole approver Kravalg",
        )
    touched = paths_touch_governance(evidence["files"])
    require(
        service or touched == governance,
        "Request routed to the wrong governance scope",
    )
    return {
        **request,
        "display_command": command.display_command,
        "base_sha": evidence["scope_base_sha"],
    }


def read_request() -> dict[str, str]:
    """Load only closed-format dispatch fields from the Actions environment."""
    patterns = {
        "pull_request_number": r"[1-9][0-9]*",
        "head_sha": r"[0-9a-f]{40}",
        "comment_id": r"[1-9][0-9]*",
        "source_run_id": r"[1-9][0-9]*",
        "command": r"plan|up",
        "target_environment": r"test|prod",
    }
    request = {}
    for key, pattern in patterns.items():
        value = os.environ.get(f"REQUEST_{key.upper()}", "")
        require(re.fullmatch(pattern, value) is not None, f"Invalid {key}")
        request[key] = value
    return request


def collect_intake_evidence(request: dict[str, str]) -> dict:
    """Fetch provenance without depending on mutable execution prerequisites."""
    repository = os.environ["GITHUB_REPOSITORY"]
    base = f"repos/{repository}"
    run_id = request["source_run_id"]
    run = gh(f"{base}/actions/runs/{run_id}")
    # Validate provenance before downloading anything supplied by another workflow.
    require(
        run["event"] == "issue_comment" and run["path"] == INTAKE_PATH,
        "Untrusted intake workflow",
    )
    with tempfile.TemporaryDirectory() as directory:
        subprocess.run(  # nosec B603 B607
            [
                "gh",
                "run",
                "download",
                run_id,
                "--repo",
                repository,
                "--name",
                "pulumi-command-request",
                "--dir",
                directory,
            ],
            check=True,
        )
        artifact = json.loads((Path(directory) / "request.json").read_text())
    pr_number = request["pull_request_number"]
    comment = gh(f"{base}/issues/comments/{request['comment_id']}")
    login = comment["user"]["login"]
    require(
        re.fullmatch(r"[A-Za-z0-9-]+", login) is not None, "Invalid commenter login"
    )
    return {
        "repository": repository,
        "api_url": os.environ.get("GITHUB_API_URL", "https://api.github.com"),
        "pr": gh(f"{base}/pulls/{pr_number}"),
        "comment": comment,
        "run": run,
        "artifact": artifact,
    }


def collect_evidence(request: dict[str, str], *, intake: dict | None = None) -> dict:
    """Fetch current execution state after the immutable origin is authenticated."""
    origin = collect_intake_evidence(request) if intake is None else intake
    authenticate_intake(request, origin)
    repository = origin["repository"]
    base = f"repos/{repository}"
    pr_number = request["pull_request_number"]
    login = origin["comment"]["user"]["login"]
    before = gh(f"{base}/pulls/{pr_number}")
    require(
        before["head"]["sha"] == request["head_sha"], "PR head moved before scope scan"
    )
    base_sha = before["base"]["sha"]
    require(re.fullmatch(r"[0-9a-f]{40}", base_sha) is not None, "Invalid base SHA")
    comparison = gh(f"{base}/compare/{base_sha}...{request['head_sha']}")
    changed = comparison["files"]
    # Compare is immutable but GitHub limits this response to 300 files.
    require(len(changed) == before["changed_files"], "Incomplete changed-file listing")
    files = [
        name
        for item in changed
        for name in (item["filename"], item.get("previous_filename", ""))
    ]
    return {
        **origin,
        "now": datetime.now(timezone.utc),
        "pr": gh(f"{base}/pulls/{pr_number}"),
        "permission": gh(f"{base}/collaborators/{login}/permission")["permission"],
        "scope_base_sha": base_sha,
        "files": files,
    }


def claim_request(request: dict[str, str]) -> None:
    """Consume a comment once; both runners serialize under the same PR group."""
    base = f"repos/{os.environ['GITHUB_REPOSITORY']}"
    sha = request["head_sha"]
    context = f"Pulumi command claim/{request['comment_id']}"
    pages = gh(f"{base}/commits/{sha}/statuses?per_page=100", "--paginate", "--slurp")
    require(
        not any(item["context"] == context for page in pages for item in page),
        "Comment command was already consumed; create a new comment",
    )
    gh(
        f"{base}/statuses/{sha}",
        "--method",
        "POST",
        "-f",
        "state=success",
        "-f",
        f"context={context}",
        "-f",
        "description=Comment command consumed",
    )


def verify_environments(request: dict[str, str], *, governance: bool) -> None:
    """Reject missing or unprotected environments instead of allowing auto-creation."""
    if governance:
        environments = ["governance-preview"]
        if request["command"] == "up":
            environments.append("governance")
    else:
        environments = ["test-preview"]
        if request["target_environment"] == "prod":
            environments.append("prod-preview")
        if request["command"] == "up":
            environments.append("test")
            if request["target_environment"] == "prod":
                environments.append("prod")
    reviewer = gh("users/Kravalg")["id"]
    repository = os.environ["GITHUB_REPOSITORY"]
    for name in environments:
        environment = gh(f"repos/{repository}/environments/{name}")
        policies = gh(
            f"repos/{repository}/environments/{name}/deployment-branch-policies"
        )
        require(
            isinstance(environment, dict) and isinstance(policies, dict),
            f"{name} environment and branch policies must be objects",
        )
        environment = dict(environment)
        environment["deployment_branch_policies"] = policies.get("branch_policies")
        blockers = protected_environment_verification_blockers(
            environment, reviewer, label=name
        )
        require(not blockers, "; ".join(blockers))


def main(argv: list[str] | None = None) -> int:
    """Authenticate and consume a request before exposing any job guard outputs."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--governance", action="store_true")
    parser.add_argument("--service", action="store_true")
    args = parser.parse_args(argv)
    require(
        os.environ.get("GITHUB_RUN_ATTEMPT") == "1", "Re-run rejected; comment again"
    )
    require(
        os.environ.get("GITHUB_EVENT_NAME") == "repository_dispatch",
        "Only repository dispatch may run preflight",
    )
    require(
        os.environ.get("GITHUB_REF") == "refs/heads/main",
        "Only the trusted main workflow may run preflight",
    )
    request = read_request()
    intake = collect_intake_evidence(request)
    command = authenticate_intake(request, intake)
    # These values permit informational feedback only, never AWS job execution.
    write_outputs(
        {
            **{
                f"feedback_{key}": request[key]
                for key in (
                    "head_sha",
                    "pull_request_number",
                    "command",
                    "target_environment",
                )
            },
            "feedback_display_command": command.display_command,
        },
        os.environ.get("GITHUB_OUTPUT"),
    )
    evidence = collect_evidence(request, intake=intake)
    require(not (args.service and args.governance), "Conflicting repository scopes")
    outputs = validate_request(
        request, evidence, governance=args.governance, service=args.service
    )
    verify_environments(request, governance=args.governance)
    claim_request(request)
    write_outputs(outputs, os.environ.get("GITHUB_OUTPUT"))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
