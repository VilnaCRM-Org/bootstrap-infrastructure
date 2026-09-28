"""Admit an exact independently reviewed PR revision from a trusted main runner.

This is a pre-execution gate: never invoke it after same-user PR code. AWS must
reject generic pull_request subjects independently of this script.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess  # nosec B404
import sys
from pathlib import Path

# Isolated execution excludes the script directory; admit only this installed
# trusted directory, never the caller's working directory or PYTHONPATH.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from pulumi_command_preflight import decode_array_pages

REPOSITORY = "VilnaCRM-Org/bootstrap-infrastructure"
REPOSITORY_ID = 1098568429
# Authorization belongs to reviewed main policy, never a PR file or variable.
AUTOMATED_REVIEWER = (136622811, "coderabbitai[bot]", "Bot")
SIGNALS = {
    ".github/workflows/pulumi-pr-guardrails.yml": "pull_request",
    ".github/workflows/reviewed-source-signal.yml": "pull_request_review",
}


def require(condition: bool, message: str) -> None:
    """Fail closed on missing, changed, or contradictory admission evidence."""
    if not condition:
        raise ValueError(message)


def gh(path: str, *args: str):
    """Read authenticated GitHub evidence without shell evaluation."""
    slurp = "--slurp" in args
    if slurp:
        require(
            args.count("--slurp") == 1 and "--paginate" in args, "Invalid page request"
        )
        args = tuple(arg for arg in args if arg != "--slurp")
    result = subprocess.run(  # nosec B603 B607
        ["gh", "api", path, *args], check=True, capture_output=True, text=True
    )
    return decode_array_pages(result.stdout) if slurp else json.loads(result.stdout)


def validate_pr(pr: dict, number: str, head_sha: str) -> None:
    """Bind admission to a live same-repository PR targeting main."""
    require(str(pr["number"]) == number, "PR number differs")
    require(pr["state"] == "open" and not pr["merged"], "PR is not open")
    require(pr["head"]["sha"] == head_sha, "PR head moved")
    require(pr["base"]["ref"] == "main", "PR must target main")
    for side in ("head", "base"):
        repo = pr[side]["repo"]
        require(
            repo["full_name"] == REPOSITORY and repo["id"] == REPOSITORY_ID,
            "Foreign PR repository",
        )


def eligible_reviews(pr: dict, reviews: list[dict]) -> list[dict]:
    """Reduce decisive reviews by immutable user ID; comments do not revoke votes."""
    latest = {}
    for review in sorted(reviews, key=lambda value: value["id"]):
        if review["state"] in {"APPROVED", "CHANGES_REQUESTED", "DISMISSED"}:
            latest[review["user"]["id"]] = review
    require(
        not any(r["state"] == "CHANGES_REQUESTED" for r in latest.values()),
        "Outstanding changes requested",
    )
    return [
        r
        for r in latest.values()
        if r["state"] == "APPROVED"
        and r["commit_id"] == pr["head"]["sha"]
        and r["user"]["id"] != pr["user"]["id"]
    ]


def automated_policy_unchanged(head_sha: str, trusted_sha: str) -> bool:
    """Do not let a PR change the configuration of its automated approver."""
    policies = []
    for sha in (head_sha, trusted_sha):
        tree = gh(f"repos/{REPOSITORY}/git/trees/{sha}")
        require(tree["truncated"] is False, "Incomplete reviewer configuration tree")
        policies.append(
            [
                {key: item[key] for key in ("path", "mode", "type", "sha")}
                for item in tree["tree"]
                if item["path"] == ".coderabbit.yaml"
            ]
        )
    return policies[0] == policies[1]


def admit(number: str, head_sha: str, trusted_sha: str) -> dict[str, str]:
    """Refresh source, reviews and authorization immediately before credentials."""
    require(re.fullmatch(r"[1-9][0-9]*", number) is not None, "Invalid PR number")
    for value in (head_sha, trusted_sha):
        require(re.fullmatch(r"[0-9a-f]{40}", value) is not None, "Invalid SHA")
    base = f"repos/{REPOSITORY}"
    require(gh(f"{base}/commits/main")["sha"] == trusted_sha, "Trusted main moved")
    pr = gh(f"{base}/pulls/{number}")
    validate_pr(pr, number, head_sha)
    pages = gh(f"{base}/pulls/{number}/reviews?per_page=100", "--paginate", "--slurp")
    reviews = [review for page in pages for review in page]
    admitted = []
    for review in eligible_reviews(pr, reviews):
        user = review["user"]
        identity = (user["id"], user["login"], user["type"])
        if identity == AUTOMATED_REVIEWER:
            if automated_policy_unchanged(head_sha, trusted_sha):
                admitted.append(review)
        elif user["type"] == "User":
            require(
                re.fullmatch(r"[A-Za-z0-9-]+", user["login"]) is not None,
                "Invalid reviewer login",
            )
            permission = gh(f"{base}/collaborators/{user['login']}/permission")
            if permission["user"]["id"] == user["id"] and permission["permission"] in {
                "write",
                "maintain",
                "admin",
            }:
                admitted.append(review)
    require(bool(admitted), "No independent current-head approval")
    # Re-read the chosen review after permission lookup; dismissal/replacement fails.
    chosen = admitted[-1]
    current = gh(f"{base}/pulls/{number}/reviews?per_page=100", "--paginate", "--slurp")
    require(current == pages, "Approval changed during admission")
    validate_pr(gh(f"{base}/pulls/{number}"), number, head_sha)
    require(gh(f"{base}/commits/main")["sha"] == trusted_sha, "Trusted main moved")
    return {
        "pull_request_number": number,
        "head_sha": head_sha,
        "review_id": str(chosen["id"]),
        "reviewer_id": str(chosen["user"]["id"]),
    }


def signal_request(event: dict) -> tuple[str, str, str]:
    """Resolve a signal using server-side run and PR identities, never artifacts."""
    run_id = event["workflow_run"]["id"]
    require(type(run_id) is int and run_id > 0, "Invalid source run ID")
    run = gh(f"repos/{REPOSITORY}/actions/runs/{run_id}")
    require(
        run["path"] in SIGNALS and run["event"] == SIGNALS[run["path"]],
        "Untrusted source run",
    )
    require(run["status"] == "completed", "Source signal is not terminal")
    require(run["head_repository"]["id"] == REPOSITORY_ID, "Foreign source run")
    head = run["head_sha"]
    require(re.fullmatch(r"[0-9a-f]{40}", head) is not None, "Invalid source SHA")
    pages = gh(
        f"repos/{REPOSITORY}/commits/{head}/pulls?per_page=100", "--paginate", "--slurp"
    )
    candidates = [
        pr
        for page in pages
        for pr in page
        if pr["state"] == "open"
        and pr["head"]["sha"] == head
        and pr["base"]["ref"] == "main"
    ]
    require(len(candidates) == 1, "Signal does not identify one live PR")
    return str(candidates[0]["number"]), head, run["conclusion"]


REQUIRED_CONTEXTS = (
    "Reviewed Preview",
    "Reviewed Destructive Diff Gate",
    "Reviewed IAM Validation",
)


PUBLISHER_ENVIRONMENT = "reviewed-source-publisher"
OWNER_ID = 114362548


def publisher_app_id() -> int:
    """Require a separately provisioned App, never a shared workflow issuer."""
    value = os.environ.get("REVIEWED_SOURCE_APP_ID", "")
    require(re.fullmatch(r"[1-9][0-9]*", value) is not None, "Missing publisher App ID")
    app_id = int(value)
    require(app_id not in {15368, 4840884}, "Publisher App must be dedicated")
    return app_id


def verify_publisher_boundary() -> None:
    """Verify the main-only App-key environment before creating its token."""
    publisher_app_id()
    base = f"repos/{REPOSITORY}/environments/{PUBLISHER_ENVIRONMENT}"
    environment = gh(base)
    policies = gh(f"{base}/deployment-branch-policies?per_page=100")
    require(environment.get("can_admins_bypass") is False, "Publisher allows bypass")
    require(
        environment.get("deployment_branch_policy")
        == {"protected_branches": False, "custom_branch_policies": True},
        "Publisher requires custom branch restrictions",
    )
    branches = policies.get("branch_policies", [])
    require(
        policies.get("total_count") == 1
        and len(branches) == 1
        and branches[0].get("name") == "main"
        and branches[0].get("type") == "branch",
        "Publisher environment must allow only main",
    )


def _verify_reviewed_ruleset_scope(ruleset: dict, updated_at: str) -> None:
    """Bind a no-bypass owner audit to the exact active ruleset revision."""
    require(
        ruleset.get("target") == "branch"
        and ruleset.get("enforcement") == "active"
        and ruleset.get("conditions")
        == {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
        "Reviewed ruleset must protect main",
    )
    timestamp_pattern = (
        r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d"
        r"(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)"
    )
    require(
        re.fullmatch(timestamp_pattern, updated_at) is not None
        and ruleset.get("updated_at") == updated_at,
        "Reviewed ruleset changed since the no-bypass owner audit",
    )
    # GitHub omits bypass_actors from a ruleset read with Administration: read.
    # The protected environment pin comes from an owner who can inspect it;
    # fail closed on any subsequently changed ruleset revision.
    if "bypass_actors" in ruleset:
        require(ruleset["bypass_actors"] == [], "Reviewed ruleset allows bypass")


def verify_reviewed_ruleset(
    ruleset: dict, app_id: int, ruleset_id: int, updated_at: str
) -> None:
    """Require actual App issuer bindings on the active default-branch ruleset."""
    require(ruleset.get("id") == ruleset_id, "Reviewed ruleset ID differs")
    _verify_reviewed_ruleset_scope(ruleset, updated_at)
    rules = [
        r for r in ruleset.get("rules", []) if r.get("type") == "required_status_checks"
    ]
    require(len(rules) == 1, "Reviewed ruleset requires one status rule")
    parameters = rules[0]["parameters"]
    require(
        parameters.get("strict_required_status_checks_policy") is True,
        "Checks must be strict",
    )
    checks = parameters.get("required_status_checks", [])
    for context in REQUIRED_CONTEXTS:
        matches = [item for item in checks if item.get("context") == context]
        require(
            len(matches) == 1
            and type(matches[0].get("integration_id")) is int
            and matches[0]["integration_id"] == app_id,
            "Reviewed context requires the dedicated App issuer",
        )


def publisher_identity() -> dict:
    """Bind status responses to the actual dedicated App's numeric bot identity."""
    app_id = publisher_app_id()
    slug = os.environ.get("REVIEWED_SOURCE_APP_SLUG", "")
    require(re.fullmatch(r"[a-z0-9-]+", slug) is not None, "Missing publisher App slug")
    app = gh(f"apps/{slug}")
    require(
        app.get("id") == app_id
        and app.get("slug") == slug
        and app.get("owner", {}).get("id") == OWNER_ID,
        "Publisher App identity differs",
    )
    bot = gh(f"users/{slug}[bot]")
    require(
        type(bot.get("id")) is int
        and bot["id"] > 0
        and bot.get("login") == f"{slug}[bot]"
        and bot.get("type") == "Bot",
        "Publisher bot identity differs",
    )
    if os.environ.get("REVIEWED_SOURCE_PREVIEW_ACTIVE") == "true":
        ruleset_id = os.environ.get("REVIEWED_SOURCE_RULESET_ID", "")
        require(
            re.fullmatch(r"[1-9][0-9]*", ruleset_id) is not None,
            "Missing reviewed ruleset ID",
        )
        verify_reviewed_ruleset(
            gh(f"repos/{REPOSITORY}/rulesets/{ruleset_id}"),
            app_id,
            int(ruleset_id),
            os.environ.get("REVIEWED_SOURCE_RULESET_UPDATED_AT", ""),
        )
    return {key: bot[key] for key in ("id", "login", "type")}


def publish_statuses(head_sha: str, state: str) -> None:
    """Publish and read back an exact-head status using the dedicated App token."""
    require(state in {"pending", "success", "failure"}, "Invalid status state")
    require(re.fullmatch(r"[0-9a-f]{40}", head_sha) is not None, "Invalid status SHA")
    creator = publisher_identity()
    run_id = os.environ["GITHUB_RUN_ID"]
    require(re.fullmatch(r"[1-9][0-9]*", run_id) is not None, "Invalid run ID")
    url = f"https://github.com/{REPOSITORY}/actions/runs/{run_id}"
    for context in REQUIRED_CONTEXTS:
        status = gh(
            f"repos/{REPOSITORY}/statuses/{head_sha}",
            "--method",
            "POST",
            "-f",
            f"state={state}",
            "-f",
            f"context={context}",
            "-f",
            f"target_url={url}",
            "-f",
            "description=Independently reviewed source: trusted AWS preview",
        )
        require(
            status["state"] == state
            and status["context"] == context
            and status["target_url"] == url
            and {key: status.get("creator", {}).get(key) for key in creator} == creator,
            "Status publication or dedicated issuer differs",
        )


def _admit_and_publish(
    args: argparse.Namespace, number: str, head: str, signal_conclusion: str
) -> dict[str, str]:
    """Invalidate rejected source before returning any admitted worker outputs."""
    if args.publish_pending:
        require(
            args.number is None and args.publish_result is None,
            "Pending publication requires a fresh workflow signal",
        )
        require(
            gh(f"repos/{REPOSITORY}/commits/main")["sha"] == os.environ["GITHUB_SHA"],
            "Trusted main moved",
        )
        validate_pr(gh(f"repos/{REPOSITORY}/pulls/{number}"), number, head)
        publish_statuses(head, "pending")
    try:
        require(signal_conclusion == "success", "Source signal did not succeed")
        result = admit(number, head, os.environ["GITHUB_SHA"])
    except Exception:
        # Invalidation is independent of successful admission. Never retain a
        # previous success after a verified signal or final recheck rejects it.
        if args.publish_pending or args.publish_result:
            publish_statuses(head, "failure")
        raise
    if args.publish_result:
        publish_statuses(result["head_sha"], args.publish_result)
    return result


def main() -> None:
    """Run only in a trusted main workflow before checking out executable PR code."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--number")
    parser.add_argument("--head-sha")
    parser.add_argument("--verify-publisher-boundary", action="store_true")
    parser.add_argument("--publish-pending", action="store_true")
    parser.add_argument("--publish-result", choices=("success", "failure"))
    args = parser.parse_args()
    require(os.environ["GITHUB_REPOSITORY"] == REPOSITORY, "Wrong repository")
    require(os.environ["GITHUB_REF"] == "refs/heads/main", "Untrusted workflow ref")
    require(
        os.environ["GITHUB_EVENT_NAME"] in {"workflow_run", "repository_dispatch"},
        "Untrusted event",
    )
    if args.verify_publisher_boundary:
        require(
            gh(f"repos/{REPOSITORY}/commits/main")["sha"] == os.environ["GITHUB_SHA"],
            "Trusted main moved",
        )
        verify_publisher_boundary()
        return
    number, head = args.number, args.head_sha
    signal_conclusion = "success"
    if number is None:
        require(
            os.environ["GITHUB_EVENT_NAME"] == "workflow_run", "Missing PR identity"
        )
        number, head, signal_conclusion = signal_request(
            json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
        )
    result = _admit_and_publish(args, number, head or "", signal_conclusion)
    with Path(os.environ["GITHUB_OUTPUT"]).open("a") as output:
        for key, value in result.items():
            output.write(f"{key}={value}\n")


if __name__ == "__main__":  # pragma: no cover
    main()
