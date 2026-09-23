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
from pathlib import Path

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
    result = subprocess.run(  # nosec B603 B607
        ["gh", "api", path, *args], check=True, capture_output=True, text=True
    )
    return json.loads(result.stdout)


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


def signal_request(event: dict) -> tuple[str, str]:
    """Resolve a signal using server-side run and PR identities, never artifacts."""
    run_id = event["workflow_run"]["id"]
    require(type(run_id) is int and run_id > 0, "Invalid source run ID")
    run = gh(f"repos/{REPOSITORY}/actions/runs/{run_id}")
    require(
        run["path"] in SIGNALS and run["event"] == SIGNALS[run["path"]],
        "Untrusted source run",
    )
    require(
        run["status"] == "completed" and run["conclusion"] == "success",
        "Source signal did not succeed",
    )
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
    return str(candidates[0]["number"]), head


REQUIRED_CONTEXTS = ("Preview", "Destructive Diff Gate", "IAM Validation")


def publish_statuses(head_sha: str, state: str) -> None:
    """Publish only from a clean trusted job with no cloud or PR execution."""
    require(state in {"pending", "success", "failure"}, "Invalid status state")
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
            and status["target_url"] == url,
            "Status publication differs",
        )


def main() -> None:
    """Run only in a trusted main workflow before checking out executable PR code."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--number")
    parser.add_argument("--head-sha")
    parser.add_argument("--publish-pending", action="store_true")
    parser.add_argument("--publish-result", choices=("success", "failure"))
    args = parser.parse_args()
    require(os.environ["GITHUB_REPOSITORY"] == REPOSITORY, "Wrong repository")
    require(os.environ["GITHUB_REF"] == "refs/heads/main", "Untrusted workflow ref")
    require(
        os.environ["GITHUB_EVENT_NAME"] in {"workflow_run", "repository_dispatch"},
        "Untrusted event",
    )
    number, head = args.number, args.head_sha
    if number is None:
        require(
            os.environ["GITHUB_EVENT_NAME"] == "workflow_run", "Missing PR identity"
        )
        number, head = signal_request(
            json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
        )
    if args.publish_pending:
        require(
            args.number is None and args.publish_result is None,
            "Pending publication requires a fresh workflow signal",
        )
        require(
            gh(f"repos/{REPOSITORY}/commits/main")["sha"] == os.environ["GITHUB_SHA"],
            "Trusted main moved",
        )
        validate_pr(gh(f"repos/{REPOSITORY}/pulls/{number}"), number, head or "")
        publish_statuses(head or "", "pending")
    result = admit(number, head or "", os.environ["GITHUB_SHA"])
    if args.publish_result:
        publish_statuses(result["head_sha"], args.publish_result)
    with Path(os.environ["GITHUB_OUTPUT"]).open("a") as output:
        for key, value in result.items():
            output.write(f"{key}={value}\n")


if __name__ == "__main__":  # pragma: no cover
    main()
