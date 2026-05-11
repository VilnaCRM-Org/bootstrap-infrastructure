from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, cast

from _script_support import run
from _well_architected_evidence_common import Runner, _check, _run_json

ADVISORY_REVIEW_THREAD_AUTHORS = frozenset({"qltysh"})


@dataclass(frozen=True)
class ReviewThreadPageRequest:
    """Inputs shared by every GitHub review-thread pagination request."""

    owner: str
    name: str
    pr_number: int
    query: str


def github_review_threads(
    repo: str,
    pr_number: int | None,
    *,
    runner: Runner = run,
) -> dict[str, object]:
    """Collect unresolved review-thread count without reading secret material."""
    if pr_number is None:
        return _check(
            "github_review_threads",
            status="missing",
            blockers=["PR number is required for review-thread evidence."],
        )
    owner, name = repo.split("/", 1)
    nodes, pagination_error = _collect_review_thread_nodes(
        owner,
        name,
        pr_number,
        runner=runner,
    )
    if pagination_error:
        return _check(
            "github_review_threads",
            status="unknown",
            blockers=[pagination_error],
        )

    evidence, blocking_count = _review_thread_counts(nodes)
    return _check(
        "github_review_threads",
        status="passed" if not blocking_count else "failed",
        evidence=evidence,
        blockers=_review_thread_blockers(blocking_count),
    )


def _review_thread_counts(nodes: list[dict]) -> tuple[dict[str, int], int]:
    """Return review-thread evidence counts and current blocking count."""
    unresolved = _unresolved_review_threads(nodes)
    outdated_count = sum(1 for node in unresolved if bool(node.get("isOutdated")))
    advisory_count = sum(1 for node in unresolved if _review_thread_is_advisory(node))
    blocking_count = sum(1 for node in unresolved if _review_thread_blocks(node))
    return (
        {
            "threadCount": len(nodes),
            "unresolvedThreadCount": len(unresolved),
            "outdatedUnresolvedThreadCount": outdated_count,
            "advisoryUnresolvedThreadCount": advisory_count,
            "blockingThreadCount": blocking_count,
        },
        blocking_count,
    )


def _unresolved_review_threads(nodes: Sequence[object]) -> list[dict[str, Any]]:
    """Return unresolved review-thread nodes."""
    unresolved = []
    for node in nodes:
        if _review_thread_unresolved(node):
            unresolved.append(cast(dict[str, Any], node))
    return unresolved


def _review_thread_unresolved(node: object) -> bool:
    """Return whether a review-thread node is unresolved."""
    return isinstance(node, dict) and not node.get("isResolved")


def _review_thread_blocks(node: dict[str, Any]) -> bool:
    """Return whether an unresolved review thread blocks evidence."""
    return not bool(node.get("isOutdated")) and not _review_thread_is_advisory(node)


def _review_thread_is_advisory(node: dict) -> bool:
    """Return whether an unresolved review thread is emitted by an advisory bot."""
    first_comment = _review_thread_first_comment(node)
    author = first_comment.get("author", {})
    login = author.get("login") if isinstance(author, dict) else ""
    return login in ADVISORY_REVIEW_THREAD_AUTHORS


def _review_thread_first_comment(node: dict) -> dict[str, Any]:
    """Return the first review-thread comment object, if present."""
    comments = node.get("comments")
    if not isinstance(comments, dict):
        return {}
    comment_nodes = comments.get("nodes")
    if not isinstance(comment_nodes, list) or not comment_nodes:
        return {}
    first_comment = comment_nodes[0]
    if not isinstance(first_comment, dict):
        return {}
    return first_comment


def _review_thread_blockers(blocking_count: int) -> list[str]:
    """Return blockers for current unresolved review threads."""
    if not blocking_count:
        return []
    return [f"{blocking_count} current review thread(s) remain unresolved."]


def _collect_review_thread_nodes(
    owner: str,
    name: str,
    pr_number: int,
    *,
    runner: Runner = run,
) -> tuple[list[dict], str]:
    """Collect paginated review-thread nodes or return a blocker."""
    request = ReviewThreadPageRequest(
        owner=owner,
        name=name,
        pr_number=pr_number,
        query=_review_threads_query(),
    )
    nodes = []
    after: str | None = None
    for _page in range(20):
        page_nodes, page_info, error = _fetch_review_thread_page(
            request,
            after,
            runner=runner,
        )
        if error:
            return [], error
        nodes.extend(page_nodes)
        should_continue, after, error = _next_review_thread_cursor(page_info)
        if error:
            return [], error
        if not should_continue:
            return nodes, ""
    return [], "GitHub review thread pagination exceeded 20 pages."


def _fetch_review_thread_page(
    request: ReviewThreadPageRequest,
    after: str | None,
    *,
    runner: Runner = run,
) -> tuple[list[dict], dict[str, Any], str]:
    """Fetch one review-thread page."""
    command = _review_threads_command(request, after)
    ok, payload, error = _run_json(command, runner=runner)
    if not ok or not isinstance(payload, dict):
        return [], {}, error
    page_nodes, page_info = _review_threads_page(payload)
    return page_nodes, page_info, ""


def _next_review_thread_cursor(
    page_info: dict[str, Any],
) -> tuple[bool, str | None, str]:
    """Return pagination decision, cursor, and blocker."""
    if not page_info.get("hasNextPage"):
        return False, None, ""
    after = page_info.get("endCursor")
    if after:
        return True, after, ""
    return False, None, "GitHub review thread pagination did not return a cursor."


def _review_threads_query() -> str:
    """Return the paginated review-thread GraphQL query."""
    return (
        "query($owner:String!, $name:String!, $number:Int!, $after:String) { "
        "repository(owner:$owner, name:$name) { "
        "pullRequest(number:$number) { "
        "reviewThreads(first:100, after:$after) { "
        "nodes { isResolved isOutdated "
        "comments(first:1) { nodes { author { login } body } } } "
        "pageInfo { hasNextPage endCursor } } } } }"
    )


def _review_threads_command(
    request: ReviewThreadPageRequest,
    after: str | None,
) -> list[str]:
    """Build a metadata-only review-thread GraphQL command."""
    command = [
        "gh",
        "api",
        "graphql",
        "-f",
        f"owner={request.owner}",
        "-f",
        f"name={request.name}",
        "-F",
        f"number={request.pr_number}",
        "-f",
        f"query={request.query}",
    ]
    if after:
        command.extend(["-f", f"after={after}"])
    return command


def _dict_child(payload: dict[str, Any], key: str) -> dict[str, Any]:
    """Return a nested mapping child, treating null GraphQL leaves as absent."""
    value = payload.get(key)
    return value if isinstance(value, dict) else {}


def _review_threads_page(payload: dict[str, Any]) -> tuple[list[dict], dict[str, Any]]:
    """Extract one review-thread page from a GraphQL response."""
    data = _dict_child(payload, "data")
    repository = _dict_child(data, "repository")
    pull_request = _dict_child(repository, "pullRequest")
    review_threads = _dict_child(pull_request, "reviewThreads")
    page_nodes = review_threads.get("nodes") or []
    page_info = _dict_child(review_threads, "pageInfo")
    nodes = [node for node in page_nodes if isinstance(node, dict)]
    return nodes, page_info
