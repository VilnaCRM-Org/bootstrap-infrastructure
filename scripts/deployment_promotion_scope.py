"""Report current central scope from immutable PR facts and original App evidence.

Read-only verification is independent of the caller workflow environment. It
re-authenticates an original published aggregate, not a copied commit status.
Observations are not atomic: callers must recheck immediately before writes or
consumption. Only the protected scope CLI can publish. Legacy Governance
Promotion is intentionally untouched until all effective main rules are verified.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import argparse  # noqa: E402
import hashlib  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402
import re  # noqa: E402
from dataclasses import asdict  # noqa: E402
from typing import Any, cast  # noqa: E402

import deployment_promotion_emitter as emitter  # noqa: E402
from deployment_contract_io import (  # noqa: E402
    _controller,
    _load_document,
    decode_deployment_contract,
)
from deployment_controller import (  # noqa: E402
    OWNER_ID,
    REPOSITORY,
    REPOSITORY_ID,
    WORKFLOW,
    ControllerMetadata,
    DeploymentContract,
    _digest,
    _object,
)
from deployment_promotion_proof import _verify_job_graph  # noqa: E402
from deployment_promotion_publication import (  # noqa: E402
    CONTEXT,
    _prepared_proof,
    _requests,
)
from deployment_scopes import select_deployment_scopes  # noqa: E402
from deployment_worker_recheck import (  # noqa: E402
    _recheck_admitted_facts,
    _verify_controller_run,
)
from deployment_worker_runtime import (  # noqa: E402
    _check_artifact_arguments,
    _contract_bytes,
    _download_zip,
    _verify_artifact,
)
from pulumi_command_preflight import require  # noqa: E402

BASE = f"repos/{REPOSITORY}"
SCOPE_WORKFLOW = ".github/workflows/governance-promotion.yml"


def _sha(value: Any, length: int = 40) -> str:
    require(
        type(value) is str
        and re.fullmatch(rf"[0-9a-f]{{{length}}}", value) is not None,
        "Invalid revision or digest",
    )
    return value


def _repository(value: Any) -> None:
    repository = _object(value, "Repository")
    emitter._equal_fields(repository, {"id": REPOSITORY_ID, "full_name": REPOSITORY})
    owner = _object(repository.get("owner"), "Repository owner")
    emitter._equal_fields(owner, {"id": OWNER_ID})


def _pr_identity(value: Any, number: int) -> dict[str, Any]:
    pr = _object(value, "Pull request")
    emitter._equal_fields(pr, {"number": number, "state": "open", "merged": False})
    base, head = (_object(pr.get(key), key) for key in ("base", "head"))
    _repository(base.get("repo"))
    _repository(head.get("repo"))
    require(base.get("ref") == "main", "Pull request no longer targets main")
    count = pr.get("changed_files")
    require(type(count) is int and 0 < count <= 300, "Incomplete PR file inventory")
    return {
        "repository": REPOSITORY,
        "pull_request_number": number,
        "head_sha": _sha(head.get("sha")),
        "base_sha": _sha(base.get("sha")),
        "changed_files": count,
    }


def _snapshot(number: int, expected_head: str | None = None) -> dict[str, Any]:
    require(type(number) is int and number > 0, "Invalid pull request number")
    if expected_head is not None:
        _sha(expected_head)
    path = f"{BASE}/pulls/{number}"
    identity = _pr_identity(emitter._read(path), number)
    require(expected_head in (None, identity["head_sha"]), "Pull request head changed")
    compare = _object(
        emitter._read(
            f"{BASE}/compare/{identity['base_sha']}...{identity['head_sha']}"
        ),
        "Immutable comparison",
    )
    files = compare.get("files")
    require(type(files) is list, "Missing immutable file inventory")
    selection = select_deployment_scopes(
        cast(list[dict[str, object]], files),
        base_sha=identity["base_sha"],
        head_sha=identity["head_sha"],
        expected_file_count=identity["changed_files"],
        complete=True,
    )
    require(
        _pr_identity(emitter._read(path), number) == identity,
        "PR moved during scope read",
    )
    return {
        "schema_version": 2,
        **identity,
        "scopes": list(selection.stacks),
        "selection_digest": _digest(asdict(selection)),
    }


def _original_controller(payload: dict[str, Any]) -> ControllerMetadata:
    identity = _object(payload.get("identity"), "Published identity")
    controller = _controller(identity.get("controller"))
    _sha(controller.sha)
    require(
        re.fullmatch(r"[1-9][0-9]*", controller.run_id) is not None,
        "Invalid original run",
    )
    require(
        controller.run_attempt == 1
        and controller.workflow_ref == f"{REPOSITORY}/{WORKFLOW}@refs/heads/main",
        "Foreign original controller",
    )
    _verify_controller_run(controller)
    run = _object(
        emitter._read(f"{BASE}/actions/runs/{controller.run_id}"), "Original run"
    )
    emitter._equal_fields(run, {"status": "completed", "conclusion": "success"})
    return controller


def _artifact_document(
    identifier: str,
    archive_sha: str,
    file_sha: str,
    controller: ControllerMetadata,
    member: str,
    name: str,
) -> bytes:
    _check_artifact_arguments(identifier, archive_sha, file_sha)
    _verify_artifact(identifier, archive_sha, controller, expected_name=name)
    raw = _download_zip(identifier)
    require(hashlib.sha256(raw).hexdigest() == archive_sha, "Artifact archive differs")
    document = _contract_bytes(raw, member_name=member)
    require(
        hashlib.sha256(document).hexdigest() == file_sha, "Artifact document differs"
    )
    return document


def _proof_artifact(controller: ControllerMetadata) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    expected_count: int | None = None
    for page in range(1, emitter.MAX_PAGES + 1):
        result = _object(
            emitter._read(
                f"{BASE}/actions/runs/{controller.run_id}/artifacts?per_page=100&page={page}"
            ),
            "Run artifacts",
        )
        count, items = result.get("total_count"), result.get("artifacts")
        require(type(count) is int and 0 <= count <= 500, "Invalid artifact count")
        require(expected_count in (None, count), "Artifact inventory changed")
        expected_count = count
        require(type(items) is list and len(items) <= 100, "Invalid artifact page")
        items = cast(list[Any], items)
        rows.extend(_object(row, "Artifact") for row in items)
        require(
            len({emitter._positive_id(row) for row in rows}) == len(rows),
            "Repeated artifact",
        )
        if len(items) < 100:
            require(len(rows) == count, "Incomplete artifact inventory")
            matches = [
                row
                for row in rows
                if row.get("name") == f"deployment-promotion-{controller.run_id}-1"
            ]
            require(
                len(matches) == 1, "Original promotion artifact missing or ambiguous"
            )
            return matches[0]
    raise ValueError("Artifact pagination exceeds bound")


def _admission(
    payload: dict[str, Any], controller: ControllerMetadata
) -> DeploymentContract:
    refs = _object(payload.get("admission"), "Admission references")
    require(
        set(refs) == {"artifact_id", "artifact_sha256", "contract_sha256"},
        "Invalid admission references",
    )
    document = _artifact_document(
        refs["artifact_id"],
        refs["artifact_sha256"],
        refs["contract_sha256"],
        controller,
        "contract.json",
        f"deployment-selection-{controller.run_id}-1",
    )
    contract = decode_deployment_contract(document)
    require(
        contract.identity.controller == controller,
        "Original admission controller differs",
    )
    require(
        contract.identity.command == "up"
        and contract.identity.target_environment == "prod",
        "Promotion requires prod up",
    )
    return contract


def _verify_proof(
    payload: dict[str, Any],
    controller: ControllerMetadata,
    contract: DeploymentContract,
) -> dict[str, Any]:
    artifact = _proof_artifact(controller)
    digest = artifact.get("digest")
    require(
        type(digest) is str and digest.startswith("sha256:"), "Missing artifact digest"
    )
    file_sha = _sha(payload.get("proof_file_sha256"), 64)
    raw = _artifact_document(
        str(emitter._positive_id(artifact)),
        cast(str, digest)[7:],
        file_sha,
        controller,
        "proof.json",
        f"deployment-promotion-{controller.run_id}-1",
    )
    canonical = _prepared_proof(raw, file_sha)
    require(
        hashlib.sha256(canonical).hexdigest() == _sha(payload.get("proof_digest"), 64),
        "Published proof digest differs",
    )
    proof = _object(_load_document(raw), "Original promotion proof")
    expected = {
        "schema_version": 2,
        "protocol": "central-v2",
        "evidence_kind": "receipt-and-job-provenance",
        "completion_kind": "apply-drift",
        "identity": asdict(contract.identity),
        "scopes": list(contract.selection.stacks),
        "selector_sha256": contract.selector_sha256,
        "selection_digest": contract.selection_digest,
        "contract_digest": contract.contract_digest,
        "admission": payload["admission"],
        "jobs": _verify_job_graph(contract),
    }
    require(
        set(proof) == set(expected) | {"barriers", "workers"},
        "Invalid original proof fields",
    )
    emitter._equal_fields(proof, expected)
    return _requests(proof, file_sha)


def _verified_candidate(
    deployment: dict[str, Any], snapshot: dict[str, Any]
) -> dict[str, Any]:
    emitter._issuer(deployment, app=True)
    payload = _object(deployment.get("payload"), "Deployment evidence")
    identity = _object(payload.get("identity"), "Deployment identity")
    emitter._equal_fields(
        identity,
        {
            "repository": REPOSITORY,
            "repository_id": REPOSITORY_ID,
            "owner_id": OWNER_ID,
            "pull_request_number": str(snapshot["pull_request_number"]),
            "head_sha": snapshot["head_sha"],
            "base_sha": snapshot["base_sha"],
        },
    )
    emitter._equal_fields(
        payload,
        {
            "scopes": snapshot["scopes"],
            "selection_digest": snapshot["selection_digest"],
        },
    )
    controller = _original_controller(payload)
    contract = _admission(payload, controller)
    require(
        contract.selection_digest == snapshot["selection_digest"],
        "Current selection differs",
    )
    _recheck_admitted_facts(contract, controller)
    requests = _verify_proof(payload, controller, contract)
    emitter._deployment(deployment, requests["deployments"][1])
    for request in requests["deployments"]:
        candidate = emitter._find_deployment(request)
        identifier = emitter._deployment(candidate, request)
        require(
            emitter._deployment(
                emitter._read(f"{BASE}/deployments/{identifier}"), request
            )
            == identifier,
            "Deployment ID changed",
        )
        path = f"{BASE}/deployments/{identifier}/statuses"
        emitter._status(emitter._latest(path), request["success_payload"], path=path)
    return requests


def _default_result(snapshot: dict[str, Any]) -> dict[str, Any]:
    empty = not snapshot["scopes"]
    kind = "no-deployment" if empty else "pending"
    state = "success" if empty else "pending"
    return {
        **snapshot,
        "state": state,
        "completion_kind": kind,
        "status_payload": {
            "context": CONTEXT,
            "state": state,
            "description": (
                f"central-v2 PR{snapshot['pull_request_number']}: "
                f"{kind} {snapshot['selection_digest']}"
            ),
            "target_url": f"https://github.com/{REPOSITORY}/pull/{snapshot['pull_request_number']}",
        },
    }


def verify_current_promotion(
    pr_number: int, *, expected_head_sha: str | None = None
) -> dict[str, Any]:
    """Return fresh success/pending evidence; no writes or caller-context assumptions.

    Success does not claim a status was posted. Call verify_current_promotion_status
    when consumption also requires the current App-issued commit status. Expired,
    stale or incomplete original publication evidence remains pending.
    """
    snapshot = _snapshot(pr_number, expected_head_sha)
    result = _default_result(snapshot)
    if snapshot["scopes"]:
        candidates = emitter._pages(
            f"{BASE}/deployments?sha={snapshot['head_sha']}&environment=prod"
        )
        for row in sorted(candidates, key=emitter._positive_id, reverse=True):
            try:
                requests = _verified_candidate(row, snapshot)
            except (ValueError, KeyError, TypeError, emitter.GitHubError):
                continue
            result.update(
                state="success",
                completion_kind="apply-drift",
                proof_digest=requests["proof_digest"],
                status_payload=requests["commit_status"]["payload"],
            )
            break
    require(
        _snapshot(pr_number, expected_head_sha) == snapshot,
        "PR scope changed during verification",
    )
    return result


def verify_current_promotion_status(snapshot: dict[str, Any]) -> dict[str, Any]:
    """Reverify facts and latest exact App status; an input dictionary is not proof."""
    current = verify_current_promotion(
        snapshot["pull_request_number"], expected_head_sha=snapshot["head_sha"]
    )
    require(
        current == snapshot and current["state"] == "success",
        "Current promotion is not verified",
    )
    head = current["head_sha"]
    status = emitter._latest(f"{BASE}/commits/{head}/statuses", context=CONTEXT)
    emitter._status(status, current["status_payload"], path=f"{BASE}/statuses/{head}")
    return _object(status, "Current promotion status")


def _scope_event(base_sha: str) -> dict[str, Any]:
    with Path(os.environ["GITHUB_EVENT_PATH"]).open("rb") as stream:
        event = _object(_load_document(stream.read(1024 * 1024 + 1)), "Scope event")
    _repository(event.get("repository"))
    number = event.get("number")
    require(type(number) is int and number > 0, "Invalid event pull request")
    pr = _object(event.get("pull_request"), "Event pull request")
    identity = _pr_identity(pr, cast(int, number))
    require(identity["base_sha"] == base_sha, "Scope source differs from event base")
    head_ref = _object(pr.get("head"), "Event head").get("ref")
    require(
        type(head_ref) is str
        and re.fullmatch(r"[^\s\x00-\x1f\x7f]{1,255}", head_ref) is not None,
        "Invalid event head ref",
    )
    return {**identity, "head_ref": head_ref}


def _context() -> dict[str, Any]:
    expected = {
        "GITHUB_REPOSITORY": REPOSITORY,
        "GITHUB_REPOSITORY_ID": str(REPOSITORY_ID),
        "GITHUB_REPOSITORY_OWNER_ID": str(OWNER_ID),
        "GITHUB_EVENT_NAME": "pull_request_target",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_WORKFLOW_REF": f"{REPOSITORY}/{SCOPE_WORKFLOW}@refs/heads/main",
    }
    require(
        all(os.environ.get(key) == value for key, value in expected.items()),
        "Untrusted scope workflow context",
    )
    sha = _sha(os.environ.get("GITHUB_SHA"))
    require(
        os.environ.get("GITHUB_WORKFLOW_SHA") == sha, "Scope source revision differs"
    )
    run_id, attempt = (
        os.environ.get("GITHUB_RUN_ID", ""),
        os.environ.get("GITHUB_RUN_ATTEMPT", ""),
    )
    require(
        re.fullmatch(r"[1-9][0-9]*", run_id) is not None
        and re.fullmatch(r"[1-9][0-9]*", attempt) is not None,
        "Invalid scope run",
    )
    identity = _scope_event(sha)
    # Unlike repository_dispatch, pull_request_target run API head fields identify
    # the PR source. GITHUB_SHA/WORKFLOW_SHA and checkout remain the trusted base.
    run = _object(emitter._read(f"{BASE}/actions/runs/{run_id}"), "Scope run")
    emitter._equal_fields(
        run,
        {
            "id": int(run_id),
            "run_attempt": int(attempt),
            "event": "pull_request_target",
            "path": SCOPE_WORKFLOW,
            "head_branch": identity["head_ref"],
            "head_sha": identity["head_sha"],
        },
    )
    _repository(run.get("repository"))
    _repository(run.get("head_repository"))
    return identity


def _verify_environment() -> None:
    environment = _object(
        emitter._read(f"{BASE}/environments/{emitter.boundary.NAME}"),
        "Evidence environment",
    )
    policies = _object(
        emitter._read(
            f"{BASE}/environments/{emitter.boundary.NAME}/deployment-branch-policies?per_page=100"
        ),
        "Evidence policies",
    )
    require(
        not emitter.boundary.verification_blockers(environment, policies),
        "Publisher environment boundary differs",
    )


def report() -> dict[str, Any]:
    """Publish exactly the current result under the scoped App and shared PR lock."""
    event = _context()
    emitter._verify_authority()
    result = verify_current_promotion(
        event["pull_request_number"], expected_head_sha=event["head_sha"]
    )
    require(result["base_sha"] == event["base_sha"], "Scope event base is stale")

    def authorize() -> None:
        require(_context() == event, "Scope context changed")
        emitter._verify_authority()
        require(
            verify_current_promotion(
                event["pull_request_number"], expected_head_sha=event["head_sha"]
            )
            == result,
            "Promotion changed before publication",
        )

    head = result["head_sha"]
    authorize()
    emitter._ensure_status(
        f"{BASE}/statuses/{head}",
        result["status_payload"],
        authorize,
        read_path=f"{BASE}/commits/{head}/statuses",
        context=CONTEXT,
    )
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("verify-environment", "scope"))
    args = parser.parse_args(argv)
    try:
        if args.command == "verify-environment":
            _context()
            _verify_environment()
        else:
            result = report()
            print(
                json.dumps(
                    {
                        key: result[key]
                        for key in (
                            "state",
                            "completion_kind",
                            "head_sha",
                            "base_sha",
                            "selection_digest",
                        )
                    }
                )
            )
    except (ValueError, KeyError, TypeError, OSError, emitter.GitHubError):
        print("Central promotion scope verification failed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
