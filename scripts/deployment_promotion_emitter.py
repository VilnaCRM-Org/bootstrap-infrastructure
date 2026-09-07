"""Publish central-v2 evidence with current authorization and verified readback.

Run only in the installed root's governance-evidence job with a dedicated App
installation token. The workflow must bind that job to the protected environment;
the jobs API does not expose its environment. Root artifact/needs inputs are trusted
workflow edges, never PR payload. No PR source executes here. An uncertain POST is
never blindly retried: bounded reads recover only the exact persisted operation.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import argparse  # noqa: E402
import hashlib  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402
import selectors  # noqa: E402
import subprocess  # noqa: E402  # nosec B404
import tempfile  # noqa: E402
import time  # noqa: E402
from collections.abc import Callable  # noqa: E402
from typing import Any  # noqa: E402

import _github_evidence_environment as boundary  # noqa: E402
import pulumi_command_preflight as preflight  # noqa: E402
from deployment_controller import REPOSITORY, REPOSITORY_ID, _object  # noqa: E402
from deployment_controller_runtime import _controller_metadata  # noqa: E402
from deployment_promotion_proof import _canonical  # noqa: E402
from deployment_promotion_publication import (  # noqa: E402
    CONTEXT,
    revalidate_publication,
)
from deployment_worker_recheck import _verify_controller_run  # noqa: E402
from deployment_worker_runtime import (  # noqa: E402
    _check_artifact_arguments,
    _contract_bytes,
    _download_zip,
    _verify_artifact,
)

# Verified dedicated repository App configuration; callers cannot override issuer.
APP_ID = 4840884
APP_SLUG = "vilnacrm-infrastructure-evidence"
APP_BOT_ID = 325299966
BASE = f"repos/{REPOSITORY}"
MAX_RESPONSE = 2 * 1024 * 1024
READ_ATTEMPTS = 3
MAX_PAGES = 5


class GitHubError(RuntimeError):
    """Transport failure with no API body, token or subprocess output attached."""


def _response(process: subprocess.Popen) -> bytes:
    result = bytearray()
    try:
        if process.stdout is None:
            raise GitHubError("Missing GitHub response stream")
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            deadline = time.monotonic() + 120
            while True:
                if time.monotonic() >= deadline:
                    raise GitHubError("GitHub request timed out")
                if not selector.select(timeout=1):
                    continue
                chunk = os.read(process.stdout.fileno(), 65536)
                if not chunk:
                    break
                result.extend(chunk)
                if len(result) > MAX_RESPONSE:
                    raise GitHubError("GitHub response exceeds bound")
        if process.wait(timeout=5) != 0:
            raise GitHubError("GitHub request failed")
        return bytes(result)
    finally:
        if process.poll() is None:
            process.kill()
        process.wait()
        if process.stdout is not None:
            process.stdout.close()


def _api(path: str, payload: dict[str, Any] | None = None) -> Any:
    """Use fixed native gh requests and a private bounded literal JSON input."""
    raw = b"" if payload is None else _canonical(payload)
    preflight.require(len(raw) <= MAX_RESPONSE, "GitHub request exceeds bound")
    with tempfile.TemporaryDirectory(prefix="promotion-api-") as directory:
        arguments = [
            "gh",
            "api",
            path,
            "--method",
            "GET" if payload is None else "POST",
        ]
        if payload is not None:
            input_path = Path(directory) / "request.json"
            input_path.write_bytes(raw)
            arguments.extend(["--input", str(input_path)])
        process = subprocess.Popen(  # nosec B603
            arguments, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
        )
        response = _response(process)
    try:
        return json.loads(response)
    except (ValueError, UnicodeError) as error:
        raise GitHubError("Invalid GitHub JSON response") from error


def _read(path: str) -> Any:
    for attempt in range(READ_ATTEMPTS):
        try:
            return _api(path)
        except GitHubError:
            if attempt == READ_ATTEMPTS - 1:
                raise
    raise AssertionError("Unreachable retry state")  # pragma: no cover


def _issuer(value: dict[str, Any], *, app: bool = False) -> None:
    creator = _object(value.get("creator"), "Publication creator")
    preflight.require(
        type(creator.get("id")) is int
        and creator["id"] == APP_BOT_ID
        and creator.get("login") == f"{APP_SLUG}[bot]"
        and creator.get("type") == "Bot",
        "Foreign publication creator",
    )
    if app:
        integration = _object(value.get("performed_via_github_app"), "Publication App")
        preflight.require(
            type(integration.get("id")) is int
            and integration["id"] == APP_ID
            and integration.get("slug") == APP_SLUG,
            "Foreign publication App",
        )


def _verify_authority() -> None:
    """Verify App token, repository authority and live environment protections."""
    viewer = _object(
        _api("graphql", {"query": "query { viewer { login databaseId } }"}),
        "Viewer response",
    )
    preflight.require(not viewer.get("errors"), "GitHub viewer query failed")
    identity = _object(
        _object(viewer.get("data"), "Viewer data").get("viewer"), "Viewer"
    )
    preflight.require(
        identity.get("login") == f"{APP_SLUG}[bot]"
        and type(identity.get("databaseId")) is int
        and identity["databaseId"] == APP_BOT_ID,
        "Foreign publisher token",
    )
    installation = _object(
        _read("installation/repositories?per_page=100"), "Installation repositories"
    )
    repositories = installation.get("repositories")
    preflight.require(
        type(installation.get("total_count")) is int
        and installation["total_count"] == 1
        and isinstance(repositories, list)
        and len(repositories) == 1,
        "Publisher token must target only this repository",
    )
    repository = _object(installation["repositories"][0], "Installation repository")
    preflight.require(
        type(repository.get("id")) is int
        and repository["id"] == REPOSITORY_ID
        and repository.get("full_name") == REPOSITORY,
        "Foreign App installation repository",
    )
    environment = _object(
        _read(f"{BASE}/environments/{boundary.NAME}"), "Evidence environment"
    )
    policies = _object(
        _read(
            f"{BASE}/environments/{boundary.NAME}/deployment-branch-policies?per_page=100"
        ),
        "Evidence policies",
    )
    preflight.require(
        not boundary.verification_blockers(environment, policies),
        "Publisher environment boundary differs",
    )


def _positive_id(value: dict[str, Any]) -> int:
    identifier = value.get("id")
    if type(identifier) is not int or identifier <= 0:
        raise ValueError("Invalid publication ID")
    return identifier


def _equal_fields(actual: dict[str, Any], expected: dict[str, Any]) -> None:
    preflight.require(
        all(
            _canonical(actual.get(key)) == _canonical(value)
            for key, value in expected.items()
        ),
        "Publication readback differs",
    )


def _deployment(value: Any, request: dict[str, Any]) -> int:
    result = _object(value, "Deployment")
    identifier = _positive_id(result)
    payload = request["create_payload"]
    _issuer(result, app=True)
    _equal_fields(
        result,
        {
            "sha": payload["ref"],
            "ref": payload["ref"],
            "environment": payload["environment"],
            "production_environment": payload["production_environment"],
            "description": payload["description"],
            "payload": payload["payload"],
            "repository_url": f"https://api.github.com/{BASE}",
        },
    )
    return identifier


def _pages(path: str) -> list[dict[str, Any]]:
    values = []
    separator = "&" if "?" in path else "?"
    for page in range(1, MAX_PAGES + 1):
        rows = _read(f"{path}{separator}per_page=100&page={page}")
        preflight.require(
            type(rows) is list and len(rows) <= 100, "Invalid publication page"
        )
        values.extend(_object(row, "Publication row") for row in rows)
        if len(rows) < 100:
            return values
    raise ValueError("Publication pagination incomplete")


def _find_deployment(request: dict[str, Any]) -> dict[str, Any] | None:
    payload = request["create_payload"]
    candidates = _pages(
        f"{BASE}/deployments?sha={payload['ref']}&environment={request['environment']}"
    )
    matching = [row for row in candidates if row.get("payload") == payload["payload"]]
    preflight.require(len(matching) <= 1, "Ambiguous existing deployment")
    return matching[0] if matching else None


def _post_once(
    path: str, payload: dict[str, Any], authorize: Callable[[], None]
) -> Any:
    authorize()
    try:
        return _api(path, payload)
    except GitHubError:
        # Recover through exact readback; never resend an ambiguous write.
        return None


def _ensure_deployment(request: dict[str, Any], authorize: Callable[[], None]) -> int:
    existing = _find_deployment(request)
    created = (
        existing
        if existing is not None
        else _post_once(request["create_path"], request["create_payload"], authorize)
    )
    if created is None:
        for _ in range(READ_ATTEMPTS):
            created = _find_deployment(request)
            if created is not None:
                break
    identifier = _deployment(created, request)
    preflight.require(
        _deployment(_read(f"{BASE}/deployments/{identifier}"), request) == identifier,
        "Deployment readback ID differs",
    )
    return identifier


def _status(value: Any, expected: dict[str, Any], *, path: str) -> int:
    result = _object(value, "Publication status")
    identifier = _positive_id(result)
    _issuer(result)
    _equal_fields(
        result,
        {key: value for key, value in expected.items() if key != "auto_inactive"},
    )
    url = f"https://api.github.com/{path}"
    if "context" not in expected:
        url += f"/{identifier}"
    _equal_fields(result, {"url": url})
    return identifier


def _latest(path: str, *, context: str | None = None) -> dict[str, Any] | None:
    rows = _pages(path)
    matching = (
        rows
        if context is None
        else [row for row in rows if row.get("context") == context]
    )
    if not matching:
        return None
    return max(matching, key=_positive_id)


def _ensure_status(
    path: str,
    payload: dict[str, Any],
    authorize: Callable[[], None],
    *,
    read_path: str | None = None,
    context: str | None = None,
) -> int:
    read_path = read_path or path
    current = _latest(read_path, context=context)
    if current is not None:
        try:
            return _status(current, payload, path=path)
        except ValueError:
            pass
    result = _post_once(path, payload, authorize)
    expected_id = _status(result, payload, path=path) if result is not None else None
    for _ in range(READ_ATTEMPTS):
        persisted = _latest(read_path, context=context)
        if persisted is not None:
            identifier = _status(persisted, payload, path=path)
            preflight.require(
                expected_id is None or identifier == expected_id,
                "Written status was superseded",
            )
            return identifier
    raise ValueError("Publication status was not persisted")


def publish(
    *,
    artifact_id: str,
    artifact_sha256: str,
    contract_sha256: str,
    proof_artifact_id: str,
    proof_artifact_sha256: str,
    proof_file_sha256: str,
    needs_payload: str,
) -> dict[str, str]:
    """Authenticate original evidence and publish only verified account projections."""
    _check_artifact_arguments(artifact_id, artifact_sha256, contract_sha256)
    _check_artifact_arguments(
        proof_artifact_id, proof_artifact_sha256, proof_file_sha256
    )
    controller = _controller_metadata()
    _verify_controller_run(controller)
    _verify_authority()
    proof_name = f"deployment-promotion-{controller.run_id}-1"
    _verify_artifact(
        proof_artifact_id, proof_artifact_sha256, controller, expected_name=proof_name
    )
    raw = _download_zip(proof_artifact_id)
    preflight.require(
        hashlib.sha256(raw).hexdigest() == proof_artifact_sha256,
        "Proof ZIP SHA256 differs",
    )
    proof = _contract_bytes(raw, member_name="proof.json")
    preflight.require(
        hashlib.sha256(proof).hexdigest() == proof_file_sha256,
        "Proof file SHA256 differs",
    )
    arguments: dict[str, Any] = dict(
        proof_payload=proof,
        proof_file_sha256=proof_file_sha256,
        artifact_id=artifact_id,
        artifact_sha256=artifact_sha256,
        contract_sha256=contract_sha256,
        needs_payload=needs_payload,
    )
    requests = revalidate_publication(**arguments)

    def authorize() -> None:
        _verify_authority()
        _verify_controller_run(controller)
        _verify_artifact(
            proof_artifact_id,
            proof_artifact_sha256,
            controller,
            expected_name=proof_name,
        )
        preflight.require(
            _canonical(revalidate_publication(**arguments)) == _canonical(requests),
            "Publication evidence changed",
        )

    deployments = []
    for request in requests["deployments"]:
        identifier = _ensure_deployment(request, authorize)
        path = f"{BASE}/deployments/{identifier}/statuses"
        _ensure_status(path, request["success_payload"], authorize)
        deployments.append((identifier, request))
    authorize()
    for identifier, request in deployments:
        preflight.require(
            _deployment(_read(f"{BASE}/deployments/{identifier}"), request)
            == identifier,
            "Deployment readback ID differs",
        )
        path = f"{BASE}/deployments/{identifier}/statuses"
        _status(_latest(path), request["success_payload"], path=path)
    status = requests["commit_status"]
    status_id = _ensure_status(
        status["path"],
        status["payload"],
        authorize,
        read_path=f"{BASE}/commits/{requests['head_sha']}/statuses",
        context=CONTEXT,
    )
    authorize()
    return {
        "published": "true",
        "head_sha": requests["head_sha"],
        "proof_digest": requests["proof_digest"],
        "status_id": str(status_id),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in (
        "artifact-id",
        "artifact-sha256",
        "contract-sha256",
        "proof-artifact-id",
        "proof-artifact-sha256",
        "proof-file-sha256",
        "output",
    ):
        parser.add_argument(f"--{name}", required=True)
    args = vars(parser.parse_args(argv))
    output = args.pop("output")
    try:
        result = publish(**args, needs_payload=os.environ.get("PROMOTION_NEEDS", ""))
    except (ValueError, OSError, GitHubError, subprocess.SubprocessError):
        print(
            "Promotion publication failed; no verified aggregate result.",
            file=sys.stderr,
        )
        return 1
    preflight.write_outputs(result, output)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
