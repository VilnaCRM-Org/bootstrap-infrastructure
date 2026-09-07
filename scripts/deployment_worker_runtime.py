"""Verify one trusted root artifact and recheck a worker before credentials.

Invoke as ``python3 -I /absolute/trusted/scripts/deployment_worker_runtime.py``.
Artifact IDs and both digests must come from the trusted root job outputs, never
PR/dispatch input. The archive stays in memory; no extracted code is executed.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Isolated Python omits the script directory. Add only this installed directory;
# the interpreter's -I flag excludes the PR cwd, PYTHONPATH and user site hooks.
sys.path.insert(0, str(Path(__file__).resolve().parent))

import argparse  # noqa: E402
import hashlib  # noqa: E402
import io  # noqa: E402
import os  # noqa: E402
import re  # noqa: E402
import selectors  # noqa: E402
import stat  # noqa: E402
import subprocess  # noqa: E402  # nosec B404
import time  # noqa: E402
import zipfile  # noqa: E402

import pulumi_command_preflight as preflight  # noqa: E402
from deployment_contract_io import (  # noqa: E402
    MAX_CONTRACT_BYTES,
    decode_deployment_contract,
)
from deployment_controller import (  # noqa: E402
    REPOSITORY,
    REPOSITORY_ID,
    ControllerMetadata,
    DeploymentContract,
    _object,
)
from deployment_controller_runtime import _controller_metadata  # noqa: E402
from deployment_worker_recheck import (  # noqa: E402
    _verify_controller_run,
    recheck_admission,
    recheck_worker,
)

MAX_ZIP_BYTES = 2 * 1024 * 1024
OUTPUT_FIELDS = (
    "head_sha",
    "base_sha",
    "command",
    "pull_request_number",
    "target_environment",
)


def _check_artifact_arguments(
    artifact_id: str,
    artifact_sha256: str,
    contract_sha256: str,
) -> None:
    """Close every externally supplied identity before constructing API paths."""
    for value, pattern, label in (
        (artifact_id, r"[1-9][0-9]*", "artifact ID"),
        (artifact_sha256, r"[0-9a-f]{64}", "artifact SHA256"),
        (contract_sha256, r"[0-9a-f]{64}", "contract SHA256"),
    ):
        preflight.require(
            isinstance(value, str) and re.fullmatch(pattern, value) is not None,
            f"Invalid {label}",
        )


def _check_arguments(
    artifact_id: str,
    artifact_sha256: str,
    contract_sha256: str,
    scope: str,
    environment: str,
) -> None:
    """Require artifact identifiers plus a closed worker scope/account pair."""
    _check_artifact_arguments(artifact_id, artifact_sha256, contract_sha256)
    preflight.require(scope in ("operator", "governance", "platform"), "Invalid scope")
    preflight.require(environment in ("test", "prod"), "Invalid environment")


def _verify_artifact(
    artifact_id: str,
    digest: str,
    controller: ControllerMetadata,
    *,
    expected_name: str | None = None,
) -> None:
    """Bind the documented GitHub artifact/run fields to trusted root outputs."""
    artifact = _object(
        preflight.gh(f"repos/{REPOSITORY}/actions/artifacts/{artifact_id}"),
        "Artifact",
    )
    expected = {
        "id": int(artifact_id),
        "name": (
            expected_name
            if expected_name is not None
            else f"deployment-selection-{controller.run_id}-1"
        ),
        "expired": False,
        "digest": f"sha256:{digest}",
    }
    run_expected = {
        "id": int(controller.run_id),
        "repository_id": REPOSITORY_ID,
        "head_repository_id": REPOSITORY_ID,
        "head_branch": "main",
        "head_sha": controller.sha,
    }
    run = _object(artifact.get("workflow_run"), "Artifact workflow run")
    for fields, required in ((artifact, expected), (run, run_expected)):
        for name, value in required.items():
            preflight.require(
                type(fields.get(name)) is type(value) and fields[name] == value,
                f"Artifact {name} differs",
            )
    size = artifact.get("size_in_bytes")
    preflight.require(
        type(size) is int and 0 < size <= MAX_ZIP_BYTES,
        "Artifact ZIP size exceeds bound",
    )


def _download_zip(artifact_id: str) -> bytes:
    """Bound stdout while gh handles authenticated GitHub download redirects."""
    process = subprocess.Popen(
        ["gh", "api", f"repos/{REPOSITORY}/actions/artifacts/{artifact_id}/zip"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )  # nosec B603 B607
    data = bytearray()
    try:
        if process.stdout is None:
            raise ValueError("Missing artifact stream")
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            deadline = time.monotonic() + 120
            while True:
                preflight.require(
                    time.monotonic() < deadline, "Artifact download timed out"
                )
                if not selector.select(timeout=1):
                    continue
                chunk = os.read(
                    process.stdout.fileno(), min(65536, MAX_ZIP_BYTES + 1 - len(data))
                )
                if not chunk:
                    break
                data.extend(chunk)
                preflight.require(
                    len(data) <= MAX_ZIP_BYTES, "Artifact ZIP exceeds bound"
                )
        preflight.require(process.wait(timeout=10) == 0, "Artifact download failed")
        return bytes(data)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=10)
        if process.stdout is not None:
            process.stdout.close()


def _contract_bytes(raw: bytes, *, member_name: str = "contract.json") -> bytes:
    """Read one bounded regular protocol document without extracting paths."""
    preflight.require(
        member_name
        in ("contract.json", "receipt.json", "test.json", "prod.json", "proof.json"),
        "Unsupported artifact member",
    )
    preflight.require(len(raw) <= MAX_ZIP_BYTES, "Artifact ZIP exceeds bound")
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        entries = archive.infolist()
        preflight.require(len(entries) == 1, "Artifact must contain exactly one member")
        member = entries[0]
        preflight.require(
            member.filename == member.orig_filename == member_name
            and not member.is_dir(),
            f"Artifact member must be {member_name}",
        )
        preflight.require(not member.flag_bits & 1, "Encrypted artifact rejected")
        preflight.require(
            stat.S_IFMT(member.external_attr >> 16) in (0, stat.S_IFREG),
            "Artifact member must be a regular file",
        )
        preflight.require(
            member.file_size <= MAX_CONTRACT_BYTES, "Contract exceeds bound"
        )
        with archive.open(member) as stream:
            payload = stream.read(MAX_CONTRACT_BYTES + 1)
        preflight.require(
            len(payload) <= MAX_CONTRACT_BYTES and len(payload) == member.file_size,
            "Contract member size differs",
        )
    return payload


def _load_contract_artifact(
    *,
    artifact_id: str,
    artifact_sha256: str,
    contract_sha256: str,
) -> DeploymentContract:
    """Authenticate immutable transport and decode; current admission checks follow."""
    _check_artifact_arguments(artifact_id, artifact_sha256, contract_sha256)
    controller = _controller_metadata()
    _verify_controller_run(controller)
    _verify_artifact(artifact_id, artifact_sha256, controller)
    raw = _download_zip(artifact_id)
    preflight.require(
        hashlib.sha256(raw).hexdigest() == artifact_sha256, "Artifact SHA256 differs"
    )
    payload = _contract_bytes(raw)
    preflight.require(
        hashlib.sha256(payload).hexdigest() == contract_sha256,
        "Contract file SHA256 differs",
    )
    return decode_deployment_contract(payload)


def load_verified_admission(
    *, artifact_id: str, artifact_sha256: str, contract_sha256: str
) -> DeploymentContract:
    """Authenticate a root admission for credential-free validation or barriers.

    An empty selection is valid here. This does not authorize a credential job;
    selected account workers must call ``load_verified_contract`` instead.
    """
    contract = _load_contract_artifact(
        artifact_id=artifact_id,
        artifact_sha256=artifact_sha256,
        contract_sha256=contract_sha256,
    )
    recheck_admission(contract)
    return contract


def load_verified_contract(
    *,
    artifact_id: str,
    artifact_sha256: str,
    contract_sha256: str,
    scope: str,
    environment: str,
) -> DeploymentContract:
    """Authenticate immutable artifact transport and recheck a selected worker."""
    _check_arguments(artifact_id, artifact_sha256, contract_sha256, scope, environment)
    contract = _load_contract_artifact(
        artifact_id=artifact_id,
        artifact_sha256=artifact_sha256,
        contract_sha256=contract_sha256,
    )
    recheck_worker(contract, scope=scope, environment=environment)
    return contract


def main(argv: list[str] | None = None) -> int:
    """Emit only validated execution fields after every check succeeds."""
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("artifact-id", "artifact-sha256", "contract-sha256", "output"):
        parser.add_argument(f"--{name}", required=True)
    parser.add_argument(
        "--scope", choices=("operator", "governance", "platform"), required=True
    )
    parser.add_argument("--environment", choices=("test", "prod"), required=True)
    arguments = vars(parser.parse_args(argv))
    output = arguments.pop("output")
    contract = load_verified_contract(**arguments)
    outputs = {key: getattr(contract.identity, key) for key in OUTPUT_FIELDS}
    outputs.update(
        selection_digest=contract.selection_digest,
        contract_digest=contract.contract_digest,
    )
    preflight.write_outputs(outputs, output)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
