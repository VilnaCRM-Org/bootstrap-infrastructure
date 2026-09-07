"""Revalidate central-v2 evidence and construct publication requests without writes.

The installed caller must authenticate the prepared proof artifact and trusted
root inputs. File/content hashes do not establish that provenance. Every call
rebuilds the original admission, receipt, barrier and job evidence; returned
requests are an immediate-use snapshot, not a transferable publishing capability.

App identity, protected publisher environment, actual API writes and response
verification belong to the future emitter. Generated services retain their
separate Governance Promotion protocol. No saved-plan artifact provenance is
claimed here.
"""

from __future__ import annotations

import hashlib
import re
from copy import deepcopy
from typing import Any

from deployment_contract_io import _load_document
from deployment_controller import _object
from deployment_promotion_proof import _canonical, build_promotion_proof
from pulumi_command_preflight import require

CONTEXT = "Infrastructure Promotion"
RECEIPT_REFERENCES = (
    "receipt_artifact_id",
    "receipt_artifact_sha256",
    "receipt_file_sha256",
    "receipt_digest",
)


def _prepared_proof(payload: str | bytes, expected_sha256: str) -> bytes:
    require(
        type(expected_sha256) is str
        and re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is not None,
        "Invalid prepared proof SHA256",
    )
    document = _object(_load_document(payload), "Prepared promotion proof")
    raw = payload.encode("utf-8") if isinstance(payload, str) else payload
    require(
        hashlib.sha256(raw).hexdigest() == expected_sha256,
        "Prepared proof file SHA256 differs",
    )
    canonical = _canonical(document)
    require(raw == canonical + b"\n", "Prepared proof is not canonical")
    return canonical


def _evidence(proof: dict[str, Any], digest: str, file_sha: str) -> dict[str, Any]:
    return {
        "protocol": "central-v2",
        "evidence_kind": "receipt-and-job-provenance",
        "proof_digest": digest,
        "proof_file_sha256": file_sha,
        "identity": deepcopy(proof["identity"]),
        "scopes": list(proof["scopes"]),
        "selection_digest": proof["selection_digest"],
        "contract_digest": proof["contract_digest"],
        "barriers": {
            account: deepcopy(proof["barriers"][account]["artifact"])
            for account in ("test", "prod")
        },
        "receipts": {
            f"{scope}_{account}": {
                key: proof["workers"][f"{scope}_{account}"]["outputs"][key]
                for key in RECEIPT_REFERENCES
            }
            for account in ("test", "prod")
            for scope in proof["scopes"]
        },
    }


def _requests(proof: dict[str, Any], file_sha: str) -> dict[str, Any]:
    """Pure request construction; only called with freshly reconstructed proof."""
    identity = proof["identity"]
    repository, head = identity["repository"], identity["head_sha"]
    run_id = identity["controller"]["run_id"]
    run_url = f"https://github.com/{repository}/actions/runs/{run_id}"
    base = f"repos/{repository}"
    digest = hashlib.sha256(_canonical(proof)).hexdigest()
    evidence = _evidence(proof, digest, file_sha)
    description = "Verified central-v2 receipt/job apply and drift"
    status_description = f"central-v2 PR{identity['pull_request_number']}: {digest}"
    return {
        "protocol": "central-v2",
        "repository": repository,
        "head_sha": head,
        "proof_digest": digest,
        "proof_file_sha256": file_sha,
        "deployments": [
            {
                "environment": account,
                "create_path": f"{base}/deployments",
                "create_payload": {
                    "ref": head,
                    "environment": account,
                    "auto_merge": False,
                    "required_contexts": [],
                    "production_environment": account == "prod",
                    "description": description,
                    "payload": deepcopy(evidence),
                },
                # No status endpoint is fabricated: the emitter must verify the
                # actual created deployment ID, SHA and account before using this.
                "success_payload": {
                    "state": "success",
                    "log_url": run_url,
                    "description": description,
                    "auto_inactive": False,
                },
            }
            for account in ("test", "prod")
        ],
        # Emit only after both account deployment/status responses are verified.
        "commit_status": {
            "path": f"{base}/statuses/{head}",
            "payload": {
                "context": CONTEXT,
                "state": "success",
                "description": status_description,
                "target_url": run_url,
            },
        },
    }


def revalidate_publication(
    *,
    proof_payload: str | bytes,
    proof_file_sha256: str,
    artifact_id: str,
    artifact_sha256: str,
    contract_sha256: str,
    needs_payload: str,
) -> dict[str, Any]:
    """Return requests only after exact prepared/current proof equality.

    Original artifact references and needs come from trusted root edges, never
    fields extracted from the supplied proof. The underlying collector rechecks
    current PR/request/controller identity and both full account graphs. It rejects
    plan, TEST-only, empty selections and unsupported operator evidence.
    """
    prepared = _prepared_proof(proof_payload, proof_file_sha256)
    current = build_promotion_proof(
        artifact_id=artifact_id,
        artifact_sha256=artifact_sha256,
        contract_sha256=contract_sha256,
        needs_payload=needs_payload,
    )
    require(
        prepared == _canonical(current), "Prepared proof differs from current evidence"
    )
    return _requests(current, proof_file_sha256)
