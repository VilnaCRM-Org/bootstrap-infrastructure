"""Admit a central deployment request through the installed trusted controller.

Admission requires explicit activation and consumes one authenticated comment.
It creates no AWS credentials, deployment receipts or promotion attestations.
Workers must independently recheck authorization before using admitted inputs.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from dataclasses import asdict
from pathlib import Path

import deployment_scopes
import pulumi_command_preflight as preflight
from _github_environment_controls import complete_branch_policies
from _github_repository_controls import protected_environment_verification_blockers
from deployment_controller import (
    OWNER_ID,
    REPOSITORY,
    REPOSITORY_ID,
    REQUEST_PATTERNS,
    WORKFLOW,
    ControllerMetadata,
    DeploymentContract,
    build_deployment_contract,
)

CONTRACT_RELATIVE_PATH = ".artifacts/deployment-selection/contract.json"
CONTRACT_PATH = Path(__file__).resolve().parents[1] / CONTRACT_RELATIVE_PATH


def _identifier(name: str, pattern: str) -> str:
    """Read a closed-format identifier without coercing arbitrary input types."""
    value = os.environ.get(name, "")
    preflight.require(
        isinstance(value, str) and re.fullmatch(pattern, value) is not None,
        f"Invalid trusted context: {name}",
    )
    return value


def _controller_metadata() -> ControllerMetadata:
    """Reject inactive installations and foreign execution contexts before I/O."""
    preflight.require(
        os.environ.get("DEPLOYMENT_COORDINATOR_MODE") == "active",
        "Deployment coordinator is not active",
    )
    required = {
        "GITHUB_EVENT_NAME": "repository_dispatch",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_REPOSITORY": REPOSITORY,
        "GITHUB_REPOSITORY_ID": str(REPOSITORY_ID),
        "GITHUB_REPOSITORY_OWNER_ID": str(OWNER_ID),
        "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_WORKFLOW_REF": f"{REPOSITORY}/{WORKFLOW}@refs/heads/main",
    }
    for name, expected in required.items():
        preflight.require(
            os.environ.get(name) == expected, f"Invalid trusted context: {name}"
        )
    return ControllerMetadata(
        sha=_identifier("GITHUB_SHA", r"[0-9a-f]{40}"),
        run_id=_identifier("GITHUB_RUN_ID", r"[1-9][0-9]*"),
        run_attempt=1,
        workflow_ref=os.environ["GITHUB_WORKFLOW_REF"],
    )


def required_environments(contract: DeploymentContract) -> tuple[str, ...]:
    """List only the protected environments used by the selected account graph."""
    names: list[str] = []
    for scope in contract.selection.stacks:
        if scope == "platform":
            accounts = (
                ("test", "prod")
                if contract.identity.target_environment == "prod"
                else ("test",)
            )
            for account in accounts:
                names.append(f"{account}-preview")
                if contract.identity.command == "up":
                    names.append(account)
        else:
            names.append(f"{scope}-preview")
            if contract.identity.command == "up":
                names.append(scope)
                if scope == "operator":
                    names.append("operator-drift")
    return tuple(dict.fromkeys(names))


def _verify_environments(contract: DeploymentContract) -> None:
    """Read current protections; never auto-create missing GitHub environments."""
    names = required_environments(contract)
    if not names:
        return
    reviewer = preflight.gh("users/Kravalg")
    preflight.require(isinstance(reviewer, dict), "Invalid Kravalg identity response")
    reviewer_id = reviewer.get("id")
    preflight.require(
        type(reviewer_id) is int and reviewer_id > 0,
        "Invalid Kravalg reviewer ID",
    )
    for name in names:
        endpoint = f"repos/{REPOSITORY}/environments/{name}"
        environment = preflight.gh(endpoint)
        policies = preflight.gh(f"{endpoint}/deployment-branch-policies")
        preflight.require(
            isinstance(environment, dict) and isinstance(policies, dict),
            f"{name} environment and branch policies must be objects",
        )
        environment = dict(environment)
        environment["deployment_branch_policies"] = complete_branch_policies(policies)
        blockers = protected_environment_verification_blockers(
            environment, reviewer_id, label=name
        )
        preflight.require(not blockers, "; ".join(blockers))


def _feedback_outputs(request: dict[str, str], display_command: str) -> dict[str, str]:
    """Expose authenticated comment targets solely for informational feedback."""
    return {
        **{
            f"feedback_{key}": request[key]
            for key in (
                "head_sha",
                "pull_request_number",
                "command",
                "target_environment",
            )
        },
        "feedback_display_command": display_command,
    }


def _persist_contract(contract: DeploymentContract) -> str:
    """Write one canonical contract after its claim; refuse an existing artifact."""
    contents = (
        json.dumps(
            asdict(contract), sort_keys=True, separators=(",", ":"), ensure_ascii=True
        )
        + "\n"
    )
    CONTRACT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with CONTRACT_PATH.open("x", encoding="utf-8") as handle:
        handle.write(contents)
    return hashlib.sha256(contents.encode("utf-8")).hexdigest()


def _execution_outputs(
    contract: DeploymentContract, file_sha256: str
) -> dict[str, str]:
    """Describe admitted inputs only after claim and persistence both succeeded."""
    identity, selection = contract.identity, contract.selection
    outputs = {key: getattr(identity, key) for key in REQUEST_PATTERNS}
    outputs.update(
        {
            "execution_ready": "true",
            "schema_version": str(contract.schema_version),
            "base_sha": identity.base_sha,
            "repository": identity.repository,
            "repository_id": str(identity.repository_id),
            "repository_owner_id": str(identity.owner_id),
            "controller_sha": identity.controller.sha,
            "controller_run_id": identity.controller.run_id,
            "controller_run_attempt": str(identity.controller.run_attempt),
            "controller_workflow_ref": identity.controller.workflow_ref,
            "contract_path": CONTRACT_RELATIVE_PATH,
            "contract_digest": contract.contract_digest,
            "contract_file_sha256": file_sha256,
            "selection_digest": contract.selection_digest,
            "selector_sha256": contract.selector_sha256,
            "scopes": json.dumps(selection.stacks, separators=(",", ":")),
            "has_deployment_scopes": str(bool(selection.stacks)).lower(),
            "display_command": (
                f"/pulumi {identity.target_environment} {identity.command}"
            ),
        }
    )
    outputs.update(
        {
            f"{scope}_selected": str(scope in selection.stacks).lower()
            for scope in deployment_scopes.STACK_ORDER
        }
    )
    outputs.update(
        {
            name: str(getattr(selection, name)).lower()
            for name in (
                "scaffold_validation",
                "execution_validation",
                "catalog_validation",
            )
        }
    )
    return outputs


def accept() -> DeploymentContract:
    """Authenticate, validate, claim once and persist; failures never emit readiness."""
    metadata = _controller_metadata()
    request = preflight.read_request()
    intake = preflight.collect_intake_evidence(request)
    command = preflight.authenticate_intake(request, intake)
    output_path = os.environ.get("GITHUB_OUTPUT")
    preflight.write_outputs(
        _feedback_outputs(request, command.display_command), output_path
    )
    evidence = preflight.collect_evidence(request, intake=intake)
    selector_sha256 = hashlib.sha256(
        Path(deployment_scopes.__file__).read_bytes()
    ).hexdigest()
    contract = build_deployment_contract(
        request,
        evidence,
        controller=metadata,
        selector_sha256=selector_sha256,
        complete=True,
    )
    _verify_environments(contract)
    preflight.claim_request(request)
    file_sha256 = _persist_contract(contract)
    preflight.write_outputs(_execution_outputs(contract, file_sha256), output_path)
    return contract


def main(argv: list[str] | None = None) -> int:
    """Expose only the explicit installed-controller admission command."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("accept",))
    parser.parse_args(argv)
    accept()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
