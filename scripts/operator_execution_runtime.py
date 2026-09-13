"""Run the admitted operator plan/replay/drift inside the installed trusted image.

Invoke with isolated Python. The root worker rechecks admission before OIDC;
this process authenticates it again, then verifies actual active enrollment and
fresh checkpoint/provider evidence. Only encrypted plan/diagnostic artifacts leave
the process. Independent seed installation is mandatory and never performed here.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path[:0] = [
    str(Path(__file__).resolve().parent),
    str(Path(__file__).resolve().parents[1] / "pulumi"),
]

import argparse  # noqa: E402
import base64  # noqa: E402
import hashlib  # noqa: E402
import io  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402
import re  # noqa: E402
import stat  # noqa: E402
import tempfile  # noqa: E402
import zipfile  # noqa: E402

import operator_plan_envelope as envelope  # noqa: E402
import pulumi_command_preflight as preflight  # noqa: E402
from deployment_worker_runtime import load_verified_contract  # noqa: E402
from operator_aws_read import AwsCliRead  # noqa: E402
from operator_enrollment_runtime import collect_enrollment  # noqa: E402
from operator_execution_transport import (  # noqa: E402
    AWS,
    MAX_BYTES,
    PROCESS_CATEGORIES,
    DiagnosticCapture,
    OperatorTransport,
    ProcessFailure,
    decode,
    encode,
    private_write,
    require,
    run,
    safe_exit_code,
)
from operator_plan_validation import _goal_inputs, validate_operator_plan  # noqa: E402
from pulumi_ci_guardrails import find_destructive_steps  # noqa: E402
from seed import policy_registry as registry  # noqa: E402

STAGES = frozenset(
    {
        "initialization",
        "transport-setup",
        "public-output",
        "admission",
        "tools",
        "initial-enrollment",
        "initial-snapshot",
        "saved-plan-input",
        "plan-validation",
        "iam-analysis",
        "destructive-review",
        "admission-recheck",
        "final-enrollment",
        "final-snapshot",
        "pulumi-preview",
        "pulumi-apply",
        "pulumi-drift",
        "post-preview-snapshot",
        "post-apply-snapshot",
        "drift-validation",
        "plan-seal",
    }
)


def _failure_record(exc, stage):
    """Emit only fixed source stages/categories and bounded native exits/signals."""
    stage = stage if type(stage) is str and stage in STAGES else "unknown"
    category, exit_code = "unknown", None
    if type(exc) is ProcessFailure:
        category = (
            exc.category
            if type(exc.category) is str and exc.category in PROCESS_CATEGORIES
            else "unknown"
        )
        exit_code = safe_exit_code(exc.exit_code)
    elif type(exc) is ValueError:
        category = "validation-rejected"
    return {"stage": stage, "category": category, "exit_code": exit_code}


def _public_record(exc, stage):
    """Keep child-selected numeric exits exclusively inside encrypted diagnostics."""
    record = _failure_record(exc, stage)
    return {"stage": record["stage"], "category": record["category"]}


PROCESS_GUIDANCE = {
    "spawn-failed": (
        "A required process could not start. Check the pinned worker "
        "image and executable permissions."
    ),
    "process-timeout": (
        "A private process exceeded its deadline. Review available "
        "encrypted diagnostics and service availability before retrying."
    ),
    "stdout-bound": (
        "Private process output exceeded its limit. Review available "
        "encrypted diagnostics; reduce unnecessary output without raising "
        "safety limits."
    ),
    "stderr-bound": (
        "Private error output exceeded its limit. Review available "
        "encrypted diagnostics without publishing the captured output."
    ),
    "process-exit": (
        "A private process failed. Follow "
        "docs/operator-preview-diagnostics.md to privately inspect the "
        "operator-diagnostic-preview artifact, when available, before "
        "retrying."
    ),
    "child-cleanup-failed": (
        "Isolated process cleanup failed. Check the trusted worker "
        "process isolation before retrying."
    ),
}
VALIDATION_GUIDANCE = {
    ("plan-validation", "unsupported-goal-option"): (
        "The saved plan contains an unsupported lifecycle option. Review "
        "import and replacement options against completed checkpoint "
        "ownership; keep validation enabled."
    ),
    ("plan-validation", "preview-old-outputs"): (
        "Preview prior outputs disagree with the checkpoint. Review "
        "checkpoint and refresh consistency privately before generating a "
        "fresh plan."
    ),
    ("plan-validation", "aws-provider-version-region"): (
        "The plan provider differs from the required version or region. "
        "Restore the reviewed provider pins before generating a fresh "
        "plan."
    ),
    ("iam-analysis", "iam-analysis-failed"): (
        "IAM analysis did not accept the complete policy result. Review "
        "the policy validation findings privately; do not bypass the IAM "
        "gate."
    ),
    ("destructive-review", "destructive-review-required"): (
        "A destructive change lacks the required review. Review its "
        "necessity and the existing destructive-change approval procedure "
        "before retrying."
    ),
    ("admission-recheck", "admission-changed"): (
        "Request admission changed during execution. Recheck the PR head "
        "and authorization, then submit a fresh request."
    ),
    ("saved-plan-input", "saved-checkpoint-changed"): (
        "The saved plan checkpoint no longer matches. Generate and review "
        "a fresh plan before applying."
    ),
    ("drift-validation", "post-apply-drift"): (
        "The drift check found remaining changes. Investigate the "
        "difference before declaring deployment complete."
    ),
}
STAGE_GUIDANCE = {
    "initial-enrollment": (
        "Active enrollment could not be verified. Review the exact role "
        "identity, trust, boundaries and policy inventory; do not "
        "reactivate roles or bypass enrollment."
    ),
    "final-enrollment": (
        "Active enrollment could not be reverified. Review changes to the "
        "exact role identity, trust, boundaries and policy inventory "
        "before retrying."
    ),
    "initial-snapshot": (
        "The checkpoint or provider could not be verified. Check the "
        "canonical backend version and pinned KMS provider through "
        "private metadata review."
    ),
    "post-preview-snapshot": (
        "Checkpoint consistency could not be verified after preview. "
        "Review backend version changes privately before generating a "
        "fresh plan."
    ),
    "final-snapshot": (
        "Checkpoint consistency could not be reverified. Review backend "
        "version changes privately before generating a fresh plan."
    ),
    "plan-validation": (
        "The private plan failed validation. Review the encrypted preview "
        "diagnostic, when available, and correct the source or state "
        "mismatch without relaxing validation."
    ),
}
UNKNOWN_GUIDANCE = (
    "The failure could not be classified more precisely without private "
    "evidence. Review available encrypted diagnostics and the trusted "
    "worker before retrying."
)


def _public_guidance(exc, record):
    """Select static advice only; never interpolate or coerce private error data."""
    if (
        type(exc) is ValueError
        and len(exc.args) == 1
        and type(exc.args[0]) is str
        and len(exc.args[0]) <= 96
    ):
        guidance = VALIDATION_GUIDANCE.get((record["stage"], exc.args[0]))
        if guidance is not None:
            return guidance
    return PROCESS_GUIDANCE.get(record["category"]) or STAGE_GUIDANCE.get(
        record["stage"], UNKNOWN_GUIDANCE
    )


def _failure_annotation(exc, stage):
    """Build a single GitHub annotation solely from trusted finite literals."""
    record = _public_record(exc, stage)
    return (
        "::error title=Operator execution failed::"
        f"Stage: {record['stage']}. Category: {record['category']}. "
        + _public_guidance(exc, record)
    )


def _publish_diagnostic(destination, encrypted):
    """Publish complete ciphertext exclusively; a failed write is never uploadable."""
    pending = destination.with_name(".operator-diagnostic.pending")
    try:
        private_write(pending, encrypted)
        pending.chmod(0o644)
        os.link(pending, destination)
    finally:
        pending.unlink(missing_ok=True)


def _write_diagnostic(arguments, transport, exc):
    """Seal preview failure bytes before cleanup; never replace the original error."""
    capture = getattr(transport, "diagnostic_capture", None)
    binding = getattr(arguments, "diagnostic_binding", None)
    if (
        arguments.stage != "preview"
        or type(capture) is not DiagnosticCapture
        or binding is None
    ):
        return
    destination = arguments.public_dir / "operator-diagnostic.encrypted.json"
    try:
        reason = ""
        if type(exc) is ValueError and len(exc.args) == 1 and type(exc.args[0]) is str:
            reason = (
                exc.args[0][:4096]
                .encode("utf-8", "replace")[:4096]
                .decode("utf-8", "ignore")
            )
        payload = {
            **_failure_record(exc, arguments.diagnostic_stage),
            "stdout": base64.b64encode(capture.stdout).decode("ascii"),
            "stderr": base64.b64encode(capture.stderr).decode("ascii"),
            "stdout_truncated": capture.stdout_truncated,
            "stderr_truncated": capture.stderr_truncated,
            "validation_reason": reason,
        }
        contract, execution = binding
        encrypted = envelope.seal_diagnostic(
            payload,
            contract=contract,
            execution=execution,
            generate_key=lambda request: transport.kms("generate-data-key", request),
        )
        _publish_diagnostic(destination, encrypted)
        print(
            json.dumps({"diagnostic_sha256": hashlib.sha256(encrypted).hexdigest()}),
            file=sys.stderr,
        )
    except Exception:
        # Remove a partial or stale exact diagnostic file, never publish plaintext.
        try:
            destination.unlink(missing_ok=True)
        except OSError:
            pass


def selected_registry(environment, key_arn):
    """Require explicit real seed-key binding; DescribeKey must later confirm it."""
    require(environment in registry.ACCOUNTS and type(key_arn) is str, "seed-account")
    account = registry.ACCOUNTS[environment]
    prefix = f"arn:aws:kms:eu-central-1:{account}:key/"
    require(key_arn.startswith(prefix), "seed-key-account")
    key = registry.SeedKeyBinding(
        key_arn,
        key_arn[len(prefix) :],
        account,
        "CUSTOMER",
        "Enabled",
        "ENCRYPT_DECRYPT",
    )
    return registry.build_registry(environment, account_id=account, seed_key=key)


def enrollment(expected, purpose):
    """Collect complete live metadata; initial disabled enrollment is insufficient."""
    observed = collect_enrollment(
        expected, purpose=purpose, call=AwsCliRead(expected, aws_executable=AWS)
    )
    return registry.verify_active_enrollment(expected, observed)


def _contract(arguments):
    """Authenticate exact same-run root artifact and repeat current admission checks."""
    return load_verified_contract(
        artifact_id=arguments.artifact_id,
        artifact_sha256=arguments.artifact_sha256,
        contract_sha256=arguments.contract_sha256,
        scope="operator",
        environment=arguments.account,
    )


def _artifact_name(contract, account):
    identity = contract.identity
    return (
        f"operator-plan-{identity.controller.run_id}-"
        f"{identity.controller.run_attempt}-{account}-{identity.head_sha}"
    )


def _artifact_metadata(arguments, contract):
    """Require exact same-run artifact metadata before downloading bytes."""
    artifact_id, digest = arguments.plan_artifact_id, arguments.plan_artifact_sha256
    require(
        type(artifact_id) is str and re.fullmatch(r"[1-9][0-9]*", artifact_id),
        "plan-artifact-id",
    )
    require(
        type(digest) is str and re.fullmatch(r"[0-9a-f]{64}", digest),
        "plan-artifact-digest",
    )
    endpoint = f"repos/{contract.identity.repository}/actions/artifacts/{artifact_id}"
    metadata = preflight.gh(endpoint)
    origin = metadata.get("workflow_run", {})
    require(
        metadata.get("id") == int(artifact_id)
        and metadata.get("name") == _artifact_name(contract, arguments.account)
        and metadata.get("expired") is False
        and metadata.get("digest") == "sha256:" + digest,
        "plan-artifact-identity",
    )
    require(
        origin.get("id") == int(contract.identity.controller.run_id)
        and origin.get("head_sha") == contract.identity.controller.sha
        and origin.get("repository_id") == contract.identity.repository_id
        and origin.get("head_repository_id") == contract.identity.repository_id,
        "plan-artifact-origin",
    )
    require(
        type(metadata.get("size_in_bytes")) is int
        and 0 < metadata["size_in_bytes"] <= MAX_BYTES,
        "plan-artifact-size",
    )
    return endpoint, metadata


def _encrypted_artifact(arguments, contract):
    """Authenticate ZIP origin and digest; read its single ciphertext member."""
    endpoint, metadata = _artifact_metadata(arguments, contract)
    raw = run(
        ["/usr/bin/gh", "api", endpoint + "/zip"],
        env={"PATH": "/usr/bin:/bin", "GH_TOKEN": os.environ["GH_TOKEN"]},
        cwd=Path(__file__).resolve().parent,
        timeout=120,
    )
    require(
        len(raw) == metadata["size_in_bytes"]
        and hashlib.sha256(raw).hexdigest() == arguments.plan_artifact_sha256,
        "plan-artifact-transport",
    )
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        members = archive.infolist()
        require(len(members) == 1, "plan-artifact-members")
        member = members[0]
        require(
            member.filename == member.orig_filename == "saved-plan.encrypted.json"
            and not member.is_dir()
            and stat.S_IFMT(member.external_attr >> 16) in (0, stat.S_IFREG)
            and member.flag_bits & 1 == 0
            and 0 < member.file_size <= envelope.MAX_ENVELOPE_BYTES,
            "plan-artifact-member",
        )
        with archive.open(member) as stream:
            result = stream.read(envelope.MAX_ENVELOPE_BYTES + 1)
        require(len(result) == member.file_size, "plan-artifact-member-size")
        return result


def _bundle(plan, preview, checkpoint):
    """Encrypt full replay evidence together; public artifacts contain no plaintext."""
    return encode(
        {
            key: base64.b64encode(value).decode()
            for key, value in {
                "plan": plan,
                "preview": preview,
                "checkpoint": checkpoint,
            }.items()
        }
    )


def _unbundle(raw):
    value = decode(raw)
    require(
        type(value) is dict and set(value) == {"plan", "preview", "checkpoint"},
        "plan-bundle-fields",
    )
    return {key: base64.b64decode(text, validate=True) for key, text in value.items()}


def _same(before, after):
    """Compare immutable object identity and complete provider/deployment bytes."""
    require(before == after, "checkpoint-or-provider-changed")


def _iam(plan, checkpoint, transport):
    """Validate every private goal's IAM document with the actual AWS analyzer."""
    goals = decode(plan)["resourcePlans"]
    prior = {row["urn"]: row for row in decode(checkpoint)["deployment"]["resources"]}
    for urn, value in goals.items():
        goal = value.get("goal")
        if goal:
            inputs = _goal_inputs(goal, prior.get(urn), tuple(value["steps"]))
            for key in ("policy", "assumeRolePolicy"):
                document = inputs.get(key)
                if document is not None:
                    _analyze(document, key, transport)
            for policy in inputs.get("inlinePolicies", []):
                _analyze(policy["policy"], "policy", transport)


def _analyze(document, key, transport):
    """Apply native policy validation; incomplete pages cannot approve a plan."""
    arguments = {
        "policyDocument": document,
        "policyType": "RESOURCE_POLICY"
        if key == "assumeRolePolicy"
        else "IDENTITY_POLICY",
    }
    if key == "assumeRolePolicy":
        arguments["validatePolicyResourceType"] = "AWS::IAM::AssumeRolePolicyDocument"
    result = transport.aws("accessanalyzer", "validate-policy", arguments)
    require(
        not result.get("nextToken")
        and type(result.get("findings")) is list
        and all(
            type(item) is dict and item.get("findingType") in ("WARNING", "SUGGESTION")
            for item in result["findings"]
        ),
        "iam-analysis-failed",
    )


def _destructive(preview, contract):
    """Apply the existing destructive-change label rule against fresh GitHub labels."""
    if find_destructive_steps(decode(preview)["steps"]):
        labels = preflight.gh(
            f"repos/{contract.identity.repository}/issues/{contract.identity.pull_request_number}/labels?per_page=100"
        )
        require(
            type(labels) is list
            and len(labels) < 100
            and any(
                row.get("name") == "allow-destructive-infra-change" for row in labels
            ),
            "destructive-review-required",
        )


def execute(arguments, transport):
    """Execute concrete stages after enrollment and fresh evidence checks."""
    arguments.diagnostic_stage = "admission"
    expected = selected_registry(arguments.account, arguments.seed_key_arn)
    contract = _contract(arguments)
    require(
        arguments.stage == "preview" or contract.identity.command == "up",
        "apply-or-drift-not-requested",
    )
    arguments.diagnostic_stage = "tools"
    transport.tools(contract.identity.head_sha)
    arguments.diagnostic_stage = "initial-enrollment"
    enrollment(expected, arguments.stage)
    arguments.diagnostic_stage = "initial-snapshot"
    before = transport.snapshot()
    arguments.diagnostic_binding = (contract, before.execution)
    catalog = registry.load_catalog(arguments.account)
    if arguments.stage == "apply":
        arguments.diagnostic_stage = "saved-plan-input"
        encrypted = _encrypted_artifact(arguments, contract)
        bundle = _unbundle(
            envelope.open_plan(
                encrypted,
                contract=contract,
                execution=before.execution,
                decrypt_key=lambda request: transport.kms("decrypt", request),
            )
        )
        require(bundle["checkpoint"] == before.checkpoint, "saved-checkpoint-changed")
        arguments.diagnostic_stage = "plan-validation"
        validate_operator_plan(
            bundle["plan"], bundle["preview"], before.checkpoint, catalog=catalog
        )
        arguments.diagnostic_stage = "iam-analysis"
        _iam(bundle["plan"], before.checkpoint, transport)
        arguments.diagnostic_stage = "destructive-review"
        _destructive(bundle["preview"], contract)
        arguments.diagnostic_stage = "admission-recheck"
        require(_contract(arguments) == contract, "admission-changed")
        arguments.diagnostic_stage = "final-enrollment"
        enrollment(expected, "apply")
        arguments.diagnostic_stage = "final-snapshot"
        _same(before, transport.snapshot())
        arguments.diagnostic_stage = "pulumi-apply"
        transport.pulumi("apply", before, bundle["plan"])
        arguments.diagnostic_stage = "post-apply-snapshot"
        after = transport.snapshot()
        require(
            after.execution.provider == before.execution.provider,
            "post-apply-provider-changed",
        )
        return {}
    arguments.diagnostic_stage = (
        "pulumi-drift" if arguments.stage == "drift" else "pulumi-preview"
    )
    plan, preview = transport.pulumi(arguments.stage, before)
    arguments.diagnostic_stage = "post-preview-snapshot"
    _same(before, transport.snapshot())
    arguments.diagnostic_stage = "plan-validation"
    validation = validate_operator_plan(
        plan, preview, before.checkpoint, catalog=catalog
    )
    if arguments.stage == "drift":
        arguments.diagnostic_stage = "drift-validation"
        require(not validation.changed_urns, "post-apply-drift")
        return {}
    arguments.diagnostic_stage = "iam-analysis"
    _iam(plan, before.checkpoint, transport)
    arguments.diagnostic_stage = "destructive-review"
    _destructive(preview, contract)
    arguments.diagnostic_stage = "admission-recheck"
    require(_contract(arguments) == contract, "admission-changed")
    arguments.diagnostic_stage = "final-enrollment"
    enrollment(expected, "preview")
    arguments.diagnostic_stage = "final-snapshot"
    _same(before, transport.snapshot())
    arguments.diagnostic_stage = "plan-seal"
    encrypted = envelope.seal_plan(
        _bundle(plan, preview, before.checkpoint),
        contract=contract,
        execution=before.execution,
        generate_key=lambda request: transport.kms("generate-data-key", request),
    )
    private_write(arguments.public_dir / "saved-plan.encrypted.json", encrypted)
    (arguments.public_dir / "saved-plan.encrypted.json").chmod(0o644)
    return {
        "plan_validated": "true",
        "envelope_sha256": hashlib.sha256(encrypted).hexdigest(),
    }


def main(argv=None):
    """Emit public coordinates/digests or fixed failure attribution, never details."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--stage", choices=("resolve", "preview", "apply", "drift"), required=True
    )
    parser.add_argument("--account", choices=("test", "prod"), required=True)
    for name in (
        "artifact-id",
        "artifact-sha256",
        "contract-sha256",
        "seed-key-arn",
        "output",
    ):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--plan-artifact-id")
    parser.add_argument("--plan-artifact-sha256")
    parser.add_argument("--source", type=Path, default=Path("/source"))
    parser.add_argument("--public-dir", type=Path, default=Path("/public"))
    arguments = parser.parse_args(argv)
    arguments.diagnostic_stage = "initialization"
    try:
        expected = selected_registry(arguments.account, arguments.seed_key_arn)
        contract = _contract(arguments)
        if arguments.stage == "resolve":
            outputs = {
                "account_id": expected.account_id,
                "head_sha": contract.identity.head_sha,
                "base_sha": contract.identity.base_sha,
                "command": contract.identity.command,
            }
            outputs.update(
                {
                    purpose + "_role": (
                        f"arn:aws:iam::{expected.account_id}:role/"
                        f"GitHubOperator{purpose.title()}-{arguments.account}"
                    )
                    for purpose in ("preview", "apply", "drift")
                }
            )
        else:
            with tempfile.TemporaryDirectory(prefix="operator-private-") as directory:
                arguments.diagnostic_stage = "transport-setup"
                transport = OperatorTransport(
                    arguments.account, Path(directory), arguments.source
                )
                try:
                    outputs = execute(arguments, transport)
                except Exception as exc:
                    _write_diagnostic(arguments, transport, exc)
                    raise
        arguments.diagnostic_stage = "public-output"
        with Path(arguments.output).open("a", encoding="utf-8") as handle:
            for key, value in outputs.items():
                handle.write(f"{key}={value}\n")
        return 0
    except Exception as exc:
        print(
            json.dumps(_public_record(exc, arguments.diagnostic_stage), sort_keys=True),
            file=sys.stderr,
        )
        print(_failure_annotation(exc, arguments.diagnostic_stage), file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
