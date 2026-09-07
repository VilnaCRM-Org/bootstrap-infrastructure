"""Run the admitted operator plan/replay/drift inside the installed trusted image.

Invoke with isolated Python. The root worker rechecks admission before OIDC;
this process authenticates it again, then verifies actual active enrollment and
fresh checkpoint/provider evidence. Only encrypted saved-plan artifacts leave
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
    OperatorTransport,
    decode,
    encode,
    private_write,
    require,
    run,
)
from operator_plan_validation import _diff, validate_operator_plan  # noqa: E402
from pulumi_ci_guardrails import find_destructive_steps  # noqa: E402
from seed import policy_registry as registry  # noqa: E402


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
    prior = {
        row["urn"]: row.get("inputs", {})
        for row in decode(checkpoint)["deployment"]["resources"]
    }
    for urn, value in goals.items():
        goal = value.get("goal")
        if goal:
            inputs = _diff(goal.get("inputDiff", {}), prior.get(urn, {}))
            for key in ("policy", "assumeRolePolicy"):
                document = inputs.get(key)
                if document is not None:
                    _analyze(document, key, transport)


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
    expected = selected_registry(arguments.account, arguments.seed_key_arn)
    contract = _contract(arguments)
    require(
        arguments.stage == "preview" or contract.identity.command == "up",
        "apply-or-drift-not-requested",
    )
    transport.tools(contract.identity.head_sha)
    enrollment(expected, arguments.stage)
    before = transport.snapshot()
    catalog = registry.load_catalog(arguments.account)
    if arguments.stage == "apply":
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
        validate_operator_plan(
            bundle["plan"], bundle["preview"], before.checkpoint, catalog=catalog
        )
        _iam(bundle["plan"], before.checkpoint, transport)
        _destructive(bundle["preview"], contract)
        require(_contract(arguments) == contract, "admission-changed")
        enrollment(expected, "apply")
        _same(before, transport.snapshot())
        transport.pulumi("apply", before, bundle["plan"])
        after = transport.snapshot()
        require(
            after.execution.provider == before.execution.provider,
            "post-apply-provider-changed",
        )
        return {}
    plan, preview = transport.pulumi(arguments.stage, before)
    _same(before, transport.snapshot())
    validation = validate_operator_plan(
        plan, preview, before.checkpoint, catalog=catalog
    )
    if arguments.stage == "drift":
        require(not validation.changed_urns, "post-apply-drift")
        return {}
    _iam(plan, before.checkpoint, transport)
    _destructive(preview, contract)
    require(_contract(arguments) == contract, "admission-changed")
    enrollment(expected, "preview")
    _same(before, transport.snapshot())
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
    """Emit only public coordinates/digests; all failures use one redacted message."""
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
                transport = OperatorTransport(
                    arguments.account, Path(directory), arguments.source
                )
                outputs = execute(arguments, transport)
        with Path(arguments.output).open("a", encoding="utf-8") as handle:
            for key, value in outputs.items():
                handle.write(f"{key}={value}\n")
        return 0
    except Exception:
        print(
            "Operator stage failed its execution or enrollment prerequisites.",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
