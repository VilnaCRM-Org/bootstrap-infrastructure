#!/usr/bin/env python3
"""Execute one reviewed TEST trust activation, then restore at proven terminal.
PROPOSER ROOT SOURCE PACKETS NEW_RECEIPTS AWS --proposal PROPOSAL_DIRECTORY
--change-set-arn EXACT_ARN --checkpoint-version VERSION --checkpoint-etag ETAG
No retry of mutations. Unknown terminal state requires separate reconciliation;
never claim restoration or alter the guard while operation state is unresolved.
"""

import argparse
import hashlib
import importlib.util
import json
import sys
import time
import uuid
from pathlib import Path

PROPOSER_HASH = "ae4f7c7519fb4a591461b0ab6a5940c2618867c68299289b3cbfa722aeabb9b7"
TERMINAL = {"UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED"}


def run_activation(
    *,
    install,
    verify_temporary,
    prestart,
    execute,
    observe,
    restore,
    save,
    sleep=time.sleep,
    polls=120,
):
    save("temporary-policy-write-intent.json", {"write": "temporary_guard"})
    try:
        install()
        verify_temporary()
        prestart()
        save("execute-write-intent.json", {"execute_once": True})
    except Exception:
        # No execution submitted by us. Prove the original AVAILABLE proposal
        # and terminal stack before restoring; do not interrupt another writer.
        prestart()
        restore()
        raise
    try:
        execute()
        save("execute-response.json", {"response_received": True})
    except Exception:
        save("execute-response.json", {"response_received": False, "uncertain": True})
    for index in range(polls):
        try:
            status, execution = observe(index)
        except Exception:
            save(f"observation-error-{index:03d}.json", {"read_failed": True})
        else:
            if status in TERMINAL and execution in {
                "EXECUTE_COMPLETE",
                "EXECUTE_FAILED",
            }:
                restore()
                result = {
                    "stack_status": status,
                    "permanent_guard_restored": True,
                    "execution_status": execution,
                    "activation_update_succeeded": (
                        status == "UPDATE_COMPLETE" and execution == "EXECUTE_COMPLETE"
                    ),
                    "active_enrollment_verified": False,
                }
                save("execution-terminal.json", result)
                if not result["activation_update_succeeded"]:
                    raise ValueError("Activation failed; permanent guard restored")
                return result
        if index + 1 < polls:
            sleep(10)
    save(
        "execution-unresolved.json",
        {
            "terminal_proven": False,
            "permanent_guard_restored": False,
            "resubmit_forbidden": True,
        },
    )
    raise ValueError(
        "No terminal proof; reconcile without resubmitting or changing guard"
    )


def main():
    if sys.flags.optimize:
        raise ValueError("Assertions must remain enabled")
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("proposer")
    # Parse known helper path before importing exact reviewed bytes.
    preliminary, _ = parser.parse_known_args()
    assert (
        hashlib.sha256(Path(preliminary.proposer).read_bytes()).hexdigest()
        == PROPOSER_HASH
    )
    spec = importlib.util.spec_from_file_location(
        "activation_proposer", preliminary.proposer
    )
    proposer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(proposer)
    proposer.arguments(parser)
    parser.add_argument("--proposal", required=True)
    parser.add_argument("--change-set-arn", required=True)
    args = parser.parse_args()
    ctx = proposer.context(
        args,
        {
            ("cloudformation", "set-stack-policy"),
            ("cloudformation", "execute-change-set"),
        },
    )
    directory = Path(args.proposal).resolve(strict=True)
    receipt = json.loads((directory / "proposal-validated.json").read_bytes())
    intent = json.loads((directory / "proposal-intent.json").read_bytes())
    change = args.change_set_arn
    digest = hashlib.sha256(ctx.activation.activation_template.encode()).hexdigest()
    assert receipt == {
        "stack_id": proposer.STACK,
        "change_set_id": change,
        "template_url": receipt["template_url"],
        "template_sha256": digest,
        "source_sha": proposer.SOURCE_SHA,
        "validated_trust_modifications": 3,
        "preserved_policies": 55,
        "checkpoint_version": args.checkpoint_version,
        "checkpoint_etag": args.checkpoint_etag,
        "executed": False,
        "stack_policy_changed": False,
    }
    assert (
        intent["stack_id"] == proposer.STACK
        and intent["source_sha"] == proposer.SOURCE_SHA
    )
    assert (
        intent["checkpoint_version"] == args.checkpoint_version
        and intent["checkpoint_etag"] == args.checkpoint_etag
    )
    assert intent["template_sha256"] == digest and intent["executed"] is False
    assert intent["bucket"] == proposer.BUCKET
    assert intent["change_set_name"] == intent["client_token"] == change.split("/")[1]
    assert (
        intent["object_key"]
        == f"pr226/test/activation/{intent['change_set_name']}.json"
    )
    uploaded = json.loads((directory / "template-upload.json").read_bytes())
    version = uploaded["VersionId"]
    assert isinstance(version, str) and version and version != "null"
    url = (
        f"https://{proposer.BUCKET}.s3.eu-central-1.amazonaws.com/"
        f"{intent['object_key']}?versionId={proposer.quote(version, safe='')}"
    )
    assert receipt["template_url"] == url
    assert (
        directory / "activation-template.json"
    ).read_bytes() == ctx.activation.activation_template.encode()
    # Reauthenticate the pinned upload version; local digest/receipt alone is
    # not evidence that the native proposal came from this reviewed template.
    path = ctx.out / "proposal-template-readback.json"
    meta = ctx.call(
        "s3api",
        "get-object",
        "--bucket",
        proposer.BUCKET,
        "--key",
        intent["object_key"],
        "--version-id",
        version,
        "--expected-bucket-owner",
        proposer.ACCOUNT,
        str(path),
    )
    assert meta["VersionId"] == version and meta["ServerSideEncryption"] == "AES256"
    assert path.read_bytes() == ctx.activation.activation_template.encode()
    ctx.save("proposal-template-readback-metadata.json", meta)
    permanent = json.loads(ctx.packet.stack_policy)
    temporary = json.loads(ctx.activation.temporary_stack_policy)
    ctx.preconditions("before")

    # Repeated validations have distinct exclusive receipt names.
    validation_index = 0

    def checked_prestart():
        nonlocal validation_index
        label = f"prestart-{validation_index}"
        validation_index += 1
        ctx.root()
        assert ctx.state()["StackStatus"] == "UPDATE_COMPLETE"
        proposer.validate_proposal(ctx, change, label)
        response = ctx.call(
            "cloudformation",
            "get-template",
            "--stack-name",
            proposer.STACK,
            "--template-stage",
            "Original",
        )
        assert proposer.document(response["TemplateBody"]) == ctx.before

    def set_guard(name):
        ctx.root()
        return ctx.call(
            "cloudformation",
            "set-stack-policy",
            "--stack-name",
            proposer.STACK,
            "--stack-policy-body",
            "file://" + str(ctx.out / name),
        )

    def restore():
        observed = ctx.state()
        assert observed["StackStatus"] in TERMINAL
        ctx.save(
            "permanent-policy-write-intent.json",
            {"stack_id": proposer.STACK, "observed_terminal": observed},
        )
        try:
            set_guard("permanent-stack-policy.json")
        except Exception:
            ctx.save("permanent-policy-response.json", {"uncertain": True})
        ctx.guard(permanent)
        ctx.save(
            "permanent-policy-restored.json", {"verified": True, "policy": permanent}
        )

    token = "pr226-" + "test-activation-execute-" + uuid.uuid4().hex
    ctx.save(
        "execution-identity.json",
        {
            "account": proposer.ACCOUNT,
            "stack_id": proposer.STACK,
            "change_set_id": change,
            "client_request_token": token,
            "template_sha256": digest,
            "caller": ctx.caller,
            "checkpoint_version": args.checkpoint_version,
            "checkpoint_etag": args.checkpoint_etag,
        },
    )
    checked_prestart()
    ctx.guard(permanent)

    def execute():
        ctx.root()
        return ctx.call(
            "cloudformation",
            "execute-change-set",
            "--stack-name",
            proposer.STACK,
            "--change-set-name",
            change,
            "--client-request-token",
            token,
        )

    def observe(index):
        observed = ctx.state()
        page, changes = proposer.change_pages(ctx, change, f"observe-{index:03d}")
        assert page["Status"] == "CREATE_COMPLETE"
        ctx.installation.validate_activation_change_set(ctx.activation, changes=changes)
        ctx.save(f"stack-observation-{index:03d}.json", observed)
        return observed["StackStatus"], page["ExecutionStatus"]

    result = run_activation(
        install=lambda: set_guard("temporary-stack-policy.json"),
        verify_temporary=lambda: ctx.guard(temporary),
        prestart=checked_prestart,
        execute=execute,
        observe=observe,
        restore=restore,
        save=ctx.save,
    )
    response = ctx.call(
        "cloudformation",
        "get-template",
        "--stack-name",
        proposer.STACK,
        "--template-stage",
        "Original",
    )
    assert proposer.document(response["TemplateBody"]) == ctx.after
    ctx.save("active-current-template.json", response)
    ctx.owners(ctx.after, "active")
    ctx.quiescence("after")
    ctx.enrollment("active", "after")
    ctx.guard(permanent)
    result["active_enrollment_verified"] = True
    result["issuance_reopened"] = False
    ctx.save("activation-verified.json", result)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print(
            "Activation incomplete. Keep issuance holds. Inspect exact native "
            "stack/change-set and private receipts; no automatic retry. Guard "
            "restoration requires its successful readback receipt.",
            file=sys.stderr,
        )
        raise SystemExit(1) from None
