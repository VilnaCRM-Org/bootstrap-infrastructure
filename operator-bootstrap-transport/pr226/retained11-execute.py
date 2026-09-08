#!/usr/bin/env python3
"""One TEST11 IMPORT execution; restore the permanent guard only at terminal.

Usage: python3 -I execute.py RECOVERY PROPOSER ROOT PRIOR SOURCE PACKETS
       PREPARED PROPOSAL_RECEIPTS NEW_RECEIPTS AWS
No retries of any mutation, no delete/recreate, no operation interruption.
"""

import hashlib
import json
import os
from pathlib import Path
import sys
import time
import uuid

RECOVERY_HASH = "f6d514f93b7f8ccbe116e257cd78251ca444daa9f357e26e27c288955035600d"
PROPOSER_HASH = "5e4a0cad1d0047f974a99705fd7efea80b9c922ba7d27be3622f014617fd28c2"
CHANGE = "arn:aws:cloudformation:eu-central-1:891377212104:changeSet/pr225-retained11-fef3b57f3d5a4a4cbde1d5b4b3b3a57f/7614fa43-a3d1-4ac5-9f09-0787c40d0738"
TEMPLATE_HASH = "068ee1b7735b51125f3f5b6daef5d4a8f595ef717ce487cd00458a56ee13503a"
VERSION = "JDZAB54s2LZXP2mFw7rsIqTnc3MW7rsn"
TERMINAL = {"IMPORT_COMPLETE", "IMPORT_ROLLBACK_COMPLETE", "IMPORT_ROLLBACK_FAILED"}


def run_import(
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
    """Never restore while an attempted execution lacks terminal evidence."""
    save("temporary-policy-write-intent.json", {"write": "temporary_guard"})
    try:
        install()
        verify_temporary()
        prestart()
        save("execute-write-intent.json", {"execute_once": True})
    except Exception:
        # No execution was submitted by us. Only restore if exact original
        # stack/proposal remain terminal/available; never interrupt another run.
        prestart()
        restore()
        raise
    try:
        execute()
        save("execute-response.json", {"response_received": True})
    except Exception:
        # The request may have reached AWS. Reconcile; never resubmit.
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
                    "import_succeeded": status == "IMPORT_COMPLETE",
                }
                save("execution-terminal.json", result)
                if status != "IMPORT_COMPLETE":
                    raise ValueError("Import failed; permanent guard restored")
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
    raise ValueError("No terminal proof; do not restore during operation or resubmit")


def main():
    if sys.flags.optimize:
        raise ValueError("Assertions must remain enabled")
    (
        recovery_path,
        proposer_path,
        root_path,
        prior_path,
        source,
        packets_path,
        prepared_path,
        proposal_path,
        output,
        executable,
    ) = sys.argv[1:]
    import importlib.util

    assert hashlib.sha256(Path(recovery_path).read_bytes()).hexdigest() == RECOVERY_HASH
    spec = importlib.util.spec_from_file_location("recovery", recovery_path)
    recovery = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(recovery)
    proposer = recovery.load(proposer_path, "proposer", PROPOSER_HASH)
    helper = recovery.load(root_path, "root_observer", recovery.ROOT_HASH)
    prior = recovery.load(prior_path, "prior_proposal", recovery.PROPOSAL_HASH)
    transport, _, installation, registry = helper.load_source(source)
    assert (
        Path(executable).is_absolute()
        and Path(executable).resolve(strict=True).name == "aws"
    )
    os.environ["AWS_MAX_ATTEMPTS"] = "1"
    os.umask(0o077)
    out = Path(output).resolve()
    out.mkdir(mode=0o700)
    prepared, proposal, packets = (
        Path(x).resolve(strict=True)
        for x in (prepared_path, proposal_path, packets_path)
    )
    account, stack = recovery.ACCOUNT, recovery.STACK
    caller = helper.root_caller(transport, executable, account)

    def save(name, value):
        with (out / name).open("x") as f:
            json.dump(value, f, sort_keys=True, separators=(",", ":"))
            f.write("\n")

    # Reuse the exact reviewed read-only preparation, including its complete
    # retained-policy ownership scan and fresh KMS/holds/state/locks checks.
    arguments = sys.argv
    try:
        sys.argv = [
            recovery_path,
            root_path,
            prior_path,
            source,
            packets_path,
            str(out / "fresh-preparation"),
            executable,
        ]
        recovery.main()
    finally:
        sys.argv = arguments
    fresh = out / "fresh-preparation"
    for name in (
        "import-template.json",
        "resources-to-import.json",
        "temporary-import-stack-policy.json",
        "permanent-stack-policy.json",
    ):
        assert (fresh / name).read_bytes() == (prepared / name).read_bytes()
    key = registry.SeedKeyBinding(
        **json.loads((packets / "seed-key-binding.json").read_text())
    )
    packet = installation.build_installation("test", account_id=account, seed_key=key)
    partition = prior.partition_for(
        packets, "test", account, json.loads(packet.enrollment_template)
    )
    current, template, imports = proposer.checked_preparation(
        fresh, packet, partition, prior, recovery, caller
    )
    permanent = json.loads((fresh / "permanent-stack-policy.json").read_text())
    temporary = json.loads((fresh / "temporary-import-stack-policy.json").read_text())
    receipt = json.loads((proposal / "proposal-validated.json").read_text())
    intent = json.loads((proposal / "proposal-intent.json").read_text())
    change, token = receipt["change_set_id"], intent["change_set_name"]
    assert change == CHANGE
    assert isinstance(token, str) and token.startswith("pr225-retained11-")
    assert change.startswith(
        f"arn:aws:cloudformation:eu-central-1:{account}:changeSet/{token}/"
    )
    digest = hashlib.sha256((fresh / "import-template.json").read_bytes()).hexdigest()
    assert digest == TEMPLATE_HASH
    assert receipt["template_url"] == (
        f"https://{proposer.BUCKET}.s3.eu-central-1.amazonaws.com/pr225/test/{token}.json?versionId={VERSION}"
    )
    assert (
        intent["bucket"] == proposer.BUCKET
        and intent["object_key"] == f"pr225/test/{token}.json"
    )
    assert receipt == {
        "stack_id": stack,
        "change_set_id": change,
        "template_url": receipt["template_url"],
        "template_sha256": digest,
        "validated_imports": 11,
        "preserved_resources": 44,
        "source_sha": helper.SOURCE_SHA,
        "executed": False,
        "stack_policy_changed": False,
    }
    assert intent["account"] == account and intent["stack_id"] == stack
    assert intent["client_token"] == token and intent["change_set_type"] == "IMPORT"
    assert (
        intent["template_sha256"] == digest and intent["resources_to_import"] == imports
    )
    assert (
        intent["source_sha"] == helper.SOURCE_SHA
        and intent["recovery_sha256"] == RECOVERY_HASH
    )
    assert intent["executed"] is False
    assert (proposal / "import-template.json").read_bytes() == (
        fresh / "import-template.json"
    ).read_bytes()

    def call(service, operation, *args):
        assert service == "cloudformation" and operation in {
            "describe-stacks",
            "describe-change-set",
            "get-template",
            "get-stack-policy",
            "list-stack-resources",
            "set-stack-policy",
            "execute-change-set",
        }
        command = [
            executable,
            service,
            operation,
            "--region",
            "eu-central-1",
            "--endpoint-url",
            "https://cloudformation.eu-central-1.amazonaws.com",
            "--output",
            "json",
            "--no-paginate",
            "--no-cli-pager",
            "--no-cli-auto-prompt",
            "--cli-connect-timeout",
            "5",
            "--cli-read-timeout",
            "20",
            *args,
        ]
        result = transport._run(command, None)
        # These two AWS CLI mutations legitimately have an empty success body.
        if not result.strip() and operation in {
            "set-stack-policy",
            "execute-change-set",
        }:
            return {}
        return transport._response(result)

    def guard(expected):
        actual = call("cloudformation", "get-stack-policy", "--stack-name", stack)
        assert prior.document(actual["StackPolicyBody"]) == expected

    def state():
        rows = call("cloudformation", "describe-stacks", "--stack-name", stack)[
            "Stacks"
        ]
        assert (
            len(rows) == 1
            and rows[0]["StackId"] == stack
            and not rows[0].get("RoleARN")
        )
        return rows[0]

    def prestart():
        assert helper.root_caller(transport, executable, account) == caller
        assert state()["StackStatus"] == "UPDATE_ROLLBACK_COMPLETE"
        page, rows = proposer.proposal_pages(
            call, lambda *_: None, stack, change, token, 0
        )
        assert (
            page["Status"] == "CREATE_COMPLETE"
            and page["ExecutionStatus"] == "AVAILABLE"
        )
        recovery.validate_import(rows, imports)
        for cs, expected in ((None, current), (change, template)):
            args = ["--stack-name", stack, "--template-stage", "Original"]
            if cs:
                args += ["--change-set-name", cs]
            body = call("cloudformation", "get-template", *args)
            assert prior.document(body["TemplateBody"]) == expected
        resources = prior.paginated(
            call,
            "cloudformation",
            "list-stack-resources",
            ["--stack-name", stack],
            "StackResourceSummaries",
            lambda *_: None,
            "current",
        )
        prior.validate_preserved(
            partition, current, resources, json.loads(packet.enrollment_template)
        )

    def set_guard(name):
        assert helper.root_caller(transport, executable, account) == caller
        return call(
            "cloudformation",
            "set-stack-policy",
            "--stack-name",
            stack,
            "--stack-policy-body",
            "file://" + str(fresh / name),
        )

    def restore():
        observed = state()
        assert observed["StackStatus"] in TERMINAL | {"UPDATE_ROLLBACK_COMPLETE"}
        save(
            "permanent-policy-write-intent.json",
            {"stack_id": stack, "terminal_state": observed},
        )
        try:
            set_guard("permanent-stack-policy.json")
        except Exception:
            save("permanent-policy-response.json", {"uncertain": True})
        guard(permanent)
        save("permanent-policy-restored.json", {"verified": True, "policy": permanent})

    execution_token = "pr225-import11-execute-" + uuid.uuid4().hex
    save(
        "execution-identity.json",
        {
            "account": account,
            "stack_id": stack,
            "change_set_id": change,
            "client_request_token": execution_token,
            "template_sha256": digest,
            "caller": caller,
        },
    )
    prestart()
    guard(permanent)

    def execute():
        assert helper.root_caller(transport, executable, account) == caller
        return call(
            "cloudformation",
            "execute-change-set",
            "--stack-name",
            stack,
            "--change-set-name",
            change,
            "--client-request-token",
            execution_token,
        )

    def observe(index):
        observed = state()
        page, rows = proposer.proposal_pages(call, save, stack, change, token, index)
        assert page["Status"] == "CREATE_COMPLETE"
        recovery.validate_import(rows, imports)
        save(f"stack-observation-{index:03d}.json", observed)
        return observed["StackStatus"], page["ExecutionStatus"]

    result = run_import(
        install=lambda: set_guard("temporary-import-stack-policy.json"),
        verify_temporary=lambda: guard(temporary),
        prestart=prestart,
        execute=execute,
        observe=observe,
        restore=restore,
        save=save,
    )
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print(
            "Execution incomplete. Inspect private execution identity and native stack/change-set status. Never resubmit or restore a guard during an operation; permanent restoration is proven only by its readback receipt.",
            file=sys.stderr,
        )
        raise SystemExit(1) from None
