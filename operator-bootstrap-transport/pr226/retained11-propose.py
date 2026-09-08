#!/usr/bin/env python3
"""One TEST retained-policy IMPORT proposal; never execute or change stack policy.

Usage: python3 -I propose.py RECOVERY ROOT_HELPER PRIOR_PROPOSAL SOURCE PACKETS
       PREPARED NEW_RECEIPTS AWS
Use only the freshly reviewed native preparation while all writer/workflow holds
remain. One conditional upload and one create, without mutation retries. On any
failure inspect recorded intent and native state; never blindly rerun.
"""

import hashlib
import importlib.util
import json
import os
import sys
import time
import uuid
from pathlib import Path
from urllib.parse import quote

RECOVERY_HASH = "f6d514f93b7f8ccbe116e257cd78251ca444daa9f357e26e27c288955035600d"
BUCKET = "issue215-independent-seed-891377212104-test"


def checked_preparation(prepared, packet, partition, prior, recovery, caller):
    current = prior.document(
        json.loads((prepared / "template-before.json").read_text())["TemplateBody"]
    )
    full = json.loads(packet.enrollment_template)
    template, imports, temporary = recovery.build_import(current, full, partition)
    for name, value in (
        ("import-template.json", template),
        ("resources-to-import.json", imports),
        ("temporary-import-stack-policy.json", temporary),
        ("permanent-stack-policy.json", json.loads(packet.stack_policy)),
    ):
        assert json.loads((prepared / name).read_text()) == value
    receipt = json.loads((prepared / "prepared.json").read_text())
    assert receipt == {
        "account": recovery.ACCOUNT,
        "stack_id": recovery.STACK,
        "source_sha": "c252f6c8c6edcea68f7fc99c147f28bfec93a013",
        "preserved": 44,
        "imports": 11,
        "total_policies": 55,
        "roles_created": 0,
        "writes_executed": False,
        "template_sha256": hashlib.sha256(
            (prepared / "import-template.json").read_bytes()
        ).hexdigest(),
        "caller": caller,
    }
    return current, template, imports


def proposal_pages(call, save, stack, change, token, observation):
    rows, next_token, seen = [], None, set()
    first = None
    for index in range(100):
        args = ["--stack-name", stack, "--change-set-name", change]
        if next_token:
            args += ["--next-token", next_token]
        page = call("cloudformation", "describe-change-set", *args)
        save(f"proposal-{observation:02d}-{index:02d}.json", page)
        assert page["StackId"] == stack and page["ChangeSetId"] == change
        assert page["ChangeSetName"] == token
        assert not page.get("RoleARN") and not page.get("ParentChangeSetId")
        assert not page.get("RootChangeSetId") and not page.get("IncludeNestedStacks")
        if first is None:
            first = page
        assert (page["Status"], page["ExecutionStatus"]) == (
            first["Status"],
            first["ExecutionStatus"],
        )
        changes = page.get("Changes", [])
        assert isinstance(changes, list) and len(changes) <= 1000
        rows.extend(changes)
        next_token = page.get("NextToken")
        if next_token is None:
            return first, rows
        assert isinstance(next_token, str) and next_token and next_token not in seen
        seen.add(next_token)
    raise ValueError("Proposal pagination bound exceeded")


def main():
    if sys.flags.optimize:
        raise ValueError("Assertions must remain enabled")
    (
        recovery_path,
        root_path,
        prior_path,
        source,
        packets_path,
        prepared_path,
        output,
        executable,
    ) = sys.argv[1:]
    assert hashlib.sha256(Path(recovery_path).read_bytes()).hexdigest() == RECOVERY_HASH
    spec = importlib.util.spec_from_file_location("retained_recovery", recovery_path)
    recovery = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(recovery)
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
    prepared = Path(prepared_path).resolve(strict=True)
    packets = Path(packets_path).resolve(strict=True)
    account, stack = recovery.ACCOUNT, recovery.STACK
    caller = helper.root_caller(transport, executable, account)

    def save(name, value):
        with (out / name).open("x") as stream:
            json.dump(value, stream, sort_keys=True, separators=(",", ":"))
            stream.write("\n")

    def call(service, operation, *arguments):
        allowed = {
            "s3api": {"put-object", "get-object"},
            "cloudformation": {
                "describe-stacks",
                "get-template",
                "get-stack-policy",
                "list-stack-resources",
                "create-change-set",
                "describe-change-set",
            },
        }
        assert operation in allowed[service]
        endpoint = "s3" if service == "s3api" else service
        command = [
            executable,
            service,
            operation,
            "--region",
            "eu-central-1",
            "--endpoint-url",
            f"https://{endpoint}.eu-central-1.amazonaws.com",
            "--output",
            "json",
            "--no-paginate",
            "--no-cli-pager",
            "--no-cli-auto-prompt",
            "--cli-connect-timeout",
            "5",
            "--cli-read-timeout",
            "20",
            *arguments,
        ]
        return transport._response(transport._run(command, None))

    key = registry.SeedKeyBinding(
        **json.loads((packets / "seed-key-binding.json").read_text())
    )
    assert (
        key.arn == f"arn:aws:kms:eu-central-1:{account}:key/{prior.SEED_KEYS['test']}"
    )
    observed = helper.ambient_read(
        transport, executable, "kms", "describe_key", {"KeyId": key.arn}
    )["KeyMetadata"]
    assert key == registry.SeedKeyBinding(
        *(
            observed[k]
            for k in (
                "Arn",
                "KeyId",
                "AWSAccountId",
                "KeyManager",
                "KeyState",
                "KeyUsage",
            )
        )
    )
    packet = installation.build_installation("test", account_id=account, seed_key=key)
    assert (
        packets / "enrollment-template.json"
    ).read_bytes() == packet.enrollment_template.encode()
    full = json.loads(packet.enrollment_template)
    partition = prior.partition_for(packets, "test", account, full)
    current, template, imports = checked_preparation(
        prepared, packet, partition, prior, recovery, caller
    )
    # Freeze locally validated bytes for upload and the native import argument.
    template_path = out / "import-template.json"
    template_path.write_bytes((prepared / "import-template.json").read_bytes())
    assert json.loads(template_path.read_bytes()) == template
    save("resources-to-import.json", imports)

    def preconditions(label):
        states = call("cloudformation", "describe-stacks", "--stack-name", stack)[
            "Stacks"
        ]
        assert len(states) == 1 and states[0]["StackId"] == stack
        assert states[0]["StackStatus"] == "UPDATE_ROLLBACK_COMPLETE" and not states[
            0
        ].get("RoleARN")
        save(f"stack-{label}.json", states)
        body = call(
            "cloudformation",
            "get-template",
            "--stack-name",
            stack,
            "--template-stage",
            "Original",
        )
        assert prior.document(body["TemplateBody"]) == current
        save(f"template-{label}.json", body)
        guard = call("cloudformation", "get-stack-policy", "--stack-name", stack)
        assert prior.document(guard["StackPolicyBody"]) == json.loads(
            packet.stack_policy
        )
        save(f"guard-{label}.json", guard)
        resources = prior.paginated(
            call,
            "cloudformation",
            "list-stack-resources",
            ["--stack-name", stack],
            "StackResourceSummaries",
            save,
            f"resources-{label}",
        )
        prior.validate_preserved(partition, current, resources, full)
        assert helper.root_caller(transport, executable, account) == caller

    preconditions("before")
    token = "pr225-retained11-" + uuid.uuid4().hex
    object_key = f"pr225/test/{token}.json"
    save(
        "proposal-intent.json",
        {
            "account": account,
            "stack_id": stack,
            "bucket": BUCKET,
            "object_key": object_key,
            "change_set_name": token,
            "client_token": token,
            "change_set_type": "IMPORT",
            "template_sha256": hashlib.sha256(template_path.read_bytes()).hexdigest(),
            "resources_to_import": imports,
            "source_sha": helper.SOURCE_SHA,
            "recovery_sha256": RECOVERY_HASH,
            "executed": False,
        },
    )
    uploaded = call(
        "s3api",
        "put-object",
        "--bucket",
        BUCKET,
        "--expected-bucket-owner",
        account,
        "--key",
        object_key,
        "--body",
        str(template_path),
        "--server-side-encryption",
        "AES256",
        "--if-none-match",
        "*",
    )
    save("template-upload.json", uploaded)
    version = uploaded["VersionId"]
    assert isinstance(version, str) and version and version != "null"
    downloaded = out / "template-readback.json"
    metadata = call(
        "s3api",
        "get-object",
        "--bucket",
        BUCKET,
        "--expected-bucket-owner",
        account,
        "--key",
        object_key,
        "--version-id",
        version,
        str(downloaded),
    )
    save("template-readback-metadata.json", metadata)
    assert (
        metadata["VersionId"] == version
        and metadata["ServerSideEncryption"] == "AES256"
    )
    assert downloaded.read_bytes() == template_path.read_bytes()
    url = (
        f"https://{BUCKET}.s3.eu-central-1.amazonaws.com/{object_key}"
        f"?versionId={quote(version, safe='')}"
    )
    created = call(
        "cloudformation",
        "create-change-set",
        "--stack-name",
        stack,
        "--change-set-name",
        token,
        "--change-set-type",
        "IMPORT",
        "--template-url",
        url,
        "--resources-to-import",
        f"file://{out / 'resources-to-import.json'}",
        "--capabilities",
        "CAPABILITY_NAMED_IAM",
        "--client-token",
        token,
        "--no-include-nested-stacks",
    )
    save("change-set-created.json", created)
    assert created["StackId"] == stack
    change = created["Id"]
    assert isinstance(change, str) and change.startswith(
        f"arn:aws:cloudformation:eu-central-1:{account}:changeSet/{token}/"
    )
    for attempt in range(40):
        proposal, changes = proposal_pages(call, save, stack, change, token, attempt)
        if proposal["Status"] not in ("CREATE_PENDING", "CREATE_IN_PROGRESS"):
            break
        time.sleep(3)
    assert (
        proposal["Status"] == "CREATE_COMPLETE"
        and proposal["ExecutionStatus"] == "AVAILABLE"
    )
    recovery.validate_import(changes, imports)
    body = call(
        "cloudformation",
        "get-template",
        "--stack-name",
        stack,
        "--change-set-name",
        change,
        "--template-stage",
        "Original",
    )
    assert prior.document(body["TemplateBody"]) == template
    save("proposed-template.json", body)
    preconditions("after")
    result = {
        "stack_id": stack,
        "change_set_id": change,
        "template_url": url,
        "template_sha256": hashlib.sha256(template_path.read_bytes()).hexdigest(),
        "validated_imports": 11,
        "preserved_resources": 44,
        "source_sha": helper.SOURCE_SHA,
        "executed": False,
        "stack_policy_changed": False,
    }
    save("proposal-validated.json", result)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print(
            "IMPORT proposal incomplete. Inspect private intent/receipts and native "
            "state before retry. No execution or stack-policy update was attempted.",
            file=sys.stderr,
        )
        raise SystemExit(1) from None
