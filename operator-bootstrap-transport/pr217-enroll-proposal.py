#!/usr/bin/env python3
"""Reviewed CloudShell-only proposal: one template upload and one CFN change set.

No execution, IAM changes, stack-policy updates or mutation retries. Run only
after six imports, native IN_SYNC drift and permanent deny-update guard.
Usage: python3 -I pr217-enroll-proposal.py ENV HELPER SOURCE PACKETS RECEIPTS AWS
RECEIPTS must be a new private directory. Never rerun to recover an uncertain
write; inspect its recorded object key/change-set name and actual AWS state.
"""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import time
from urllib.parse import quote
import uuid


def main():
    environment, helper_path, source, packets, receipts, executable = sys.argv[1:]
    accounts = {"test": "891377212104", "prod": "933245420672"}
    stacks = {"test": "21e44890-ab23-11f1-bc2a-027c8dcc491b", "prod": "2d3d1960-ab23-11f1-b7dc-02b3dc85e917"}
    account = accounts[environment]
    assert Path(executable).is_absolute() and Path(executable).resolve().name == "aws"
    assert hashlib.sha256(Path(helper_path).read_bytes()).hexdigest() == "764e6a919ec48a62417948a93c2716610ab2ede96df260cf3f9ca1d634756723"
    spec = importlib.util.spec_from_file_location("reviewed_bootstrap", helper_path)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    transport, _, installation, registry = helper.load_source(source)
    os.environ["AWS_MAX_ATTEMPTS"] = "1"  # No implicit mutation retry; credentials stay native.
    helper.root_caller(transport, executable, account)
    directory, receipt = Path(packets).resolve(strict=True), Path(receipts)
    os.umask(0o077)
    receipt.mkdir(mode=0o700)
    key = registry.SeedKeyBinding(**json.loads((directory / "seed-key-binding.json").read_text()))
    observed = helper.ambient_read(transport, executable, "kms", "describe_key", {"KeyId": key.arn})["KeyMetadata"]
    assert key == registry.SeedKeyBinding(*(observed[k] for k in ("Arn", "KeyId", "AWSAccountId", "KeyManager", "KeyState", "KeyUsage")))
    packet = installation.build_installation(environment, account_id=account, seed_key=key)
    template = directory / "enrollment-template.json"
    assert template.read_bytes() == packet.enrollment_template.encode()
    assert (directory / "stack-policy.json").read_text() == packet.stack_policy
    stack = f"arn:aws:cloudformation:eu-central-1:{account}:stack/issue215-operator-seed-{environment}/{stacks[environment]}"
    bucket = f"issue215-independent-seed-{account}-{environment}"
    token = "pr217-enroll-" + uuid.uuid4().hex
    object_key = f"pr217/{environment}/{token}.json"

    def save(name, value):
        with (receipt / name).open("x") as stream:
            json.dump(value, stream, sort_keys=True)
            stream.write("\n")

    def call(service, operation, *arguments):
        endpoint = f"https://{'s3' if service == 's3api' else service}.eu-central-1.amazonaws.com"
        command = [executable, service, operation, "--region", "eu-central-1", "--endpoint-url", endpoint,
                   "--output", "json", "--no-cli-pager", "--no-cli-auto-prompt", "--cli-connect-timeout", "5", "--cli-read-timeout", "20", *arguments]
        return transport._response(transport._run(command, None))

    state = call("cloudformation", "describe-stacks", "--stack-name", stack)["Stacks"]
    assert len(state) == 1 and state[0]["StackId"] == stack and state[0]["StackStatus"] == "IMPORT_COMPLETE"
    assert state[0]["DriftInformation"]["StackDriftStatus"] == "IN_SYNC" and not state[0].get("RoleARN")
    policy = call("cloudformation", "get-stack-policy", "--stack-name", stack)
    assert json.loads(policy["StackPolicyBody"]) == json.loads(packet.stack_policy)
    save("proposal-intent.json", {"stack_id": stack, "bucket": bucket, "object_key": object_key, "change_set_name": token,
                                 "template_sha256": hashlib.sha256(template.read_bytes()).hexdigest(), "execution_authorized": False})
    uploaded = call("s3api", "put-object", "--bucket", bucket, "--expected-bucket-owner", account, "--key", object_key,
                    "--body", str(template), "--server-side-encryption", "AES256", "--if-none-match", "*")
    save("template-upload.json", uploaded)
    version = uploaded["VersionId"]
    assert isinstance(version, str) and version and version != "null"
    downloaded = receipt / "enrollment-template-readback.json"
    metadata = call("s3api", "get-object", "--bucket", bucket, "--expected-bucket-owner", account,
                    "--key", object_key, "--version-id", version, str(downloaded))
    save("template-readback-metadata.json", metadata)
    assert metadata["VersionId"] == version and metadata["ServerSideEncryption"] == "AES256"
    assert downloaded.read_bytes() == template.read_bytes()
    url = f"https://{bucket}.s3.eu-central-1.amazonaws.com/{object_key}?versionId={quote(version, safe='')}"
    created = call("cloudformation", "create-change-set", "--stack-name", stack, "--change-set-name", token,
                   "--change-set-type", "UPDATE", "--template-url", url, "--capabilities", "CAPABILITY_NAMED_IAM", "--client-token", token)
    save("change-set-created.json", created)
    assert created["StackId"] == stack
    change = created["Id"]
    for attempt in range(40):
        proposal = call("cloudformation", "describe-change-set", "--stack-name", stack, "--change-set-name", change)
        save(f"change-set-observation-{attempt:02d}.json", proposal)
        assert proposal["StackId"] == stack and proposal["ChangeSetId"] == change and not proposal.get("NextToken")
        if proposal["Status"] not in ("CREATE_PENDING", "CREATE_IN_PROGRESS"):
            break
        time.sleep(3)
    assert proposal["Status"] == "CREATE_COMPLETE" and proposal["ExecutionStatus"] == "AVAILABLE" and not proposal.get("RoleARN")
    installation.validate_change_set(packet, phase="enroll", changes=proposal["Changes"])
    proposed_template = call("cloudformation", "get-template", "--stack-name", stack, "--change-set-name", change, "--template-stage", "Original")
    save("proposed-template.json", proposed_template)
    body = proposed_template["TemplateBody"]
    assert (json.loads(body) if isinstance(body, str) else body) == json.loads(packet.enrollment_template)
    assert json.loads(call("cloudformation", "get-stack-policy", "--stack-name", stack)["StackPolicyBody"]) == json.loads(packet.stack_policy)
    helper.root_caller(transport, executable, account)
    result = {"change_set_id": change, "stack_id": stack, "template_url": url, "validated_adds": len(proposal["Changes"]), "executed": False}
    save("proposal-validated.json", result)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("Enrollment proposal incomplete; inspect private receipts and actual AWS state before any retry. No execution was attempted.", file=sys.stderr)
        raise SystemExit(1) from None
