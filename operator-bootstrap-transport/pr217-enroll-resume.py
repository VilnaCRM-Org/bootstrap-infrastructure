#!/usr/bin/env python3
"""Resume only the recorded PROD enrollment upload; never upload again.

Usage: python3 -I pr217-enroll-resume.py prod HELPER SOURCE PACKETS RECEIPTS AWS
RECEIPTS is the existing failed attempt directory with only its intent/upload
receipts. Parent confirmed the prior attempt failed before CFN proposal creation.
Native reads recheck all prerequisites and exact uploaded VersionId/bytes; one
CFN proposal creation is permitted, with no retries and no execution.
"""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import time
from urllib.parse import quote


def main():
    environment, helper_path, source, packets, receipts, executable = sys.argv[1:]
    accounts = {"test": "891377212104", "prod": "933245420672"}
    stacks = {"test": "21e44890-ab23-11f1-bc2a-027c8dcc491b", "prod": "2d3d1960-ab23-11f1-b7dc-02b3dc85e917"}
    assert environment == "prod"
    account = accounts[environment]
    assert Path(executable).is_absolute() and Path(executable).resolve().name == "aws"
    assert hashlib.sha256(Path(helper_path).read_bytes()).hexdigest() == "764e6a919ec48a62417948a93c2716610ab2ede96df260cf3f9ca1d634756723"
    spec = importlib.util.spec_from_file_location("reviewed_bootstrap", helper_path)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    transport, _, installation, registry = helper.load_source(source)
    os.environ["AWS_MAX_ATTEMPTS"] = "1"  # No implicit mutation retry; credentials stay native.
    helper.root_caller(transport, executable, account)
    directory, receipt = Path(packets).resolve(strict=True), Path(receipts).resolve()
    os.umask(0o077)
    assert receipt.is_dir()
    assert {x.name for x in receipt.iterdir()} == {"proposal-intent.json", "template-upload.json"}
    key = registry.SeedKeyBinding(**json.loads((directory / "seed-key-binding.json").read_text()))
    observed = helper.ambient_read(transport, executable, "kms", "describe_key", {"KeyId": key.arn})["KeyMetadata"]
    assert key == registry.SeedKeyBinding(*(observed[k] for k in ("Arn", "KeyId", "AWSAccountId", "KeyManager", "KeyState", "KeyUsage")))
    packet = installation.build_installation(environment, account_id=account, seed_key=key)
    template = directory / "enrollment-template.json"
    assert template.read_bytes() == packet.enrollment_template.encode()
    assert (directory / "stack-policy.json").read_text() == packet.stack_policy
    stack = f"arn:aws:cloudformation:eu-central-1:{account}:stack/issue215-operator-seed-{environment}/{stacks[environment]}"
    bucket = f"issue215-independent-seed-{account}-{environment}"
    intent = json.loads((receipt / "proposal-intent.json").read_text())
    uploaded = json.loads((receipt / "template-upload.json").read_text())
    token = "pr217-enroll-3632aa81b7d144438e8e9dd368377c3d"
    object_key = "pr217/prod/pr217-enroll-3632aa81b7d144438e8e9dd368377c3d.json"
    template_hash = "973d10beab21ff48a0440d4bfe39c8e6b0e6f43f235577cc514c3e324b01f88b"
    assert intent == {"stack_id": stack, "bucket": bucket, "object_key": object_key, "change_set_name": token,
                      "template_sha256": template_hash, "execution_authorized": False}
    assert hashlib.sha256(template.read_bytes()).hexdigest() == template_hash
    assert uploaded["VersionId"] == "G49zkd7mAIEIo.kO9dhgxWz8BYHYyriR"

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
    version = uploaded["VersionId"]
    assert isinstance(version, str) and version and version != "null"
    downloaded = receipt / "enrollment-template-readback.json"
    metadata = call("s3api", "get-object", "--bucket", bucket, "--expected-bucket-owner", account,
                    "--key", object_key, "--version-id", version, str(downloaded))
    save("template-readback-metadata.json", metadata)
    assert metadata["VersionId"] == version and metadata["ServerSideEncryption"] == "AES256"
    assert downloaded.read_bytes() == template.read_bytes()
    url = f"https://{bucket}.s3.eu-central-1.amazonaws.com/{object_key}?versionId={quote(version, safe='')}"
    existing = call("cloudformation", "list-change-sets", "--stack-name", stack)
    assert not existing.get("NextToken")
    assert all(x["ChangeSetName"] != token for x in existing["Summaries"])
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
        print("Enrollment resume incomplete; inspect private receipts and actual AWS state. Do not rerun. No upload or execution was attempted.", file=sys.stderr)
        raise SystemExit(1) from None
