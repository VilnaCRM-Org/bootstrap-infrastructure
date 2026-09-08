#!/usr/bin/env python3
"""TEST exact three-role change set: validate, submit once, never retry.
Usage: python3 -I execute.py PROPOSER ROOT SOURCE PACKETS PROPOSAL NEW_RECEIPTS AWS
No stack-policy edits; submission receipt is not terminal enrollment success.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import uuid

ACCOUNT = "891377212104"
STACK = "arn:aws:cloudformation:eu-central-1:891377212104:stack/issue215-operator-seed-test/21e44890-ab23-11f1-bc2a-027c8dcc491b"
CHANGE = "arn:aws:cloudformation:eu-central-1:891377212104:changeSet/pr226-three-roles-1d68e2e847294d6c858b04b9884fe016/cdd89d64-9ca1-4e46-9624-b94715d840d9"
PROPOSER_HASH = "72d32655a82c45288ffb281ed593f13aa338357f5761d9e9a5cd5e22202109d1"
ROOT_HASH = "262ddcb3b76a82a0306c2df5735418f4b58cf5205292a8f8e614d0cbb8e8bb18"
TEMPLATE_HASH = "85b7d2544624c8f022b39a35679ec6079d3a1ae2533c8ea3c638e0b283e8b35c"


def load(path, name, digest):
    assert hashlib.sha256(Path(path).read_bytes()).hexdigest() == digest
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    assert not sys.flags.optimize
    proposer_path, root_path, source, packet_path, proposal_path, output, executable = sys.argv[1:]
    proposer = load(proposer_path, "proposer", PROPOSER_HASH)
    helper = load(root_path, "root_observer", ROOT_HASH)
    assert helper.SOURCE_SHA == proposer.SOURCE_SHA == "88dfaf1f47e1afe55d282e7a2b2efa9afa2be78d"
    transport, _, installation, registry = helper.load_source(source)
    assert Path(executable).is_absolute() and Path(executable).resolve(strict=True).name == "aws"
    os.environ["AWS_MAX_ATTEMPTS"] = "1"
    os.umask(0o077)
    out = Path(output).resolve()
    out.mkdir(mode=0o700)
    packets, proposal = Path(packet_path).resolve(strict=True), Path(proposal_path).resolve(strict=True)
    caller = helper.root_caller(transport, executable, ACCOUNT)

    def save(name, value):
        with (out / name).open("x") as stream:
            json.dump(value, stream, sort_keys=True)
            stream.write("\n")

    def call(service, operation, *args):
        assert (service, operation) in {
            ("cloudformation", "describe-stacks"), ("cloudformation", "get-template"),
            ("cloudformation", "list-stack-resources"), ("cloudformation", "get-stack-policy"),
            ("cloudformation", "describe-change-set"), ("cloudformation", "execute-change-set"),
            ("iam", "list-roles"), ("iam", "get-role-policy"),
            ("s3api", "head-object"), ("s3api", "list-objects-v2")}
        region = "us-east-1" if service == "iam" else "eu-central-1"
        endpoint = "https://iam.amazonaws.com" if service == "iam" else f"https://{'s3' if service == 's3api' else service}.eu-central-1.amazonaws.com"
        raw = transport._run([executable, service, operation, "--region", region,
            "--endpoint-url", endpoint, "--output", "json", "--no-paginate", "--no-cli-pager",
            "--no-cli-auto-prompt", "--cli-connect-timeout", "5", "--cli-read-timeout", "20", *args], None)
        return {} if operation == "execute-change-set" and not raw.strip() else transport._response(raw)

    key = registry.SeedKeyBinding(**json.loads((packets / "seed-key-binding.json").read_text()))
    assert key.arn == f"arn:aws:kms:eu-central-1:{ACCOUNT}:key/{proposer.SEED_KEYS['test']}"
    packet = installation.build_installation("test", account_id=ACCOUNT, seed_key=key)
    raw = (packets / "enrollment-template.json").read_bytes()
    assert raw == packet.enrollment_template.encode() and hashlib.sha256(raw).hexdigest() == TEMPLATE_HASH
    full = json.loads(raw)
    partition = proposer.partition_for(packets, "test", ACCOUNT, full)
    recorded = json.loads((proposal / "proposal-validated.json").read_text())
    assert recorded["change_set_id"] == CHANGE and recorded["stack_id"] == STACK
    assert recorded["validated_adds"] == 3 and recorded["preserved_resources"] == 55
    assert recorded["source_sha"] == helper.SOURCE_SHA and recorded["executed"] is False
    assert recorded["partition_sha256"] == proposer.PARTITION_HASHES["test"]
    original = proposer.document(json.loads((proposal / "before-current-template.json").read_text())["TemplateBody"])

    def proposal_check():
        change = call("cloudformation", "describe-change-set", "--stack-name", STACK, "--change-set-name", CHANGE)
        assert change["StackId"] == STACK and change["ChangeSetId"] == CHANGE
        assert change["ChangeSetName"] == CHANGE.split("/")[1]
        assert change["Status"] == "CREATE_COMPLETE" and change["ExecutionStatus"] == "AVAILABLE"
        assert not any(change.get(k) for k in ("NextToken", "RoleARN", "ParentChangeSetId", "RootChangeSetId", "IncludeNestedStacks"))
        proposer.validate_additions(partition, change["Changes"])
        return change

    states = call("cloudformation", "describe-stacks", "--stack-name", STACK)["Stacks"]
    assert len(states) == 1 and states[0]["StackId"] == STACK and states[0]["StackStatus"] == "IMPORT_COMPLETE"
    assert states[0]["DriftInformation"]["StackDriftStatus"] == "IN_SYNC" and not states[0].get("RoleARN")
    save("stack-before.json", states)
    for name, target, args in (("current", original, []), ("proposed", full, ["--change-set-name", CHANGE])):
        body = call("cloudformation", "get-template", "--stack-name", STACK, "--template-stage", "Original", *args)
        assert proposer.document(body["TemplateBody"]) == target
        save(name + "-template.json", body)
    rows = proposer.paginated(call, "cloudformation", "list-stack-resources", ["--stack-name", STACK], "StackResourceSummaries", save, "resources")
    proposer.validate_preserved(partition, original, rows, full)
    proposer.validate_provenance(original, full)
    guard = call("cloudformation", "get-stack-policy", "--stack-name", STACK)
    assert proposer.document(guard["StackPolicyBody"]) == json.loads(packet.stack_policy)
    save("permanent-guard.json", guard)
    save("proposal-before.json", proposal_check())
    roles = proposer.paginated(call, "iam", "list-roles", [], "Roles", save, "roles")
    names = {r["RoleName"].casefold() for r in roles}
    assert len(names) == len(roles)
    for row in partition["required_additions"]:
        assert row["expected_physical_arn"].rsplit("/", 1)[-1].casefold() not in names
    held = ["GitHubGovernanceApply-test", "GitHubCiApply-bootstrap-infrastructure-test",
        "GitHubCiApply-user-service-infrastructure-test", "PulumiAutomation-bootstrap-infrastructure-test", "PulumiDeploy-bootstrap-infrastructure"]
    deny = {"Version": "2012-10-17", "Statement": [{"Sid": "HoldOrdinaryIacDuringIndependentCutover", "Effect": "Deny", "Action": "*", "Resource": "*"}]}
    for index, name in enumerate(held):
        response = call("iam", "get-role-policy", "--role-name", name, "--policy-name", "Issue215CutoverSessions")
        assert response["RoleName"] == name and response["PolicyName"] == "Issue215CutoverSessions"
        assert proposer.document(response["PolicyDocument"]) == deny
        save(f"hold-{index}.json", response)
    bucket = "pulumi-bootstrap-infrastructure-test-state"
    head = call("s3api", "head-object", "--bucket", bucket, "--expected-bucket-owner", ACCOUNT, "--key", ".pulumi/stacks/github-ci-bootstrap/test.json")
    assert (head["VersionId"], head["ETag"]) == proposer.RELEASED_STATE["test"]
    assert head["ServerSideEncryption"] == "AES256" and not head.get("SSEKMSKeyId")
    save("checkpoint-head.json", head)
    locks = call("s3api", "list-objects-v2", "--bucket", bucket, "--expected-bucket-owner", ACCOUNT, "--prefix", ".pulumi/locks/")
    assert locks["IsTruncated"] is False and locks["KeyCount"] == 0 and not locks.get("Contents")
    save("locks.json", locks)
    assert helper.root_caller(transport, executable, ACCOUNT) == caller
    save("proposal-final.json", proposal_check())
    assert proposer.document(call("cloudformation", "get-stack-policy", "--stack-name", STACK)["StackPolicyBody"]) == json.loads(packet.stack_policy)
    token = "pr226-three-role-execute-" + uuid.uuid4().hex
    save("execution-intent.json", {"stack_id": STACK, "change_set_id": CHANGE,
        "client_request_token": token, "template_sha256": TEMPLATE_HASH, "caller": caller,
        "terminal_success_verified": False})
    try:
        call("cloudformation", "execute-change-set", "--stack-name", STACK,
             "--change-set-name", CHANGE, "--client-request-token", token)
    except Exception:
        save("execution-response.json", {"submission_uncertain": True, "resubmit_forbidden": True})
        raise
    save("execution-response.json", {"submission_acknowledged": True, "terminal_success_verified": False})
    print("Exact three-role execution submitted once. Observe native terminal status; do not resubmit.")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("Three-role execution incomplete. Inspect private intent and native exact change-set/stack status; never rerun an uncertain execution. No stack-policy update attempted.", file=sys.stderr)
        raise SystemExit(1) from None
