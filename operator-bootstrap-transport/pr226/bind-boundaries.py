#!/usr/bin/env python3
"""TEST eight reviewed boundary additions, once each; no retries or activation.
Usage: python3 -I bind-boundaries.py ROOT SOURCE PACKETS NEW_RECEIPTS AWS
All eight must initially be unbound. Partial runs require independent reconciliation.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys

ACCOUNT = "891377212104"
STACK = "arn:aws:cloudformation:eu-central-1:891377212104:stack/issue215-operator-seed-test/21e44890-ab23-11f1-bc2a-027c8dcc491b"
HELPER_HASH = "262ddcb3b76a82a0306c2df5735418f4b58cf5205292a8f8e614d0cbb8e8bb18"
TEMPLATE_HASH = "85b7d2544624c8f022b39a35679ec6079d3a1ae2533c8ea3c638e0b283e8b35c"
VERSION = "hdhCm7nMHn1nLS1tFKw9YwChUVjUOCVP"
ETAG = '"9490f9b2b9f19fb7d3c05f2340348101"'


def role_matches(response, operation, boundary):
    role = response["Role"]
    assert role["Arn"] == operation["precondition"]["RoleArn"]
    assert role["RoleName"] == operation["parameters"]["RoleName"]
    if boundary:
        assert role["PermissionsBoundary"] == {"PermissionsBoundaryType": "Policy",
            "PermissionsBoundaryArn": operation["parameters"]["PermissionsBoundary"]}
    else:
        assert role.get("PermissionsBoundary") is None
    return role["RoleId"]


def main():
    assert not sys.flags.optimize
    helper_path, source, packets_path, output, executable = sys.argv[1:]
    assert hashlib.sha256(Path(helper_path).read_bytes()).hexdigest() == HELPER_HASH
    spec = importlib.util.spec_from_file_location("root_observer", helper_path)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    assert helper.SOURCE_SHA == "88dfaf1f47e1afe55d282e7a2b2efa9afa2be78d"
    transport, _, installation, registry = helper.load_source(source)
    assert Path(executable).is_absolute() and Path(executable).resolve(strict=True).name == "aws"
    os.environ["AWS_MAX_ATTEMPTS"] = "1"
    os.umask(0o077)
    out = Path(output).resolve()
    out.mkdir(mode=0o700)
    packets = Path(packets_path).resolve(strict=True)
    caller = helper.root_caller(transport, executable, ACCOUNT)
    key = registry.SeedKeyBinding(**json.loads((packets / "seed-key-binding.json").read_text()))
    assert key.arn == f"arn:aws:kms:eu-central-1:{ACCOUNT}:key/64db70a2-7c25-420f-85b6-eeae0618897d"
    packet = installation.build_installation("test", account_id=ACCOUNT, seed_key=key)
    raw = (packets / "enrollment-template.json").read_bytes()
    assert raw == packet.enrollment_template.encode() and hashlib.sha256(raw).hexdigest() == TEMPLATE_HASH
    manifest = json.loads((packets / "boundary-manifest.json").read_text())
    assert manifest == json.loads(packet.boundary_manifest)
    assert manifest["account_id"] == ACCOUNT and manifest["activation_authorized"] is False
    operations = manifest["operations"]
    assert len(operations) == 8 and len({x["precondition"]["RoleArn"] for x in operations}) == 8
    for op in operations:
        assert op["operation"] == "put_role_permissions_boundary"
        assert op["precondition"]["PermissionsBoundary"] is None
    full = json.loads(raw)
    assert len(full["Resources"]) == 58

    def save(name, value):
        with (out / name).open("x") as stream:
            json.dump(value, stream, sort_keys=True)
            stream.write("\n")

    def call(service, operation, *args):
        assert (service, operation) in {
            ("cloudformation", "describe-stacks"), ("cloudformation", "get-template"),
            ("cloudformation", "get-stack-policy"), ("cloudformation", "list-stack-resources"),
            ("iam", "get-role"), ("iam", "get-role-policy"), ("iam", "put-role-permissions-boundary"),
            ("s3api", "head-object"), ("s3api", "list-objects-v2")}
        region = "us-east-1" if service == "iam" else "eu-central-1"
        endpoint = "https://iam.amazonaws.com" if service == "iam" else f"https://{'s3' if service == 's3api' else service}.eu-central-1.amazonaws.com"
        response = transport._run([executable, service, operation, "--region", region,
            "--endpoint-url", endpoint, "--output", "json", "--no-paginate", "--no-cli-pager",
            "--no-cli-auto-prompt", "--cli-connect-timeout", "5", "--cli-read-timeout", "20", *args], None)
        return {} if operation == "put-role-permissions-boundary" and not response.strip() else transport._response(response)

    def guard_state(label):
        states = call("cloudformation", "describe-stacks", "--stack-name", STACK)["Stacks"]
        assert len(states) == 1 and states[0]["StackId"] == STACK
        assert states[0]["StackStatus"] == "UPDATE_COMPLETE" and not states[0].get("RoleARN")
        body = call("cloudformation", "get-template", "--stack-name", STACK, "--template-stage", "Original")
        assert body["TemplateBody"] == full or json.loads(body["TemplateBody"]) == full
        guard = call("cloudformation", "get-stack-policy", "--stack-name", STACK)
        assert json.loads(guard["StackPolicyBody"]) == json.loads(packet.stack_policy)
        save(label + "-stack.json", states)
        save(label + "-template.json", body)
        save(label + "-guard.json", guard)
        head = call("s3api", "head-object", "--bucket", "pulumi-bootstrap-infrastructure-test-state",
            "--expected-bucket-owner", ACCOUNT, "--key", ".pulumi/stacks/github-ci-bootstrap/test.json")
        assert (head["VersionId"], head["ETag"]) == (VERSION, ETAG)
        assert head["ServerSideEncryption"] == "AES256" and not head.get("SSEKMSKeyId")
        save(label + "-checkpoint.json", head)

    guard_state("before")
    # Exact native58 logical/physical owners, bounded complete pagination.
    rows, marker, seen = [], None, set()
    for index in range(100):
        args = ["--stack-name", STACK] + (["--next-token", marker] if marker else [])
        page = call("cloudformation", "list-stack-resources", *args)
        save(f"resources-{index}.json", page)
        rows.extend(page["StackResourceSummaries"])
        marker = page.get("NextToken")
        if marker is None:
            break
        assert isinstance(marker, str) and marker and marker not in seen
        seen.add(marker)
    else:
        raise ValueError("Resource pagination bound")
    assert len(rows) == 58 and {r["LogicalResourceId"] for r in rows} == set(full["Resources"])
    for row in rows:
        definition = full["Resources"][row["LogicalResourceId"]]
        props = definition["Properties"]
        assert row["ResourceType"] == definition["Type"]
        assert row["ResourceStatus"] in {"CREATE_COMPLETE", "UPDATE_COMPLETE", "IMPORT_COMPLETE"}
        physical = (f"arn:aws:iam::{ACCOUNT}:policy" + props["Path"] + props["ManagedPolicyName"]
                    if definition["Type"] == "AWS::IAM::ManagedPolicy" else props["RoleName"])
        assert row["PhysicalResourceId"] == physical
    deny = {"Version": "2012-10-17", "Statement": [{"Sid": "HoldOrdinaryIacDuringIndependentCutover", "Effect": "Deny", "Action": "*", "Resource": "*"}]}
    held = ["GitHubGovernanceApply-test", "GitHubCiApply-bootstrap-infrastructure-test",
        "GitHubCiApply-user-service-infrastructure-test", "PulumiAutomation-bootstrap-infrastructure-test", "PulumiDeploy-bootstrap-infrastructure"]
    for index, name in enumerate(held):
        response = call("iam", "get-role-policy", "--role-name", name, "--policy-name", "Issue215CutoverSessions")
        assert response["RoleName"] == name and response["PolicyName"] == "Issue215CutoverSessions"
        document = response["PolicyDocument"]
        assert (document if isinstance(document, dict) else json.loads(document)) == deny
        save(f"hold-{index}.json", response)
    locks = call("s3api", "list-objects-v2", "--bucket", "pulumi-bootstrap-infrastructure-test-state",
        "--expected-bucket-owner", ACCOUNT, "--prefix", ".pulumi/locks/")
    assert locks["IsTruncated"] is False and locks["KeyCount"] == 0 and not locks.get("Contents")
    save("locks.json", locks)
    before = {}
    for index, op in enumerate(operations):
        response = call("iam", "get-role", "--role-name", op["parameters"]["RoleName"])
        role_matches(response, op, False)
        before[op["precondition"]["RoleArn"]] = response
        save(f"role-before-{index}.json", response)
    assert helper.root_caller(transport, executable, ACCOUNT) == caller
    save("binding-intent.json", {"account": ACCOUNT, "caller": caller, "operations": operations,
        "source_sha": helper.SOURCE_SHA, "checkpoint_version": VERSION, "activation_authorized": False})
    after = {}
    for index, op in enumerate(operations):
        arn = op["precondition"]["RoleArn"]
        current = call("iam", "get-role", "--role-name", op["parameters"]["RoleName"])
        assert role_matches(current, op, False) == before[arn]["Role"]["RoleId"]
        save(f"write-intent-{index}.json", op)
        try:
            call("iam", "put-role-permissions-boundary", "--role-name", op["parameters"]["RoleName"],
                 "--permissions-boundary", op["parameters"]["PermissionsBoundary"])
        except Exception:
            save(f"write-response-{index}.json", {"uncertain": True, "retry_forbidden": True})
            # Read back once to resolve delivery; never repeat the mutation.
        response = call("iam", "get-role", "--role-name", op["parameters"]["RoleName"])
        assert role_matches(response, op, True) == before[arn]["Role"]["RoleId"]
        after[arn] = response
        save(f"role-after-{index}.json", response)
    assert helper.root_caller(transport, executable, ACCOUNT) == caller
    guard_state("after")
    save("live-roles.json", after)
    save("bindings-verified.json", {"account": ACCOUNT, "verified": 8, "checkpoint_published": False,
        "full_enrollment_verified": False, "activation_authorized": False})
    print("Eight exact TEST boundaries installed/read back. Checkpoint reconciliation and disabled enrollment remain required.")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("Boundary operation incomplete. Inspect private per-role intent/readbacks before any further write; never automatically rerun a partial or uncertain operation.", file=sys.stderr)
        raise SystemExit(1) from None
