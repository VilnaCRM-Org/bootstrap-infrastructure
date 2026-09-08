#!/usr/bin/env python3
"""PROD reconcile only partial-run operations 6 and 7; no activation.
Usage: python3 -I recover-boundaries.py ROOT SOURCE PACKETS ORIGINAL_RECEIPTS NEW_RECEIPTS AWS
Original ops0..5 must remain exact. Op6 may be absent or exact after uncertainty.
Op7 must be untouched. No mutation retries within this recovery; no raw stderr logs.
"""
import hashlib
import importlib.util
import json
import os
import re
import selectors
import subprocess
import time
from pathlib import Path
import sys

ACCOUNT = "933245420672"
STACK = "arn:aws:cloudformation:eu-central-1:933245420672:stack/issue215-operator-seed-prod/2d3d1960-ab23-11f1-b7dc-02b3dc85e917"
HELPER_HASH = "262ddcb3b76a82a0306c2df5735418f4b58cf5205292a8f8e614d0cbb8e8bb18"
TEMPLATE_HASH = "d7913272c088f6c57469dfcf3ad3f3ba4b0e13111a1e8d5dc4c22895ce40eb9f"
VERSION = "tJ6HbWVZBsGpK.bPrNqW4p3YYfu8zh1Y"
ETAG = '"d59097a7d19a46e1d7dc8b8ca2aa28f9"'


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


def run_put(command):
    """One CLI attempt, bounded diagnostics; no stdout/stderr or credentials persisted."""
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    receipt = {"submission_acknowledged": False, "uncertain": True,
        "retry_forbidden": True, "exit_code": None, "aws_error_code": None}
    process = None
    try:
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, cwd=str(Path(command[0]).parent), shell=False)
        deadline = time.monotonic() + 45
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ, "stdout")
            selector.register(process.stderr, selectors.EVENT_READ, "stderr")
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError()
                for key, _ in selector.select(remaining):
                    chunk = os.read(key.fd, 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    if len(buffers[key.data]) + len(chunk) > 65536:
                        raise ValueError("Output limit")
                    buffers[key.data].extend(chunk)
            process.wait(timeout=max(0.01, deadline - time.monotonic()))
        receipt["exit_code"] = process.returncode
        receipt["submission_acknowledged"] = process.returncode == 0
        receipt["uncertain"] = process.returncode != 0
    except Exception as error:
        receipt["transport_error_type"] = type(error).__name__
    finally:
        if process is not None:
            if process.poll() is None:
                process.kill()
            process.wait()
            if process.stdout is not None:
                process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()
    match = re.search(rb"An error occurred \(([A-Za-z][A-Za-z0-9.]{0,79})\) when calling the PutRolePermissionsBoundary operation", buffers["stderr"])
    if match:
        receipt["aws_error_code"] = match.group(1).decode("ascii")
    for name, value in buffers.items():
        receipt[name + "_bytes"] = len(value)
        receipt[name + "_sha256"] = hashlib.sha256(value).hexdigest()
    return receipt


def main():
    if sys.flags.optimize:
        raise ValueError("Optimized Python forbidden")
    helper_path, source, packets_path, original_path, output, executable = sys.argv[1:]
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
    original = Path(original_path).resolve(strict=True)
    assert original.is_dir() and original != out
    caller = helper.root_caller(transport, executable, ACCOUNT)
    key = registry.SeedKeyBinding(**json.loads((packets / "seed-key-binding.json").read_text()))
    assert key.arn == f"arn:aws:kms:eu-central-1:{ACCOUNT}:key/2d42d715-1452-4766-8cfa-020b53288443"
    packet = installation.build_installation("prod", account_id=ACCOUNT, seed_key=key)
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
        command = [executable, service, operation, "--region", region,
            "--endpoint-url", endpoint, "--output", "json", "--no-paginate", "--no-cli-pager",
            "--no-cli-auto-prompt", "--cli-connect-timeout", "5", "--cli-read-timeout", "20", *args]
        if operation == "put-role-permissions-boundary":
            return run_put(command)
        return transport._response(transport._run(command, None))

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
        head = call("s3api", "head-object", "--bucket", "pulumi-bootstrap-infrastructure-prod-state",
            "--expected-bucket-owner", ACCOUNT, "--key", ".pulumi/stacks/github-ci-bootstrap/prod.json")
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
    held = ["GitHubGovernanceApply-prod", "GitHubCiApply-bootstrap-infrastructure-prod",
        "GitHubCiApply-user-service-infrastructure-prod", "PulumiAutomation-bootstrap-infrastructure-prod", "PulumiDeploy-bootstrap-infrastructure"]
    for index, name in enumerate(held):
        response = call("iam", "get-role-policy", "--role-name", name, "--policy-name", "Issue215CutoverSessions")
        assert response["RoleName"] == name and response["PolicyName"] == "Issue215CutoverSessions"
        document = response["PolicyDocument"]
        assert (document if isinstance(document, dict) else json.loads(document)) == deny
        save(f"hold-{index}.json", response)
    locks = call("s3api", "list-objects-v2", "--bucket", "pulumi-bootstrap-infrastructure-prod-state",
        "--expected-bucket-owner", ACCOUNT, "--prefix", ".pulumi/locks/")
    assert locks["IsTruncated"] is False and locks["KeyCount"] == 0 and not locks.get("Contents")
    save("locks.json", locks)
    previous = json.loads((original / "binding-intent.json").read_text())
    assert previous == {"account": ACCOUNT, "caller": caller, "operations": operations,
        "source_sha": helper.SOURCE_SHA, "checkpoint_version": VERSION, "activation_authorized": False}
    assert operations[6]["parameters"]["RoleName"] == "GitHubGovernancePreview-prod"
    assert operations[7]["parameters"]["RoleName"] == "OperationsAlertTriage-bootstrap-infrastructure-prod"
    assert not (original / "write-intent-7.json").exists()
    uncertain = json.loads((original / "write-response-6.json").read_text())
    assert uncertain == {"uncertain": True, "retry_forbidden": True}
    before = {}
    for index, op in enumerate(operations):
        prior = json.loads((original / f"role-before-{index}.json").read_text())
        role_id = role_matches(prior, op, False)
        assert isinstance(role_id, str) and role_id
        if index < 7:
            assert json.loads((original / f"write-intent-{index}.json").read_text()) == op
        if index < 6:
            completed = json.loads((original / f"role-after-{index}.json").read_text())
            assert role_matches(completed, op, True) == role_id
        response = call("iam", "get-role", "--role-name", op["parameters"]["RoleName"])
        bound = index < 6 or (index == 6 and response["Role"].get("PermissionsBoundary") is not None)
        assert role_matches(response, op, bound) == role_id
        before[op["precondition"]["RoleArn"]] = prior
        save(f"role-before-{index}.json", response)
    assert helper.root_caller(transport, executable, ACCOUNT) == caller
    save("recovery-intent.json", {"account": ACCOUNT, "caller": caller,
        "permitted_operation_indices": [6, 7], "original_receipts": str(original),
        "source_sha": helper.SOURCE_SHA, "checkpoint_version": VERSION,
        "original_failure_cause_proven": False, "activation_authorized": False})
    for index in (6, 7):
        op = operations[index]
        arn = op["precondition"]["RoleArn"]
        current = call("iam", "get-role", "--role-name", op["parameters"]["RoleName"])
        if index == 6 and current["Role"].get("PermissionsBoundary") is not None:
            assert role_matches(current, op, True) == before[arn]["Role"]["RoleId"]
            save("operation-6-already-exact.json", current)
            continue
        assert role_matches(current, op, False) == before[arn]["Role"]["RoleId"]
        save(f"write-intent-{index}.json", op)
        result = call("iam", "put-role-permissions-boundary", "--role-name", op["parameters"]["RoleName"],
            "--permissions-boundary", op["parameters"]["PermissionsBoundary"])
        save(f"write-response-{index}.json", result)
        # Bounded reads tolerate IAM propagation; never repeat the write.
        for attempt in range(5):
            response = call("iam", "get-role", "--role-name", op["parameters"]["RoleName"])
            save(f"role-after-{index}-{attempt}.json", response)
            assert response["Role"]["RoleId"] == before[arn]["Role"]["RoleId"]
            if response["Role"].get("PermissionsBoundary") is not None:
                assert role_matches(response, op, True) == before[arn]["Role"]["RoleId"]
                break
            role_matches(response, op, False)
            if attempt < 4:
                time.sleep(2)
        else:
            raise ValueError("Boundary remains absent; inspect receipt, never rerun automatically")
    after = {}
    for index, op in enumerate(operations):
        arn = op["precondition"]["RoleArn"]
        response = call("iam", "get-role", "--role-name", op["parameters"]["RoleName"])
        assert role_matches(response, op, True) == before[arn]["Role"]["RoleId"]
        after[arn] = response
        save(f"role-final-{index}.json", response)
    assert helper.root_caller(transport, executable, ACCOUNT) == caller
    guard_state("after")
    save("live-roles.json", after)
    save("bindings-verified.json", {"account": ACCOUNT, "verified": 8, "permitted_write_indices": [6, 7], "checkpoint_published": False,
        "full_enrollment_verified": False, "activation_authorized": False})
    print("Eight exact PROD boundaries reconciled/read back. Checkpoint reconciliation and disabled enrollment remain required.")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("Boundary operation incomplete. Inspect private per-role intent/readbacks before any further write; never automatically rerun a partial or uncertain operation.", file=sys.stderr)
        raise SystemExit(1) from None
