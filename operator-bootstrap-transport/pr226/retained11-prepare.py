#!/usr/bin/env python3
"""Read-only TEST root CloudShell recovery preparation. Never calls AWS writes.

Usage: python3 -I prepare.py ROOT_HELPER PROPOSAL_HELPER SOURCE PACKETS NEW_OUTPUT AWS
Output is public policy metadata in private files, not authenticated execution
approval. A subsequent separately reviewed native IMPORT must adopt exactly11.
"""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys

ACCOUNT = "891377212104"
STACK = "arn:aws:cloudformation:eu-central-1:891377212104:stack/issue215-operator-seed-test/21e44890-ab23-11f1-bc2a-027c8dcc491b"
ROOT_HASH = "6b87328dbff92f6f2fa440f1ebc86196d4dcb54274dab0d1421a9da1f2acc35a"
PROPOSAL_HASH = "68ea9d891a113a7cbbdaf45e9097bbdb131a1101ee488352e027163dbc59767a"


def load(path, name, expected_hash):
    assert hashlib.sha256(Path(path).read_bytes()).hexdigest() == expected_hash
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def build_import(current, full, partition):
    preserved = {x["logical_resource_id"] for x in partition["preserved"]}
    assert len(preserved) == 44 and set(current["Resources"]) == preserved
    targets = [
        x
        for x in partition["required_additions"]
        if x["resource_type"] == "AWS::IAM::ManagedPolicy"
    ]
    assert len(targets) == 11 and len(partition["required_additions"]) == 14
    result = json.loads(json.dumps(current))
    imports = []
    for logical in preserved:
        assert current["Resources"][logical] == full["Resources"][logical]
    for row in targets:
        logical = row["logical_resource_id"]
        assert logical not in result["Resources"]
        definition = full["Resources"][logical]
        assert definition["Type"] == "AWS::IAM::ManagedPolicy"
        assert (
            definition["DeletionPolicy"]
            == definition["UpdateReplacePolicy"]
            == "Retain"
        )
        result["Resources"][logical] = definition
        imports.append(
            {
                "ResourceType": "AWS::IAM::ManagedPolicy",
                "LogicalResourceId": logical,
                "ResourceIdentifier": {"PolicyArn": row["expected_physical_arn"]},
            }
        )
    assert len(result["Resources"]) == 55
    temporary = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "Update:*",
                "Principal": "*",
                "Resource": "*",
                "Condition": {
                    "StringEquals": {"ResourceType": ["AWS::IAM::ManagedPolicy"]}
                },
            },
            {
                "Effect": "Deny",
                "Action": "Update:*",
                "Principal": "*",
                "Resource": sorted(f"LogicalResourceId/{x}" for x in preserved),
            },
        ]
    }
    return result, imports, temporary


def validate_import(changes, imports):
    expected = {
        x["LogicalResourceId"]: x["ResourceIdentifier"]["PolicyArn"] for x in imports
    }
    actual = {}
    assert isinstance(changes, list) and len(changes) == 11
    for change in changes:
        assert change["Type"] == "Resource"
        row = change["ResourceChange"]
        assert (
            row["Action"] == "Import"
            and row["ResourceType"] == "AWS::IAM::ManagedPolicy"
        )
        assert row.get("Replacement") in (None, "False") and row.get(
            "PolicyAction"
        ) in (None, "Retain")
        assert row.get("ChangeSetId") is None
        logical = row["LogicalResourceId"]
        assert logical not in actual
        actual[logical] = row["PhysicalResourceId"]
    assert actual == expected


def main():
    if sys.flags.optimize:
        raise ValueError("Assertions must remain enabled")
    helper_path, proposal_path, source, packets, destination, executable = sys.argv[1:]
    helper = load(helper_path, "root_observer", ROOT_HASH)
    prior = load(proposal_path, "prior_proposal", PROPOSAL_HASH)
    transport, _, installation, registry = helper.load_source(source)
    assert Path(executable).is_absolute() and Path(executable).resolve().name == "aws"
    os.environ["AWS_MAX_ATTEMPTS"] = "1"
    os.umask(0o077)
    out = Path(destination).resolve()
    out.mkdir(mode=0o700)
    directory = Path(packets).resolve(strict=True)
    caller = helper.root_caller(transport, executable, ACCOUNT)

    def save(name, value):
        with (out / name).open("x") as stream:
            json.dump(value, stream, sort_keys=True, separators=(",", ":"))
            stream.write("\n")

    def call(service, operation, *arguments, region="eu-central-1"):
        allowed = {
            "cloudformation": {
                "describe-stacks",
                "get-template",
                "get-stack-policy",
                "list-stack-resources",
                "list-stacks",
            },
            "iam": {
                "get-policy",
                "get-policy-version",
                "list-entities-for-policy",
                "list-roles",
                "get-role-policy",
            },
            "s3api": {"head-object", "list-objects-v2"},
            "ec2": {"describe-regions"},
        }
        assert operation in allowed[service] and re.fullmatch(
            r"[a-z]{2}(?:-[a-z]+)+-\d", region
        )
        endpoint = (
            "https://iam.amazonaws.com"
            if service == "iam"
            else f"https://{'s3' if service == 's3api' else service}.{region}.amazonaws.com"
        )
        signing = "us-east-1" if service == "iam" else region
        command = [
            executable,
            service,
            operation,
            "--region",
            signing,
            "--endpoint-url",
            endpoint,
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
        **json.loads((directory / "seed-key-binding.json").read_text())
    )
    assert (
        key.arn == f"arn:aws:kms:eu-central-1:{ACCOUNT}:key/{prior.SEED_KEYS['test']}"
    )
    native_key = helper.ambient_read(
        transport, executable, "kms", "describe_key", {"KeyId": key.arn}
    )["KeyMetadata"]
    assert key == registry.SeedKeyBinding(
        *(
            native_key[k]
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
    packet = installation.build_installation("test", account_id=ACCOUNT, seed_key=key)
    assert (
        directory / "enrollment-template.json"
    ).read_bytes() == packet.enrollment_template.encode()
    full = json.loads(packet.enrollment_template)
    partition = prior.partition_for(directory, "test", ACCOUNT, full)
    state = call("cloudformation", "describe-stacks", "--stack-name", STACK)["Stacks"]
    assert (
        len(state) == 1
        and state[0]["StackId"] == STACK
        and state[0]["StackStatus"] == "UPDATE_ROLLBACK_COMPLETE"
        and not state[0].get("RoleARN")
    )
    save("stack-before.json", state)
    guard = call("cloudformation", "get-stack-policy", "--stack-name", STACK)
    assert prior.document(guard["StackPolicyBody"]) == json.loads(packet.stack_policy)
    save("permanent-policy.json", guard)
    current_response = call(
        "cloudformation",
        "get-template",
        "--stack-name",
        STACK,
        "--template-stage",
        "Original",
    )
    current = prior.document(current_response["TemplateBody"])
    save("template-before.json", current_response)
    resources = prior.paginated(
        call,
        "cloudformation",
        "list-stack-resources",
        ["--stack-name", STACK],
        "StackResourceSummaries",
        save,
        "resources-before",
    )
    prior.validate_preserved(partition, current, resources, full)
    template, imports, temporary = build_import(current, full, partition)
    wanted = {row["ResourceIdentifier"]["PolicyArn"] for row in imports}

    # Exhaust current CFN ownership in every enabled region; historical deleted
    # stacks are not current owners. Never infer no owner from a failed lookup.
    regions = call("ec2", "describe-regions")["Regions"]
    save("enabled-regions.json", regions)
    assert regions and len({x["RegionName"] for x in regions}) == len(regions)
    for index, region in enumerate(regions):
        assert region["OptInStatus"] in ("opt-in-not-required", "opted-in")
        name = region["RegionName"]

        def regional(service, operation, *args):
            return call(service, operation, *args, region=name)

        stacks = prior.paginated(
            regional,
            "cloudformation",
            "list-stacks",
            [],
            "StackSummaries",
            save,
            f"region-{index}-stacks",
        )
        for stack_index, item in enumerate(stacks):
            if item["StackStatus"] == "DELETE_COMPLETE":
                continue
            stack_id = item["StackId"]
            assert stack_id.startswith(
                f"arn:aws:cloudformation:{name}:{ACCOUNT}:stack/"
            )
            owned = prior.paginated(
                regional,
                "cloudformation",
                "list-stack-resources",
                ["--stack-name", stack_id],
                "StackResourceSummaries",
                save,
                f"region-{index}-stack-{stack_index}",
            )
            assert not wanted.intersection(x.get("PhysicalResourceId") for x in owned)

    for index, row in enumerate(imports):
        arn = row["ResourceIdentifier"]["PolicyArn"]
        definition = full["Resources"][row["LogicalResourceId"]]["Properties"]
        before = call("iam", "get-policy", "--policy-arn", arn)["Policy"]
        assert (
            before["Arn"] == arn
            and before["PolicyName"] == definition["ManagedPolicyName"]
            and before["Path"] == definition["Path"]
        )
        assert before["PermissionsBoundaryUsageCount"] == 0
        version = before["DefaultVersionId"]
        doc = call(
            "iam", "get-policy-version", "--policy-arn", arn, "--version-id", version
        )["PolicyVersion"]
        assert doc["VersionId"] == version and doc["IsDefaultVersion"] is True
        assert prior.document(doc["Document"]) == definition["PolicyDocument"]
        save(f"retained-{index}-policy.json", before)
        save(f"retained-{index}-version.json", doc)
        for usage in ("PermissionsPolicy", "PermissionsBoundary"):
            role_names, marker, seen = [], None, set()
            for page_index in range(100):
                args = ["--policy-arn", arn, "--policy-usage-filter", usage]
                if marker:
                    args += ["--marker", marker]
                page = call("iam", "list-entities-for-policy", *args)
                save(f"retained-{index}-{usage}-{page_index}.json", page)
                assert not page["PolicyUsers"] and not page["PolicyGroups"]
                role_names += [r["RoleName"] for r in page["PolicyRoles"]]
                assert type(page["IsTruncated"]) is bool
                if not page["IsTruncated"]:
                    break
                marker = page.get("Marker")
                assert isinstance(marker, str) and marker and marker not in seen
                seen.add(marker)
            else:
                raise ValueError("Entity pagination limit")
            expected_names = (
                definition.get("Roles", []) if usage == "PermissionsPolicy" else []
            )
            assert len(role_names) == len(set(role_names)) and set(role_names) == set(
                expected_names
            )
        after = call("iam", "get-policy", "--policy-arn", arn)["Policy"]
        assert after == before
    roles = prior.paginated(
        call, "iam", "list-roles", [], "Roles", save, "role-inventory"
    )
    forbidden = {
        f"GitHubOperator{purpose}-test" for purpose in ("Preview", "Apply", "Drift")
    }
    assert not {name.casefold() for name in forbidden}.intersection(
        r["RoleName"].casefold() for r in roles
    )

    held = [
        "GitHubGovernanceApply-test",
        "GitHubCiApply-bootstrap-infrastructure-test",
        "GitHubCiApply-user-service-infrastructure-test",
        "PulumiAutomation-bootstrap-infrastructure-test",
        "PulumiDeploy-bootstrap-infrastructure",
    ]
    hold_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "HoldOrdinaryIacDuringIndependentCutover",
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*",
            }
        ],
    }
    for index, name in enumerate(held):
        response = call(
            "iam",
            "get-role-policy",
            "--role-name",
            name,
            "--policy-name",
            "Issue215CutoverSessions",
        )
        assert (
            response["RoleName"] == name
            and response["PolicyName"] == "Issue215CutoverSessions"
        )
        assert prior.document(response["PolicyDocument"]) == hold_document
        save(f"writer-hold-{index}.json", response)
    bucket = "pulumi-bootstrap-infrastructure-test-state"
    head = call(
        "s3api",
        "head-object",
        "--bucket",
        bucket,
        "--expected-bucket-owner",
        ACCOUNT,
        "--key",
        ".pulumi/stacks/github-ci-bootstrap/test.json",
    )
    assert (head["VersionId"], head["ETag"]) == prior.RELEASED_STATE["test"]
    assert head["ServerSideEncryption"] == "AES256" and not head.get("SSEKMSKeyId")
    save("checkpoint-head.json", head)
    locks = call(
        "s3api",
        "list-objects-v2",
        "--bucket",
        bucket,
        "--expected-bucket-owner",
        ACCOUNT,
        "--prefix",
        ".pulumi/locks/",
    )
    assert (
        locks["IsTruncated"] is False
        and locks["KeyCount"] == 0
        and not locks.get("Contents")
    )
    save("locks.json", locks)
    assert (
        prior.document(
            call(
                "cloudformation",
                "get-template",
                "--stack-name",
                STACK,
                "--template-stage",
                "Original",
            )["TemplateBody"]
        )
        == current
    )
    assert prior.document(
        call("cloudformation", "get-stack-policy", "--stack-name", STACK)[
            "StackPolicyBody"
        ]
    ) == json.loads(packet.stack_policy)
    assert helper.root_caller(transport, executable, ACCOUNT) == caller
    save("import-template.json", template)
    save("resources-to-import.json", imports)
    save("temporary-import-stack-policy.json", temporary)
    save("permanent-stack-policy.json", json.loads(packet.stack_policy))
    save(
        "prepared.json",
        {
            "account": ACCOUNT,
            "stack_id": STACK,
            "source_sha": helper.SOURCE_SHA,
            "preserved": 44,
            "imports": 11,
            "total_policies": 55,
            "roles_created": 0,
            "writes_executed": False,
            "template_sha256": hashlib.sha256(
                (out / "import-template.json").read_bytes()
            ).hexdigest(),
            "caller": caller,
        },
    )
    print("Prepared exact TEST44+11 import; no cloud writes or execution performed.")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print(
            "Recovery preparation failed. Inspect private native receipts; no AWS writes were attempted.",
            file=sys.stderr,
        )
        raise SystemExit(1) from None
