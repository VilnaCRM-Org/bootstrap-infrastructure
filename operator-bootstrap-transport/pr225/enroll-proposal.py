#!/usr/bin/env python3
"""Reviewed CloudShell-only proposal: one template upload and one CFN change set.

No execution, IAM changes, stack-policy updates or mutation retries. Run only
after exact TEST44/PROD6 imports, native IN_SYNC drift and permanent guard.
PACKETS must contain the independently pinned expected-proposal-partition.json
and native flat seed-key-binding.json. This validates a proposal, not execution.
Usage: python3 -I pr225-enroll-proposal.py ENV HELPER SOURCE PACKETS RECEIPTS AWS
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
from urllib.parse import quote, unquote
import uuid


PARTITION_HASHES = {
    "test": "f460c234c0d75cc6c96c4bd5e716c13db3b6e7fb5ffb02a76c9df57c82640135",
    "prod": "989f08425a2bc779ef8a22eddf238477d0541baab078f7ca66dc9c6f46ae443d",
}
RELEASED_STATE = {
    "test": ("hdhCm7nMHn1nLS1tFKw9YwChUVjUOCVP", '"9490f9b2b9f19fb7d3c05f2340348101"'),
    "prod": ("tJ6HbWVZBsGpK.bPrNqW4p3YYfu8zh1Y", '"d59097a7d19a46e1d7dc8b8ca2aa28f9"'),
}
SEED_KEYS = {
    "test": "64db70a2-7c25-420f-85b6-eeae0618897d",
    "prod": "2d42d715-1452-4766-8cfa-020b53288443",
}


def canonical_hash(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def document(value):
    if isinstance(value, dict):
        return value
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return json.loads(unquote(value))


def partition_for(directory, environment, account, full):
    raw = (directory / "expected-proposal-partition.json").read_bytes()
    assert hashlib.sha256(raw).hexdigest() == PARTITION_HASHES[environment]
    partition = json.loads(raw)
    assert partition["account_id"] == account
    assert partition["source_sha"] == "c252f6c8c6edcea68f7fc99c147f28bfec93a013"
    counts = (44, 14) if environment == "test" else (6, 52)
    assert (partition["preserved_count"], partition["remaining_add_count"]) == counts
    preserved, additions = partition["preserved"], partition["required_additions"]
    assert (len(preserved), len(additions)) == counts
    rows = preserved + additions
    assert len({x["logical_resource_id"] for x in rows}) == 58
    assert {x["logical_resource_id"] for x in rows} == set(full["Resources"])
    for row in rows:
        definition = full["Resources"][row["logical_resource_id"]]
        assert canonical_hash(definition) == row["definition_sha256"]
        assert definition["Type"] == row["resource_type"]
        assert (
            definition["DeletionPolicy"]
            == definition["UpdateReplacePolicy"]
            == "Retain"
        )
        kind = "policy" if definition["Type"] == "AWS::IAM::ManagedPolicy" else "role"
        assert definition["Type"] in ("AWS::IAM::ManagedPolicy", "AWS::IAM::Role")
        properties = definition["Properties"]
        name = properties["ManagedPolicyName" if kind == "policy" else "RoleName"]
        arn = f"arn:aws:iam::{account}:{kind}{properties['Path']}{name}"
        assert arn == row.get("physical_arn", row.get("expected_physical_arn"))
    return partition


def validate_preserved(partition, current, resources, full):
    expected = {x["logical_resource_id"]: x for x in partition["preserved"]}
    assert set(current["Resources"]) == set(expected)
    assert len(resources) == len(expected)
    actual = {}
    for resource in resources:
        logical = resource["LogicalResourceId"]
        assert logical not in actual and logical in expected
        target = expected[logical]
        assert (
            resource["ResourceType"]
            == target["resource_type"]
            == "AWS::IAM::ManagedPolicy"
        )
        assert resource["PhysicalResourceId"] == target["physical_arn"]
        assert resource["ResourceStatus"] in (
            "IMPORT_COMPLETE",
            "CREATE_COMPLETE",
            "UPDATE_COMPLETE",
        )
        actual[logical] = resource
        assert current["Resources"][logical] == full["Resources"][logical]
        assert (
            canonical_hash(current["Resources"][logical]) == target["definition_sha256"]
        )
    assert set(actual) == set(expected)


def validate_additions(partition, changes):
    assert isinstance(changes, list)
    expected = {
        x["logical_resource_id"]: x["resource_type"]
        for x in partition["required_additions"]
    }
    actual = {}
    for change in changes:
        assert change["Type"] == "Resource"
        resource = change["ResourceChange"]
        assert resource["Action"] == "Add"
        assert resource.get("Replacement") in (None, "False")
        assert resource.get("PolicyAction") in (None, "Retain")
        assert (
            resource.get("ChangeSetId") is None
            and resource.get("PhysicalResourceId") is None
        )
        logical = resource["LogicalResourceId"]
        assert logical not in actual
        actual[logical] = resource["ResourceType"]
    assert actual == expected


def paginated(call, service, operation, arguments, item_key, save, label):
    rows, token, seen = [], None, set()
    for index in range(100):
        args = list(arguments)
        if token:
            args += ["--marker" if service == "iam" else "--next-token", token]
        page = call(service, operation, *args)
        save(f"{label}-{index:02d}.json", page)
        items = page[item_key]
        assert isinstance(items, list) and len(items) <= 1000
        rows.extend(items)
        if service == "iam":
            assert type(page.get("IsTruncated")) is bool
            more, next_token = page["IsTruncated"], page.get("Marker")
        else:
            next_token = page.get("NextToken")
            more = next_token is not None
        if not more:
            assert not next_token
            return rows
        assert isinstance(next_token, str) and next_token and next_token not in seen
        seen.add(next_token)
        token = next_token
    raise ValueError("Pagination bound exceeded")


def validate_names(partition, policies, roles):
    policy_names, role_names = {}, set()
    account = partition["account_id"]
    for row in policies:
        name = row["PolicyName"]
        assert isinstance(name, str) and name
        folded = name.casefold()
        assert folded not in policy_names
        assert row["Arn"] == f"arn:aws:iam::{account}:policy{row['Path']}{name}"
        policy_names[folded] = row["Arn"]
    for row in roles:
        name = row["RoleName"]
        assert isinstance(name, str) and name and name.casefold() not in role_names
        assert row["Arn"] == f"arn:aws:iam::{account}:role{row['Path']}{name}"
        role_names.add(name.casefold())
    for row in partition["preserved"]:
        arn = row["physical_arn"]
        assert policy_names.get(arn.rsplit("/", 1)[1].casefold()) == arn
    for row in partition["required_additions"]:
        arn = row["expected_physical_arn"]
        names = (
            policy_names
            if row["resource_type"] == "AWS::IAM::ManagedPolicy"
            else role_names
        )
        assert arn.rsplit("/", 1)[1].casefold() not in names


def main():
    if sys.flags.optimize:
        raise ValueError("Assertions must remain enabled")
    environment, helper_path, source, packets, receipts, executable = sys.argv[1:]
    accounts = {"test": "891377212104", "prod": "933245420672"}
    stacks = {
        "test": "21e44890-ab23-11f1-bc2a-027c8dcc491b",
        "prod": "2d3d1960-ab23-11f1-b7dc-02b3dc85e917",
    }
    account = accounts[environment]
    assert Path(executable).is_absolute() and Path(executable).resolve().name == "aws"
    assert (
        hashlib.sha256(Path(helper_path).read_bytes()).hexdigest()
        == "6b87328dbff92f6f2fa440f1ebc86196d4dcb54274dab0d1421a9da1f2acc35a"
    )
    spec = importlib.util.spec_from_file_location("reviewed_bootstrap", helper_path)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    transport, _, installation, registry = helper.load_source(source)
    os.environ["AWS_MAX_ATTEMPTS"] = (
        "1"  # No implicit mutation retry; credentials stay native.
    )
    helper.root_caller(transport, executable, account)
    directory, receipt = Path(packets).resolve(strict=True), Path(receipts).resolve()
    os.umask(0o077)
    receipt.mkdir(mode=0o700)
    key = registry.SeedKeyBinding(
        **json.loads((directory / "seed-key-binding.json").read_text())
    )
    assert key.arn == f"arn:aws:kms:eu-central-1:{account}:key/{SEED_KEYS[environment]}"
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
    packet = installation.build_installation(
        environment, account_id=account, seed_key=key
    )
    template = directory / "enrollment-template.json"
    assert template.read_bytes() == packet.enrollment_template.encode()
    assert (directory / "stack-policy.json").read_text() == packet.stack_policy
    full = json.loads(packet.enrollment_template)
    partition = partition_for(directory, environment, account, full)
    stack = f"arn:aws:cloudformation:eu-central-1:{account}:stack/issue215-operator-seed-{environment}/{stacks[environment]}"
    bucket = f"issue215-independent-seed-{account}-{environment}"
    token = "pr225-enroll-" + uuid.uuid4().hex
    object_key = f"pr225/{environment}/{token}.json"

    def save(name, value):
        with (receipt / name).open("x") as stream:
            json.dump(value, stream, sort_keys=True)
            stream.write("\n")

    def call(service, operation, *arguments):
        endpoint = (
            "https://iam.amazonaws.com"
            if service == "iam"
            else f"https://{'s3' if service == 's3api' else service}.eu-central-1.amazonaws.com"
        )
        region = "us-east-1" if service == "iam" else "eu-central-1"
        command = [
            executable,
            service,
            operation,
            "--region",
            region,
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

    def preconditions(stage):
        helper.root_caller(transport, executable, account)
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
        save(f"{stage}-seed-key.json", native_key)
        state = call("cloudformation", "describe-stacks", "--stack-name", stack)[
            "Stacks"
        ]
        assert (
            len(state) == 1
            and state[0]["StackId"] == stack
            and state[0]["StackStatus"] == "IMPORT_COMPLETE"
        )
        assert state[0]["DriftInformation"][
            "StackDriftStatus"
        ] == "IN_SYNC" and not state[0].get("RoleARN")
        save(f"{stage}-stack.json", state)
        policy = call("cloudformation", "get-stack-policy", "--stack-name", stack)
        assert document(policy["StackPolicyBody"]) == json.loads(packet.stack_policy)
        save(f"{stage}-stack-policy.json", policy)
        current = call(
            "cloudformation",
            "get-template",
            "--stack-name",
            stack,
            "--template-stage",
            "Original",
        )
        save(f"{stage}-current-template.json", current)
        resources = paginated(
            call,
            "cloudformation",
            "list-stack-resources",
            ["--stack-name", stack],
            "StackResourceSummaries",
            save,
            stage + "-stack-resources",
        )
        validate_preserved(
            partition, document(current["TemplateBody"]), resources, full
        )
        policies = paginated(
            call,
            "iam",
            "list-policies",
            ["--scope", "Local"],
            "Policies",
            save,
            stage + "-policies",
        )
        roles = paginated(
            call, "iam", "list-roles", [], "Roles", save, stage + "-roles"
        )
        validate_names(partition, policies, roles)
        held = [
            f"GitHubGovernanceApply-{environment}",
            f"GitHubCiApply-bootstrap-infrastructure-{environment}",
            f"GitHubCiApply-user-service-infrastructure-{environment}",
            f"PulumiAutomation-bootstrap-infrastructure-{environment}",
            "PulumiDeploy-bootstrap-infrastructure",
        ]
        hold_doc = {
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
            held_role = call(
                "iam",
                "get-role-policy",
                "--role-name",
                name,
                "--policy-name",
                "Issue215CutoverSessions",
            )
            save(f"{stage}-writer-hold-{index}.json", held_role)
            assert (
                held_role["RoleName"] == name
                and held_role["PolicyName"] == "Issue215CutoverSessions"
            )
            assert document(held_role["PolicyDocument"]) == hold_doc
        state_bucket = f"pulumi-bootstrap-infrastructure-{environment}-state"
        state_head = call(
            "s3api",
            "head-object",
            "--bucket",
            state_bucket,
            "--expected-bucket-owner",
            account,
            "--key",
            f".pulumi/stacks/github-ci-bootstrap/{environment}.json",
        )
        save(f"{stage}-released-checkpoint-head.json", state_head)
        assert (state_head["VersionId"], state_head["ETag"]) == RELEASED_STATE[
            environment
        ]
        assert state_head["ServerSideEncryption"] == "AES256" and not state_head.get(
            "SSEKMSKeyId"
        )
        locks = call(
            "s3api",
            "list-objects-v2",
            "--bucket",
            state_bucket,
            "--expected-bucket-owner",
            account,
            "--prefix",
            ".pulumi/locks/",
        )
        save(f"{stage}-lock-list.json", locks)
        assert (
            locks["IsTruncated"] is False
            and locks["KeyCount"] == 0
            and not locks.get("Contents")
        )

    preconditions("before")
    save(
        "proposal-intent.json",
        {
            "stack_id": stack,
            "bucket": bucket,
            "object_key": object_key,
            "change_set_name": token,
            "template_sha256": hashlib.sha256(template.read_bytes()).hexdigest(),
            "execution_authorized": False,
        },
    )
    uploaded = call(
        "s3api",
        "put-object",
        "--bucket",
        bucket,
        "--expected-bucket-owner",
        account,
        "--key",
        object_key,
        "--body",
        str(template),
        "--server-side-encryption",
        "AES256",
        "--if-none-match",
        "*",
    )
    save("template-upload.json", uploaded)
    version = uploaded["VersionId"]
    assert isinstance(version, str) and version and version != "null"
    downloaded = receipt / "enrollment-template-readback.json"
    metadata = call(
        "s3api",
        "get-object",
        "--bucket",
        bucket,
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
    assert downloaded.read_bytes() == template.read_bytes()
    url = f"https://{bucket}.s3.eu-central-1.amazonaws.com/{object_key}?versionId={quote(version, safe='')}"
    created = call(
        "cloudformation",
        "create-change-set",
        "--stack-name",
        stack,
        "--change-set-name",
        token,
        "--change-set-type",
        "UPDATE",
        "--template-url",
        url,
        "--capabilities",
        "CAPABILITY_NAMED_IAM",
        "--client-token",
        token,
    )
    save("change-set-created.json", created)
    assert created["StackId"] == stack
    change = created["Id"]
    assert isinstance(change, str) and change.startswith(
        f"arn:aws:cloudformation:eu-central-1:{account}:changeSet/{token}/"
    )
    for attempt in range(40):
        proposal = call(
            "cloudformation",
            "describe-change-set",
            "--stack-name",
            stack,
            "--change-set-name",
            change,
        )
        save(f"change-set-observation-{attempt:02d}.json", proposal)
        assert (
            proposal["StackId"] == stack
            and proposal["ChangeSetId"] == change
            and not proposal.get("NextToken")
        )
        if proposal["Status"] not in ("CREATE_PENDING", "CREATE_IN_PROGRESS"):
            break
        time.sleep(3)
    assert (
        proposal["Status"] == "CREATE_COMPLETE"
        and proposal["ExecutionStatus"] == "AVAILABLE"
        and not proposal.get("RoleARN")
    )
    assert (
        not proposal.get("ParentChangeSetId")
        and not proposal.get("RootChangeSetId")
        and not proposal.get("IncludeNestedStacks")
    )
    validate_additions(partition, proposal["Changes"])
    if environment == "prod":
        installation.validate_change_set(
            packet, phase="enroll", changes=proposal["Changes"]
        )
    proposed_template = call(
        "cloudformation",
        "get-template",
        "--stack-name",
        stack,
        "--change-set-name",
        change,
        "--template-stage",
        "Original",
    )
    save("proposed-template.json", proposed_template)
    body = proposed_template["TemplateBody"]
    assert (json.loads(body) if isinstance(body, str) else body) == json.loads(
        packet.enrollment_template
    )
    assert json.loads(
        call("cloudformation", "get-stack-policy", "--stack-name", stack)[
            "StackPolicyBody"
        ]
    ) == json.loads(packet.stack_policy)
    preconditions("after")
    result = {
        "change_set_id": change,
        "stack_id": stack,
        "template_url": url,
        "validated_adds": len(proposal["Changes"]),
        "preserved_resources": partition["preserved_count"],
        "source_sha": helper.SOURCE_SHA,
        "partition_sha256": PARTITION_HASHES[environment],
        "executed": False,
    }
    save("proposal-validated.json", result)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print(
            "Enrollment proposal incomplete; inspect private receipts and actual AWS state before any retry. No execution was attempted.",
            file=sys.stderr,
        )
        raise SystemExit(1) from None
