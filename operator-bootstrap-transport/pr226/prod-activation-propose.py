#!/usr/bin/env python3
"""PROD three-trust activation proposal only. No execution or policy changes.
ROOT SOURCE PACKETS NEW_RECEIPTS AWS --checkpoint-version VERSION --checkpoint-etag ETAG
Requires coordinated protections, reconciled checkpoints and issuance holds.
Never rerun after an uncertain upload/create; inspect the unique saved intent.
"""

import argparse
import hashlib
import importlib.util
import json
import os
import re
import sys
import time
import uuid
from functools import partial
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import quote

ROOT_HASH = "262ddcb3b76a82a0306c2df5735418f4b58cf5205292a8f8e614d0cbb8e8bb18"
SOURCE_SHA = "88dfaf1f47e1afe55d282e7a2b2efa9afa2be78d"
ACCOUNT = "933245420672"
STACK = (
    "arn:aws:cloudformation:eu-central-1:933245420672:stack/"
    "issue215-operator-seed-prod/2d3d1960-ab23-11f1-b7dc-02b3dc85e917"
)
BUCKET = "issue215-independent-seed-933245420672-prod"
SEED_KEY = (
    "arn:aws:kms:eu-central-1:933245420672:key/2d42d715-1452-4766-8cfa-020b53288443"
)
STATE_BUCKET = "pulumi-bootstrap-infrastructure-prod-state"
STATE_KEY = ".pulumi/stacks/github-ci-bootstrap/prod.json"


def arguments(parser):
    for name in ("root", "source", "packets", "output", "aws"):
        parser.add_argument(name)
    parser.add_argument("--checkpoint-version", required=True)
    parser.add_argument("--checkpoint-etag", required=True)
    return parser


def document(value):
    return value if isinstance(value, dict) else json.loads(value)


def verify_owners(call, save, template, label):
    rows, token, seen = [], None, set()
    for index in range(100):
        params = ["--stack-name", STACK] + (["--next-token", token] if token else [])
        page = call("cloudformation", "list-stack-resources", *params)
        save(f"{label}-resources-{index:02d}.json", page)
        items = page["StackResourceSummaries"]
        assert isinstance(items, list) and len(items) <= 1000
        rows.extend(items)
        token = page.get("NextToken")
        if token is None:
            break
        assert isinstance(token, str) and token and token not in seen
        seen.add(token)
    else:
        raise ValueError("Resource pagination bound")
    assert len(rows) == 58 and {r["LogicalResourceId"] for r in rows} == set(
        template["Resources"]
    )
    for row in rows:
        definition = template["Resources"][row["LogicalResourceId"]]
        props = definition["Properties"]
        assert row["ResourceType"] == definition["Type"]
        assert row["ResourceStatus"] in (
            "CREATE_COMPLETE",
            "UPDATE_COMPLETE",
            "IMPORT_COMPLETE",
        )
        physical = (
            f"arn:aws:iam::{ACCOUNT}:policy{props['Path']}{props['ManagedPolicyName']}"
            if definition["Type"] == "AWS::IAM::ManagedPolicy"
            else props["RoleName"]
        )
        assert row["PhysicalResourceId"] == physical


def native_call(transport, executable, writes, service, operation, *parameters):
    reads = {
        ("cloudformation", x)
        for x in (
            "describe-stacks",
            "get-template",
            "get-stack-policy",
            "list-stack-resources",
            "describe-change-set",
        )
    }
    reads |= {
        ("s3api", "head-object"),
        ("s3api", "get-object"),
        ("s3api", "list-objects-v2"),
        ("iam", "get-role-policy"),
    }
    assert (service, operation) in reads | set(writes)
    region = "us-east-1" if service == "iam" else "eu-central-1"
    endpoint = (
        "https://iam.amazonaws.com"
        if service == "iam"
        else (
            f"https://{'s3' if service == 's3api' else service}"
            ".eu-central-1.amazonaws.com"
        )
    )
    raw = transport._run(
        [
            executable,
            service,
            operation,
            "--region",
            region,
            "--endpoint-url",
            endpoint,
            "--output",
            "json",
            "--no-cli-pager",
            "--no-cli-auto-prompt",
            "--no-paginate",
            "--cli-connect-timeout",
            "5",
            "--cli-read-timeout",
            "20",
            *parameters,
        ],
        None,
    )
    if operation in ("set-stack-policy", "execute-change-set") and not raw.strip():
        return {}
    return transport._response(raw)


def load_root(path):
    if sys.flags.optimize:
        raise ValueError("Assertions must remain enabled")
    assert hashlib.sha256(Path(path).read_bytes()).hexdigest() == ROOT_HASH
    spec = importlib.util.spec_from_file_location("activation_root_observer", path)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    assert helper.SOURCE_SHA == SOURCE_SHA
    return helper


def write_artifacts(out, packet, activation):
    for name, raw in (
        ("activation-template.json", activation.activation_template),
        ("temporary-stack-policy.json", activation.temporary_stack_policy),
        ("permanent-stack-policy.json", packet.stack_policy),
    ):
        with (out / name).open("xb") as stream:
            stream.write(raw.encode())


def validate_stack_status(observed):
    assert observed["StackStatus"] == "UPDATE_COMPLETE"
    assert observed["DriftInformation"]["StackDriftStatus"] in {
        "IN_SYNC",
        "NOT_CHECKED",
    }


def context(args, writes):
    helper = load_root(args.root)
    transport, _, installation, registry = helper.load_source(args.source)
    assert (
        Path(args.aws).is_absolute()
        and Path(args.aws).resolve(strict=True).name == "aws"
    )
    assert args.checkpoint_version and args.checkpoint_version != "null"
    assert re.fullmatch(r'"[0-9a-f]{32}"', args.checkpoint_etag)
    os.environ["AWS_MAX_ATTEMPTS"] = "1"
    os.umask(0o077)
    out = Path(args.output).resolve()
    out.mkdir(mode=0o700)
    packets = Path(args.packets).resolve(strict=True)
    key = registry.SeedKeyBinding(
        **json.loads((packets / "seed-key-binding.json").read_bytes())
    )
    assert key.arn == SEED_KEY
    packet = installation.build_installation("prod", account_id=ACCOUNT, seed_key=key)
    activation = installation.build_activation(packet)
    installation.validate_activation(activation)
    before, after = (
        json.loads(packet.enrollment_template),
        json.loads(activation.activation_template),
    )
    assert len(before["Resources"]) == len(after["Resources"]) == 58
    assert (
        packets / "enrollment-template.json"
    ).read_bytes() == packet.enrollment_template.encode()
    caller = helper.root_caller(transport, args.aws, ACCOUNT)

    def save(name, value):
        with (out / name).open("x") as stream:
            json.dump(value, stream, sort_keys=True, separators=(",", ":"))
            stream.write("\n")

    write_artifacts(out, packet, activation)

    call = partial(native_call, transport, args.aws, writes)

    def root():
        assert helper.root_caller(transport, args.aws, ACCOUNT) == caller

    def state():
        rows = call("cloudformation", "describe-stacks", "--stack-name", STACK)[
            "Stacks"
        ]
        assert (
            len(rows) == 1
            and rows[0]["StackId"] == STACK
            and not rows[0].get("RoleARN")
        )
        return rows[0]

    def guard(expected):
        response = call("cloudformation", "get-stack-policy", "--stack-name", STACK)
        assert document(response["StackPolicyBody"]) == expected
        return response

    def enrollment(mode, label):
        receipt = helper.run(
            SimpleNamespace(
                source=args.source,
                aws_executable=args.aws,
                environment="prod",
                seed_key_arn=SEED_KEY,
                mode=mode,
                output_directory=None,
            )
        )
        assert (
            receipt["caller_provenance"] == caller
            and receipt["source_sha"] == SOURCE_SHA
        )
        save(label + "-enrollment.json", receipt)

    def quiescence(label):
        root()
        deny = {
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
        held = [
            "GitHubGovernanceApply-prod",
            "GitHubCiApply-bootstrap-infrastructure-prod",
            "GitHubCiApply-user-service-infrastructure-prod",
            "PulumiAutomation-bootstrap-infrastructure-prod",
            "PulumiDeploy-bootstrap-infrastructure",
        ]
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
            assert document(response["PolicyDocument"]) == deny
            save(f"{label}-hold-{index}.json", response)
        head = call(
            "s3api",
            "head-object",
            "--bucket",
            STATE_BUCKET,
            "--key",
            STATE_KEY,
            "--expected-bucket-owner",
            ACCOUNT,
        )
        assert (head["VersionId"], head["ETag"]) == (
            args.checkpoint_version,
            args.checkpoint_etag,
        )
        assert head["ServerSideEncryption"] == "AES256" and not head.get("SSEKMSKeyId")
        save(label + "-checkpoint-head.json", head)
        locks = call(
            "s3api",
            "list-objects-v2",
            "--bucket",
            STATE_BUCKET,
            "--prefix",
            ".pulumi/locks/",
            "--expected-bucket-owner",
            ACCOUNT,
        )
        assert (
            locks["IsTruncated"] is False
            and locks["KeyCount"] == 0
            and not locks.get("Contents")
        )
        save(label + "-locks.json", locks)

    def preconditions(label, expected_guard=None, *, verify_enrollment=True):
        quiescence(label)
        observed = state()
        validate_stack_status(observed)
        save(label + "-stack.json", observed)
        response = call(
            "cloudformation",
            "get-template",
            "--stack-name",
            STACK,
            "--template-stage",
            "Original",
        )
        assert document(response["TemplateBody"]) == before
        save(label + "-template.json", response)
        guard(
            json.loads(packet.stack_policy)
            if expected_guard is None
            else expected_guard
        )
        verify_owners(call, save, before, label)
        if verify_enrollment:
            enrollment("disabled", label)
        root()

    return SimpleNamespace(
        args=args,
        helper=helper,
        installation=installation,
        packet=packet,
        activation=activation,
        before=before,
        after=after,
        out=out,
        caller=caller,
        save=save,
        call=call,
        root=root,
        state=state,
        guard=guard,
        enrollment=enrollment,
        quiescence=quiescence,
        owners=lambda template, label: verify_owners(call, save, template, label),
        preconditions=preconditions,
    )


def change_pages(ctx, change, label):
    assert re.fullmatch(
        r"arn:aws:cloudformation:eu-central-1:933245420672:changeSet/pr226-prod-activation-[0-9a-f]{32}/[0-9a-f-]{36}",
        change,
    )
    token, rows, seen, first = None, [], set(), None
    for index in range(100):
        params = ["--stack-name", STACK, "--change-set-name", change] + (
            ["--next-token", token] if token else []
        )
        page = ctx.call("cloudformation", "describe-change-set", *params)
        ctx.save(f"{label}-change-{index:02d}.json", page)
        assert page["StackId"] == STACK and page["ChangeSetId"] == change
        assert page["ChangeSetName"] == change.split("/")[1]
        assert not any(
            page.get(k)
            for k in (
                "RoleARN",
                "ParentChangeSetId",
                "RootChangeSetId",
                "IncludeNestedStacks",
            )
        )
        if first is None:
            first = page
        assert (page["Status"], page["ExecutionStatus"]) == (
            first["Status"],
            first["ExecutionStatus"],
        )
        items = page.get("Changes", [])
        assert isinstance(items, list) and len(items) <= 1000
        rows.extend(items)
        token = page.get("NextToken")
        if token is None:
            return first, rows
        assert isinstance(token, str) and token and token not in seen
        seen.add(token)
    raise ValueError("Change pagination bound")


def validate_proposal(ctx, change, label, execution="AVAILABLE"):
    page, rows = change_pages(ctx, change, label)
    assert page["Status"] == "CREATE_COMPLETE" and page["ExecutionStatus"] == execution
    ctx.installation.validate_activation_change_set(ctx.activation, changes=rows)
    response = ctx.call(
        "cloudformation",
        "get-template",
        "--stack-name",
        STACK,
        "--change-set-name",
        change,
        "--template-stage",
        "Original",
    )
    assert document(response["TemplateBody"]) == ctx.after
    ctx.save(label + "-proposed-template.json", response)
    return page


def main():
    parser = arguments(argparse.ArgumentParser(description=__doc__, allow_abbrev=False))
    ctx = context(
        parser.parse_args(),
        {("s3api", "put-object"), ("cloudformation", "create-change-set")},
    )
    ctx.preconditions("before", verify_enrollment=False)
    token = "pr226-" + "prod-activation-" + uuid.uuid4().hex
    key = f"pr226/prod/activation/{token}.json"
    template = ctx.out / "activation-template.json"
    digest = hashlib.sha256(template.read_bytes()).hexdigest()
    ctx.save(
        "proposal-intent.json",
        {
            "stack_id": STACK,
            "bucket": BUCKET,
            "object_key": key,
            "change_set_name": token,
            "client_token": token,
            "template_sha256": digest,
            "source_sha": SOURCE_SHA,
            "checkpoint_version": ctx.args.checkpoint_version,
            "checkpoint_etag": ctx.args.checkpoint_etag,
            "executed": False,
        },
    )
    uploaded = ctx.call(
        "s3api",
        "put-object",
        "--bucket",
        BUCKET,
        "--key",
        key,
        "--expected-bucket-owner",
        ACCOUNT,
        "--body",
        str(template),
        "--server-side-encryption",
        "AES256",
        "--if-none-match",
        "*",
    )
    ctx.save("template-upload.json", uploaded)
    version = uploaded["VersionId"]
    assert isinstance(version, str) and version and version != "null"
    downloaded = ctx.out / "template-readback.json"
    meta = ctx.call(
        "s3api",
        "get-object",
        "--bucket",
        BUCKET,
        "--key",
        key,
        "--version-id",
        version,
        "--expected-bucket-owner",
        ACCOUNT,
        str(downloaded),
    )
    ctx.save("template-readback-metadata.json", meta)
    assert meta["VersionId"] == version and meta["ServerSideEncryption"] == "AES256"
    assert downloaded.read_bytes() == template.read_bytes()
    url = (
        f"https://{BUCKET}.s3.eu-central-1.amazonaws.com/{key}"
        f"?versionId={quote(version, safe='')}"
    )
    created = ctx.call(
        "cloudformation",
        "create-change-set",
        "--stack-name",
        STACK,
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
        "--no-include-nested-stacks",
    )
    ctx.save("change-set-created.json", created)
    assert created["StackId"] == STACK
    change = created["Id"]
    for index in range(40):
        page, _ = change_pages(ctx, change, f"pending-{index:02d}")
        if page["Status"] not in ("CREATE_PENDING", "CREATE_IN_PROGRESS"):
            break
        time.sleep(3)
    validate_proposal(ctx, change, "complete")
    ctx.preconditions("after", verify_enrollment=False)
    result = {
        "stack_id": STACK,
        "change_set_id": change,
        "template_url": url,
        "template_sha256": digest,
        "source_sha": SOURCE_SHA,
        "validated_trust_modifications": 3,
        "preserved_policies": 55,
        "checkpoint_version": ctx.args.checkpoint_version,
        "checkpoint_etag": ctx.args.checkpoint_etag,
        "executed": False,
        "stack_policy_changed": False,
    }
    ctx.save("proposal-validated.json", result)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print(
            "Activation proposal incomplete. Inspect private intent and native state "
            "before further action. No execution or stack-policy update attempted.",
            file=sys.stderr,
        )
        raise SystemExit(1) from None
