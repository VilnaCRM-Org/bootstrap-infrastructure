#!/usr/bin/env python3
"""Read-only TEST55 ownership/IAM verification and existing drift observation.

Usage: python3 -I verify55.py RECOVERY ROOT PRIOR SOURCE PACKETS EXECUTION NEW_OUTPUT AWS DRIFT_ID
No AWS writes. DRIFT_ID must be the one already requested for this exact stack.
"""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import time

RECOVERY_HASH = "f6d514f93b7f8ccbe116e257cd78251ca444daa9f357e26e27c288955035600d"
TEMPLATE_HASH = "068ee1b7735b51125f3f5b6daef5d4a8f595ef717ce487cd00458a56ee13503a"

CHANGE = "arn:aws:cloudformation:eu-central-1:891377212104:changeSet/pr225-retained11-fef3b57f3d5a4a4cbde1d5b4b3b3a57f/7614fa43-a3d1-4ac5-9f09-0787c40d0738"


def validate_resources(template, rows, imports):
    expected = template["Resources"]
    assert len(expected) == 55 and len(rows) == 55
    imported = {x["LogicalResourceId"] for x in imports}
    assert len(imported) == 11 and imported <= set(expected)
    seen = set()
    for row in rows:
        logical = row["LogicalResourceId"]
        assert logical in expected and logical not in seen
        seen.add(logical)
        definition = expected[logical]
        assert row["ResourceType"] == definition["Type"] == "AWS::IAM::ManagedPolicy"
        props = definition["Properties"]
        arn = (
            "arn:aws:iam::891377212104:policy"
            + props["Path"]
            + props["ManagedPolicyName"]
        )
        assert row["PhysicalResourceId"] == arn
        assert row["ResourceStatus"] in {
            "IMPORT_COMPLETE",
            "CREATE_COMPLETE",
            "UPDATE_COMPLETE",
        }
    return seen


def executed_changes(call, save, stack):
    changes, marker, seen = [], None, set()
    for index in range(100):
        args = ["--stack-name", stack, "--change-set-name", CHANGE]
        if marker:
            args += ["--next-token", marker]
        page = call("cloudformation", "describe-change-set", *args)
        save(f"executed-change-{index:03d}.json", page)
        assert page["StackId"] == stack and page["ChangeSetId"] == CHANGE
        assert (
            page["ChangeSetName"] == "pr225-retained11-fef3b57f3d5a4a4cbde1d5b4b3b3a57f"
        )
        assert (
            page["Status"] == "CREATE_COMPLETE"
            and page["ExecutionStatus"] == "EXECUTE_COMPLETE"
        )
        assert not page.get("RoleARN") and not page.get("ParentChangeSetId")
        assert not page.get("RootChangeSetId") and not page.get("IncludeNestedStacks")
        assert isinstance(page["Changes"], list) and len(page["Changes"]) <= 1000
        changes.extend(page["Changes"])
        marker = page.get("NextToken")
        if marker is None:
            return changes
        assert isinstance(marker, str) and marker and marker not in seen
        seen.add(marker)
    raise ValueError("Executed change-set pagination bound")


def drift_coverage(rows, identities):
    checked, not_checked, seen = set(), set(), set()
    for row in rows:
        logical = row["LogicalResourceId"]
        assert logical in identities and logical not in seen
        seen.add(logical)
        assert row["ResourceType"] == "AWS::IAM::ManagedPolicy"
        assert row["StackResourceDriftStatus"] in {"IN_SYNC", "NOT_CHECKED"}
        (checked if row["StackResourceDriftStatus"] == "IN_SYNC" else not_checked).add(
            logical
        )
    return {
        "in_sync": sorted(checked),
        "not_checked": sorted(not_checked),
        "not_reported": sorted(identities - seen),
        "all55_covered_by_cfn": len(checked) == 55,
    }


def main():
    if sys.flags.optimize:
        raise ValueError("Assertions must remain enabled")
    (
        recovery_path,
        root_path,
        prior_path,
        source,
        packets_path,
        execution_path,
        output,
        executable,
        detection,
    ) = sys.argv[1:]
    assert hashlib.sha256(Path(recovery_path).read_bytes()).hexdigest() == RECOVERY_HASH
    spec = importlib.util.spec_from_file_location("recovery", recovery_path)
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
    execution = Path(execution_path).resolve(strict=True)
    fresh = execution / "fresh-preparation"
    packets = Path(packets_path).resolve(strict=True)
    caller = helper.root_caller(transport, executable, recovery.ACCOUNT)
    assert json.loads((execution / "execution-terminal.json").read_text()) == {
        "stack_status": "IMPORT_COMPLETE",
        "permanent_guard_restored": True,
        "import_succeeded": True,
    }
    raw = (fresh / "import-template.json").read_bytes()
    assert hashlib.sha256(raw).hexdigest() == TEMPLATE_HASH
    template = json.loads(raw)
    imports = json.loads((fresh / "resources-to-import.json").read_text())
    key = registry.SeedKeyBinding(
        **json.loads((packets / "seed-key-binding.json").read_text())
    )
    expected = registry.build_registry(
        "test", account_id=recovery.ACCOUNT, seed_key=key
    )
    packet = installation.build_installation(
        "test", account_id=recovery.ACCOUNT, seed_key=key
    )
    partition = prior.partition_for(
        packets, "test", recovery.ACCOUNT, json.loads(packet.enrollment_template)
    )
    before = prior.document(
        json.loads((fresh / "template-before.json").read_text())["TemplateBody"]
    )
    built, required_imports, _ = recovery.build_import(
        before, json.loads(packet.enrollment_template), partition
    )
    assert built == template and imports == required_imports
    permanent = json.loads(packet.stack_policy)

    def save(name, value):
        with (out / name).open("x") as f:
            json.dump(value, f, sort_keys=True, separators=(",", ":"))
            f.write("\n")

    def call(service, operation, *args):
        assert (
            service == "cloudformation"
            and operation
            in {
                "describe-stacks",
                "describe-change-set",
                "get-template",
                "list-stack-resources",
                "get-stack-policy",
                "describe-stack-drift-detection-status",
                "describe-stack-resource-drifts",
            }
        ) or (
            service == "iam"
            and operation
            in {"get-policy", "get-policy-version", "list-entities-for-policy"}
        )
        region = "us-east-1" if service == "iam" else "eu-central-1"
        endpoint = (
            "https://iam.amazonaws.com"
            if service == "iam"
            else "https://cloudformation.eu-central-1.amazonaws.com"
        )
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
            *args,
        ]
        return transport._response(transport._run(command, None))

    def check_stack(label):
        states = call(
            "cloudformation", "describe-stacks", "--stack-name", recovery.STACK
        )["Stacks"]
        assert len(states) == 1 and states[0]["StackId"] == recovery.STACK
        assert states[0]["StackStatus"] == "IMPORT_COMPLETE" and not states[0].get(
            "RoleARN"
        )
        body = call(
            "cloudformation",
            "get-template",
            "--stack-name",
            recovery.STACK,
            "--template-stage",
            "Original",
        )
        assert prior.document(body["TemplateBody"]) == template
        guard = call(
            "cloudformation", "get-stack-policy", "--stack-name", recovery.STACK
        )
        assert prior.document(guard["StackPolicyBody"]) == permanent
        rows = prior.paginated(
            call,
            "cloudformation",
            "list-stack-resources",
            ["--stack-name", recovery.STACK],
            "StackResourceSummaries",
            save,
            label + "-resources",
        )
        identities = validate_resources(template, rows, imports)
        save(label + "-stack.json", states)
        save(label + "-template.json", body)
        save(label + "-guard.json", guard)
        return identities

    changes = executed_changes(call, save, recovery.STACK)
    recovery.validate_import(changes, imports)
    executed_template = call(
        "cloudformation",
        "get-template",
        "--stack-name",
        recovery.STACK,
        "--change-set-name",
        CHANGE,
        "--template-stage",
        "Original",
    )
    assert prior.document(executed_template["TemplateBody"]) == template
    save("executed-template.json", executed_template)
    identities = check_stack("before")
    imported_six = set(json.loads(packet.import_template)["Resources"])
    assert len(imported_six) == 6
    six_arns = {
        "arn:aws:iam::891377212104:policy"
        + template["Resources"][logical]["Properties"]["Path"]
        + template["Resources"][logical]["Properties"]["ManagedPolicyName"]
        for logical in imported_six
    }
    imported_order = {r["LogicalResourceId"]: i for i, r in enumerate(imports)}
    hashes = {}
    for index, (logical, definition) in enumerate(
        sorted(template["Resources"].items())
    ):
        props = definition["Properties"]
        arn = (
            "arn:aws:iam::891377212104:policy"
            + props["Path"]
            + props["ManagedPolicyName"]
        )
        policy = call("iam", "get-policy", "--policy-arn", arn)["Policy"]
        assert (
            policy["Arn"] == arn
            and policy["Path"] == props["Path"]
            and policy["PolicyName"] == props["ManagedPolicyName"]
        )
        version = call(
            "iam",
            "get-policy-version",
            "--policy-arn",
            arn,
            "--version-id",
            policy["DefaultVersionId"],
        )["PolicyVersion"]
        assert (
            version["IsDefaultVersion"] is True
            and version["VersionId"] == policy["DefaultVersionId"]
        )
        assert prior.document(version["Document"]) == props["PolicyDocument"]
        if logical in imported_order:
            old = json.loads(
                (fresh / f"retained-{imported_order[logical]}-policy.json").read_text()
            )
            assert policy["DefaultVersionId"] == old["DefaultVersionId"]
            assert policy["PolicyId"] == old["PolicyId"]
        save(f"iam-{index:02d}-policy.json", policy)
        save(f"iam-{index:02d}-version.json", version)
        for usage in ("PermissionsPolicy", "PermissionsBoundary"):
            expected_names = (
                set(props.get("Roles", []))
                if usage == "PermissionsPolicy"
                else {
                    p.arn.rsplit("/", 1)[-1]
                    for p in expected.principals
                    if p.existing and p.boundary_arn == arn and arn in six_arns
                }
            )
            names, marker, seen = [], None, set()
            for page_index in range(100):
                args = ["--policy-arn", arn, "--policy-usage-filter", usage]
                if marker:
                    args += ["--marker", marker]
                page = call("iam", "list-entities-for-policy", *args)
                save(f"iam-{index:02d}-{usage}-{page_index}.json", page)
                assert not page["PolicyUsers"] and not page["PolicyGroups"]
                names += [x["RoleName"] for x in page["PolicyRoles"]]
                assert type(page["IsTruncated"]) is bool
                if not page["IsTruncated"]:
                    assert not page.get("Marker")
                    break
                marker = page.get("Marker")
                assert isinstance(marker, str) and marker and marker not in seen
                seen.add(marker)
            else:
                raise ValueError("IAM pagination bound")
            assert len(names) == len(set(names)) and set(names) == expected_names
            if usage == "PermissionsBoundary":
                assert policy["PermissionsBoundaryUsageCount"] == len(expected_names)
        assert call("iam", "get-policy", "--policy-arn", arn)["Policy"] == policy
        hashes[arn] = {
            "default_version": policy["DefaultVersionId"],
            "document_sha256": prior.canonical_hash(props["PolicyDocument"]),
        }
    assert helper.root_caller(transport, executable, recovery.ACCOUNT) == caller
    save(
        "iam55-verified.json",
        {"policies": hashes, "count": 55, "full_enrollment_verified": False},
    )
    assert isinstance(detection, str) and len(detection) == 36
    save(
        "existing-drift-identity.json",
        {
            "stack_id": recovery.STACK,
            "detection_id": detection,
            "drift_requests_by_helper": 0,
        },
    )
    for attempt in range(120):
        status = call(
            "cloudformation",
            "describe-stack-drift-detection-status",
            "--stack-drift-detection-id",
            detection,
        )
        save(f"drift-{attempt:03d}.json", status)
        assert (
            status["StackId"] == recovery.STACK
            and status["StackDriftDetectionId"] == detection
        )
        if status["DetectionStatus"] != "DETECTION_IN_PROGRESS":
            break
        time.sleep(10)
    assert status["DetectionStatus"] == "DETECTION_COMPLETE"
    rows = prior.paginated(
        call,
        "cloudformation",
        "describe-stack-resource-drifts",
        ["--stack-name", recovery.STACK],
        "StackResourceDrifts",
        save,
        "drift-resources",
    )
    for row in rows:
        properties = template["Resources"][row["LogicalResourceId"]]["Properties"]
        assert row["PhysicalResourceId"] == (
            "arn:aws:iam::891377212104:policy"
            + properties["Path"]
            + properties["ManagedPolicyName"]
        )
    coverage = drift_coverage(rows, identities)
    save("cfn-drift-coverage.json", coverage)
    check_stack("after")
    assert helper.root_caller(transport, executable, recovery.ACCOUNT) == caller
    result = {
        "account": recovery.ACCOUNT,
        "owned_policies": 55,
        "new_imports": 11,
        "iam55_verified": True,
        "permanent_guard_verified": True,
        "cfn_stack_drift_status": status["StackDriftStatus"],
        "cfn_resource_coverage": coverage,
        "full_enrollment_verified": False,
    }
    save("verification.json", result)
    assert status["StackDriftStatus"] == "IN_SYNC"
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print(
            "Post-import verification incomplete. Inspect private receipts; do not claim full enrollment or CFN coverage for unsupported resources.",
            file=sys.stderr,
        )
        raise SystemExit(1) from None
