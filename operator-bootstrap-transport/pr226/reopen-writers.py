#!/usr/bin/env python3
"""Replace only two full writer holds with a future timestamp deny; never enable CI.
ENV PROPOSER ROOT SOURCE PACKETS NEW_RECEIPTS AWS --activation-receipts DIRECTORY
--checkpoint-version VERSION --checkpoint-etag ETAG
Run only after both accounts' active verification and coordinated GitHub checks.
"""
import argparse
import hashlib
import importlib.util
import json
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

PINS = {
    "test": ("f5020d483a002dd1afb06bf6861bd45df66ee16a8ab06bf7896e1e688bafb096",
        "891377212104", "P45Q2mwgSObe3oeopxw.tI4upFqxgCzU", '"2f6db21edf320cfa8fd9223a3bd3c771"'),
    "prod": ("9ed4f221451037970a220da145020f77ae965e112016f25ca65a0d97f62381d9",
        "933245420672", "xD328JzUrlJCGLcBjHlzoLXPbob_Adsy", '"1fd025b0f1747a1d28a02489fafa40ba"'),
}
POLICY_NAME = "Issue215CutoverSessions"
FULL_HOLD = {"Version": "2012-10-17", "Statement": [{
    "Sid": "HoldOrdinaryIacDuringIndependentCutover", "Effect": "Deny", "Action": "*", "Resource": "*"}]}


def utc_text(value):
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def revocation(cutoff):
    return {"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*",
        "Condition": {"DateLessThan": {"aws:TokenIssueTime": utc_text(cutoff)}}}]}


def require_margin(cutoff, now):
    if cutoff.tzinfo is None or now.tzinfo is None or (cutoff - now).total_seconds() < 60:
        raise ValueError("At least sixty seconds until cutoff required; no automatic retry")


def resolve_boundary_arn(template, reference, account):
    """Resolve only the authenticated template's exact managed-policy Ref."""
    assert isinstance(reference, dict) and set(reference) == {"Ref"}
    assert isinstance(reference["Ref"], str)
    definition = template["Resources"][reference["Ref"]]
    assert definition["Type"] == "AWS::IAM::ManagedPolicy"
    properties = definition["Properties"]
    return f"arn:aws:iam::{account}:policy{properties['Path']}{properties['ManagedPolicyName']}"


def held_names(environment):
    return [f"GitHubGovernanceApply-{environment}",
        f"GitHubCiApply-bootstrap-infrastructure-{environment}",
        f"GitHubCiApply-user-service-infrastructure-{environment}",
        f"PulumiAutomation-bootstrap-infrastructure-{environment}", "PulumiDeploy-bootstrap-infrastructure"]


def replace_two(*, names, before, read, write, save, root, sleep=time.sleep, now=lambda: datetime.now(timezone.utc)):
    """One future cutoff, one write attempt per exact target; read-only reconciliation."""
    assert len(names) == 2 and len(set(names)) == 2
    cutoff = (now() + timedelta(minutes=5)).replace(microsecond=0)
    desired = revocation(cutoff)
    save("cutoff-intent.json", {"roles": names, "cutoff": utc_text(cutoff),
        "retain_policy_until_at_least": utc_text(cutoff + timedelta(hours=12)),
        "earliest_issuance_recheck": utc_text(cutoff + timedelta(seconds=60)),
        "policy_name": POLICY_NAME, "policy": desired, "workflows_enabled": False})
    for index, name in enumerate(names):
        root()
        current_role, current_policy = read(name, f"target-before-{index}")
        assert current_role == before[name] and current_policy == FULL_HOLD
        require_margin(cutoff, now())
        save(f"write-intent-{index}.json", {"role": name, "policy_name": POLICY_NAME, "policy": desired,
            "role_id": before[name]["RoleId"], "retry_forbidden": True})
        try:
            write(name, desired)
        except Exception:
            save(f"write-response-{index}.json", {"uncertain": True, "retry_forbidden": True})
        else:
            save(f"write-response-{index}.json", {"response_received": True, "retry_forbidden": True})
        for attempt in range(5):
            role, policy = read(name, f"target-after-{index}-{attempt}")
            assert role == before[name]
            if policy == desired:
                break
            assert policy == FULL_HOLD
            if attempt < 4:
                sleep(2)
        else:
            raise ValueError("Expected conditional policy unconfirmed; reconcile, never rerun")
    return cutoff, desired


def main():
    if sys.flags.optimize:
        raise ValueError("Optimized Python forbidden")
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("environment", choices=tuple(PINS))
    parser.add_argument("proposer")
    preliminary, _ = parser.parse_known_args()
    digest, account, version, etag = PINS[preliminary.environment]
    assert hashlib.sha256(Path(preliminary.proposer).read_bytes()).hexdigest() == digest
    spec = importlib.util.spec_from_file_location("writer_reopen_proposer", preliminary.proposer)
    proposer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(proposer)
    assert proposer.ACCOUNT == account
    proposer.arguments(parser)
    parser.add_argument("--activation-receipts", required=True)
    args = parser.parse_args()
    assert (args.checkpoint_version, args.checkpoint_etag) == (version, etag)
    ctx = proposer.context(args, {("iam", "get-role"), ("iam", "put-role-policy")})
    previous = Path(args.activation_receipts).resolve(strict=True)
    assert previous.is_dir() and previous != ctx.out
    def read_json(name):
        return json.loads((previous / name).read_bytes())
    assert read_json("activation-verified.json") == {
        "stack_status": "UPDATE_COMPLETE", "permanent_guard_restored": True,
        "execution_status": "EXECUTE_COMPLETE", "activation_update_succeeded": True,
        "active_enrollment_verified": True, "issuance_reopened": False}
    identity = read_json("execution-identity.json")
    assert identity["account"] == account and identity["stack_id"] == proposer.STACK
    assert identity["caller"] == ctx.caller
    assert identity["checkpoint_version"] == version and identity["checkpoint_etag"] == etag
    assert identity["template_sha256"] == hashlib.sha256(ctx.activation.activation_template.encode()).hexdigest()
    prior_enrollment = read_json("after-enrollment.json")
    assert prior_enrollment["source_sha"] == proposer.SOURCE_SHA
    assert prior_enrollment["caller_provenance"] == ctx.caller
    assert prior_enrollment["environment"] == args.environment and prior_enrollment["mode"] == "active"
    assert prior_enrollment["verification"] == {"registry_sha256": ctx.packet.registry.sha256,
        "policies_verified": 55, "principals_verified": 24, "active_executors_verified": 3,
        "activation_authorized": False}
    observed_at = datetime.fromisoformat(prior_enrollment["observed_at"])
    assert observed_at.tzinfo is not None and observed_at <= datetime.now(timezone.utc)
    proposer.validate_proposal(ctx, identity["change_set_id"], "executed", execution="EXECUTE_COMPLETE")
    permanent = json.loads(ctx.packet.stack_policy)

    def infrastructure(label):
        ctx.root()
        state = ctx.state()
        assert state["StackStatus"] == "UPDATE_COMPLETE"
        assert observed_at >= datetime.fromisoformat(state["LastUpdatedTime"].replace("Z", "+00:00"))
        response = ctx.call("cloudformation", "get-template", "--stack-name", proposer.STACK,
            "--template-stage", "Original")
        assert proposer.document(response["TemplateBody"]) == ctx.after
        ctx.save(label + "-template.json", response)
        ctx.guard(permanent)
        ctx.save(label + "-stack.json", state)
        head = ctx.call("s3api", "head-object", "--bucket", proposer.STATE_BUCKET,
            "--key", proposer.STATE_KEY, "--expected-bucket-owner", account)
        assert (head["VersionId"], head["ETag"]) == (version, etag)
        assert head["ServerSideEncryption"] == "AES256" and not head.get("SSEKMSKeyId")
        ctx.save(label + "-checkpoint.json", head)
        locks = ctx.call("s3api", "list-objects-v2", "--bucket", proposer.STATE_BUCKET,
            "--prefix", ".pulumi/locks/", "--expected-bucket-owner", account)
        assert locks["IsTruncated"] is False and locks["KeyCount"] == 0 and not locks.get("Contents")
        ctx.save(label + "-locks.json", locks)

    infrastructure("before")
    ctx.owners(ctx.after, "before")
    # Reauthenticate the three active trusts; keep the prior full native55/24 scan bound to this update.
    for index, definition in enumerate(d for d in ctx.after["Resources"].values() if d["Type"] == "AWS::IAM::Role"):
        props = definition["Properties"]
        response = ctx.call("iam", "get-role", "--role-name", props["RoleName"])
        role = response["Role"]
        assert role["RoleName"] == props["RoleName"] and role["Arn"] == f"arn:aws:iam::{account}:role/{props['RoleName']}"
        assert proposer.document(role["AssumeRolePolicyDocument"]) == props["AssumeRolePolicyDocument"]
        assert role["PermissionsBoundary"] == {"PermissionsBoundaryType": "Policy", "PermissionsBoundaryArn": resolve_boundary_arn(ctx.after, props["PermissionsBoundary"], account)}
        ctx.save(f"active-executor-{index}.json", response)

    def read(name, label):
        response = ctx.call("iam", "get-role", "--role-name", name)
        role = response["Role"]
        assert role["RoleName"] == name and role["Arn"] == f"arn:aws:iam::{account}:role/{name}"
        assert isinstance(role["RoleId"], str) and role["RoleId"]
        policy = ctx.call("iam", "get-role-policy", "--role-name", name, "--policy-name", POLICY_NAME)
        assert policy["RoleName"] == name and policy["PolicyName"] == POLICY_NAME
        ctx.save(label + "-role.json", response)
        ctx.save(label + "-policy.json", policy)
        # Last-used metadata may legitimately change; compare only stable IAM role authority fields.
        stable = {key: role.get(key) for key in ("Arn", "RoleName", "RoleId", "Path", "CreateDate",
            "AssumeRolePolicyDocument", "PermissionsBoundary", "MaxSessionDuration")}
        stable["AssumeRolePolicyDocument"] = proposer.document(stable["AssumeRolePolicyDocument"])
        return stable, proposer.document(policy["PolicyDocument"])

    names, before = held_names(args.environment), {}
    for index, name in enumerate(names):
        role, policy = read(name, f"hold-before-{index}")
        assert policy == FULL_HOLD
        before[name] = role

    def write(name, document):
        assert name in names[:2]
        path = ctx.out / (name + "-timestamp-policy.json")
        with path.open("x") as stream:
            json.dump(document, stream, sort_keys=True)
        ctx.call("iam", "put-role-policy", "--role-name", name,
            "--policy-name", POLICY_NAME, "--policy-document", "file://" + str(path))

    cutoff, desired = replace_two(names=names[:2], before=before, read=read, write=write, save=ctx.save, root=ctx.root)
    infrastructure("after")
    for index, name in enumerate(names):
        role, policy = read(name, f"hold-final-{index}")
        assert role == before[name] and policy == (desired if index < 2 else FULL_HOLD)
    ctx.root()
    ctx.save("writers-reconciled.json", {"account": account, "roles_changed": names[:2],
        "roles_kept_fully_held": names[2:], "cutoff": utc_text(cutoff),
        "retain_policy_until_at_least": utc_text(cutoff + timedelta(hours=12)),
        "earliest_issuance_recheck": utc_text(cutoff + timedelta(seconds=60)),
        "workflows_enabled": False, "issuance_authorized": False,
        "checkpoint_version": version, "permanent_guard_verified": True})
    print("Two timestamp policies verified; three full holds retained. Keep workflows held through cutoff and fresh recheck. No issuance enabled.")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("Writer reopening incomplete. Keep all workflow holds; inspect exact per-role receipts. Never blindly rerun or delete revocation policies.", file=sys.stderr)
        raise SystemExit(1) from None
