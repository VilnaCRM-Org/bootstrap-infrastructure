#!/usr/bin/env python3
"""Read-only post-cutoff writer verification; no CI enabling or revocation cleanup.
ENV WRITER_HELPER PROPOSER ROOT SOURCE PACKETS NEW_RECEIPTS AWS
--writer-receipts DIRECTORY --checkpoint-version VERSION --checkpoint-etag ETAG
"""
import argparse
import hashlib
import importlib.util
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

WRITER_HASH = "f9a546887d585efbe5b3d84bebb91b433654b13f83fb8fbc81377f7dba587c00"
ROLE_FIELDS = ("Arn", "RoleName", "RoleId", "Path", "CreateDate", "AssumeRolePolicyDocument",
    "PermissionsBoundary", "MaxSessionDuration")


def load_module(path, name, digest):
    assert hashlib.sha256(Path(path).read_bytes()).hexdigest() == digest
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def parse_utc(value):
    assert isinstance(value, str)
    parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    assert parsed.strftime("%Y-%m-%dT%H:%M:%SZ") == value
    return parsed


def check_times(receipt, now):
    assert now.tzinfo is not None
    cutoff = parse_utc(receipt["cutoff"])
    earliest = parse_utc(receipt["earliest_issuance_recheck"])
    retention = parse_utc(receipt["retain_policy_until_at_least"])
    assert earliest == cutoff + timedelta(seconds=60)
    assert retention == cutoff + timedelta(hours=12)
    if now < earliest:
        raise ValueError("Cutoff plus sixty seconds has not elapsed")
    return cutoff, earliest, retention


def stable_role(response, name, account):
    role = response["Role"]
    assert role["RoleName"] == name and role["Arn"] == f"arn:aws:iam::{account}:role/{name}"
    assert isinstance(role["RoleId"], str) and role["RoleId"]
    result = {key: role.get(key) for key in ROLE_FIELDS}
    trust = result["AssumeRolePolicyDocument"]
    result["AssumeRolePolicyDocument"] = trust if isinstance(trust, dict) else json.loads(trust)
    return result


def main():
    if sys.flags.optimize:
        raise ValueError("Optimized Python forbidden")
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("environment", choices=("test", "prod"))
    parser.add_argument("writer_helper")
    parser.add_argument("proposer")
    preliminary, _ = parser.parse_known_args()
    writer = load_module(preliminary.writer_helper, "recheck_writer", WRITER_HASH)
    digest, account, version, etag = writer.PINS[preliminary.environment]
    proposer = load_module(preliminary.proposer, "recheck_proposer", digest)
    assert proposer.ACCOUNT == account
    proposer.arguments(parser)
    parser.add_argument("--writer-receipts", required=True)
    args = parser.parse_args()
    assert (args.checkpoint_version, args.checkpoint_etag) == (version, etag)
    directory = Path(args.writer_receipts).resolve(strict=True)

    def read_json(name):
        with (directory / name).open("rb") as stream:
            raw = stream.read(2 * 1024 * 1024 + 1)
        assert len(raw) <= 2 * 1024 * 1024
        return json.loads(raw)

    completed = read_json("writers-reconciled.json")
    cutoff, earliest, retention = check_times(completed, datetime.now(timezone.utc))
    names = writer.held_names(args.environment)
    desired = writer.revocation(cutoff)
    assert completed == {"account": account, "roles_changed": names[:2],
        "roles_kept_fully_held": names[2:], "cutoff": writer.utc_text(cutoff),
        "retain_policy_until_at_least": writer.utc_text(retention),
        "earliest_issuance_recheck": writer.utc_text(earliest),
        "workflows_enabled": False, "issuance_authorized": False,
        "checkpoint_version": version, "permanent_guard_verified": True}
    assert read_json("cutoff-intent.json") == {"roles": names[:2], "cutoff": writer.utc_text(cutoff),
        "retain_policy_until_at_least": writer.utc_text(retention),
        "earliest_issuance_recheck": writer.utc_text(earliest), "policy_name": writer.POLICY_NAME,
        "policy": desired, "workflows_enabled": False}
    # Add only IAM GetRole to the pinned proposer's read transport; no mutation API.
    ctx = proposer.context(args, {("iam", "get-role")})
    assert directory != ctx.out
    state = ctx.state()
    assert state["StackStatus"] == "UPDATE_COMPLETE"
    ctx.save("stack.json", state)
    template = ctx.call("cloudformation", "get-template", "--stack-name", proposer.STACK,
        "--template-stage", "Original")
    assert proposer.document(template["TemplateBody"]) == ctx.after
    ctx.save("active-template.json", template)
    ctx.save("permanent-guard.json", ctx.guard(json.loads(ctx.packet.stack_policy)))
    identities = {}
    for index, name in enumerate(names):
        original = stable_role(read_json(f"hold-before-{index}-role.json"), name, account)
        recorded = stable_role(read_json(f"hold-final-{index}-role.json"), name, account)
        assert recorded == original
        response = ctx.call("iam", "get-role", "--role-name", name)
        actual = stable_role(response, name, account)
        assert actual == original
        ctx.save(f"role-{index}.json", response)
        policy = ctx.call("iam", "get-role-policy", "--role-name", name,
            "--policy-name", writer.POLICY_NAME)
        assert policy["RoleName"] == name and policy["PolicyName"] == writer.POLICY_NAME
        expected = desired if index < 2 else writer.FULL_HOLD
        assert proposer.document(policy["PolicyDocument"]) == expected
        ctx.save(f"policy-{index}.json", policy)
        identities[name] = actual["RoleId"]
    head = ctx.call("s3api", "head-object", "--bucket", proposer.STATE_BUCKET,
        "--key", proposer.STATE_KEY, "--expected-bucket-owner", account)
    assert (head["VersionId"], head["ETag"]) == (version, etag)
    assert head["ServerSideEncryption"] == "AES256" and not head.get("SSEKMSKeyId")
    ctx.save("checkpoint-head.json", head)
    locks = ctx.call("s3api", "list-objects-v2", "--bucket", proposer.STATE_BUCKET,
        "--prefix", ".pulumi/locks/", "--expected-bucket-owner", account)
    assert locks["IsTruncated"] is False and locks["KeyCount"] == 0 and not locks.get("Contents")
    ctx.save("locks.json", locks)
    ctx.root()
    assert ctx.state()["StackStatus"] == "UPDATE_COMPLETE"
    ctx.guard(json.loads(ctx.packet.stack_policy))
    now = datetime.now(timezone.utc)
    check_times(completed, now)
    result = {"account": account, "environment": args.environment, "observed_at": now.isoformat(),
        "source_sha": proposer.SOURCE_SHA, "caller_provenance": ctx.caller,
        "cutoff": writer.utc_text(cutoff), "retain_policy_until_at_least": writer.utc_text(retention),
        "conditional_policies_verified": names[:2], "full_holds_verified": names[2:],
        "role_ids": identities, "checkpoint_version": version, "checkpoint_etag": etag,
        "permanent_guard_verified": True, "cutoff_margin_elapsed": True,
        "minimum_retention_elapsed": now >= retention, "cleanup_authorized": False,
        "github_readiness_verified": False, "workflows_enabled": False,
        "ordinary_controller_acceptance_verified": False}
    ctx.save("post-cutoff-verified.json", result)
    print("Post-cutoff native metadata verified. No workflows enabled, policies removed or acceptance claimed.")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("Post-cutoff verification failed. Keep workflow holds; inspect private receipts. No AWS mutation attempted.", file=sys.stderr)
        raise SystemExit(1) from None
