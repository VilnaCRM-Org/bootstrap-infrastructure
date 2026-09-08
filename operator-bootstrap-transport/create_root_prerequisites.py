#!/usr/bin/env python3
"""Authorized root CloudShell only: complete seed bucket and rotate existing key.

Execute with python3 -I and the four reviewed policy files beside this script.
No key creation, IAM, state, upload, credential export, or downloaded execution.
Failures leave a public partial receipt; retry with a new receipt filename after
reviewing it. Existing exact-owned resources are reconciled, never deleted.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from datetime import datetime, timezone

ACCOUNTS = {"test": "891377212104", "prod": "933245420672"}
REGION = "eu-central-1"
TEST_KEY = "arn:aws:kms:eu-central-1:891377212104:key/64db70a2-7c25-420f-85b6-eeae0618897d"
POLICY_HASHES = {
    "test-seed-key-policy.json": "077eef29aa1a594f48543cee556bebdf8dee1ee7df309c5f08ec11f16a8f74b4",
    "prod-seed-key-policy.json": "f49cf3b04a541bf3e7e1197f7f6ccc1971272008ef7fdf09c5e5831d5cb507b1",
    "test-seed-artifact-bucket-policy.json": "8515d688a716db512016813f8775dfa2dd296277a1b2f3469b8f2f06d1bb8467",
    "prod-seed-artifact-bucket-policy.json": "3b1a2d0ee883e43f2bb26202aa18489a2d1fb47fd275b2126f412eec05765b4b",
}
PAB = {k: True for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")}
OWNERSHIP = {"Rules": [{"ObjectOwnership": "BucketOwnerEnforced"}]}
ENCRYPTION = {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def policy(environment, suffix):
    name = f"{environment}-{suffix}-policy.json"
    data = (Path(__file__).resolve().parent / name).read_bytes()
    require(hashlib.sha256(data).hexdigest() == POLICY_HASHES[name], "Reviewed policy bytes changed")
    return json.loads(data)


class Native:
    def __init__(self, executable):
        path = Path(executable)
        require(path.is_absolute() and path.resolve(strict=True).name == "aws" and os.access(path, os.X_OK), "Absolute trusted native aws executable required")
        self.executable = str(path.resolve(strict=True))

    def __call__(self, service, operation, arguments, absent=()):
        require(service in {"sts", "kms", "s3api"}, "Unsupported service")
        endpoint = "s3" if service == "s3api" else service
        command = [self.executable, service, operation, "--cli-input-json", json.dumps(arguments),
                   "--region", REGION, "--endpoint-url", f"https://{endpoint}.{REGION}.amazonaws.com",
                   "--output", "json", "--no-cli-pager", "--no-paginate", "--no-cli-auto-prompt",
                   "--cli-connect-timeout", "5", "--cli-read-timeout", "20"]
        # Native CloudShell credential delivery remains inside AWS CLI. Never
        # inspect or print environment credentials, CLI stderr, or config files.
        result = subprocess.run(command, capture_output=True, timeout=90, check=False)
        if result.returncode:
            match = re.search(rb"An error occurred \(([A-Za-z0-9]+)\) when calling", result.stderr)
            code = match.group(1).decode() if match else "Unknown"
            if code in absent:
                return None
            raise RuntimeError(f"AWS {service}/{operation} failed ({code}); review partial receipt")
        require(len(result.stdout) <= 1048576, "Oversized AWS response")
        value = json.loads(result.stdout or b"{}")
        require(isinstance(value, dict), "Malformed AWS response")
        return value


def root(call, account):
    caller = call("sts", "get-caller-identity", {})
    expected = {"Account": account, "Arn": f"arn:aws:iam::{account}:root", "UserId": account}
    require(all(caller.get(k) == v for k, v in expected.items()), "Exact account root session required")
    return expected


def complete(environment, key, call, receipt):
    account = ACCOUNTS[environment]
    require(re.fullmatch(f"arn:aws:kms:{REGION}:{account}:key/[0-9a-f]{{8}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-[0-9a-f]{{12}}", key), "Exact account single-region key ARN required")
    require(environment != "test" or key == TEST_KEY, "TEST key differs from independently created key")
    kp, bp = policy(environment, "seed-key"), policy(environment, "seed-artifact-bucket")
    receipt["caller_before"] = root(call, account)
    metadata = call("kms", "describe-key", {"KeyId": key})["KeyMetadata"]
    expected = {"Arn": key, "AWSAccountId": account, "KeyId": key.rsplit("/", 1)[1], "KeyManager": "CUSTOMER", "KeyState": "Enabled", "KeyUsage": "ENCRYPT_DECRYPT", "KeySpec": "SYMMETRIC_DEFAULT", "Origin": "AWS_KMS", "MultiRegion": False, "Enabled": True}
    require(all(metadata.get(k) == v for k, v in expected.items()), "Key metadata mismatch")
    actual_policy = json.loads(call("kms", "get-key-policy", {"KeyId": key, "PolicyName": "default"})["Policy"])
    require(actual_policy == kp, "Key policy differs from reviewed exact policy")
    bucket = f"issue215-independent-seed-{account}-{environment}"
    args = {"Bucket": bucket, "ExpectedBucketOwner": account}
    head = call("s3api", "head-bucket", args, absent=("404", "NoSuchBucket", "NotFound"))
    receipt.update(environment=environment, account_id=account, seed_key_arn=key, bucket=bucket, key_policy_sha256=digest(kp), bucket_policy_sha256=digest(bp), initial_bucket_observation="404-absent" if head is None else "owned-existing")
    if head is not None:
        require(call("s3api", "get-bucket-location", args).get("LocationConstraint") == REGION, "Existing bucket region mismatch")
        existing = call("s3api", "get-bucket-policy", args, absent=("NoSuchBucketPolicy",))
        require(existing is None or json.loads(existing["Policy"]) == bp, "Existing bucket has an unreviewed policy; refusing overwrite")

    def write(service, operation, parameters):
        root(call, account)
        receipt["attempted_writes"].append(f"{service}/{operation}")
        call(service, operation, parameters)
        receipt["completed_writes"].append(f"{service}/{operation}")

    if head is None:
        write("s3api", "create-bucket", {"Bucket": bucket, "CreateBucketConfiguration": {"LocationConstraint": REGION}, "ObjectOwnership": "BucketOwnerEnforced"})
    call("s3api", "head-bucket", args)
    require(call("s3api", "get-bucket-location", args).get("LocationConstraint") == REGION, "Bucket region mismatch")
    write("s3api", "put-public-access-block", dict(args, PublicAccessBlockConfiguration=PAB))
    write("s3api", "put-bucket-ownership-controls", dict(args, OwnershipControls=OWNERSHIP))
    write("s3api", "put-bucket-policy", dict(args, Policy=json.dumps(bp)))
    write("s3api", "put-bucket-versioning", dict(args, VersioningConfiguration={"Status": "Enabled"}))
    write("s3api", "put-bucket-encryption", dict(args, ServerSideEncryptionConfiguration=ENCRYPTION))
    write("kms", "enable-key-rotation", {"KeyId": key, "RotationPeriodInDays": 365})
    observed = {
        "public_access_block": call("s3api", "get-public-access-block", args)["PublicAccessBlockConfiguration"],
        "ownership": call("s3api", "get-bucket-ownership-controls", args)["OwnershipControls"],
        "versioning": call("s3api", "get-bucket-versioning", args),
        "encryption": call("s3api", "get-bucket-encryption", args)["ServerSideEncryptionConfiguration"],
        "bucket_policy": json.loads(call("s3api", "get-bucket-policy", args)["Policy"]),
        "rotation": call("kms", "get-key-rotation-status", {"KeyId": key}),
    }
    require(observed["public_access_block"] == PAB and observed["ownership"] == OWNERSHIP, "Bucket public-access/ownership readback mismatch")
    require(observed["versioning"].get("Status") == "Enabled", "Versioning readback mismatch")
    rules = observed["encryption"].get("Rules", [])
    require(len(rules) == 1 and rules[0].get("ApplyServerSideEncryptionByDefault") == {"SSEAlgorithm": "AES256"}, "SSE-S3 readback mismatch")
    require(observed["bucket_policy"] == bp, "Bucket policy readback mismatch")
    rotation = observed["rotation"]
    require(rotation.get("KeyId") in {key, expected["KeyId"]} and rotation.get("KeyRotationEnabled") is True and rotation.get("RotationPeriodInDays") == 365, "Rotation readback mismatch")
    require(json.loads(call("kms", "get-key-policy", {"KeyId": key, "PolicyName": "default"})["Policy"]) == kp, "Final key policy changed")
    final_key = call("kms", "describe-key", {"KeyId": key})["KeyMetadata"]
    require(all(final_key.get(k) == v for k, v in expected.items()), "Final key metadata changed")
    receipt["caller_after"] = root(call, account)
    receipt.update(status="verified-prerequisites-only", observed=observed, key_metadata=expected)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--environment", choices=tuple(ACCOUNTS), required=True)
    parser.add_argument("--seed-key-arn", required=True)
    parser.add_argument("--aws-executable", required=True)
    parser.add_argument("--receipt", required=True)
    args = parser.parse_args()
    receipt = {"schema_version": 1, "status": "incomplete", "attempted_writes": [], "completed_writes": [], "seed_enrollment_verified": False, "ownership_migrated": False, "activation_authorized": False}
    # Exclusive file reserves the receipt before any AWS call. A retry uses a new
    # filename; no historical receipt or resource is destroyed to recover.
    with open(args.receipt, "x", encoding="utf-8") as stream:
        os.chmod(args.receipt, 0o600)
        try:
            complete(args.environment, args.seed_key_arn, Native(args.aws_executable), receipt)
        finally:
            receipt["recorded_at"] = datetime.now(timezone.utc).isoformat()
            json.dump(receipt, stream, indent=2)
            stream.write("\n")
    print(json.dumps({"status": receipt["status"], "receipt": args.receipt}))


if __name__ == "__main__":
    main()
