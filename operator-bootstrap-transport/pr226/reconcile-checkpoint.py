#!/usr/bin/env python3
"""Private TEST8 checkpoint reconciliation. No body output; no mutation retries.
prepare ROOT OWNER INVENTORY SOURCE PACKETS NEW_OUTPUT AWS
publish ROOT OWNER INVENTORY SOURCE PACKETS NEW_OUTPUT AWS --prepared PREPARED
Prepare is read-only. Publish writes one verified recovery then one IfMatch object.
"""
import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
from urllib.parse import urlencode
import uuid

ACCOUNT = "891377212104"
BUCKET = "pulumi-bootstrap-infrastructure-test-state"
KEY = ".pulumi/stacks/github-ci-bootstrap/test.json"
VERSION = "hdhCm7nMHn1nLS1tFKw9YwChUVjUOCVP"
ETAG = '"9490f9b2b9f19fb7d3c05f2340348101"'
SEED_BUCKET = "issue215-independent-seed-891377212104-test"
SEED_KEY = "arn:aws:kms:eu-central-1:891377212104:key/64db70a2-7c25-420f-85b6-eeae0618897d"
ROOT_HASH = "262ddcb3b76a82a0306c2df5735418f4b58cf5205292a8f8e614d0cbb8e8bb18"
OWNER_HASH = "8b878242238af9c82345274a9ab4842b8df0220801b84074e6cd92deb6507e05"
INVENTORY_HASH = "4bf0860348f3218137da784d0c68fe2ea2e7c71442788e0ea2252aad2e280847"
ATTRIBUTES = ("ContentType", "ContentEncoding", "ContentLanguage", "ContentDisposition",
              "CacheControl", "Expires", "WebsiteRedirectLocation")


def load(path, name, digest):
    assert hashlib.sha256(Path(path).read_bytes()).hexdigest() == digest
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def checksum(raw):
    return base64.b64encode(hashlib.sha256(raw).digest()).decode("ascii")


def attributes(head):
    assert head["ServerSideEncryption"] == "AES256" and not head.get("SSEKMSKeyId")
    assert not head.get("BucketKeyEnabled") and head.get("StorageClass", "STANDARD") == "STANDARD"
    assert not any(head.get(k) for k in ("ObjectLockMode", "ObjectLockRetainUntilDate", "ObjectLockLegalHoldStatus"))
    result = {k: head[k] for k in ATTRIBUTES if k in head}
    assert isinstance(head.get("Metadata", {}), dict)
    result.update(Metadata=head.get("Metadata", {}), ServerSideEncryption="AES256")
    return result


def tags(value):
    rows = value["TagSet"]
    assert isinstance(rows, list) and len(rows) <= 10
    assert all(set(x) == {"Key", "Value"} and all(isinstance(v, str) for v in x.values()) for x in rows)
    assert len({x["Key"] for x in rows}) == len(rows)
    return sorted((x["Key"], x["Value"]) for x in rows)


def main():
    if sys.flags.optimize:
        raise ValueError("Assertions must remain enabled")
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("phase", choices=("prepare", "publish"))
    for name in ("root", "owner", "inventory", "source", "packets", "output", "aws"):
        parser.add_argument(name)
    parser.add_argument("--prepared")
    args = parser.parse_args()
    assert (args.prepared is not None) == (args.phase == "publish")
    helper = load(args.root, "root_observer", ROOT_HASH)
    owner = load(args.owner, "checkpoint_owner", OWNER_HASH)
    assert hashlib.sha256(Path(args.inventory).read_bytes()).hexdigest() == INVENTORY_HASH
    inventory = owner.decode(owner.read_bounded(Path(args.inventory)))
    config = dict(inventory["accounts"]["test"], environment="test")
    assert config["account_id"] == ACCOUNT and config["bucket"] == BUCKET and config["operator_key"] == KEY
    assert helper.SOURCE_SHA == "88dfaf1f47e1afe55d282e7a2b2efa9afa2be78d"
    transport, _, installation, registry = helper.load_source(args.source)
    assert Path(args.aws).is_absolute() and Path(args.aws).resolve(strict=True).name == "aws"
    os.environ["AWS_MAX_ATTEMPTS"] = "1"
    os.umask(0o077)
    out = Path(args.output).resolve()
    out.mkdir(mode=0o700)
    packets = Path(args.packets).resolve(strict=True)
    key = registry.SeedKeyBinding(**owner.decode(owner.read_bounded(packets / "seed-key-binding.json")))
    assert key.arn == SEED_KEY
    packet = installation.build_installation("test", account_id=ACCOUNT, seed_key=key)
    manifest = owner.decode(packet.boundary_manifest.encode())
    assert {x["precondition"]["RoleArn"]: x["parameters"]["PermissionsBoundary"] for x in manifest["operations"]} == config["role_boundaries"]
    caller = helper.root_caller(transport, args.aws, ACCOUNT)

    def write(name, raw):
        fd = os.open(out / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)

    def save(name, value):
        write(name, (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode())

    def call(service, operation, *parameters):
        assert (service == "s3api" and operation in {
            "get-bucket-versioning", "head-object", "get-object", "get-object-tagging", "list-objects-v2", "put-object"
        }) or (service == "iam" and operation in {"get-role", "get-role-policy"})
        region = "us-east-1" if service == "iam" else "eu-central-1"
        endpoint = "https://iam.amazonaws.com" if service == "iam" else "https://s3.eu-central-1.amazonaws.com"
        command = [args.aws, service, operation, "--region", region, "--endpoint-url", endpoint,
            "--no-cli-pager", "--no-cli-auto-prompt", "--no-paginate", "--output", "json",
            "--cli-connect-timeout", "5", "--cli-read-timeout", "20", *parameters]
        return transport._response(transport._run(command, None))

    def source_head(label):
        head = call("s3api", "head-object", "--bucket", BUCKET, "--key", KEY, "--expected-bucket-owner", ACCOUNT)
        assert (head["VersionId"], head["ETag"]) == (VERSION, ETAG)
        assert type(head["ContentLength"]) is int and 0 < head["ContentLength"] <= owner.LIMIT
        attributes(head)
        save(label, head)
        return head

    def read_tags(bucket, object_key, version):
        result = call("s3api", "get-object-tagging", "--bucket", bucket, "--key", object_key,
                      "--version-id", version, "--expected-bucket-owner", ACCOUNT)
        tags(result)
        return result

    def conditions(label):
        assert helper.root_caller(transport, args.aws, ACCOUNT) == caller
        metadata = helper.ambient_read(transport, args.aws, "kms", "describe_key", {"KeyId": SEED_KEY})["KeyMetadata"]
        assert key == registry.SeedKeyBinding(*(metadata[k] for k in ("Arn", "KeyId", "AWSAccountId", "KeyManager", "KeyState", "KeyUsage")))
        save(label + "-seed-key.json", metadata)
        for index, bucket in enumerate((BUCKET, SEED_BUCKET)):
            versioning = call("s3api", "get-bucket-versioning", "--bucket", bucket, "--expected-bucket-owner", ACCOUNT)
            assert versioning["Status"] == "Enabled"
            save(f"{label}-versioning-{index}.json", versioning)
        live = {}
        assert len(config["role_boundaries"]) == 8
        for index, (arn, boundary) in enumerate(config["role_boundaries"].items()):
            response = call("iam", "get-role", "--role-name", arn.rsplit("/", 1)[-1])
            role = response["Role"]
            assert role["Arn"] == arn and role["RoleName"] == arn.rsplit("/", 1)[-1]
            assert role["PermissionsBoundary"] == {"PermissionsBoundaryType": "Policy", "PermissionsBoundaryArn": boundary}
            live[arn] = response
            save(f"{label}-role-{index}.json", response)
        held = ["GitHubGovernanceApply-test", "GitHubCiApply-bootstrap-infrastructure-test",
            "GitHubCiApply-user-service-infrastructure-test", "PulumiAutomation-bootstrap-infrastructure-test", "PulumiDeploy-bootstrap-infrastructure"]
        deny = {"Version": "2012-10-17", "Statement": [{"Sid": "HoldOrdinaryIacDuringIndependentCutover", "Effect": "Deny", "Action": "*", "Resource": "*"}]}
        for index, name in enumerate(held):
            response = call("iam", "get-role-policy", "--role-name", name, "--policy-name", "Issue215CutoverSessions")
            assert response["RoleName"] == name and response["PolicyName"] == "Issue215CutoverSessions"
            document = response["PolicyDocument"]
            assert (document if isinstance(document, dict) else owner.decode(document.encode())) == deny
            save(f"{label}-hold-{index}.json", response)
        locks = call("s3api", "list-objects-v2", "--bucket", BUCKET, "--expected-bucket-owner", ACCOUNT, "--prefix", ".pulumi/locks/")
        assert locks["IsTruncated"] is False and locks["KeyCount"] == 0 and not locks.get("Contents")
        save(label + "-locks.json", locks)
        return live

    def download(bucket, object_key, version, etag, name, *, recovery=False):
        path = out / name
        assert not path.exists()
        parameters = ["--bucket", bucket, "--key", object_key, "--expected-bucket-owner", ACCOUNT,
                      "--version-id", version, "--if-match", etag]
        if recovery:
            parameters += ["--checksum-mode", "ENABLED"]
        response = call("s3api", "get-object", *parameters, str(path))
        assert response["VersionId"] == version and response["ETag"] == etag
        raw = owner.read_bounded(path)
        assert len(raw) == response["ContentLength"]
        save(name + ".metadata.json", response)
        return raw, response

    live = conditions("before")
    head = source_head("source-head-before.json")
    original_tags = read_tags(BUCKET, KEY, VERSION)
    save("source-tags.json", original_tags)
    if args.phase == "prepare":
        original, get = download(BUCKET, KEY, VERSION, ETAG, "operator-original.json")
        after = source_head("source-head-after.json")
        observation = {"caller": caller, "bucket": BUCKET, "key": KEY, "before": head,
            "get": get, "after": after, "sha256": owner.digest(original)}
        candidate, receipt = owner.prepare(original, config, "bindings", observation, live)
        receipt["source_commit"] = inventory["source_commit"]
        assert len(receipt["changed_fields"]) == 8 and receipt["removed_urns"] == []
        assert all(x["fields"] == ["inputs.permissionsBoundary", "outputs.permissionsBoundary"] for x in receipt["changed_fields"])
        assert len(candidate) <= owner.LIMIT
        assert attributes(head) == attributes(get) == attributes(after)
        assert tags(read_tags(BUCKET, KEY, VERSION)) == tags(original_tags)
        assert helper.root_caller(transport, args.aws, ACCOUNT) == caller
        save("operator-observation.json", observation)
        save("live-roles.json", live)
        write("operator-bindings.json", candidate)
        save("bindings-receipt.json", receipt)
        print("CANDIDATE_ONLY: eight boundary records; private files prepared; no S3 writes.")
        return

    prepared = Path(args.prepared).resolve(strict=True)
    def read(name):
        return owner.decode(owner.read_bounded(prepared / name))
    original = owner.read_bounded(prepared / "operator-original.json")
    observation = read("operator-observation.json")
    candidate, receipt = owner.prepare(original, config, "bindings", observation, live)
    receipt["source_commit"] = inventory["source_commit"]
    assert candidate == owner.read_bounded(prepared / "operator-bindings.json") and receipt == read("bindings-receipt.json")
    assert len(receipt["changed_fields"]) == 8 and receipt["removed_urns"] == []
    assert len(candidate) <= owner.LIMIT
    assert head["ContentLength"] == len(original) and attributes(head) == attributes(observation["before"])
    assert tags(original_tags) == tags(read("source-tags.json"))
    # Reauthenticate source bytes from the immutable version; never let a
    # coherent edit of local original/observation/receipt authorize other changes.
    authenticated_original, authenticated_meta = download(BUCKET, KEY, VERSION, ETAG, "source-version-readback.json")
    assert authenticated_original == original and attributes(authenticated_meta) == attributes(head)
    write("original-for-recovery.json", original)
    write("candidate-for-publication.json", candidate)
    recovery_key = "pr226/test/checkpoint-bindings/" + uuid.uuid4().hex + ".json"
    recovery_metadata = {"ServerSideEncryption": "aws:kms", "SSEKMSKeyId": SEED_KEY,
        "ChecksumSHA256": checksum(original), "Metadata": {"source-bucket": BUCKET,
        "source-key": KEY, "source-version": VERSION, "source-sha256": owner.digest(original)}}
    save("recovery-metadata.json", recovery_metadata)
    save("recovery-intent.json", {"bucket": SEED_BUCKET, "key": recovery_key,
        "source_version": VERSION, "source_sha256": owner.digest(original), "caller": caller})
    recovered = call("s3api", "put-object", "--bucket", SEED_BUCKET, "--key", recovery_key,
        "--expected-bucket-owner", ACCOUNT, "--body", str(out / "original-for-recovery.json"),
        "--if-none-match", "*", "--cli-input-json", "file://" + str(out / "recovery-metadata.json"))
    save("recovery-put.json", recovered)
    recovery_version = recovered["VersionId"]
    assert recovery_version not in ("", "null") and recovered["ChecksumSHA256"] == checksum(original)
    body, meta = download(SEED_BUCKET, recovery_key, recovery_version, recovered["ETag"], "recovery-readback.json", recovery=True)
    assert body == original and meta["ServerSideEncryption"] == "aws:kms" and meta["SSEKMSKeyId"] == SEED_KEY
    assert meta["ChecksumSHA256"] == checksum(original)
    save("recovery-verified.json", {"bucket": SEED_BUCKET, "key": recovery_key,
        "version_id": recovery_version, "sha256": owner.digest(body), "seed_key": SEED_KEY})
    conditions("prepublication")
    latest = source_head("source-head-prepublication.json")
    assert latest["ContentLength"] == len(original) and attributes(latest) == attributes(head)
    assert tags(read_tags(BUCKET, KEY, VERSION)) == tags(original_tags)
    publish_metadata = attributes(head)
    publish_metadata["ChecksumSHA256"] = checksum(candidate)
    if tags(original_tags):
        publish_metadata["Tagging"] = urlencode(tags(original_tags))
    save("publish-metadata.json", publish_metadata)
    save("publication-intent.json", {"bucket": BUCKET, "key": KEY, "source_version": VERSION,
        "if_match": ETAG, "candidate_sha256": owner.digest(candidate), "recovery_version": recovery_version,
        "source_sha256": owner.digest(original), "caller": caller, "attempts": 1})
    published = call("s3api", "put-object", "--bucket", BUCKET, "--key", KEY, "--expected-bucket-owner", ACCOUNT,
        "--body", str(out / "candidate-for-publication.json"), "--if-match", ETAG,
        "--cli-input-json", "file://" + str(out / "publish-metadata.json"))
    save("publication-put.json", published)
    version = published["VersionId"]
    assert isinstance(version, str) and version not in ("", "null", VERSION)
    assert published["ChecksumSHA256"] == checksum(candidate)
    body, meta = download(BUCKET, KEY, version, published["ETag"], "published-readback.json", recovery=True)
    assert body == candidate and attributes(meta) == attributes(head) and meta["ChecksumSHA256"] == checksum(candidate)
    assert tags(read_tags(BUCKET, KEY, version)) == tags(original_tags)
    current = call("s3api", "head-object", "--bucket", BUCKET, "--key", KEY, "--expected-bucket-owner", ACCOUNT)
    assert (current["VersionId"], current["ETag"], current["ContentLength"]) == (version, published["ETag"], len(candidate))
    assert attributes(current) == attributes(head)
    assert helper.root_caller(transport, args.aws, ACCOUNT) == caller
    save("current-pointer.json", current)
    save("publication-verified.json", {"account": ACCOUNT, "source_version": VERSION,
        "new_version": version, "new_etag": published["ETag"], "candidate_sha256": owner.digest(candidate),
        "recovery_bucket": SEED_BUCKET, "recovery_key": recovery_key, "recovery_version": recovery_version,
        "verified_role_records": 8, "activation_authorized": False, "full_enrollment_verified": False})
    print("Eight-boundary checkpoint publication verified by immutable and current-pointer readback; activation remains separate.")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("Checkpoint reconciliation incomplete. Keep private files and holds; inspect recorded intent/current immutable S3 versions before further actions. Never automatically retry an uncertain write.", file=sys.stderr)
        raise SystemExit(1) from None
