"""Private CloudShell-only candidate preparation; no network or mutation APIs.

Input is the versioned S3 checkpoint, not Pulumi stack export. Only synthetic
fixtures may be processed locally. Caller authenticates STS and S3 observations;
this pure helper checks their shape/bindings, not their provenance or freshness.
"""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import os
import stat
from pathlib import Path

LIMIT = 32 * 1024 * 1024
POLICY = "aws:iam/policy:Policy"
ROLE = "aws:iam/role:Role"
OIDC = "aws:iam/openIdConnectProvider:OpenIdConnectProvider"


def require(ok, code):
    if not ok:
        raise ValueError(code)


def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, "duplicate-json-key")
        result[key] = value
    return result


def decode(raw):
    require(0 < len(raw) <= LIMIT, "checkpoint-size")
    return json.loads(
        raw,
        object_pairs_hook=pairs,
        parse_constant=lambda _: require(False, "nonfinite-json"),
    )


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def read_bounded(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(
            stat.S_ISREG(info.st_mode) and info.st_size <= LIMIT,
            "input-file-type-or-size",
        )
        raw = stream.read(LIMIT + 1)
    require(len(raw) <= LIMIT, "input-size")
    return raw


def strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for child in value.values():
            yield from strings(child)
    elif isinstance(value, list):
        for child in value:
            yield from strings(child)


def graph(resources, environment):
    require(isinstance(resources, list) and bool(resources), "resource-list-required")
    urns = [r["urn"] for r in resources]
    require(len(urns) == len(set(urns)), "duplicate-urn")
    known = set(urns)
    prefix = f"urn:pulumi:{environment}::github-ci-bootstrap::"
    for row in resources:
        require(row["urn"].startswith(prefix), "foreign-stack-urn")
        require(
            not row.get("delete") and not row.get("pendingReplacement"),
            "pending-resource",
        )
        require(isinstance(row.get("dependencies", []), list), "dependency-shape")
        refs = list(row.get("dependencies", []))
        for values in row.get("propertyDependencies", {}).values():
            require(isinstance(values, list), "property-dependency-shape")
            refs.extend(values)
        refs.extend(row[k] for k in ("parent", "deletedWith") if row.get(k))
        if row.get("provider"):
            refs.append(row["provider"].rsplit("::", 1)[0])
        require(all(ref in known for ref in refs), "dangling-structural-reference")


def owned(resources, kind, identity):
    matches = [
        r
        for r in resources
        if r.get("type") == kind
        and r.get("id") == identity
        and not r.get("external", False)
    ]
    require(
        len(matches) == 1 and matches[0].get("custom") is True, "managed-owner-mismatch"
    )
    return matches[0]


def validate_observation(observed, config, raw):
    account = config["account_id"]
    require(
        observed["caller"]["Account"] == account
        and observed["caller"]["Arn"] == f"arn:aws:iam::{account}:root"
        and observed["caller"]["UserId"] == account,
        "root-account-mismatch",
    )
    require(
        observed["bucket"] == config["bucket"]
        and observed["key"] == config["operator_key"],
        "backend-mismatch",
    )
    head = observed["before"]
    require(
        isinstance(head["VersionId"], str)
        and head["VersionId"] not in ("", "null")
        and isinstance(head["ETag"], str)
        and head["ETag"].startswith('"')
        and head["ETag"].endswith('"'),
        "versioned-object-required",
    )
    fields = (
        "VersionId",
        "ETag",
        "ContentLength",
        "ServerSideEncryption",
        "SSEKMSKeyId",
        "BucketKeyEnabled",
    )
    require(
        all(observed["after"].get(k) == head.get(k) for k in fields),
        "current-pointer-changed",
    )
    require(
        all(observed["get"].get(k) == head.get(k) for k in fields)
        and head["ContentLength"] == len(raw)
        and observed["sha256"] == digest(raw),
        "download-mismatch",
    )
    require(
        (
            head.get("ServerSideEncryption") == "AES256"
            and head.get("SSEKMSKeyId") is None
        )
        or (
            head.get("ServerSideEncryption") == "aws:kms"
            and head.get("SSEKMSKeyId") == config["backend_key"]
        ),
        "backend-encryption-mismatch",
    )


def prepare(raw, config, phase, observation, live_roles=None):
    validate_observation(observation, config, raw)
    original = decode(raw)
    require(
        type(original.get("version")) is int and original["version"] == 3,
        "checkpoint-version",
    )
    result = copy.deepcopy(original)
    latest = result["checkpoint"]["latest"]
    require(
        isinstance(latest.get("pending_operations", []), list),
        "pending-operation-shape",
    )
    require(
        not latest.get("pending_operations")
        and not latest.get("metadata", {}).get("integrity_error"),
        "pending-or-corrupt-checkpoint",
    )
    provider = latest["secrets_providers"]
    require(
        provider["type"] == "cloud"
        and provider["state"]["url"] == config["secrets_provider"],
        "secrets-provider-mismatch",
    )
    require(
        bool(base64.b64decode(provider["state"]["encryptedkey"], validate=True)),
        "encrypted-key-required",
    )
    rows = latest["resources"]
    graph(rows, config["environment"])
    removed = set()
    changed = []
    if phase == "release":
        for arn in config["boundary_arns"]:
            row = owned(rows, POLICY, arn)
            name = arn.rsplit("/", 1)[-1]
            require(
                row["outputs"]["arn"] == arn and row["inputs"]["name"] == name,
                "boundary-identity-mismatch",
            )
            parent_type = (
                "bootstrap:iam:PlatformIamBoundaries"
                if name.startswith("PlatformBoundary-")
                else "bootstrap:ci:GovernanceAutomation"
            )
            require(
                f"::{parent_type}${POLICY}::" in row["urn"], "boundary-parent-mismatch"
            )
            removed.add(row["urn"])
        require(len(removed) == 6, "six-boundaries-required")
        rows[:] = [r for r in rows if r["urn"] not in removed]
        for row in rows:
            if "dependencies" in row:
                row["dependencies"] = [
                    r for r in row["dependencies"] if r not in removed
                ]
            for key, refs in row.get("propertyDependencies", {}).items():
                row["propertyDependencies"][key] = [r for r in refs if r not in removed]
            require(
                not removed.intersection(strings(row)),
                "unsupported-removed-resource-reference",
            )
        oidc = owned(rows, OIDC, config["oidc_arn"])
        require(
            oidc["urn"].endswith("::github-ci-bootstrap-oidc-provider")
            and "bootstrap:ci:GitHubCiBootstrap$bootstrap:iam:GitHubOidcRoles$"
            in oidc["urn"],
            "oidc-owner-urn",
        )
        oidc["external"] = True
        changed.append({"urn": oidc["urn"], "fields": ["external"]})
    elif phase == "bindings":
        require(
            not any(
                r.get("type") == POLICY and r.get("id") in config["boundary_arns"]
                for r in rows
            ),
            "boundary-records-not-released",
        )
        require(
            any(
                r.get("id") == config["oidc_arn"]
                and r.get("external")
                and r["urn"].endswith("::github-ci-bootstrap-oidc-provider")
                for r in rows
            ),
            "oidc-not-external",
        )
        require(
            isinstance(live_roles, dict)
            and set(live_roles) == set(config["role_boundaries"]),
            "eight-live-roles-required",
        )
        for arn, boundary in config["role_boundaries"].items():
            live = live_roles[arn]["Role"]
            require(
                live["Arn"] == arn
                and live["RoleName"] == arn.rsplit("/", 1)[-1]
                and live["PermissionsBoundary"]
                == {
                    "PermissionsBoundaryType": "Policy",
                    "PermissionsBoundaryArn": boundary,
                },
                "live-boundary-mismatch",
            )
            row = owned(rows, ROLE, live["RoleName"])
            require(row["outputs"]["arn"] == arn, "role-arn-mismatch")
            for key in ("inputs", "outputs"):
                require(
                    row[key].get("permissionsBoundary") in (None, ""),
                    "existing-boundary-conflict",
                )
                row[key]["permissionsBoundary"] = boundary
            changed.append(
                {
                    "urn": row["urn"],
                    "fields": [
                        "inputs.permissionsBoundary",
                        "outputs.permissionsBoundary",
                    ],
                }
            )
    else:
        raise ValueError("unknown-phase")
    graph(rows, config["environment"])
    require(
        latest["secrets_providers"]
        == original["checkpoint"]["latest"]["secrets_providers"],
        "provider-mutated",
    )
    candidate = (
        json.dumps(result, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
        + "\n"
    ).encode()
    receipt = {
        "status": "CANDIDATE_ONLY",
        "phase": phase,
        "account_id": config["account_id"],
        "source_sha256": digest(raw),
        "candidate_sha256": digest(candidate),
        "source_version_id": observation["before"]["VersionId"],
        "source_etag": observation["before"]["ETag"],
        "removed_urns": sorted(removed),
        "changed_fields": changed,
        "remaining_urns_preserved": True,
        "secrets_ciphertext_preserved": True,
        "live_provenance_authenticated_by_helper": False,
        "writes_executed": False,
    }
    return candidate, receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("checkpoint", "observation", "candidate", "receipt", "inventory"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--environment", choices=("test", "prod"), required=True)
    parser.add_argument("--phase", choices=("release", "bindings"), required=True)
    parser.add_argument("--live-roles", type=Path)
    args = parser.parse_args()
    inventory = decode(read_bounded(args.inventory))
    config = dict(inventory["accounts"][args.environment], environment=args.environment)
    raw = read_bounded(args.checkpoint)
    live = decode(read_bounded(args.live_roles)) if args.live_roles else None
    candidate, receipt = prepare(
        raw, config, args.phase, decode(read_bounded(args.observation)), live
    )
    receipt["source_commit"] = inventory["source_commit"]
    for path, payload in (
        (args.candidate, candidate),
        (args.receipt, (json.dumps(receipt, indent=2) + "\n").encode()),
    ):
        descriptor = os.open(
            path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
        )
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
    print("CANDIDATE_ONLY: private files prepared; no AWS calls or writes")


if __name__ == "__main__":
    main()
