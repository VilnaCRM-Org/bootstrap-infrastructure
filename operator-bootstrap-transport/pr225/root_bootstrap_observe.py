#!/usr/bin/env python3
"""One-time authorized root-CloudShell observation/packet helper; no AWS writes.

Run only the independently reviewed file from browser CloudShell. This is not a
routine worker, nonroot installer receipt, atomic snapshot, or apply authority.
Native CloudShell credential delivery stays inside AWS CLI; never export it.
"""

from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from dataclasses import asdict
from datetime import datetime, timezone

SOURCE_SHA = "c252f6c8c6edcea68f7fc99c147f28bfec93a013"
SOURCE_FILES = {
    "scripts/operator_aws_read.py": "1964b7dd292882048333dbb8455db73487aa9753c87effdc8b262cdaf4021a95",
    "scripts/operator_enrollment_runtime.py": "facb830e6d08b27da6a4d2e0a4cfacfb5f62fb473b3d0d8c44ab4078108e2bb6",
    "scripts/operator_seed_installation.py": "e40182f2e0fdd84b9471d2b2989dd38d56a1dba5cfde10fdb2569a8f2c9c32b5",
    "pulumi/seed/__init__.py": "a1803964acf8aa97a65e80c35f094c2b2b0ef53467377757402c8d8f829b166f",
    "pulumi/seed/operator_trust.py": "555a5e98d93704934958f1a1e37dddb37ea3a68a1d7fc169a7f93b47a5e2f3ea",
    "pulumi/seed/policy_registry.py": "49b6175eb3e6da6925a3d165691956abe9e926dc1b1011ed5a70acc5f3c1df43",
    "pulumi/seed/catalogs/test.json": "2402fb3bfa90bf490d2e67752f3b6ac56bd843c471a8ec5fa7570117937f16c0",
    "pulumi/seed/catalogs/prod.json": "06db09faeef44d39ecf1e588d053d19b81502ce042192ddbbc13d855f7c31beb",
}
ACCOUNTS = {"test": "891377212104", "prod": "933245420672"}
ENDPOINTS = {
    "sts": "https://sts.eu-central-1.amazonaws.com",
    "iam": "https://iam.amazonaws.com",
    "kms": "https://kms.eu-central-1.amazonaws.com",
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def load_source(path):
    source = Path(path).resolve(strict=True)
    for relative, expected_hash in SOURCE_FILES.items():
        item = source / relative
        require(item.resolve(strict=True).is_relative_to(source), "Source escaped root")
        require(
            hashlib.sha256(item.read_bytes()).hexdigest() == expected_hash,
            "Source differs from reviewed commit",
        )
    sys.path[:0] = [str(source / "scripts"), str(source / "pulumi")]
    import operator_aws_read as transport
    import operator_enrollment_runtime as enrollment
    import operator_seed_installation as installation
    from seed import policy_registry

    return transport, enrollment, installation, policy_registry


def ambient_read(transport, executable, service, operation, arguments):
    # Native AWS CLI resolves CloudShell's managed credential provider. No SDK
    # credential extraction, environment enumeration, shell, or raw log output.
    require(service in ENDPOINTS, "Unsupported service")
    command = [
        executable,
        service,
        operation.replace("_", "-"),
        "--cli-input-json",
        json.dumps(arguments, separators=(",", ":")),
        "--region",
        "us-east-1" if service == "iam" else "eu-central-1",
        "--endpoint-url",
        ENDPOINTS[service],
        "--output",
        "json",
        "--no-cli-pager",
        "--no-paginate",
        "--no-cli-auto-prompt",
        "--cli-connect-timeout",
        "5",
        "--cli-read-timeout",
        "20",
    ]
    # env=None intentionally inherits AWS-managed delivery without reading or
    # exposing its credential variables. Run in a fresh trusted CloudShell.
    return transport._response(transport._run(command, None))


def root_caller(transport, executable, account):
    caller = ambient_read(transport, executable, "sts", "get_caller_identity", {})
    require(
        caller.get("Account") == account
        and caller.get("Arn") == f"arn:aws:iam::{account}:root"
        and caller.get("UserId") == account,
        "Exact authorized account root session required",
    )
    return {key: caller[key] for key in ("Account", "Arn", "UserId")}


def run(args):
    transport, enrollment, installation, registry = load_source(args.source)
    executable = str(Path(args.aws_executable).resolve(strict=True))
    require(
        Path(executable).name == "aws" and os.access(executable, os.X_OK),
        "Trusted absolute AWS CLI v2 executable required",
    )
    require(Path(args.aws_executable).is_absolute(), "Absolute AWS CLI path required")
    account = ACCOUNTS[args.environment]
    caller = root_caller(transport, executable, account)
    require(
        re.fullmatch(
            f"arn:aws:kms:eu-central-1:{account}:key/"
            r"(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|mrk-[0-9a-f]{32})",
            args.seed_key_arn,
        )
        is not None,
        "Exact account seed key ARN required",
    )
    metadata = ambient_read(
        transport, executable, "kms", "describe_key", {"KeyId": args.seed_key_arn}
    ).get("KeyMetadata", {})
    key = registry.SeedKeyBinding(
        *(
            metadata.get(name)
            for name in (
                "Arn",
                "KeyId",
                "AWSAccountId",
                "KeyManager",
                "KeyState",
                "KeyUsage",
            )
        )
    )
    require(key.arn == args.seed_key_arn, "Observed seed key ARN mismatch")
    expected = registry.build_registry(
        args.environment, account_id=account, seed_key=key
    )
    guard = transport.AwsCliRead(expected, aws_executable=executable)

    def call(service, operation, arguments):
        guard._parameters(service, operation, arguments)
        return ambient_read(transport, executable, service, operation, arguments)

    receipt = {
        "source_sha": SOURCE_SHA,
        "caller_provenance": caller,
        "authorization": "User-authorized one-time root browser bootstrap",
        "mode": args.mode,
        "environment": args.environment,
        "activation_authorized": False,
        "atomic_snapshot": False,
    }
    if args.mode == "packets":
        packet = installation.build_installation(
            args.environment, account_id=account, seed_key=key
        )
        activation = installation.build_activation(packet)
        destination = Path(args.output_directory)
        destination.mkdir(mode=0o700, parents=True, exist_ok=True)
        documents = {
            "import-template.json": packet.import_template,
            "resources-to-import.json": packet.resources_to_import,
            "enrollment-template.json": packet.enrollment_template,
            "boundary-manifest.json": packet.boundary_manifest,
            "stack-policy.json": packet.stack_policy,
            "activation-template.json": activation.activation_template,
            "activation-temporary-stack-policy.json": activation.temporary_stack_policy,
            "seed-key-binding.json": registry.canonical_json(asdict(key)),
        }
        require(
            not any((destination / name).exists() for name in documents),
            "Packet files already exist; do not overwrite reviewed artifacts",
        )
        hashes = {}
        for name, value in documents.items():
            data = value.encode("utf-8")
            with (destination / name).open("xb") as stream:
                stream.write(data)
            hashes[name] = {
                "sha256": hashlib.sha256(data).hexdigest(),
                "bytes": len(data),
            }
        receipt.update(artifacts=hashes, installation_verified=False)
    else:
        observed = enrollment._collect_metadata(expected, call=call)
        verifier = (
            registry.verify_enrollment
            if args.mode == "disabled"
            else registry.verify_active_enrollment
        )
        receipt["verification"] = asdict(verifier(expected, observed))
    require(
        root_caller(transport, executable, account) == caller,
        "Caller changed during observation",
    )
    receipt["observed_at"] = datetime.now(timezone.utc).isoformat()
    return receipt


def main():
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--source", required=True)
    parser.add_argument("--aws-executable", required=True)
    parser.add_argument("--environment", required=True, choices=tuple(ACCOUNTS))
    parser.add_argument("--seed-key-arn", required=True)
    parser.add_argument(
        "--mode", required=True, choices=("packets", "disabled", "active")
    )
    parser.add_argument("--output-directory", default="seed-packets")
    try:
        result = run(parser.parse_args())
    except Exception:
        print(
            "Root bootstrap observation failed; no success receipt issued.",
            file=sys.stderr,
        )
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
