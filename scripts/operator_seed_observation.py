"""Independently authenticated, read-only initial seed enrollment CLI.

Invoke trusted source with isolated Python and an already-issued nonroot AWS
session. The caller supplies a separately reviewed installer IAM role ARN and
public DescribeKey binding. Matching that ARN authenticates identity, not its
administrative authority or approval. Those remain external prerequisites.

Only STS identity, the one exact installer GetRole, and the existing closed
enrollment metadata operations are read. No role assumption, secret retrieval,
credential creation, IAM mutation or trust activation occurs. Successful output
contains public digests/counts for disabled enrollment; it is not a deployment
authorization or proof that IAM stayed unchanged after these non-atomic reads.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path[:0] = [
    str(Path(__file__).resolve().parent),
    str(Path(__file__).resolve().parents[1] / "pulumi"),
]

import argparse  # noqa: E402
import json  # noqa: E402
import re  # noqa: E402
from dataclasses import asdict, fields  # noqa: E402
from typing import Any, NoReturn, cast  # noqa: E402

import operator_aws_read as aws_read  # noqa: E402
import operator_enrollment_runtime as enrollment  # noqa: E402
from seed import policy_registry as registry  # noqa: E402


def _require(condition: bool, message: str) -> None:
    """Use safe constant diagnostics without embedding caller or AWS values."""
    if not condition:
        raise registry.RegistryError(message)


def _installer_name(expected: registry.SeedRegistry, installer_role_arn: str) -> str:
    """Reject roots, users, foreign accounts and known routine principals."""
    prefix = f"arn:aws:iam::{expected.account_id}:role/"
    _require(type(installer_role_arn) is str, "Invalid installer role identity")
    _require(installer_role_arn.startswith(prefix), "Invalid installer account or role")
    resource = installer_role_arn[len(prefix) :]
    _require(
        len(resource) <= 576
        and re.fullmatch(r"(?:[A-Za-z0-9_+=,.@-]+/)*[A-Za-z0-9_+=,.@-]{1,64}", resource)
        is not None,
        "Invalid installer role path or name",
    )
    _require(
        installer_role_arn not in {p.arn for p in expected.principals},
        "Routine enrolled roles cannot be independent installers",
    )
    return resource.rsplit("/", 1)[-1]


def _installer_role(aws_executable: str, region: str, role_name: str) -> dict[str, Any]:
    """Read only the validated installer's GetRole using the bounded transport.

    AwsCliRead has already validated the trusted absolute executable. Keeping
    this one operation separate preserves its routine 24-role resource ceiling.
    """
    command = [
        aws_executable,
        "iam",
        "get-role",
        "--cli-input-json",
        json.dumps({"RoleName": role_name}),
        "--region",
        region,
        "--output",
        "json",
        "--no-cli-pager",
        "--no-paginate",
        "--cli-connect-timeout",
        "5",
        "--cli-read-timeout",
        "20",
    ]
    response = aws_read._response(
        aws_read._run(command, aws_read._session_environment())
    )
    return dict(enrollment._object(response.get("Role")))


def _authenticate_installer(
    expected: registry.SeedRegistry,
    installer_role_arn: str,
    *,
    call: enrollment.AwsRead,
    aws_executable: str,
) -> None:
    """Bind STS session identity to live exact-path IAM ARN and immutable RoleId."""
    name = _installer_name(expected, installer_role_arn)
    caller = enrollment._read(call, "sts", "get_caller_identity")
    prefix = f"arn:aws:sts::{expected.account_id}:assumed-role/{name}/"
    arn = caller.get("Arn")
    _require(
        caller.get("Account") == expected.account_id
        and type(arn) is str
        and arn.startswith(prefix)
        and re.fullmatch(r"[A-Za-z0-9_+=,.@-]{2,64}", arn[len(prefix) :]) is not None,
        "STS caller is not the reviewed installer role",
    )
    session = cast(str, arn)[len(prefix) :]
    role = _installer_role(aws_executable, expected.region, name)
    role_id = role.get("RoleId")
    _require(
        role.get("Arn") == installer_role_arn
        and role.get("RoleName") == name
        and type(role_id) is str
        and re.fullmatch(r"AROA[A-Z0-9]{12,124}", role_id) is not None,
        "Live installer role metadata does not match reviewed identity",
    )
    _require(
        caller.get("UserId") == f"{role_id}:{session}",
        "Installer session does not match immutable role identity",
    )


def observe_initial_enrollment(
    environment: str,
    *,
    account_id: str,
    seed_key: registry.SeedKeyBinding,
    installer_role_arn: str,
    aws_executable: str,
) -> registry.EnrollmentVerification:
    """Use actual ambient session credentials and verify complete disabled IAM."""
    expected = registry.build_registry(
        environment, account_id=account_id, seed_key=seed_key
    )
    call = aws_read.AwsCliRead(expected, aws_executable=aws_executable)
    _authenticate_installer(
        expected, installer_role_arn, call=call, aws_executable=aws_executable
    )
    observed = enrollment._collect_metadata(expected, call=call)
    return registry.verify_enrollment(expected, observed)


def _key_binding(payload: str) -> registry.SeedKeyBinding:
    """Decode bounded strict public metadata, never a credential-file source."""
    _require(len(payload.encode("utf-8")) <= 4096, "Seed binding exceeds bound")
    value = aws_read._response(payload.encode("utf-8"))
    _require(
        set(value) == {field.name for field in fields(registry.SeedKeyBinding)}
        and all(type(item) is str for item in value.values()),
        "Exact public seed key fields are required",
    )
    return registry.SeedKeyBinding(**cast(dict[str, str], value))


class _Parser(argparse.ArgumentParser):
    """Never reflect malformed argument values in diagnostics."""

    def error(self, message: str) -> NoReturn:
        """Replace argparse's value-bearing error text with a constant error."""
        raise ValueError("Invalid initial observation arguments")


def main(argv: list[str] | None = None) -> int:
    """Run the native read-only CLI and print only verified digests and counts."""
    parser = _Parser(description=__doc__, allow_abbrev=False)
    for name in (
        "environment",
        "account-id",
        "seed-key-binding",
        "installer-role-arn",
        "aws-executable",
    ):
        parser.add_argument(f"--{name}", required=True)
    try:
        arguments = parser.parse_args(argv)
        result = observe_initial_enrollment(
            arguments.environment,
            account_id=arguments.account_id,
            seed_key=_key_binding(arguments.seed_key_binding),
            installer_role_arn=arguments.installer_role_arn,
            aws_executable=arguments.aws_executable,
        )
    except Exception:
        print("Initial seed enrollment observation failed.", file=sys.stderr)
        return 1
    print(registry.canonical_json(asdict(result)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
