"""Bounded AWS CLI transport for public operator enrollment metadata only.

The trusted worker supplies an absolute AWS CLI v2 executable and already-issued
ambient OIDC session credentials. This adapter never assumes roles or loads
credential files. The collector verifies the exact STS caller before other reads;
neither credential presence nor this transport proves OIDC provenance or admits
a deployment. Policy/trust/document and pagination semantics remain the
collector's responsibility. Each invocation returns exactly one API page.
"""

from __future__ import annotations

import json
import os
import re
import selectors
import subprocess  # nosec B404
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any, BinaryIO, cast

from seed import policy_registry as registry

MAX_STDOUT_BYTES = 2 * 1024 * 1024
MAX_STDERR_BYTES = 64 * 1024
PROCESS_TIMEOUT_SECONDS = 45
_SESSION_KEYS = ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN")
_READS = {
    ("sts", "get_caller_identity"): (),
    ("kms", "describe_key"): ("KeyId",),
    ("iam", "get_policy"): ("PolicyArn",),
    ("iam", "get_policy_version"): ("PolicyArn", "VersionId"),
    ("iam", "get_role"): ("RoleName",),
    ("iam", "list_attached_role_policies"): ("RoleName", "MaxItems"),
    ("iam", "list_role_policies"): ("RoleName", "MaxItems"),
    ("iam", "get_role_policy"): ("RoleName", "PolicyName"),
}


class AwsReadError(ValueError):
    """A safe error that contains no AWS response, stderr, or credential values."""


def _require(condition: bool, message: str) -> None:
    """Reject invalid inputs before starting any process."""
    if not condition:
        raise AwsReadError(message)


def _session_environment() -> dict[str, str]:
    """Forward only issued session credentials; disable other credential sources."""
    session = {key: os.environ.get(key, "") for key in _SESSION_KEYS}
    _require(
        all(
            value and "\0" not in value and len(value) <= 8192
            for value in session.values()
        ),
        "An ambient AWS session is required",
    )
    return {
        **session,
        "PATH": os.defpath,
        "AWS_CONFIG_FILE": os.devnull,
        "AWS_SHARED_CREDENTIALS_FILE": os.devnull,
        "BOTO_CONFIG": os.devnull,
        "AWS_EC2_METADATA_DISABLED": "true",
        "AWS_CLI_AUTO_PROMPT": "off",
        "AWS_PAGER": "",
        "AWS_MAX_ATTEMPTS": "2",
        "AWS_RETRY_MODE": "standard",
    }


def _read_streams(process: subprocess.Popen[bytes]) -> bytes:
    """Drain both pipes concurrently, enforcing byte and wall-clock bounds."""
    output = bytearray()
    stderr_bytes = 0
    deadline = time.monotonic() + PROCESS_TIMEOUT_SECONDS
    with selectors.DefaultSelector() as selector:
        selector.register(
            cast(BinaryIO, process.stdout), selectors.EVENT_READ, "stdout"
        )
        selector.register(
            cast(BinaryIO, process.stderr), selectors.EVENT_READ, "stderr"
        )
        while selector.get_map():
            remaining = deadline - time.monotonic()
            _require(remaining > 0, "AWS metadata command timed out")
            for key, _ in selector.select(remaining):
                chunk = os.read(key.fd, 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if key.data == "stdout":
                    _require(
                        len(output) + len(chunk) <= MAX_STDOUT_BYTES,
                        "AWS metadata output exceeds bound",
                    )
                    output.extend(chunk)
                else:
                    stderr_bytes += len(chunk)
                    _require(
                        stderr_bytes <= MAX_STDERR_BYTES,
                        "AWS metadata stderr exceeds bound",
                    )
        remaining = deadline - time.monotonic()
        _require(remaining > 0, "AWS metadata command timed out")
        _require(process.wait(timeout=remaining) == 0, "AWS metadata command failed")
    return bytes(output)


def _run(command: list[str], environment: dict[str, str]) -> bytes:
    """Run only the constructed argv; never print process output or exceptions."""
    try:
        # Fixed argv, no shell, and an explicitly supplied trusted executable.
        with subprocess.Popen(  # nosec B603
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            cwd=str(Path(command[0]).parent),
            shell=False,
        ) as process:
            try:
                return _read_streams(process)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()
    except AwsReadError:
        raise
    except Exception:
        raise AwsReadError("AWS metadata command failed") from None


def _unique_fields(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject duplicate fields even inside nested returned policy documents."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        _require(key not in result, "Duplicate AWS metadata JSON field")
        result[key] = value
    return result


def _response(data: bytes) -> Mapping[str, Any]:
    """Decode strict, bounded JSON without exposing malformed response contents."""
    _require(
        type(data) is bytes and len(data) <= MAX_STDOUT_BYTES,
        "Invalid AWS metadata output",
    )
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=_unique_fields)
        _require(type(value) is dict, "AWS metadata response must be an object")
        # JSON's nonstandard NaN/Infinity constants are not AWS metadata.
        json.dumps(value, allow_nan=False)
        return value
    except AwsReadError:
        raise
    except (UnicodeError, ValueError, TypeError, RecursionError):
        raise AwsReadError("Invalid AWS metadata JSON") from None


class AwsCliRead:
    """Callable implementing operator_enrollment_runtime.AwsRead for one registry.

    The executable must come from the trusted worker installation, never PR
    inputs or a PR-controlled PATH. The closed registry limits requested roles,
    managed policies and KMS metadata. Inline names and page markers are bounded
    values obtained by the collector; they never become command-line options.
    """

    def __init__(self, expected: registry.SeedRegistry, *, aws_executable: str):
        _require(
            expected
            == registry.build_registry(
                expected.environment,
                account_id=expected.account_id,
                seed_key=expected.seed_key,
            ),
            "Untrusted enrollment registry",
        )
        _require(
            type(aws_executable) is str
            and os.path.isabs(aws_executable)
            and "\0" not in aws_executable
            and Path(aws_executable).name == "aws"
            and os.path.isfile(aws_executable)
            and os.access(aws_executable, os.X_OK),
            "A trusted absolute AWS CLI executable is required",
        )
        self._executable = aws_executable
        self._region = expected.region
        self._key_arn = expected.seed_key.arn
        self._roles = frozenset(p.arn.rsplit("/", 1)[-1] for p in expected.principals)
        self._policies = frozenset(p.arn for p in expected.policies) | frozenset(
            p.frozen_config.aws_policy_arn
            for p in expected.principals
            if p.frozen_config
        )

    def _parameters(
        self, service: str, operation: str, arguments: dict[str, Any]
    ) -> None:
        """Accept only the collector's operation shapes and closed read resources."""
        _require(
            type(service) is str and type(operation) is str,
            "Unsupported AWS metadata operation",
        )
        fields = _READS.get((service, operation))
        if fields is None or type(arguments) is not dict:
            raise AwsReadError("Unsupported AWS metadata operation")
        paginated = operation in ("list_attached_role_policies", "list_role_policies")
        actual = set(arguments) - ({"Marker"} if paginated else set())
        _require(actual == set(fields), "Unsupported AWS metadata parameters")
        allowed_values = {
            "KeyId": {self._key_arn},
            "RoleName": self._roles,
            "PolicyArn": self._policies,
        }
        for field in fields:
            value = arguments[field]
            if field in allowed_values:
                _require(
                    type(value) is str and value in allowed_values[field],
                    "AWS metadata resource is outside registry",
                )
        self._variable_parameters(arguments)

    @staticmethod
    def _variable_parameters(arguments: dict[str, Any]) -> None:
        """Validate service versions/names and explicit one-page pagination values."""
        patterns = {
            "VersionId": r"v[1-9][0-9]{0,127}",
            "PolicyName": r"[A-Za-z0-9_+=,.@-]{1,128}",
        }
        for field, pattern in patterns.items():
            if field in arguments:
                value = arguments[field]
                _require(
                    type(value) is str and re.fullmatch(pattern, value) is not None,
                    "Invalid AWS metadata parameter value",
                )
        if "MaxItems" in arguments:
            _require(
                type(arguments["MaxItems"]) is int and arguments["MaxItems"] == 100,
                "Invalid AWS metadata page size",
            )
        if "Marker" in arguments:
            marker = arguments["Marker"]
            _require(
                type(marker) is str and 0 < len(marker) <= 1024 and "\0" not in marker,
                "Invalid AWS metadata page marker",
            )

    def __call__(
        self, service: str, operation: str, arguments: dict[str, Any]
    ) -> Mapping[str, Any]:
        """Return one unfiltered JSON API response; the collector checks semantics."""
        self._parameters(service, operation, arguments)
        command = [
            self._executable,
            service,
            operation.replace("_", "-"),
            "--cli-input-json",
            json.dumps(arguments, sort_keys=True, separators=(",", ":")),
            "--region",
            self._region,
            "--output",
            "json",
            "--no-cli-pager",
            "--no-paginate",
            "--cli-connect-timeout",
            "5",
            "--cli-read-timeout",
            "20",
        ]
        return _response(_run(command, _session_environment()))
