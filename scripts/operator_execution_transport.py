"""Private bounded processes for the installed operator container, never PR tools."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import selectors
import signal
import stat
import subprocess  # nosec B404
import time
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, cast

import yaml
from _pulumi_command_support import CommandContext
from _pulumi_stack_config import _configuration
from operator_aws_read import _session_environment
from operator_plan_envelope import (
    ACCOUNTS,
    CheckpointBinding,
    ExecutionBinding,
    ProviderBinding,
    _validate_execution,
)

MAX_BYTES = 48 * 1024 * 1024
AWS = "/usr/local/bin/aws"
PULUMI = "/opt/pulumi/pulumi"
PYTHON = "/home/dev/.venvs/bootstrap-infrastructure/bin/python"
PLUGIN = Path("/opt/operator-plugins/plugins/resource-aws-v7.23.0/pulumi-resource-aws")
PLUGIN_SHA256 = "ad2008620e4504705db055f27c2cbd76f34c6e29fb465278464c286c30d63196"


def require(value, message):
    """Report only bounded categories, never program output or private documents."""
    if not value:
        raise ValueError(message)


def pairs(values):
    """Reject duplicate JSON fields at every nesting level."""
    result = {}
    for key, value in values:
        require(key not in result, "duplicate-private-json-field")
        result[key] = value
    return result


def encode(value):
    """Canonical finite JSON used only in private memory/files."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def decode(raw):
    """Bound parsing and suppress all document contents on failures."""
    require(type(raw) is bytes and len(raw) <= MAX_BYTES, "private-document-bound")
    try:
        value = json.loads(raw, object_pairs_hook=pairs)
        encode(value)
        return value
    except (ValueError, TypeError, RecursionError):
        raise ValueError("invalid-private-json") from None


def private_write(path, raw, *, child=False):
    """Create a fresh private file; never follow existing paths or symlinks."""
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(raw)
    if child:
        os.chown(path, 2000, 2000)


def private_read(path):
    """Read only a regular nonsymlink private process result with a strict bound."""
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        raise ValueError("private-file-required") from None
    with os.fdopen(descriptor, "rb") as handle:
        require(
            stat.S_ISREG(os.fstat(handle.fileno()).st_mode), "private-file-required"
        )
        raw = handle.read(MAX_BYTES + 1)
    require(len(raw) <= MAX_BYTES, "private-document-bound")
    return raw


def _streams(process, timeout):
    """Drain bounded stdout/stderr concurrently to prevent pipe deadlocks."""
    result = bytearray()
    errors = 0
    deadline = time.monotonic() + timeout
    with selectors.DefaultSelector() as selector:
        selector.register(cast(BinaryIO, process.stdout), selectors.EVENT_READ, True)
        selector.register(cast(BinaryIO, process.stderr), selectors.EVENT_READ, False)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            require(remaining > 0, "private-process-timeout")
            for key, _ in selector.select(remaining):
                chunk = os.read(key.fd, 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                elif key.data:
                    require(
                        len(result) + len(chunk) <= MAX_BYTES, "private-output-bound"
                    )
                    result.extend(chunk)
                else:
                    errors += len(chunk)
                    require(errors <= 1024 * 1024, "private-error-bound")
        require(
            process.wait(timeout=max(0.01, deadline - time.monotonic())) == 0,
            "private-process-failed",
        )
    return bytes(result)


def _child_pids():
    """Find every live PR UID in the worker's private PID namespace."""
    found = []
    for path in Path("/proc").glob("[0-9]*/status"):
        try:
            fields = dict(row.split(":", 1) for row in path.read_text().splitlines())
        except FileNotFoundError:
            continue
        if fields["Uid"].split()[0] == "2000" and "Z" not in fields["State"]:
            found.append(int(path.parent.name))
    return found


def _stop_children():
    """Kill detached descendants too; no PR process survives a verifier recheck."""
    require(os.getpid() == 1, "private-pid-namespace-required")
    deadline = time.monotonic() + 5
    while pids := _child_pids():
        require(time.monotonic() < deadline, "child-cleanup-timeout")
        for pid in pids:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        time.sleep(0.01)


def run(command, *, env, cwd, child=False, timeout=1200):
    """Execute trusted absolute binaries without a shell or unbounded output."""
    require(Path(command[0]).is_absolute(), "absolute-executable-required")
    try:
        # Only installed fixed executables reach this private dispatcher.
        with subprocess.Popen(  # nosec B603
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            cwd=cwd,
            shell=False,
            user=2000 if child else None,
            group=2000 if child else None,
            extra_groups=() if child else None,
        ) as process:
            try:
                return _streams(process, timeout)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()
                if child:
                    _stop_children()
    except Exception:
        raise ValueError("private-process-failed") from None


@dataclass(frozen=True)
class Snapshot:
    """Authenticated checkpoint version, exported deployment and provider state."""

    execution: ExecutionBinding
    checkpoint: bytes
    provider: dict


class OperatorTransport:
    """Concrete S3/KMS/Pulumi ports inside a trusted, ephemeral Linux container."""

    def __init__(self, environment: str, area: Path, source: Path):
        require(
            environment in ACCOUNTS and os.geteuid() == 0 and os.getpid() == 1,
            "installed-container-required",
        )
        self.environment = environment
        self.account, self.key = ACCOUNTS[environment]
        self.area, self.source = area, source
        self.bucket = f"pulumi-bootstrap-infrastructure-{environment}-state"
        self.object_key = f".pulumi/stacks/github-ci-bootstrap/{environment}.json"
        self.uri = f"awskms://alias/pulumi-platform-bootstrap-{environment}?region=eu-central-1"
        self.aws_env = _session_environment()
        self.work = area / "program"
        self.work.mkdir(mode=0o700)
        os.chown(self.work, 2000, 2000)
        # The PR process cannot inspect the root verifier's environment or files.
        area.chmod(0o711)
        self.child_env = {
            **self.aws_env,
            "PATH": "/opt/pulumi:/usr/local/bin:/usr/bin:/bin",
            "USER": "operator-program",
            "HOME": str(self.work),
            "PULUMI_HOME": str(self.work / "home"),
            "PULUMI_BACKEND_URL": "s3://" + self.bucket,
            "AWS_REGION": "eu-central-1",
            "AWS_ACCOUNT_ID": self.account,
            "PULUMI_SKIP_UPDATE_CHECK": "true",
            "PULUMI_PYTHON_CMD": PYTHON,
            "PULUMI_DISABLE_AUTOMATIC_PLUGIN_ACQUISITION": "true",
            "PULUMI_IGNORE_AMBIENT_PLUGINS": "true",
        }

    def tools(self, head_sha):
        """Check pinned tooling and the admitted read-only checkout."""
        safe = {"PATH": "/usr/bin:/bin"}
        actual = run(
            [
                "/usr/bin/git",
                "-c",
                f"safe.directory={self.source}",
                "-C",
                str(self.source),
                "rev-parse",
                "HEAD",
            ],
            env=safe,
            cwd=self.area,
        )
        require(actual.strip().decode() == head_sha, "source-head-mismatch")
        require(
            run([PULUMI, "version"], env=safe, cwd=self.area).strip() == b"v3.223.0",
            "pulumi-version",
        )
        digest = hashlib.sha256()
        with PLUGIN.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        require(digest.hexdigest() == PLUGIN_SHA256, "aws-plugin-hash")
        require(
            run([str(PLUGIN), "--version"], env=safe, cwd=self.area).strip()
            == b"7.23.0",
            "aws-plugin-version",
        )
        require(
            run(
                [
                    PYTHON,
                    "-I",
                    "-c",
                    "from importlib.metadata import version; "
                    "print(version('pulumi-aws'))",
                ],
                env=safe,
                cwd=self.area,
            ).strip()
            == b"7.23.0",
            "aws-sdk-version",
        )
        project = yaml.safe_load(
            (self.source / "pulumi/github-ci-bootstrap/Pulumi.yaml").read_text()
        )
        require(
            project.get("name") == "github-ci-bootstrap"
            and project.get("runtime") == {"name": "python"},
            "operator-project-runtime",
        )
        home = self.work / "home"
        home.mkdir()
        os.chown(home, 2000, 2000)
        (home / "plugins").symlink_to(PLUGIN.parent.parent, target_is_directory=True)

    def aws(self, service, operation, arguments, output=None):
        """Issue internal fixed-coordinate AWS calls with private output."""
        command = [
            AWS,
            service,
            operation,
            "--cli-input-json",
            json.dumps(arguments),
            "--region",
            "eu-central-1",
            "--output",
            "json",
            "--no-cli-pager",
            "--no-paginate",
        ]
        if output is not None:
            command.append(str(output))
        return decode(run(command, env=self.aws_env, cwd=self.area, timeout=90))

    def head(self):
        """Require an existing, bounded, versioned canonical operator checkpoint."""
        result = self.aws(
            "s3api",
            "head-object",
            {
                "Bucket": self.bucket,
                "Key": self.object_key,
                "ExpectedBucketOwner": self.account,
            },
        )
        require(
            type(result.get("VersionId")) is str
            and result["VersionId"] not in ("", "null"),
            "versioned-checkpoint-required",
        )
        require(type(result.get("ETag")) is str and result["ETag"], "checkpoint-etag")
        require(
            type(result.get("ContentLength")) is int
            and 0 < result["ContentLength"] <= MAX_BYTES,
            "checkpoint-size",
        )
        return {key: result[key] for key in ("VersionId", "ETag", "ContentLength")}

    def snapshot(self):
        """Read an immutable version; recheck its pointer after key resolution."""
        before = self.head()
        path = self.area / ("checkpoint-" + str(time.monotonic_ns()))
        private_write(path, b"")
        result = self.aws(
            "s3api",
            "get-object",
            {
                "Bucket": self.bucket,
                "Key": self.object_key,
                "VersionId": before["VersionId"],
                "ExpectedBucketOwner": self.account,
            },
            path,
        )
        raw = private_read(path)
        path.unlink()
        require(
            result.get("VersionId") == before["VersionId"]
            and result.get("ETag") == before["ETag"]
            and len(raw) == before["ContentLength"],
            "checkpoint-read-mismatch",
        )
        document = decode(raw)
        require(document.get("version") == 3, "checkpoint-format")
        deployment = document["checkpoint"]["latest"]
        provider = deployment["secrets_providers"]
        require(
            provider["type"] == "cloud" and provider["state"]["url"] == self.uri,
            "provider-uri",
        )
        require(
            bool(base64.b64decode(provider["state"]["encryptedkey"], validate=True)),
            "provider-encrypted-key-required",
        )
        metadata = self.aws(
            "kms",
            "describe-key",
            {"KeyId": f"alias/pulumi-platform-bootstrap-{self.environment}"},
        )["KeyMetadata"]
        require(
            metadata["Arn"] == self.key
            and metadata["KeyState"] == "Enabled"
            and metadata["KeyManager"] == "CUSTOMER"
            and metadata["KeyUsage"] == "ENCRYPT_DECRYPT",
            "provider-key-mismatch",
        )
        require(before == self.head(), "checkpoint-read-race")
        execution = ExecutionBinding(
            self.environment,
            self.account,
            "eu-central-1",
            "github-ci-bootstrap",
            "s3://" + self.bucket,
            self.key,
            CheckpointBinding(
                self.bucket, self.object_key, before["VersionId"], before["ETag"]
            ),
            ProviderBinding(
                self.uri, self.key, hashlib.sha256(encode(provider)).hexdigest()
            ),
        )
        _validate_execution(execution)
        return Snapshot(
            execution, encode({"version": 3, "deployment": deployment}), provider
        )

    def kms(self, operation, request):
        """Convert CLI base64 to the envelope's native-byte KMS callback contract."""
        require(
            operation in ("generate-data-key", "decrypt")
            and request.get("KeyId") == self.key,
            "envelope-key",
        )
        arguments = {
            key: base64.b64encode(value).decode() if type(value) is bytes else value
            for key, value in request.items()
        }
        result = self.aws("kms", operation, arguments)
        return {
            key: base64.b64decode(value, validate=True)
            if key in ("Plaintext", "CiphertextBlob")
            else value
            for key, value in result.items()
        }

    def pulumi(self, stage, snapshot, plan=None):
        """Keep complete plan evidence private and execute the pinned CLI."""
        require(stage in ("preview", "apply", "drift"), "invalid-stage")
        context = CommandContext(
            root_dir=self.source,
            env=self.child_env,
            pulumi_dir=self.source / "pulumi/github-ci-bootstrap",
            policy_pack_dir=self.source / "policy",
            plan_dir=self.work,
            preview_artifact_dir=self.work,
            backend_url="s3://" + self.bucket,
            secrets_provider=self.uri,
        )
        config = _configuration(context, self.environment, snapshot.provider)
        config_path = self.work / (stage + "-config.yaml")
        private_write(config_path, yaml.safe_dump(config).encode(), child=True)
        plan_path = self.work / (stage + ".plan")
        command = [
            PULUMI,
            "-C",
            str(context.pulumi_dir),
            "up" if stage == "apply" else "preview",
            "--stack",
            self.environment,
            "--config-file",
            str(config_path),
            "--non-interactive",
            "--json",
            "--color",
            "never",
        ]
        if stage == "apply":
            require(type(plan) is bytes, "saved-plan-required")
            private_write(plan_path, plan, child=True)
            command += ["--yes", "--plan", str(plan_path)]
        else:
            command += [
                "--show-sames",
                "--show-replacement-steps",
                "--save-plan",
                str(plan_path),
            ]
            if stage == "drift":
                command += ["--refresh", "--expect-no-changes"]
        try:
            result = run(command, env=self.child_env, cwd=self.work, child=True)
            return (b"", b"") if stage == "apply" else (private_read(plan_path), result)
        finally:
            config_path.unlink(missing_ok=True)
            plan_path.unlink(missing_ok=True)
