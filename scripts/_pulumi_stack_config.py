"""Preserve existing S3 stack encryption without publishing checkpoint values."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import TYPE_CHECKING, Any, Iterator
from urllib.parse import SplitResult, parse_qs, unquote, urlsplit

import yaml

if TYPE_CHECKING:
    from _pulumi_command_support import CommandContext


class StackConfigError(ValueError):
    """A stack configuration could not be verified without replacing its key."""


def _require(condition: Any, message: str) -> None:
    if not condition:
        raise StackConfigError(message)


def _digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _read_json(context: CommandContext, command: list[str]) -> dict[str, Any]:
    result = context.runner(
        command,
        env={**context.env, "PULUMI_BACKEND_URL": context.backend_url},
        check=False,
        capture_output=True,
    )
    _require(result.returncode == 0, "Stack configuration metadata read failed.")
    try:
        value = json.loads(result.stdout)
    except (ValueError, TypeError):
        raise StackConfigError(
            "Invalid stack configuration metadata response."
        ) from None
    _require(isinstance(value, dict), "Invalid stack configuration metadata shape.")
    return value


def _yaml_document(path: Path) -> dict[str, Any]:
    _require(not path.is_symlink(), "Stack configuration symlinks are not allowed.")
    try:
        value = yaml.safe_load(path.read_text())
    except (OSError, yaml.YAMLError):
        raise StackConfigError("Unable to read stack configuration YAML.") from None
    _require(isinstance(value, dict), "Stack configuration must be a YAML mapping.")
    return value


def _validate_backend(backend: SplitResult) -> None:
    _require(
        backend.scheme == "s3"
        and re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", backend.netloc)
        and not backend.query
        and not backend.fragment
        and all(
            p not in {".", "..", ""}
            for p in backend.path.removeprefix("/").split("/")
            if backend.path.removeprefix("/")
        ),
        "An exact S3 backend is required for shared stack configuration.",
    )


def _split_uri(value: str) -> SplitResult:
    """Convert malformed URI syntax into the guarded configuration error."""
    try:
        return urlsplit(value)
    except ValueError:
        raise StackConfigError(
            "Invalid stack backend or secrets provider URI."
        ) from None


def _coordinates(context: CommandContext, stack: str) -> dict[str, str]:
    _require(
        not re.search(r"[%\\\x00-\x20]", context.backend_url),
        "An exact S3 backend cannot contain escapes or control characters.",
    )
    backend = _split_uri(context.backend_url)
    _validate_backend(backend)
    _require(
        context.env.get("PULUMI_BACKEND_URL", context.backend_url)
        == context.backend_url
        and not context.env.get("PULUMI_CLOUD_SECRET_OVERRIDE"),
        "Backend or cloud secrets override differs from the requested stack.",
    )
    account = context.env.get("AWS_ACCOUNT_ID", "")
    _require(
        re.fullmatch(r"[0-9]{12}", account),
        "AWS_ACCOUNT_ID must pin the stack account.",
    )
    project = _yaml_document(context.pulumi_dir / "Pulumi.yaml").get("name")
    _require(
        isinstance(project, str)
        and re.fullmatch(r"[A-Za-z0-9_.-]+", project)
        and re.fullmatch(r"[A-Za-z0-9_.-]+", stack),
        "Exact project and unqualified stack names are required.",
    )
    prefix = backend.path.strip("/")
    key = f".pulumi/stacks/{project}/{stack}.json"
    return {
        "accountId": account,
        "project": str(project),
        "stack": stack,
        "backendUrl": context.backend_url,
        "bucket": backend.netloc,
        "key": f"{prefix}/{key}" if prefix else key,
    }


def _checkpoint_version(
    context: CommandContext, target: dict[str, str]
) -> dict[str, str]:
    metadata = _read_json(
        context,
        [
            "aws",
            "s3api",
            "head-object",
            "--bucket",
            target["bucket"],
            "--key",
            target["key"],
            "--expected-bucket-owner",
            target["accountId"],
            "--output",
            "json",
        ],
    )
    _require(
        isinstance(metadata.get("VersionId"), str)
        and metadata["VersionId"] not in {"", "null"}
        and isinstance(metadata.get("ETag"), str)
        and metadata["ETag"],
        "A versioned existing stack checkpoint is required.",
    )
    return {
        "checkpointVersionId": metadata["VersionId"],
        "checkpointETag": metadata["ETag"],
    }


def _validate_deployment(deployment: Any, target: dict[str, str]) -> None:
    _require(isinstance(deployment, dict), "Invalid stack deployment metadata.")
    prefix = f"urn:pulumi:{target['stack']}::{target['project']}::"
    resources = deployment.get("resources", [])
    # Official stack init stores provider state before the first root resource.
    # Existing nonempty inventories must still identify this exact stack.
    _require(
        isinstance(resources, list)
        and all(
            isinstance(r, dict) and str(r.get("urn", "")).startswith(prefix)
            for r in resources
        )
        and (
            not resources
            or any(
                r.get("urn")
                == f"{prefix}pulumi:pulumi:Stack::{target['project']}-{target['stack']}"
                for r in resources
            )
        )
        and not deployment.get("pending_operations"),
        "Checkpoint project, stack or pending operation precondition failed.",
    )


def _provider_state(context: CommandContext, target: dict[str, str]) -> dict[str, Any]:
    checkpoint = _read_json(
        context,
        [
            "pulumi",
            "-C",
            str(context.pulumi_dir),
            "stack",
            "export",
            "--stack",
            target["stack"],
            "--non-interactive",
        ],
    )
    deployment = checkpoint.get("deployment", {})
    _validate_deployment(deployment, target)
    provider = deployment.get("secrets_providers", {})
    _require(
        isinstance(provider, dict)
        and provider.get("type") == "cloud"
        and isinstance(provider.get("state"), dict),
        "Existing cloud secrets-provider state is required.",
    )
    state = provider["state"]
    _require(
        state.get("url") == context.secrets_provider,
        "Checkpoint secrets provider differs from requested provider.",
    )
    try:
        valid_key = bool(base64.b64decode(state.get("encryptedkey", ""), validate=True))
    except (ValueError, TypeError, binascii.Error):
        valid_key = False
    _require(
        valid_key,
        "Existing encrypted data key is required; key generation is forbidden.",
    )
    return provider


def _key_identity(context: CommandContext, account: str) -> str:
    provider = _split_uri(context.secrets_provider)
    region = context.env.get("AWS_REGION") or context.env.get("AWS_DEFAULT_REGION", "")
    _require(
        provider.scheme == "awskms"
        and not provider.fragment
        and region
        and parse_qs(provider.query, keep_blank_values=True) == {"region": [region]},
        "Secrets provider must use the pinned AWS region.",
    )
    identifier = unquote(provider.netloc + provider.path)
    _require(bool(identifier), "An existing KMS key identifier is required.")
    metadata = _read_json(
        context,
        [
            "aws",
            "kms",
            "describe-key",
            "--key-id",
            identifier,
            "--region",
            region,
            "--output",
            "json",
        ],
    ).get("KeyMetadata", {})
    return _validate_key_metadata(metadata, account, region)


def _validate_key_metadata(metadata: Any, account: str, region: str) -> str:
    arn = metadata.get("Arn", "") if isinstance(metadata, dict) else ""
    pieces = arn.split(":") if isinstance(arn, str) else []
    _require(
        len(pieces) == 6
        and pieces[0] == "arn"
        and pieces[2] == "kms"
        and pieces[3] == region
        and pieces[4] == account
        and pieces[5].startswith("key/")
        and metadata.get("KeyState") == "Enabled",
        "Secrets-provider KMS key account, region or state differs.",
    )
    return arn


def _configuration(
    context: CommandContext, stack: str, provider: dict[str, Any]
) -> dict[str, Any]:
    config = _yaml_document(context.pulumi_dir / f"Pulumi.{stack}.yaml")
    state = provider["state"]
    _require(
        not config.get("encryptionsalt")
        and config.get("secretsprovider", state["url"]) == state["url"]
        and config.get("encryptedkey", state["encryptedkey"]) == state["encryptedkey"],
        "Committed configuration encryption differs from the existing stack.",
    )
    config.pop("encryptionsalt", None)
    config.update(secretsprovider=state["url"], encryptedkey=state["encryptedkey"])
    return config


@contextmanager
def prepared_stack_configuration(
    context: CommandContext, stack: str
) -> Iterator[CommandContext]:
    """Use the existing encrypted key in a private, automatically removed config."""
    if context.backend_url.startswith("file://"):
        yield context
        return
    target = _coordinates(context, stack)
    identity = _read_json(
        context, ["aws", "sts", "get-caller-identity", "--output", "json"]
    )
    _require(
        identity.get("Account") == target["accountId"],
        "AWS caller account differs from the pinned stack account.",
    )
    before = _checkpoint_version(context, target)
    provider = _provider_state(context, target)
    key_arn = _key_identity(context, target["accountId"])
    _require(
        before == _checkpoint_version(context, target),
        "Checkpoint changed during configuration preparation.",
    )
    config = _configuration(context, stack, provider)
    binding = {
        **{k: target[k] for k in ("accountId", "backendUrl", "project", "stack")},
        **before,
        "kmsKeyArn": key_arn,
        "providerStateSha256": _digest(provider),
        "stackConfigSha256": _digest(config),
    }
    with TemporaryDirectory(prefix="pulumi-stack-config-") as directory:
        path = Path(directory) / "config.yaml"
        path.write_text(yaml.safe_dump(config, sort_keys=True))
        path.chmod(0o600)
        yield replace(context, config_file=path, provider_identity=binding)


def verify_provider_identity(context: CommandContext, entry: dict[str, Any]) -> None:
    """Reject missing, rotated or retargeted provider state before saved-plan replay."""
    if context.provider_identity is not None:
        _require(
            entry.get("secretsProviderIdentity") == context.provider_identity,
            "Saved-plan provider, configuration or checkpoint identity changed.",
        )
