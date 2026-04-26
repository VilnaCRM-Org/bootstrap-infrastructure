"""Shared pytest fixtures for Pulumi automation and infra unit tests."""

from __future__ import annotations

import asyncio
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pulumi.runtime
import pytest
from pulumi.runtime.mocks import MockCallArgs, MockResourceArgs

import pulumi

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PULUMI_PROGRAM_ROOT = PROJECT_ROOT / "pulumi"
_COVERAGE_CONFIG = PROJECT_ROOT / ".coveragerc"

os.environ.setdefault("PULUMI_ALLOW_TEST_DEFAULTS", "1")

if str(PULUMI_PROGRAM_ROOT) not in sys.path:
    sys.path.insert(0, str(PULUMI_PROGRAM_ROOT))


class TestMocks(pulumi.runtime.Mocks):
    """Pulumi mocks used by infra unit tests."""

    def __init__(self) -> None:
        self.resources: list[tuple[str, str, dict[str, Any]]] = []

    def new_resource(self, args: MockResourceArgs) -> tuple[str | None, dict[str, Any]]:
        type_ = args.typ
        name = args.name
        inputs = dict(args.inputs)
        state = dict(inputs)
        if type_ == "aws:s3/bucket:Bucket":
            bucket = inputs.get("bucket") or name
            state.setdefault("bucket", bucket)
            state.setdefault("arn", f"arn:aws:s3:::{bucket}")
        elif type_ == "aws:iam/role:Role":
            role_name = inputs.get("name") or name
            state.setdefault("name", role_name)
            state.setdefault("arn", f"arn:aws:iam::123456789012:role/{role_name}")
        elif type_ == "aws:iam/openIdConnectProvider:OpenIdConnectProvider":
            state.setdefault(
                "arn",
                "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com",
            )
        elif type_ == "aws:ecr/repository:Repository":
            repository_name = inputs.get("name") or name
            repository_url = (
                f"123456789012.dkr.ecr.us-east-1.amazonaws.com/{repository_name}"
            )
            state.setdefault("name", repository_name)
            state.setdefault("repositoryUrl", repository_url)
            state.setdefault("repository_url", repository_url)
        elif type_ == "aws:kms/key:Key":
            state.setdefault("arn", f"arn:aws:kms:us-east-1:123456789012:key/{name}")
            state.setdefault("keyId", f"{name}-key-id")
            state.setdefault("key_id", f"{name}-key-id")
        elif type_ == "aws:kms/alias:Alias":
            alias_name = inputs.get("name") or name
            state.setdefault("name", alias_name)
            state.setdefault("arn", f"arn:aws:kms:us-east-1:123456789012:{alias_name}")
        elif type_ == "aws:backup/vault:Vault":
            vault_name = inputs.get("name", name)
            state.setdefault("name", vault_name)
            state.setdefault(
                "arn",
                f"arn:aws:backup:us-east-1:123456789012:backup-vault:{vault_name}",
            )
        elif type_ == "aws:sns/topic:Topic":
            topic_name = inputs.get("name", name)
            state.setdefault("name", topic_name)
            state.setdefault(
                "arn",
                f"arn:aws:sns:us-east-1:123456789012:{topic_name}",
            )
        elif type_ == "aws:cloudwatch/eventRule:EventRule":
            rule_name = inputs.get("name", name)
            state.setdefault("name", rule_name)
            state.setdefault(
                "arn",
                f"arn:aws:events:us-east-1:123456789012:rule/{rule_name}",
            )
        self.resources.append((type_, name, state))
        resource_id = None if args.custom is False else f"{name}_id"
        return resource_id, state

    def call(self, args: MockCallArgs) -> tuple[dict[str, Any], list[tuple[str, str]]]:
        token = args.token
        payload = args.args
        if token == "aws:index/getRegion:getRegion":  # nosec B105
            return {"name": "us-east-1", "region": "us-east-1"}, []
        if token == "aws:index/getCallerIdentity:getCallerIdentity":  # nosec B105
            return {"accountId": "123456789012"}, []
        if token == "aws:index/getPartition:getPartition":  # nosec B105
            return {
                "partition": "aws",
                "dnsSuffix": "amazonaws.com",
                "reverseDnsPrefix": "com.amazonaws",
            }, []
        if token == "aws:iam/getRole:getRole":  # nosec B105
            return {"arn": f"arn:aws:iam::123456789012:role/{payload.get('name')}"}, []
        if token == "aws:s3/getBucket:getBucket":  # nosec B105
            return {"id": payload.get("bucket")}, []
        return {}, []


class AnyThreadEventLoopPolicy(asyncio.DefaultEventLoopPolicy):
    """Create an event loop on demand for Pulumi mock worker threads."""

    def get_event_loop(self):  # type: ignore[override]
        try:
            return super().get_event_loop()
        except RuntimeError:
            loop = self.new_event_loop()
            self.set_event_loop(loop)
            return loop


@pytest.fixture(scope="session", autouse=True)
def any_thread_event_loop_policy():
    """Allow Pulumi mocks to create event loops from worker threads."""
    previous_policy = asyncio.get_event_loop_policy()
    policy = AnyThreadEventLoopPolicy()
    asyncio.set_event_loop_policy(policy)
    policy.set_event_loop(policy.new_event_loop())
    yield
    try:
        loop = policy.get_event_loop()
    except RuntimeError:
        loop = None
    if loop is not None and not loop.is_closed():
        loop.close()
    asyncio.set_event_loop_policy(previous_policy)


@pytest.fixture()
def pulumi_mocks() -> TestMocks:
    """Expose isolated Pulumi mocks for tests that validate generated resources."""
    mocks = TestMocks()
    pulumi.runtime.set_mocks(mocks, project="bootstrap", stack="test", preview=False)
    try:
        yield mocks
    finally:
        # Reset the synthetic root stack between tests so later modules can
        # install their own Pulumi mock runtime without inheriting leaked state.
        pulumi.runtime.settings.reset_options(project=None, stack=None)


@pytest.fixture(scope="session", autouse=True)
def pulumi_automation_environment(tmp_path_factory: pytest.TempPathFactory) -> None:
    """Prepare a local backend while leaving secrets-provider control explicit."""
    if shutil.which("pulumi") is None:
        return

    os.environ.setdefault("PULUMI_SKIP_UPDATE_CHECK", "true")
    python_cmd = sys.executable

    if _COVERAGE_CONFIG.exists():
        os.environ.setdefault("COVERAGE_PROCESS_START", str(_COVERAGE_CONFIG))
        os.environ.setdefault("COVERAGE_FILE", str(PROJECT_ROOT / ".coverage"))

    os.environ.setdefault("PULUMI_PYTHON_CMD", python_cmd)
    backend_url = os.environ.get("PULUMI_BACKEND_URL", "")

    if os.environ.get("PULUMI_ACCESS_TOKEN"):
        return
    if backend_url:
        return

    backend_dir = tmp_path_factory.mktemp("pulumi-backend")
    backend_uri = Path(backend_dir).resolve().as_uri()

    env = os.environ.copy()
    env["PULUMI_HOME"] = str(backend_dir)

    subprocess.run(["pulumi", "login", backend_uri], check=True, env=env, timeout=30)

    os.environ.setdefault("PULUMI_HOME", str(backend_dir))
    os.environ.setdefault("PULUMI_BACKEND_URL", backend_uri)


@pytest.fixture(scope="session")
def ensure_pulumi_cli() -> None:
    """Skip integration cases that require the Pulumi CLI when it is unavailable."""
    if shutil.which("pulumi") is None:
        pytest.skip("Pulumi CLI binary is not available in PATH.")


@pytest.fixture(scope="session")
def ensure_pulumi_secrets_provider() -> None:
    """Require an explicit non-passphrase secrets provider for automation tests."""
    if os.environ.get("PULUMI_ACCESS_TOKEN"):
        return
    if not os.environ.get("PULUMI_SECRETS_PROVIDER"):
        pytest.skip(
            "Set PULUMI_SECRETS_PROVIDER to run Pulumi automation tests without "
            "passphrase-backed stacks."
        )
