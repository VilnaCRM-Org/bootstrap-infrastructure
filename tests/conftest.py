import asyncio
import os
import sys
from pathlib import Path

import pulumi.runtime
import pytest

import pulumi

os.environ.setdefault("PULUMI_ALLOW_TEST_DEFAULTS", "1")

ROOT = Path(__file__).resolve().parents[1]
PULUMI_DIR = ROOT / "pulumi"
if str(PULUMI_DIR) not in sys.path:
    sys.path.append(str(PULUMI_DIR))


class TestMocks(pulumi.runtime.Mocks):
    def __init__(self) -> None:
        self.resources = []

    def new_resource(self, type_, name=None, inputs=None, provider=None, id_=None):
        if name is None and hasattr(type_, "typ"):
            resource_args = type_
            type_ = resource_args.typ
            name = resource_args.name
            inputs = resource_args.inputs

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
        elif type_ == "aws:kms/key:Key":
            state.setdefault("arn", f"arn:aws:kms:us-east-1:123456789012:key/{name}")
            state.setdefault("keyId", f"{name}-key-id")
            state.setdefault("key_id", f"{name}-key-id")
        elif type_ == "aws:kms/alias:Alias":
            alias_name = inputs.get("name") or name
            state.setdefault("name", alias_name)
            state.setdefault("arn", f"arn:aws:kms:us-east-1:123456789012:{alias_name}")
        elif type_ == "aws:backup/vault:Vault":
            state.setdefault("name", inputs.get("name", name))
        self.resources.append((type_, name, state))
        return f"{name}_id", state

    def call(self, args):
        token = args.token
        payload = args.args
        if token == "aws:index/getRegion:getRegion":  # nosec B105
            return {"name": "us-east-1"}
        if token == "aws:index/getCallerIdentity:getCallerIdentity":  # nosec B105
            return {"accountId": "123456789012"}
        if token == "aws:s3/getBucket:getBucket":  # nosec B105
            return {"id": payload.get("bucket")}
        return {}


class AnyThreadEventLoopPolicy(asyncio.DefaultEventLoopPolicy):
    """Create an event loop on demand for Pulumi mock worker threads."""

    def get_event_loop(self):
        try:
            return super().get_event_loop()
        except RuntimeError:
            loop = self.new_event_loop()
            self.set_event_loop(loop)
            return loop


@pytest.fixture(scope="session", autouse=True)
def any_thread_event_loop_policy():
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


@pytest.fixture(scope="session", autouse=True)
def pulumi_mocks():
    mocks = TestMocks()
    pulumi.runtime.set_mocks(mocks, project="bootstrap", stack="test", preview=False)
    return mocks
