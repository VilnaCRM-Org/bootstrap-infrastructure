import os
import sys
from pathlib import Path

import pulumi
import pulumi.runtime
import pytest

os.environ.setdefault("PULUMI_ALLOW_TEST_DEFAULTS", "1")

ROOT = Path(__file__).resolve().parents[1]
PULUMI_DIR = ROOT / "pulumi"
if str(PULUMI_DIR) not in sys.path:
  sys.path.append(str(PULUMI_DIR))


class TestMocks(pulumi.runtime.Mocks):
  def __init__(self) -> None:
    self.resources = []

  def new_resource(self, type_, name, inputs, provider, id_):
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
      state.setdefault("arn", "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com")
    elif type_ == "aws:backup/vault:Vault":
      state.setdefault("name", inputs.get("name", name))
    self.resources.append((type_, name, state))
    return f"{name}_id", state

  def call(self, args):
    token = args.token
    payload = args.args
    if token == "aws:index/getRegion:getRegion":
      return {"name": "us-east-1"}
    if token == "aws:index/getCallerIdentity:getCallerIdentity":
      return {"accountId": "123456789012"}
    if token == "aws:s3/getBucket:getBucket":
      return {"id": payload.get("bucket")}
    return {}


@pytest.fixture(scope="session", autouse=True)
def pulumi_mocks():
  mocks = TestMocks()
  pulumi.runtime.set_mocks(mocks, project="bootstrap", stack="test", preview=False)
  return mocks
