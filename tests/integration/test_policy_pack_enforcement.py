"""Integration tests for Pulumi policy-pack execution."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
POLICY_DIR = PROJECT_ROOT / "policy"
PREPARE_POLICY_PACK = PROJECT_ROOT / "scripts" / "prepare_policy_pack.py"
MAIN_PY_TEMPLATE = """import pulumi


class BucketStub(pulumi.ComponentResource):
    def __init__(self, name: str) -> None:
        super().__init__(
            "tests:s3/bucket:Bucket",
            name,
            {{
                "acl": "{acl}",
                "logging": {{"targetBucket": "audit-logs", "targetPrefix": "bucket/"}},
                "serverSideEncryptionConfiguration": {{
                    "rule": {{
                        "applyServerSideEncryptionByDefault": {{
                            "sseAlgorithm": "AES256"
                        }}
                    }}
                }},
                "tags": {{
                    "Project": "demo",
                    "Environment": "dev",
                    "Owner": "platform",
                    "CostCenter": "engineering",
                }},
            }},
        )
        self.register_outputs({{}})


BucketStub("bucket")
"""

pytestmark = pytest.mark.usefixtures(
    "ensure_pulumi_cli", "ensure_pulumi_secrets_provider"
)


def _write_program(tmp_path: Path, *, acl: str) -> Path:
    """Create a small Pulumi program that exercises the S3 ACL guardrail."""
    work_dir = tmp_path / f"policy-{acl.replace('-', '_')}"
    work_dir.mkdir()
    (work_dir / ".state").mkdir()
    (work_dir / "Pulumi.yaml").write_text(
        "name: policy-pack-integration\nruntime:\n  name: python\n",
        encoding="utf-8",
    )
    (work_dir / "__main__.py").write_text(
        MAIN_PY_TEMPLATE.format(acl=acl),
        encoding="utf-8",
    )
    return work_dir


def _preview_with_policy_pack(work_dir: Path) -> subprocess.CompletedProcess[str]:
    """Run a local Pulumi preview with the repository policy pack enabled."""
    env = {
        **os.environ,
        "PULUMI_BACKEND_URL": f"file://{work_dir / '.state'}",
        "PULUMI_SECRETS_PROVIDER": os.environ["PULUMI_SECRETS_PROVIDER"],
    }

    subprocess.run(
        ["uv", "run", "python", str(PREPARE_POLICY_PACK)],
        check=True,
        cwd=PROJECT_ROOT,
        env=env,
        text=True,
        capture_output=True,
        timeout=120,
    )
    try:
        subprocess.run(
            [
                "pulumi",
                "--cwd",
                str(work_dir),
                "stack",
                "init",
                "dev",
                "--non-interactive",
                "--secrets-provider",
                env["PULUMI_SECRETS_PROVIDER"],
            ],
            check=True,
            cwd=PROJECT_ROOT,
            env=env,
            text=True,
            capture_output=True,
            timeout=120,
        )

        return subprocess.run(
            [
                "pulumi",
                "--cwd",
                str(work_dir),
                "preview",
                "--stack",
                "dev",
                "--non-interactive",
                "--policy-pack",
                str(POLICY_DIR),
            ],
            check=False,
            cwd=PROJECT_ROOT,
            env=env,
            text=True,
            capture_output=True,
            timeout=120,
        )
    finally:
        subprocess.run(
            ["pulumi", "--cwd", str(work_dir), "stack", "rm", "dev", "--yes"],
            check=False,
            cwd=PROJECT_ROOT,
            env=env,
            text=True,
            capture_output=True,
            timeout=120,
        )


def test_policy_pack_allows_private_bucket_acl(tmp_path: Path) -> None:
    """Keep the happy path green for compliant resource definitions."""
    result = _preview_with_policy_pack(_write_program(tmp_path, acl="private"))
    combined_output = f"{result.stdout}\n{result.stderr}"

    assert result.returncode == 0, combined_output


def test_policy_pack_blocks_public_bucket_acl(tmp_path: Path) -> None:
    """Reject public-read ACLs during a real Pulumi preview."""
    result = _preview_with_policy_pack(_write_program(tmp_path, acl="public-read"))
    combined_output = f"{result.stdout}\n{result.stderr}"

    assert result.returncode != 0, combined_output
    assert "s3-no-public-exposure" in combined_output
    assert "public ACLs" in combined_output
