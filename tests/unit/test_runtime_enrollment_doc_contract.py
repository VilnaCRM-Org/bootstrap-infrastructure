"""Documentation lists must equal the renderer's credential trigger tuple."""

from __future__ import annotations

import importlib
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

renderer = importlib.import_module("render_runtime_seed_policies")

DOCS = (
    ROOT / "specs/219-test-workload-capability/runtime-enrollment.md",
    ROOT / "docs/testing.md",
)


def test_documented_credential_triggers_match_renderer():
    """Every trigger variable is named, and no undocumented AWS trigger is."""
    compose = (ROOT / "docker-compose.yml").read_text()
    assert "env_file:" in compose and "path: .env" in compose
    for doc in DOCS:
        text = doc.read_text()
        assert ".env" in text
        for name in renderer.CREDENTIAL_VARIABLES:
            assert f"`{name}`" in text, (doc, name)
    section = DOCS[0].read_text().split("`CREDENTIAL_VARIABLES`")[1]
    listed = re.findall(r"`(AWS_[A-Z_]+)`", section.split("`docker-compose.yml`")[0])
    assert listed == list(renderer.CREDENTIAL_VARIABLES)


def _compose_forwarded():
    """Bare names of the pulumi service `environment` list are host-forwarded."""
    service = yaml.safe_load((ROOT / "docker-compose.yml").read_text())["services"]
    env = service["pulumi"]["environment"]
    assert isinstance(env, list)
    return [entry for entry in env if "=" not in entry]


def test_documented_forwarded_variables_match_compose_environment():
    """Both docs name exactly the compose-forwarded host variables."""
    forwarded = _compose_forwarded()
    assert "AWS_DEFAULT_REGION" in forwarded and "PYTHONPATH" not in forwarded
    for doc, marker, end in (
        (DOCS[0], "`docker-compose.yml` forwards only", "from the host"),
        (DOCS[1], "Compose forwards", "from the host"),
    ):
        sentence = doc.read_text().split(marker)[1].split(end)[0]
        assert re.findall(r"`([A-Za-z0-9_]+)`", sentence) == forwarded, doc


# Break-glass CLI subcommand -> IAM actions its documented use requires.
CLI_PERMISSIONS = {
    "create-change-set": {"cloudformation:CreateChangeSet"},
    "wait change-set-create-complete": {"cloudformation:DescribeChangeSet"},
    "describe-change-set": {"cloudformation:DescribeChangeSet"},
    "delete-change-set": {"cloudformation:DeleteChangeSet"},
    "update-stack": {"cloudformation:UpdateStack"},
    "wait stack-update-complete": {"cloudformation:DescribeStacks"},
    "detect-stack-drift": {
        "cloudformation:DetectStackDrift",
        "cloudformation:DetectStackResourceDrift",
        "cloudformation:BatchDescribeTypeConfigurations",
    },
    "describe-stack-drift-detection-status": {
        "cloudformation:DescribeStackDriftDetectionStatus"
    },
    "describe-stack-resource-drifts": {"cloudformation:DescribeStackResourceDrifts"},
}
# Extra permissions implied by a flag (AWS "Prevent updates to stack resources").
FLAG_PERMISSIONS = {
    "--stack-policy-during-update-body": {"cloudformation:SetStackPolicy"},
}


def _break_glass_section():
    text = DOCS[0].read_text()
    return text.split("## Break-glass revocation of publisher trust")[1].split(
        "\n4. **Removal**"
    )[0]


def _holder_permissions():
    section = _break_glass_section()
    holder = section.split("Mutating")[1].split("`docs/governance-stack.md`")[0]
    return set(re.findall(r"`((?:cloudformation|iam):[A-Za-z]+)`", holder))


def _verifier_input_apis():
    text = DOCS[0].read_text()
    para = text.split("Inputs must be\nauthenticated")[1].split("It\nreturns")[0]
    names = re.findall(r"[A-Z][A-Za-z]+", para.replace("\n", " "))
    cfn = {"DescribeStacks", "GetTemplate", "GetStackPolicy", "ListStackResources"}
    wanted = set()
    for name in names:
        if name in cfn:
            wanted.add(f"cloudformation:{name}")
        elif name.startswith(("Get", "List")):
            wanted.add(f"iam:{name}")
    return wanted


def test_break_glass_holder_list_covers_verifier_inputs():
    """Every API named as a verifier input is granted to the holder."""
    wanted = _verifier_input_apis()
    assert {
        "cloudformation:ListStackResources",
        "iam:GetPolicy",
        "iam:GetPolicyVersion",
        "iam:ListRoleTags",
        "iam:GetRole",
    } <= wanted
    assert wanted <= _holder_permissions(), wanted - _holder_permissions()


def test_break_glass_commands_map_to_listed_permissions():
    """Each aws cloudformation subcommand and flag in the block is granted."""
    section = _break_glass_section()
    holder = _holder_permissions()
    block = section.split("```bash")[1].split("```")[0]
    commands = re.findall(r"aws cloudformation ((?:wait )?[a-z-]+)", block)
    assert commands
    for command in commands:
        assert command in CLI_PERMISSIONS, command
        assert CLI_PERMISSIONS[command] <= holder, command
    for flag, perms in FLAG_PERMISSIONS.items():
        assert flag in block and perms <= holder
    # Drift and executable alternatives are documented in prose, not the block.
    for command in ("detect-stack-drift", "wait stack-update-complete"):
        assert command.split()[-1] in section
        assert CLI_PERMISSIONS[command] <= holder
    assert "cloudformation:ExecuteChangeSet" in holder
