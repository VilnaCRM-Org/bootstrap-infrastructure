"""Render the reviewed publisher stack and its IAM documents for validation.

Rendering is offline and always runs. Only when an AWS credential variable is set
and ``--render-only`` is absent does it call the read-only IAM Access Analyzer
ValidatePolicy and CloudFormation ValidateTemplate APIs through the AWS CLI. It
never creates, updates, executes or deletes a stack or change set. ERROR and
SECURITY_WARNING findings fail the run; an unavailable CLI or failed call blocks.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from _script_support import run
from seed.poc_publisher_stack_verification import _amended_packet
from seed.poc_runtime_fence_stack import (
    break_glass_during_update_policy_json,
    build_fence_stack_packet,
)

DEFAULT_OUTPUT = Path(".artifacts/runtime-seed-policies")
REGION = "eu-central-1"
CREDENTIAL_VARIABLES = (
    "AWS_ACCESS_KEY_ID",
    "AWS_PROFILE",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
    "AWS_CONTAINER_CREDENTIALS_FULL_URI",
    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
)
FAIL_FINDING_TYPES = frozenset({"ERROR", "SECURITY_WARNING"})
TRUST_RESOURCE_TYPE = "AWS::IAM::AssumeRolePolicyDocument"


class ValidationError(RuntimeError):
    """A required read-only AWS validation call did not complete."""


def _documents(template: Mapping[str, Any]) -> list[tuple[str, str, Any]]:
    """List every IAM document with the Access Analyzer policy type it needs."""
    rows = []
    for resource in template["Resources"].values():
        properties = resource["Properties"]
        if resource["Type"] == "AWS::IAM::ManagedPolicy":
            name = properties["ManagedPolicyName"]
            document = properties["PolicyDocument"]
            rows.append((f"policies/{name}.json", "IDENTITY_POLICY", document))
            continue
        role = properties["RoleName"]
        trust = properties["AssumeRolePolicyDocument"]
        rows.append((f"trust/{role}.json", "RESOURCE_POLICY", trust))
        for inline in properties["Policies"]:
            path = f"inline/{role}-{inline['PolicyName']}.json"
            rows.append((path, "IDENTITY_POLICY", inline["PolicyDocument"]))
    return sorted(rows, key=lambda row: row[0])


def render(output: Path) -> dict[str, Any]:
    """Write the exact template, stack policy, every IAM document and a manifest."""
    packet = build_fence_stack_packet()
    output.mkdir(parents=True, exist_ok=True)
    (output / "template.json").write_text(packet.template_json, encoding="utf-8")
    (output / "stack-policy.json").write_text(
        packet.deny_update_policy_json, encoding="utf-8"
    )
    during_update = break_glass_during_update_policy_json()
    (output / "break-glass-during-update-policy.json").write_text(
        during_update, encoding="utf-8"
    )
    amended = _amended_packet()
    (output / "amended-template.json").write_text(
        amended.template_json, encoding="utf-8"
    )
    documents = []
    template = json.loads(packet.template_json)
    for relative, policy_type, document in _documents(template):
        text = json.dumps(document, indent=2, sort_keys=True) + "\n"
        path = output / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        documents.append(
            {"path": relative, "policy_type": policy_type, "sha256": digest}
        )
    manifest = {
        "stack_name": packet.stack_name,
        "template_sha256": packet.template_sha256,
        "amended_template_sha256": amended.template_sha256,
        "break_glass_during_update_policy_sha256": hashlib.sha256(
            during_update.encode("utf-8")
        ).hexdigest(),
        "documents": documents,
    }
    text = json.dumps(manifest, indent=2) + "\n"
    (output / "manifest.json").write_text(text, encoding="utf-8")
    return manifest


def credentials_present(environ: Mapping[str, str]) -> bool:
    """Detect explicit credential variables without reading credential files."""
    return any(environ.get(name) for name in CREDENTIAL_VARIABLES)


def _aws(arguments: list[str]) -> dict[str, Any]:
    """Run one read-only AWS CLI validation call and parse its JSON result."""
    result = run(
        ["aws", *arguments, "--region", REGION, "--output", "json"],
        check=False,
        capture_output=True,
    )
    if result.returncode != 0:
        command = " ".join(arguments[:2])
        raise ValidationError(f"aws {command} failed: {result.stderr.strip()}")
    return json.loads(result.stdout or "{}")


def _policy_arguments(output: Path, row: Mapping[str, str]) -> list[str]:
    """Select identity or role-trust validation for one rendered document."""
    arguments = [
        "accessanalyzer",
        "validate-policy",
        "--policy-type",
        row["policy_type"],
        "--policy-document",
        f"file://{output / row['path']}",
    ]
    if row["policy_type"] == "RESOURCE_POLICY":
        arguments += ["--validate-policy-resource-type", TRUST_RESOURCE_TYPE]
    return arguments


def validate(output: Path, manifest: Mapping[str, Any]) -> list[str]:
    """Return blocking Access Analyzer findings; a failed call raises."""
    failures = []
    for row in manifest["documents"]:
        findings = _aws(_policy_arguments(output, row)).get("findings", [])
        failures.extend(
            f"{row['path']}: {finding.get('findingType')} {finding.get('issueCode')}"
            for finding in findings
            if finding.get("findingType") in FAIL_FINDING_TYPES
        )
    template = f"file://{output / 'template.json'}"
    _aws(["cloudformation", "validate-template", "--template-body", template])
    return failures


def main(
    argv: list[str] | None = None, environ: Mapping[str, str] | None = None
) -> int:
    """Render always; validate with AWS only when credential variables are set."""
    parser = argparse.ArgumentParser(
        description="Render and optionally validate publisher stack IAM documents."
    )
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--render-only", action="store_true")
    args = parser.parse_args(argv)
    manifest = render(args.output)
    print(
        f"Rendered {len(manifest['documents'])} IAM documents to {args.output}; "
        f"template sha256 {manifest['template_sha256']}"
    )
    environment = os.environ if environ is None else environ
    if args.render_only or not credentials_present(environment):
        print("AWS validation SKIPPED: render-only mode or no credential variables.")
        return 0
    if shutil.which("aws") is None:
        print("AWS validation BLOCKED: aws CLI is not installed.", file=sys.stderr)
        return 2
    try:
        failures = validate(args.output, manifest)
    except ValidationError as error:
        print(f"AWS validation BLOCKED: {error}", file=sys.stderr)
        return 2
    for failure in failures:
        print(failure, file=sys.stderr)
    print(f"AWS validation: {len(failures)} blocking finding(s).")
    return int(bool(failures))


if __name__ == "__main__":
    raise SystemExit(main())
