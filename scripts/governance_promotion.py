#!/usr/bin/env python3
"""Report governance scope and publish verified, SHA-bound promotion evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess  # nosec B404
from pathlib import Path
from typing import Any

import _github_evidence_environment as evidence_environment
from governance_paths import paths_touch_governance
from pulumi_command_preflight import gh, require

CONTEXT = "Governance Promotion"
PROMOTION_DESCRIPTION = "Infrastructure test and prod promotion verified"
PROOF_PATH = Path(".artifacts/governance-promotion/proof.json")
PLAN_INPUT_PATH = Path(".artifacts/promotion-inputs")
# The scope workflow checks out trusted default-branch source before this script.
TRUSTED_SOURCE_ROOT = Path(__file__).resolve().parents[1]
REQUIRED_STAGES = (
    "preflight",
    "governance_test_apply",
    "governance_test_post_apply_drift",
    "governance_prod_apply",
    "governance_prod_post_apply_drift",
)
PLATFORM_STAGES = (
    "preflight",
    "test_apply",
    "test_post_apply_drift",
    "prod_apply",
    "prod_post_apply_drift",
)
PROMOTION_WORKFLOWS = {
    "governance": ".github/workflows/pulumi-governance.yml",
    "platform": ".github/workflows/pulumi-pr-command-runner.yml",
    "service": ".github/workflows/self-deploy.yml",
}


def api_write(path: str, payload: dict[str, Any]) -> dict:
    """Send literal JSON to GitHub; never interpolate payload into shell source."""
    response = subprocess.run(  # nosec B603 B607
        ["gh", "api", path, "--method", "POST", "--input", "-"],
        input=json.dumps(payload),
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(response.stdout)


def post_status(sha: str, state: str, description: str, url: str) -> None:
    """Publish the dedicated merge signal from a credential-free trusted job."""
    api_write(
        f"repos/{os.environ['GITHUB_REPOSITORY']}/statuses/{sha}",
        {
            "context": CONTEXT,
            "state": state,
            "description": description,
            "target_url": url,
        },
    )


def report_scope() -> None:
    """Mark governance heads pending without overwriting verified promotion proof."""
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    pr_number = event["number"]
    require(isinstance(pr_number, int) and pr_number > 0, "Invalid PR number")
    base = f"repos/{os.environ['GITHUB_REPOSITORY']}"
    pr = gh(f"{base}/pulls/{pr_number}")
    sha = pr["head"]["sha"]
    require(re.fullmatch(r"[0-9a-f]{40}", sha) is not None, "Invalid PR SHA")
    require(pr["base"]["ref"] == "main", "PR must target main")
    base_sha = pr["base"]["sha"]
    require(re.fullmatch(r"[0-9a-f]{40}", base_sha) is not None, "Invalid base SHA")
    changed = gh(f"{base}/compare/{base_sha}...{sha}")["files"]
    require(len(changed) == pr["changed_files"], "Incomplete changed-file listing")
    current = gh(f"{base}/pulls/{pr_number}")
    require(
        current["head"]["sha"] == sha and current["base"]["sha"] == base_sha,
        "PR head or base moved",
    )
    files = [
        name
        for item in changed
        for name in (item["filename"], item.get("previous_filename", ""))
    ]
    governance = paths_touch_governance(files)
    kind = scope_promotion_kind(governance)
    needs_promotion = governance or kind == "service"
    if matching_promotion_exists(base, sha, pr_number, base_sha, kind):
        return
    post_status(
        sha,
        "pending" if needs_promotion else "success",
        f"{kind.title()} requires test and prod apply plus drift"
        if needs_promotion
        else "No governance changes",
        f"{os.environ['GITHUB_SERVER_URL']}/{os.environ['GITHUB_REPOSITORY']}/pull/{pr_number}",
    )


def scope_promotion_kind(governance: bool) -> str:
    """Select service scope only from the fixed trusted controller source tree."""
    if (TRUSTED_SOURCE_ROOT / PROMOTION_WORKFLOWS["service"]).is_file():
        return "service"
    return "governance" if governance else "platform"


def matching_promotion_exists(
    base: str, sha: str, pr_number: int, base_sha: str, kind: str
) -> bool:
    """Look up only App attestations bound to this PR's exact current scope."""
    statuses = gh(
        f"{base}/commits/{sha}/statuses?per_page=100", "--paginate", "--slurp"
    )
    latest = next(
        (
            status
            for page in statuses
            for status in page
            if status.get("context") == CONTEXT
            and status.get("creator", {}).get("login")
            == f"{os.environ['PROMOTION_APP_SLUG']}[bot]"
        ),
        {},
    )
    return verified_promotion_status(latest, pr_number, base_sha, kind)


def promotion_description(pr_number: int | str, base_sha: str, kind: str) -> str:
    """Bind the App attestation to one PR, base revision and deployment scope."""
    return f"{PROMOTION_DESCRIPTION}: PR{pr_number} {kind} {base_sha}"


def verified_promotion_status(
    status: dict, pr_number: int | str, base_sha: str, kind: str
) -> bool:
    """Only the isolated promotion App can preserve its completed proof."""
    return (
        status.get("context") == CONTEXT
        and status.get("state") == "success"
        and status.get("description")
        == promotion_description(pr_number, base_sha, kind)
        and status.get("creator", {}).get("login")
        == f"{os.environ['PROMOTION_APP_SLUG']}[bot]"
    )


def saved_plan_evidence(sha: str) -> dict:
    """Hash the exact saved plans downloaded only from this workflow run."""
    evidence = {}
    for environment in ("test", "prod"):
        directory = PLAN_INPUT_PATH / environment
        raw_manifest = (directory / "manifest.json").read_bytes()
        manifest = json.loads(raw_manifest)
        require(manifest["commitSha"] == sha, "Saved plan belongs to another SHA")
        require(manifest["schemaVersion"] == 1, "Unknown saved-plan schema")
        require(bool(manifest["stacks"]), "Empty saved-plan manifest")
        for entry in manifest["stacks"]:
            relative = Path(entry["planFile"])
            require(
                relative.parent == Path(".artifacts/pulumi-plan"),
                "Unexpected saved-plan artifact path",
            )
            digest = hashlib.sha256(
                (directory / relative.name).read_bytes()
            ).hexdigest()
            require(digest == entry["planSha256"], "Saved-plan artifact hash mismatch")
        evidence[environment] = {
            "manifestSha256": hashlib.sha256(raw_manifest).hexdigest(),
            "backendUrl": manifest["backendUrl"],
            "pulumiDir": manifest["pulumiDir"],
            "policyPackDir": manifest["policyPackDir"],
            "stacks": manifest["stacks"],
        }
    return evidence


def build_proof(needs: dict) -> dict:
    """Require both account applies and post-apply drift from this exact run."""
    kind = os.environ.get("PROMOTION_KIND", "governance")
    require(kind in PROMOTION_WORKFLOWS, "Invalid promotion kind")
    stages = REQUIRED_STAGES if kind == "governance" else PLATFORM_STAGES
    require(
        all(needs.get(stage, {}).get("result") == "success" for stage in stages),
        "Promotion stages did not all succeed",
    )
    outputs = needs["preflight"]["outputs"]
    require(
        outputs["command"] == "up" and outputs["target_environment"] == "prod",
        "Only prod up can publish promotion",
    )
    sha = outputs["head_sha"]
    require(re.fullmatch(r"[0-9a-f]{40}", sha) is not None, "Invalid verified SHA")
    pr_number = outputs["pull_request_number"]
    require(re.fullmatch(r"[1-9][0-9]*", pr_number) is not None, "Invalid verified PR")
    run_id = os.environ["GITHUB_RUN_ID"]
    require(re.fullmatch(r"[1-9][0-9]*", run_id) is not None, "Invalid run ID")
    provenance = {
        "base_sha": outputs["base_sha"],
        "source_run_id": outputs["source_run_id"],
        "comment_id": outputs["comment_id"],
    }
    require(
        re.fullmatch(r"[0-9a-f]{40}", provenance["base_sha"]) is not None,
        "Invalid authenticated base SHA",
    )
    require(
        all(
            re.fullmatch(r"[1-9][0-9]*", provenance[key])
            for key in ("source_run_id", "comment_id")
        ),
        "Invalid authenticated intake provenance",
    )
    return {
        **provenance,
        "kind": kind,
        "saved_plans": saved_plan_evidence(sha),
        "repository": os.environ["GITHUB_REPOSITORY"],
        "head_sha": sha,
        "pull_request_number": pr_number,
        "run_id": run_id,
        "run_url": (
            f"{os.environ['GITHUB_SERVER_URL']}/"
            f"{os.environ['GITHUB_REPOSITORY']}/actions/runs/{run_id}"
        ),
        "workflow": PROMOTION_WORKFLOWS[kind],
        "stages": {stage: "success" for stage in stages},
    }


def publish_proof(proof: dict) -> None:
    """Project actual verified account applies into required deployment records."""
    require(
        proof["repository"] == os.environ["GITHUB_REPOSITORY"],
        "Promotion belongs to another repository",
    )
    base = f"repos/{proof['repository']}"
    pr = gh(f"{base}/pulls/{proof['pull_request_number']}")
    require(pr["state"] == "open" and pr["merged"] is False, "PR closed or merged")
    require(pr["head"]["sha"] == proof["head_sha"], "PR head moved after promotion")
    require(pr["base"]["sha"] == proof["base_sha"], "PR base moved after promotion")
    require(pr["base"].get("ref") == "main", "PR no longer targets main")
    require(
        all(
            isinstance(pr[side].get("repo"), dict)
            and pr[side]["repo"].get("full_name") == proof["repository"]
            for side in ("base", "head")
        ),
        "PR repository identity changed after promotion",
    )
    artifact_id = os.environ["PROMOTION_ARTIFACT_ID"]
    require(
        re.fullmatch(r"[1-9][0-9]*", artifact_id) is not None, "Missing proof artifact"
    )
    evidence = {**proof, "artifact_url": f"{proof['run_url']}/artifacts/{artifact_id}"}
    for environment in ("test", "prod"):
        deployment = api_write(
            f"{base}/deployments",
            {
                "ref": proof["head_sha"],
                "environment": environment,
                "auto_merge": False,
                "required_contexts": [],
                "production_environment": environment == "prod",
                "description": "Verified infrastructure saved-plan apply and drift",
                "payload": evidence,
            },
        )
        require(deployment["sha"] == proof["head_sha"], "Deployment SHA mismatch")
        api_write(
            f"{base}/deployments/{deployment['id']}/statuses",
            {
                "state": "success",
                "log_url": evidence["artifact_url"],
                "description": "Infrastructure saved-plan apply and drift succeeded",
                "auto_inactive": False,
            },
        )
    post_status(
        proof["head_sha"],
        "success",
        promotion_description(
            proof["pull_request_number"], proof["base_sha"], proof["kind"]
        ),
        evidence["artifact_url"],
    )


def main(argv: list[str] | None = None) -> int:
    """Run only from default-branch scope or final promotion reporter jobs."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "mode", choices=("scope", "prepare", "publish", "verify-environment")
    )
    mode = parser.parse_args(argv).mode
    if mode == "verify-environment":
        endpoint = (
            f"repos/{os.environ['GITHUB_REPOSITORY']}/environments/"
            f"{evidence_environment.NAME}"
        )
        blockers = evidence_environment.verification_blockers(
            gh(endpoint), gh(f"{endpoint}/deployment-branch-policies")
        )
        require(not blockers, "; ".join(blockers))
        return 0
    if mode == "scope":
        report_scope()
        return 0
    proof = build_proof(json.loads(os.environ["PROMOTION_NEEDS"]))
    if mode == "prepare":
        PROOF_PATH.parent.mkdir(parents=True, exist_ok=True)
        PROOF_PATH.write_text(json.dumps(proof, sort_keys=True, indent=2) + "\n")
    else:
        require(
            json.loads(PROOF_PATH.read_text()) == proof, "Promotion artifact changed"
        )
        publish_proof(proof)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
