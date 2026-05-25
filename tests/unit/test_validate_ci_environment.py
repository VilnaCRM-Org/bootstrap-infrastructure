from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parents[2] / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

validator = importlib.import_module("validate_ci_environment")


def _valid_environment() -> dict[str, str]:
    return {
        "AWS_ACCOUNT_ID": "123456789012",
        "AWS_REGION": "eu-central-1",
        "AWS_PREVIEW_ROLE_ARN": "arn:aws:iam::123456789012:role/Preview",
        "AWS_APPLY_ROLE_ARN": "arn:aws:iam::123456789012:role/Apply",
        "AWS_DRIFT_ROLE_ARN": "arn:aws:iam::123456789012:role/Drift",
        "AWS_OPERATIONS_ALERT_TRIAGE_ROLE_ARN": (
            "arn:aws:iam::123456789012:role/OperationsAlertTriage"
        ),
        "PULUMI_BACKEND_URL": "s3://pulumi-bootstrap-infrastructure-test/state/test",
        "PULUMI_SECRETS_PROVIDER": (
            "awskms://alias/pulumi-platform-bootstrap-test?region=eu-central-1"
        ),
        "PULUMI_PREVIEW_STACKS": "test,prod",
        "PULUMI_DRIFT_STACKS": "test",
        "OPERATIONS_TOPIC_ARN": "arn:aws:sns:eu-central-1:123456789012:bootstrap-test",
        "OPERATIONS_ALERT_QUEUE_NAME": "bootstrap-test-operations-alerts",
        "OPERATIONS_CLOUDTRAIL_NAME": "bootstrap-test-management-events",
    }


def test_parse_required_keys_strips_blank_items() -> None:
    assert validator.parse_required_keys(" AWS_ACCOUNT_ID, ,AWS_REGION ") == (
        "AWS_ACCOUNT_ID",
        "AWS_REGION",
    )


def test_validate_environment_accepts_aws_secrets_manager_derived_values() -> None:
    keys = validator.parse_required_keys(
        "AWS_ACCOUNT_ID,AWS_REGION,AWS_PREVIEW_ROLE_ARN,"
        "PULUMI_BACKEND_URL,PULUMI_SECRETS_PROVIDER,PULUMI_PREVIEW_STACKS"
    )

    assert validator.validate_environment(keys, _valid_environment()) == []


def test_validate_environment_rejects_missing_or_blank_values() -> None:
    keys = ("AWS_ACCOUNT_ID", "AWS_REGION")
    environment = {"AWS_ACCOUNT_ID": "   "}

    issues = validator.validate_environment(keys, environment)

    assert [issue.name for issue in issues] == ["AWS_ACCOUNT_ID", "AWS_REGION"]
    assert {issue.message for issue in issues} == {"is required"}


def test_validate_environment_rejects_unsafe_shapes() -> None:
    environment = {
        **_valid_environment(),
        "AWS_ACCOUNT_ID": "not-account",
        "AWS_REGION": "central",
        "AWS_PREVIEW_ROLE_ARN": "arn:aws:iam::123456789012:user/not-role",
        "PULUMI_BACKEND_URL": "file:///tmp/backend",
        "PULUMI_SECRETS_PROVIDER": "passphrase",
        "PULUMI_PREVIEW_STACKS": "test,$(secret)",
    }
    keys = validator.parse_required_keys(
        "AWS_ACCOUNT_ID,AWS_REGION,AWS_PREVIEW_ROLE_ARN,"
        "PULUMI_BACKEND_URL,PULUMI_SECRETS_PROVIDER,PULUMI_PREVIEW_STACKS"
    )

    issues = validator.validate_environment(keys, environment)

    assert {issue.name for issue in issues} == {
        "AWS_ACCOUNT_ID",
        "AWS_REGION",
        "AWS_PREVIEW_ROLE_ARN",
        "PULUMI_BACKEND_URL",
        "PULUMI_SECRETS_PROVIDER",
        "PULUMI_PREVIEW_STACKS",
    }


def test_validate_environment_accepts_job_specific_and_unknown_keys() -> None:
    keys = validator.parse_required_keys(
        "OPERATIONS_TOPIC_ARN,OPERATIONS_ALERT_QUEUE_NAME,"
        "OPERATIONS_CLOUDTRAIL_NAME,UNVALIDATED_METADATA"
    )
    environment = {**_valid_environment(), "UNVALIDATED_METADATA": "value"}

    assert validator.validate_environment(keys, environment) == []


def test_validate_environment_rejects_job_specific_shapes() -> None:
    environment = {
        **_valid_environment(),
        "OPERATIONS_TOPIC_ARN": "not-an-arn",
        "OPERATIONS_ALERT_QUEUE_NAME": "bad/resource/name",
        "OPERATIONS_CLOUDTRAIL_NAME": "",
    }
    keys = validator.parse_required_keys(
        "OPERATIONS_TOPIC_ARN,OPERATIONS_ALERT_QUEUE_NAME,OPERATIONS_CLOUDTRAIL_NAME"
    )

    issues = validator.validate_environment(keys, environment)

    assert {issue.name for issue in issues} == {  # nosec B101
        "OPERATIONS_CLOUDTRAIL_NAME"
    }

    environment["OPERATIONS_CLOUDTRAIL_NAME"] = "bootstrap-test-management-events"
    issues = validator.validate_environment(keys, environment)

    assert {issue.name for issue in issues} == {  # nosec B101
        "OPERATIONS_TOPIC_ARN",
        "OPERATIONS_ALERT_QUEUE_NAME",
    }


def test_write_github_environment_skips_missing_output_and_region(
    tmp_path: Path,
) -> None:
    validator.write_github_environment({}, None)

    github_env = tmp_path / "github-env"
    validator.write_github_environment({}, str(github_env))

    assert github_env.read_text(encoding="utf-8") == ""


def test_write_github_environment_sets_default_region(tmp_path: Path) -> None:
    github_env = tmp_path / "github-env"

    validator.write_github_environment(
        {"AWS_REGION": "eu-central-1"},
        str(github_env),
    )

    assert github_env.read_text(encoding="utf-8") == "AWS_DEFAULT_REGION=eu-central-1\n"


def test_write_github_environment_rejects_multiline_region(tmp_path: Path) -> None:
    github_env = tmp_path / "github-env"

    try:
        validator.write_github_environment(
            {"AWS_REGION": "eu-central-1\nINJECTED=value"},
            str(github_env),
        )
    except ValueError as exc:
        assert "newline" in str(exc)  # nosec B101
    else:  # pragma: no cover
        raise AssertionError("expected multiline region rejection")

    assert not github_env.exists()


def test_main_reports_errors_without_printing_values(capsys) -> None:
    original_environ = dict(os.environ)
    try:
        os.environ.clear()
        os.environ.update({"AWS_ACCOUNT_ID": "not-account"})

        assert (
            validator.main(
                [
                    "--purpose",
                    "unit",
                    "--required-keys",
                    "AWS_ACCOUNT_ID,AWS_REGION",
                ]
            )
            == 1
        )
    finally:
        os.environ.clear()
        os.environ.update(original_environ)

    output = capsys.readouterr().out
    assert "AWS_REGION is required" in output
    assert "not-account" not in output


def test_main_rejects_empty_required_keys(capsys) -> None:
    assert (
        validator.main(
            [
                "--purpose",
                "unit",
                "--required-keys",
                " , ",
            ]
        )
        == 1
    )

    assert "required-keys must include at least one" in capsys.readouterr().out


def test_main_writes_default_region_and_summary(tmp_path: Path, capsys) -> None:
    original_environ = dict(os.environ)
    github_env = tmp_path / "github-env"
    secret_id = "/bootstrap-infrastructure/ci/test"
    try:
        os.environ.clear()
        os.environ.update(
            {
                **_valid_environment(),
                "GITHUB_ENV": str(github_env),
                "CI_CONFIG_SECRET_ID": secret_id,
            }
        )

        assert (
            validator.main(
                [
                    "--purpose",
                    "unit",
                    "--required-keys",
                    "AWS_ACCOUNT_ID,AWS_REGION,PULUMI_BACKEND_URL,"
                    "PULUMI_SECRETS_PROVIDER",
                ]
            )
            == 0
        )
    finally:
        os.environ.clear()
        os.environ.update(original_environ)

    assert github_env.read_text(encoding="utf-8") == "AWS_DEFAULT_REGION=eu-central-1\n"
    output = capsys.readouterr().out
    assert "using a fixed CI secret" in output
    assert secret_id not in output


def test_main_rejects_multiline_github_env_write(tmp_path: Path, capsys) -> None:
    original_environ = dict(os.environ)
    github_env = tmp_path / "github-env"
    try:
        os.environ.clear()
        os.environ.update(
            {
                **_valid_environment(),
                "AWS_REGION": "eu-central-1\nINJECTED=value",
                "GITHUB_ENV": str(github_env),
            }
        )

        assert (
            validator.main(
                [
                    "--purpose",
                    "unit",
                    "--required-keys",
                    "AWS_ACCOUNT_ID",
                ]
            )
            == 1
        )
    finally:
        os.environ.clear()
        os.environ.update(original_environ)

    assert "AWS_REGION must not contain newline" in capsys.readouterr().out
    assert not github_env.exists()
