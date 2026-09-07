from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path

import pytest

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
        "PULUMI_DIR": "pulumi",
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
        "PULUMI_BACKEND_URL,PULUMI_DIR,PULUMI_SECRETS_PROVIDER,"
        "PULUMI_PREVIEW_STACKS"
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
        "PULUMI_DIR": "../pulumi",
        "PULUMI_SECRETS_PROVIDER": "passphrase",
        "PULUMI_PREVIEW_STACKS": "test,$(secret)",
    }
    keys = validator.parse_required_keys(
        "AWS_ACCOUNT_ID,AWS_REGION,AWS_PREVIEW_ROLE_ARN,"
        "PULUMI_BACKEND_URL,PULUMI_DIR,PULUMI_SECRETS_PROVIDER,"
        "PULUMI_PREVIEW_STACKS"
    )

    issues = validator.validate_environment(keys, environment)

    assert {issue.name for issue in issues} == {
        "AWS_ACCOUNT_ID",
        "AWS_REGION",
        "AWS_PREVIEW_ROLE_ARN",
        "PULUMI_BACKEND_URL",
        "PULUMI_DIR",
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


def test_required_keys_accept_newlines_commas_and_mixed_blank_delimiters() -> None:
    assert validator.parse_required_keys(
        "AWS_ACCOUNT_ID\r\n AWS_REGION,\n,,PULUMI_BACKEND_URL\n"
    ) == ("AWS_ACCOUNT_ID", "AWS_REGION", "PULUMI_BACKEND_URL")


def test_all_published_key_validators_accept_commercial_metadata() -> None:
    environment = _valid_environment()
    assert validator.validate_environment(tuple(environment), environment) == []


def test_s3_validation_matches_frozen_stack_coordinates(tmp_path: Path) -> None:
    from types import SimpleNamespace

    import _pulumi_stack_config as stack_config
    import pytest

    (tmp_path / "Pulumi.yaml").write_text("name: exact-project\n")
    valid = ["s3://abc", "s3://abc/", "s3://a.b-c/state/test", "s3://" + "a" * 63]
    invalid = [
        "s3://",
        "s3://ab",
        "s3://" + "a" * 64,
        "s3://UPPER",
        "s3://-abc",
        "s3://abc-",
        "s3://user@abc",
        "s3://abc:443",
        "s3://[",
        "s3://abc//test",
        "s3://abc/state/",
        "s3://abc/.",
        "s3://abc/..",
        "s3://abc/state/../test",
        "s3://abc?region=x",
        "s3://abc#fragment",
        "s3://abc/%2e",
        "s3://abc\\test",
        "s3://abc/with space",
        " s3://abc",
        "s3://abc\n",
        "https://abc",
    ]
    for value in valid + invalid:
        context = SimpleNamespace(
            backend_url=value,
            env={"AWS_ACCOUNT_ID": "123456789012"},
            pulumi_dir=tmp_path,
        )
        if value in valid:
            assert validator._validate_backend_url(value) is None
            assert stack_config._coordinates(context, "test")["backendUrl"] == value
        else:
            assert validator._validate_backend_url(value) is not None
            with pytest.raises(ValueError):
                stack_config._coordinates(context, "test")


def test_kms_syntax_and_explicit_arn_pins_match_frozen_key_contract() -> None:
    import json
    from types import SimpleNamespace

    import _pulumi_stack_config as stack_config

    environment = _valid_environment()
    arn = (
        "arn:aws:kms:eu-central-1:123456789012:key/12345678-1234-1234-1234-123456789012"
    )
    valid = [
        "awskms://alias/example?region=eu-central-1",
        "awskms://12345678-1234-1234-1234-123456789012?region=eu-central-1",
        f"awskms://{arn}?region=eu-central-1",
        "awskms://arn%3Aaws%3Akms%3Aeu-central-1%3A123456789012%3Aalias/example?region=eu-central-1",
    ]
    for value in valid:
        calls = []

        def read(command, **kwargs):
            calls.append(command)
            return SimpleNamespace(
                returncode=0,
                stdout=json.dumps({"KeyMetadata": {"Arn": arn, "KeyState": "Enabled"}}),
            )

        context = SimpleNamespace(
            secrets_provider=value,
            env=environment,
            backend_url=environment["PULUMI_BACKEND_URL"],
            runner=read,
        )
        assert validator._validate_secrets_provider(value, environment) is None
        assert stack_config._key_identity(context, environment["AWS_ACCOUNT_ID"]) == arn
        assert calls[0][:3] == ["aws", "kms", "describe-key"]


def test_kms_rejects_malformed_missing_cross_region_and_foreign_account_values() -> (
    None
):
    environment = _valid_environment()
    invalid = [
        "awskms://",
        "awskms://?region=eu-central-1",
        "awskms://alias/example",
        "awskms:alias/example?region=eu-central-1",
        "awskms://[",
        "awskms://alias/example?region=",
        "awskms://alias/example?region=us-east-1",
        "awskms://alias/example?region=eu-central-1&region=eu-central-1",
        "awskms://alias/example?region=eu-central-1&profile=other",
        "awskms://alias/example?region=eu-central-1#fragment",
        "awskms://alias/%00?region=eu-central-1",
        "awskms://alias/with space?region=eu-central-1",
        "awskms://alias/example?region=eu-central-1\n",
        "awskms://arn:aws:kms:us-east-1:123456789012:key/existing?region=eu-central-1",
        "awskms://arn:aws:kms:eu-central-1:999999999999:key/existing?region=eu-central-1",
        "awskms://arn:aws-cn:kms:eu-central-1:123456789012:key/existing?region=eu-central-1",
        "awskms://arn:aws:kms:eu-central-1:123456789012:other/existing?region=eu-central-1",
        "awskms://ARN:aws:kms:eu-central-1:123456789012:key/existing?region=eu-central-1",
        "file://alias/example?region=eu-central-1",
    ]
    for value in invalid:
        assert validator.validate_environment(
            ("PULUMI_SECRETS_PROVIDER",),
            {**environment, "PULUMI_SECRETS_PROVIDER": value},
        )
    for field, value in [
        ("AWS_ACCOUNT_ID", ""),
        ("AWS_ACCOUNT_ID", "١٢٣٤٥٦٧٨٩٠١٢"),
        ("AWS_REGION", ""),
        ("AWS_REGION", "cn-north-1"),
        ("AWS_REGION", "us-gov-west-1"),
    ]:
        assert validator._validate_secrets_provider(
            environment["PULUMI_SECRETS_PROVIDER"], {**environment, field: value}
        )
    fallback = {key: value for key, value in environment.items() if key != "AWS_REGION"}
    fallback["AWS_DEFAULT_REGION"] = "eu-central-1"
    assert (
        validator._validate_secrets_provider(
            environment["PULUMI_SECRETS_PROVIDER"], fallback
        )
        is None
    )


def test_partition_scope_is_explicitly_commercial_only() -> None:
    for partition in ("aws-us-gov", "aws-cn", "aws-iso"):
        assert "commercial" in validator._validate_role_arn(
            f"arn:{partition}:iam::123456789012:role/Example"
        )
        assert "commercial" in validator._validate_sns_topic_arn(
            f"arn:{partition}:sns:us-east-1:123456789012:Example"
        )
    for region in ("us-gov-west-1", "us-iso-east-1", "cn-north-1"):
        assert "commercial" in validator._validate_region(region)
    assert validator._validate_account_id("١٢٣٤٥٦٧٨٩٠١٢")


def test_invalid_uris_are_not_printed_or_exported(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    for key, value in [
        ("PULUMI_BACKEND_URL", "s3://private-fragment#DO-NOT-LOG"),
        ("PULUMI_SECRETS_PROVIDER", "awskms://PRIVATE?region=wrong"),
    ]:
        for name, setting in _valid_environment().items():
            monkeypatch.setenv(name, setting)
        monkeypatch.setenv(key, value)
        env_file = tmp_path / "env"
        monkeypatch.setenv("GITHUB_ENV", str(env_file))
        assert validator.main(["--purpose", "test", "--required-keys", key]) == 1
        assert value not in capsys.readouterr().out
        assert not env_file.exists()


@pytest.mark.parametrize(
    "value", ["org:stack", "test,org:prod", "organization/project/test"]
)
def test_stack_list_rejects_qualified_or_colon_names(value):
    assert validator._validate_stack_list(value) is not None


@pytest.mark.parametrize(
    "value",
    [
        "pulumi/.",
        "pulumi/..",
        "pulumi/a/../b",
        "pulumi/./governance",
        "pulumi/a/../../outside",
    ],
)
def test_pulumi_project_path_rejects_dot_segments(value):
    environment = {**_valid_environment(), "PULUMI_DIR": value}
    assert validator.validate_environment(("PULUMI_DIR",), environment)


@pytest.mark.parametrize(
    "value",
    [
        "pulumi",
        "pulumi/governance",
        "pulumi/service-v1",
        "pulumi/with.dot",
        "pulumi/a_b/c-2",
    ],
)
def test_pulumi_project_path_preserves_documented_relative_paths(value):
    environment = {**_valid_environment(), "PULUMI_DIR": value}
    assert validator.validate_environment(("PULUMI_DIR",), environment) == []
