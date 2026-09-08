"""Offline transport tests; subprocess fixtures never contact AWS."""

import json
import os
import sys
import time
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))

import operator_aws_read as transport  # noqa: E402
import operator_enrollment_runtime as collector  # noqa: E402
from test_operator_enrollment_runtime import Reader, build  # noqa: E402


@pytest.fixture(autouse=True)
def ambient_session(monkeypatch):
    """Replace ambient inputs with visibly synthetic, nonfunctional credentials."""
    for key in transport._SESSION_KEYS:
        monkeypatch.setenv(key, "synthetic-session-value")


@pytest.fixture
def executable(tmp_path):
    """Write a local fake CLI under an absolute path containing spaces."""
    path = tmp_path / "trusted bin" / "aws"
    path.parent.mkdir()

    def write(source='print("{}")'):
        path.write_text(f"#!{sys.executable}\n{source}\n", encoding="utf-8")
        path.chmod(0o700)
        return str(path)

    return write


@pytest.fixture
def reader(executable):
    """Construct the production adapter against the synthetic executable."""
    return transport.AwsCliRead(build(), aws_executable=executable())


@pytest.mark.parametrize("environment", ["test", "prod"])
@pytest.mark.parametrize("purpose", ["preview", "apply", "drift"])
def test_complete_collector_dispatch_preserves_all_metadata(
    monkeypatch, executable, environment, purpose
):
    expected = build(environment)
    sdk = Reader(expected, purpose, "encoded")
    executable_path = executable()
    commands = []

    def run(argv, environment):
        commands.append(argv)
        assert environment["AWS_CONFIG_FILE"] == os.devnull
        arguments = json.loads(argv[argv.index("--cli-input-json") + 1])
        result = sdk(argv[1], argv[2].replace("-", "_"), arguments)
        return json.dumps(result).encode()

    monkeypatch.setattr(transport, "_run", run)
    callback = transport.AwsCliRead(expected, aws_executable=executable_path)
    actual = collector.collect_enrollment(expected, purpose=purpose, call=callback)
    assert len(actual.policies) == 55
    assert len(actual.principals) == 24
    assert len(actual.aws_managed_policies) == 1
    assert {(service, operation) for service, operation, _ in sdk.calls} == set(
        transport._READS
    )
    for argv in commands:
        assert argv[:1] == [executable_path]
        assert argv[5:] == [
            "--region",
            "eu-central-1",
            "--output",
            "json",
            "--no-cli-pager",
            "--no-paginate",
            "--cli-connect-timeout",
            "5",
            "--cli-read-timeout",
            "20",
        ]
    assert commands[0][1:3] == ["sts", "get-caller-identity"]


def test_environment_excludes_files_profiles_endpoints_and_alternative_credentials(
    monkeypatch,
):
    forbidden = (
        "AWS_PROFILE",
        "AWS_DEFAULT_PROFILE",
        "AWS_CONFIG_FILE",
        "AWS_SHARED_CREDENTIALS_FILE",
        "AWS_WEB_IDENTITY_TOKEN_FILE",
        "AWS_ROLE_ARN",
        "AWS_CONTAINER_CREDENTIALS_FULL_URI",
        "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
        "AWS_ENDPOINT_URL",
        "AWS_ENDPOINT_URL_IAM",
        "AWS_DATA_PATH",
        "AWS_CA_BUNDLE",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "PYTHONPATH",
        "LD_PRELOAD",
        "BOTO_CONFIG",
    )
    for key in forbidden:
        monkeypatch.setenv(key, "hostile-value")
    result = transport._session_environment()
    assert set(result) == set(transport._SESSION_KEYS) | {
        "PATH",
        "AWS_CONFIG_FILE",
        "AWS_SHARED_CREDENTIALS_FILE",
        "BOTO_CONFIG",
        "AWS_EC2_METADATA_DISABLED",
        "AWS_CLI_AUTO_PROMPT",
        "AWS_PAGER",
        "AWS_MAX_ATTEMPTS",
        "AWS_RETRY_MODE",
    }
    assert all(
        result[key] == "synthetic-session-value" for key in transport._SESSION_KEYS
    )
    assert result["PATH"] == os.defpath
    assert result["AWS_EC2_METADATA_DISABLED"] == "true"
    assert "hostile-value" not in result.values()


@pytest.mark.parametrize("key", transport._SESSION_KEYS)
@pytest.mark.parametrize("value", [None, "", "x\0y", "x" * 8193])
def test_missing_or_malformed_issued_session_fails_before_process(
    reader, monkeypatch, key, value
):
    if value is None:
        monkeypatch.delenv(key)
    else:
        # os.environ rejects NUL itself; patch its mapping for that boundary case.
        monkeypatch.setattr(transport.os, "environ", {**os.environ, key: value})
    calls = []
    monkeypatch.setattr(transport, "_run", lambda *args: calls.append(args))
    with pytest.raises(transport.AwsReadError, match="ambient AWS session"):
        reader("sts", "get_caller_identity", {})
    assert not calls


@pytest.mark.parametrize(
    "service,operation,arguments",
    [
        ("sts", "assume_role", {}),
        ("sts", "assume_role_with_web_identity", {}),
        ("iam", "delete_role", {"RoleName": "Role"}),
        ("kms", "decrypt", {}),
        ("secretsmanager", "get_secret_value", {}),
        ("STS", "get_caller_identity", {}),
        (["sts"], "get_caller_identity", {}),
        ("sts", ["get_caller_identity"], {}),
        ("sts", "get_caller_identity", []),
        ("sts", "get_caller_identity", {"Profile": "root"}),
        ("sts", "get_caller_identity", {"Marker": "x"}),
        ("iam", "get_role", {}),
        ("iam", "get_role", {"RoleName": "outside-registry"}),
        ("iam", "get_role", {"RoleName": []}),
        ("iam", "get_role", {"RoleName": "x", "endpoint_url": "https://evil.invalid"}),
        (
            "kms",
            "describe_key",
            {"KeyId": "arn:aws:kms:eu-central-1:999999999999:key/other"},
        ),
        (
            "iam",
            "get_policy",
            {"PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"},
        ),
        (
            "iam",
            "get_policy",
            {"PolicyArn": "arn:aws:iam::999999999999:policy/foreign"},
        ),
    ],
)
def test_hostile_dispatch_never_starts_a_process(
    reader, monkeypatch, service, operation, arguments
):
    calls = []
    monkeypatch.setattr(transport, "_run", lambda *args: calls.append(args))
    with pytest.raises(transport.AwsReadError):
        reader(service, operation, arguments)
    assert not calls


@pytest.mark.parametrize(
    "field,value",
    [
        ("VersionId", "v0"),
        ("VersionId", "v1; command"),
        ("VersionId", None),
        ("VersionId", "v" + "1" * 129),
        ("PolicyName", "bad/name"),
        ("PolicyName", "аbc"),
        ("PolicyName", "x" * 129),
        ("PolicyName", None),
        ("MaxItems", True),
        ("MaxItems", 99),
        ("MaxItems", "100"),
        ("Marker", ""),
        ("Marker", "x" * 1025),
        ("Marker", None),
        ("Marker", "x\0y"),
    ],
)
def test_invalid_variable_parameters_rejected(field, value):
    with pytest.raises(transport.AwsReadError, match="Invalid AWS metadata"):
        transport.AwsCliRead._variable_parameters({field: value})


def test_marker_is_opaque_json_data_and_exactly_one_page_is_returned(
    executable, tmp_path
):
    source = (
        "import json, sys\n"
        "args = json.loads(sys.argv[sys.argv.index('--cli-input-json') + 1])\n"
        "print(json.dumps({'IsTruncated': True, 'Marker': args['Marker'], "
        "'PolicyNames': []}))"
    )
    callback = transport.AwsCliRead(build(), aws_executable=executable(source))
    marker = f"--endpoint-url https://evil.invalid ; touch '{tmp_path}/unwanted' $(id)"
    name = build().principals[0].arn.rsplit("/", 1)[-1]
    actual = callback(
        "iam",
        "list_role_policies",
        {"RoleName": name, "MaxItems": 100, "Marker": marker},
    )
    assert actual == {"IsTruncated": True, "Marker": marker, "PolicyNames": []}
    assert not (tmp_path / "unwanted").exists()


@pytest.mark.parametrize("value", [None, "aws", "/missing/aws", "/tmp/aws\0bad"])
def test_missing_or_relative_executable_rejected(value):
    with pytest.raises(transport.AwsReadError, match="trusted absolute"):
        transport.AwsCliRead(build(), aws_executable=value)


def test_directory_nonexecutable_and_wrong_binary_names_rejected(executable, tmp_path):
    path = Path(executable())
    path.chmod(0o600)
    with pytest.raises(transport.AwsReadError, match="trusted absolute"):
        transport.AwsCliRead(build(), aws_executable=str(path))
    wrong = path.rename(path.with_name("python"))
    with pytest.raises(transport.AwsReadError, match="trusted absolute"):
        transport.AwsCliRead(build(), aws_executable=str(wrong))
    directory = tmp_path / "aws"
    directory.mkdir()
    with pytest.raises(transport.AwsReadError, match="trusted absolute"):
        transport.AwsCliRead(build(), aws_executable=str(directory))


def test_forged_registry_rejected_before_transport(executable):
    expected = build()
    with pytest.raises(transport.AwsReadError, match="Untrusted enrollment registry"):
        transport.AwsCliRead(
            replace(expected, policies=()), aws_executable=executable()
        )


@pytest.mark.parametrize(
    "data,match",
    [
        (b"", "Invalid AWS metadata JSON"),
        (b"private-response-text", "Invalid AWS metadata JSON"),
        (b"\xff", "Invalid AWS metadata JSON"),
        (b"[]", "must be an object"),
        (b"null", "must be an object"),
        (b'{"key":1,"key":2}', "Duplicate AWS metadata JSON field"),
        (
            b'{"nested":{"Effect":"Allow","Effect":"Deny"}}',
            "Duplicate AWS metadata JSON field",
        ),
        (b'{"key":NaN}', "Invalid AWS metadata JSON"),
        (b'{"key":Infinity}', "Invalid AWS metadata JSON"),
        (b"[" * 2000 + b"]" * 2000, "Invalid AWS metadata JSON"),
        (b"x" * (transport.MAX_STDOUT_BYTES + 1), "Invalid AWS metadata output"),
        ("{}", "Invalid AWS metadata output"),
    ],
)
def test_malformed_duplicate_or_oversized_response_is_redacted(data, match):
    with pytest.raises(transport.AwsReadError, match=match) as error:
        transport._response(data)
    assert "private-response-text" not in str(error.value)


def test_complete_json_preserves_literal_policy_values():
    data = {"Policy": {"Document": {"Resource": "arn:aws:s3:::bucket/a%2Fb+literal"}}}
    assert transport._response(json.dumps(data).encode()) == data


def test_real_process_drains_both_pipes_and_redacts_stderr(executable):
    source = (
        "import sys\nsys.stderr.write('private-stderr-text')\nprint('{\"ok\":true}')"
    )
    callback = transport.AwsCliRead(build(), aws_executable=executable(source))
    assert callback("sts", "get_caller_identity", {}) == {"ok": True}


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_real_process_output_limit_kills_and_reaps(executable, monkeypatch, stream):
    monkeypatch.setattr(transport, "MAX_STDOUT_BYTES", 256)
    monkeypatch.setattr(transport, "MAX_STDERR_BYTES", 256)
    source = (
        f"import sys, time\nsys.{stream}.write('x' * 1000)\n"
        f"sys.{stream}.flush()\ntime.sleep(30)"
    )
    callback = transport.AwsCliRead(build(), aws_executable=executable(source))
    processes = []
    popen = transport.subprocess.Popen

    def record(*args, **kwargs):
        assert kwargs["shell"] is False
        assert kwargs["stdin"] == transport.subprocess.DEVNULL
        process = popen(*args, **kwargs)
        processes.append(process)
        return process

    monkeypatch.setattr(transport.subprocess, "Popen", record)
    with pytest.raises(transport.AwsReadError, match="exceeds bound"):
        callback("sts", "get_caller_identity", {})
    assert len(processes) == 1
    assert processes[0].poll() is not None


@pytest.mark.parametrize("closed_pipes", [True, False])
def test_process_timeout_is_bounded_and_redacted(executable, monkeypatch, closed_pipes):
    monkeypatch.setattr(transport, "PROCESS_TIMEOUT_SECONDS", 0.1)
    source = "import os, time\n"
    if closed_pipes:
        source += "os.close(1)\nos.close(2)\n"
    source += "time.sleep(30)"
    callback = transport.AwsCliRead(build(), aws_executable=executable(source))
    started = time.monotonic()
    with pytest.raises(transport.AwsReadError, match="timed out|command failed"):
        callback("sts", "get_caller_identity", {})
    assert time.monotonic() - started < 3


def test_nonzero_exit_and_spawn_failure_are_redacted(executable, monkeypatch):
    source = "import sys\nsys.stderr.write('private-response-text')\nsys.exit(1)"
    callback = transport.AwsCliRead(build(), aws_executable=executable(source))
    with pytest.raises(transport.AwsReadError, match="command failed") as error:
        callback("sts", "get_caller_identity", {})
    assert "private-response-text" not in str(error.value)

    def failed(*_args, **_kwargs):
        raise OSError("private-response-text")

    monkeypatch.setattr(transport.subprocess, "Popen", failed)
    with pytest.raises(transport.AwsReadError, match="command failed") as error:
        callback("sts", "get_caller_identity", {})
    assert "private-response-text" not in str(error.value)
    assert error.value.__suppress_context__ is True


def test_timeout_after_pipe_closure_does_not_wait_without_a_bound(monkeypatch):
    clock = iter([0, 100])
    monkeypatch.setattr(transport.time, "monotonic", lambda: next(clock))

    class EmptySelector:
        """Model a stream set already closed exactly as the deadline expires."""

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return None

        def register(self, *_):
            return None

        def get_map(self):
            return {}

    monkeypatch.setattr(transport.selectors, "DefaultSelector", EmptySelector)
    with pytest.raises(transport.AwsReadError, match="timed out"):
        transport._read_streams(SimpleNamespace(stdout=None, stderr=None))
