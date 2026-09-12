"""Initial installer observation uses native read transport and real verification."""

import json
import runpy
import sys
from dataclasses import asdict
from pathlib import Path

import pytest
from seed import policy_registry as registry
from test_operator_enrollment_runtime import Reader, build

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))

import operator_seed_observation as observation  # noqa: E402


class InitialReader(Reader):
    """Model installed disabled seed metadata, never an actual AWS installation."""

    def role_metadata(self, principal):
        """Keep all three new executor trusts disabled for initial verification."""
        role = super().role_metadata(principal)
        if not principal.existing:
            role["AssumeRolePolicyDocument"] = registry.disabled_trust_policy(
                self.expected.account_id
            )
        return role


@pytest.fixture
def native(monkeypatch, tmp_path, request):
    """Replace only subprocess execution, retaining real native input/JSON checks."""
    expected = build(getattr(request, "param", "test"))
    reader = InitialReader(expected)
    policy = json.loads(
        (
            Path(__file__).resolve().parents[1] / "fixtures/aws-config-role-v72.json"
        ).read_text()
    )
    frozen = next(p.frozen_config for p in expected.principals if p.frozen_config)
    assert registry.document_hash(policy) == frozen.aws_policy_sha256
    reader.policies[frozen.aws_policy_arn] = (frozen.aws_policy_version, policy)
    role_name = "IndependentInstaller"
    role_arn = f"arn:aws:iam::{expected.account_id}:role/reviewed/{role_name}"
    role_id = (
        "AROA" + "A" * 17
    )  # Synthetic immutable identifier, not live IAM evidence.
    reader.caller = {
        "Arn": f"arn:aws:sts::{expected.account_id}:assumed-role/{role_name}/session-1",
        "Account": expected.account_id,
        "UserId": f"{role_id}:session-1",
    }
    installer = {"Role": {"Arn": role_arn, "RoleName": role_name, "RoleId": role_id}}
    executable = tmp_path / "aws"
    executable.write_text("unused test executable\n")
    executable.chmod(0o700)
    # No subprocess executes and these non-secret strings are only test inputs.
    for key in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"):
        monkeypatch.setenv(key, "synthetic-test-session")
    calls = []

    def run(command, environment):
        """Serve exactly the native adapter's closed JSON argument requests."""
        assert command[0] == str(executable)
        assert environment["AWS_SHARED_CREDENTIALS_FILE"] == "/dev/null"
        assert environment["AWS_CONFIG_FILE"] == "/dev/null"
        service, operation = command[1], command[2].replace("-", "_")
        arguments = json.loads(command[command.index("--cli-input-json") + 1])
        calls.append((service, operation, arguments))
        if (service, operation, arguments) == (
            "iam",
            "get_role",
            {"RoleName": role_name},
        ):
            response = installer
        else:
            response = reader(service, operation, arguments)
        return json.dumps(response).encode()

    monkeypatch.setattr(observation.aws_read, "_run", run)
    return expected, reader, installer, str(executable), calls


def invoke(native, **overrides):
    """Call the real initial entry point with its explicit public inputs."""
    expected, _, installer, executable, _ = native
    arguments = {
        "account_id": expected.account_id,
        "seed_key": expected.seed_key,
        "installer_role_arn": installer["Role"]["Arn"],
        "aws_executable": executable,
    }
    arguments.update(overrides)
    return observation.observe_initial_enrollment(expected.environment, **arguments)


def cli_arguments(native):
    """Supply full public key metadata, without any secret argument values."""
    expected, _, installer, executable, _ = native
    return [
        "--environment",
        expected.environment,
        "--account-id",
        expected.account_id,
        "--seed-key-binding",
        registry.canonical_json(asdict(expected.seed_key)),
        "--installer-role-arn",
        installer["Role"]["Arn"],
        "--aws-executable",
        executable,
    ]


@pytest.mark.parametrize("native", ["test", "prod"], indirect=True)
def test_native_initial_observation_checks_complete_disabled_enrollment(native):
    expected, _, installer, _, calls = native
    verified = invoke(native)
    assert verified == registry.EnrollmentVerification(expected.sha256, 55, 24, 3)
    assert calls[:3] == [
        ("sts", "get_caller_identity", {}),
        ("iam", "get_role", {"RoleName": installer["Role"]["RoleName"]}),
        ("kms", "describe_key", {"KeyId": expected.seed_key.arn}),
    ]
    assert (
        len({a["PolicyArn"] for _, operation, a in calls if operation == "get_policy"})
        == 56
    )
    assert (
        len({a["RoleName"] for _, operation, a in calls if operation == "get_role"})
        == 25
    )
    assert {operation for _, operation, _ in calls} == {
        "get_caller_identity",
        "get_role",
        "describe_key",
        "get_policy",
        "get_policy_version",
        "list_attached_role_policies",
        "list_role_policies",
        "get_role_policy",
    }


@pytest.mark.parametrize(
    "value",
    [
        None,
        "arn:aws:iam::891377212104:root",
        "arn:aws:iam::891377212104:user/admin",
        "arn:aws:iam::933245420672:role/IndependentInstaller",
        "arn:aws:iam::891377212104:role/invalid path/IndependentInstaller",
        "arn:aws:iam::891377212104:role/GitHubOperatorApply-test",
    ],
)
def test_invalid_installer_request_never_reads_aws(native, value):
    with pytest.raises(ValueError):
        invoke(native, installer_role_arn=value)
    assert native[-1] == []


@pytest.mark.parametrize(
    "field,value",
    [
        ("Account", "933245420672"),
        ("Arn", None),
        ("Arn", "arn:aws:iam::891377212104:root"),
        ("Arn", "arn:aws:sts::891377212104:assumed-role/AnotherRole/session-1"),
        ("Arn", "arn:aws:sts::891377212104:assumed-role/IndependentInstaller/x"),
    ],
)
def test_wrong_session_stops_before_installer_or_enrollment_reads(native, field, value):
    native[1].caller[field] = value
    with pytest.raises(ValueError, match="STS caller"):
        invoke(native)
    assert native[-1] == [("sts", "get_caller_identity", {})]


@pytest.mark.parametrize(
    "field,value",
    [
        ("Arn", "arn:aws:iam::891377212104:role/other-path/IndependentInstaller"),
        ("RoleName", "Foreign"),
        ("RoleId", None),
        ("RoleId", "AIDA" + "A" * 17),
        ("RoleId", "AROA" + "B" * 17),
    ],
)
def test_live_role_mismatch_stops_before_broad_reads(native, field, value):
    arn = native[2]["Role"]["Arn"]
    native[2]["Role"][field] = value
    with pytest.raises(ValueError):
        invoke(native, installer_role_arn=arn)
    assert len(native[-1]) == 2


@pytest.mark.parametrize(
    "value", [None, "AROA" + "A" * 17 + ":different-session", "foreign"]
)
def test_sts_userid_must_bind_same_immutable_role_and_session(native, value):
    native[1].caller["UserId"] = value
    with pytest.raises(ValueError, match="immutable role"):
        invoke(native)
    assert len(native[-1]) == 2


@pytest.mark.parametrize("kind", ["guard", "boundary", "active_trust", "config", "key"])
def test_real_verifier_rejects_incomplete_or_changed_initial_enrollment(
    native, monkeypatch, kind
):
    expected, reader, _, _, _ = native
    if kind == "guard":
        arn = expected.principals[0].guard_arns[0]
        reader.policies[arn] = ("v3", {"Version": "2012-10-17", "Statement": []})
    elif kind == "key":
        reader.key["KeyState"] = "Disabled"
    elif kind == "config":
        frozen = next(p.frozen_config for p in expected.principals if p.frozen_config)
        reader.policies[frozen.aws_policy_arn] = (frozen.aws_policy_version, {})
    else:
        original = reader.role_metadata

        def changed(principal):
            """Return one genuinely invalid role field through the AWS transport."""
            value = original(principal)
            if not principal.existing:
                if kind == "boundary":
                    value.pop("PermissionsBoundary")
                else:
                    value["AssumeRolePolicyDocument"]["Statement"][0]["Effect"] = (
                        "Allow"
                    )
            return value

        monkeypatch.setattr(reader, "role_metadata", changed)
    with pytest.raises(ValueError):
        invoke(native)


@pytest.mark.parametrize(
    "payload",
    [
        "{}",
        "[]",
        '{"arn":"x","arn":"y"}',
        '{"arn":NaN}',
        '{"arn":Infinity}',
        "{",
        "x" * 4097,
    ],
)
def test_malformed_binding_rejected_without_aws(native, payload):
    with pytest.raises(ValueError):
        observation._key_binding(payload)
    assert native[-1] == []


def test_wrong_binding_field_type_and_unknown_field_rejected(native):
    binding = asdict(native[0].seed_key)
    binding["key_id"] = True
    with pytest.raises(ValueError):
        observation._key_binding(json.dumps(binding))
    binding = asdict(native[0].seed_key) | {"unexpected": "value"}
    with pytest.raises(ValueError):
        observation._key_binding(json.dumps(binding))


def test_cli_prints_only_verified_digest_counts_and_no_authorization(native, capsys):
    assert observation.main(cli_arguments(native)) == 0
    output = capsys.readouterr()
    assert output.err == ""
    assert json.loads(output.out) == asdict(
        registry.EnrollmentVerification(native[0].sha256, 55, 24, 3)
    )
    assert "arn:" not in output.out


def test_cli_sanitizes_transport_and_argument_errors(native, monkeypatch, capsys):
    def failed(*_):
        """Model an unsafe upstream exception that must not reach CLI output."""
        raise RuntimeError("synthetic-sensitive-upstream-error")

    monkeypatch.setattr(observation.aws_read, "_run", failed)
    assert observation.main(cli_arguments(native)) == 1
    assert observation.main(["--unexpected", "synthetic-sensitive-input"]) == 1
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == "Initial seed enrollment observation failed.\n" * 2


def test_script_entrypoint_fails_safely_without_arguments(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", [str(Path(observation.__file__))])
    with pytest.raises(SystemExit) as result:
        runpy.run_path(observation.__file__, run_name="__main__")
    assert result.value.code == 1
    assert capsys.readouterr().err == "Initial seed enrollment observation failed.\n"
