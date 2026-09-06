"""Existing encryption state must survive separate preview and apply jobs."""

import base64
import copy
import importlib
import json
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest
import yaml


@pytest.fixture
def setup(monkeypatch, tmp_path):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[2] / "scripts"))
    module = importlib.import_module("_pulumi_stack_config")
    command = importlib.import_module("run_pulumi_command")
    project = tmp_path / "pulumi"
    project.mkdir()
    (project / "Pulumi.yaml").write_text("name: example\nruntime: python\n")
    provider = "awskms://alias/example?region=eu-central-1"
    (project / "Pulumi.test.yaml").write_text(
        yaml.safe_dump(
            {"secretsprovider": provider, "config": {"example:value": "safe"}}
        )
    )
    values = {
        "sts": {"Account": "123456789012"},
        "s3api": {"VersionId": "version-1", "ETag": '"etag"'},
        "kms": {
            "KeyMetadata": {
                "Arn": "arn:aws:kms:eu-central-1:123456789012:key/existing",
                "KeyState": "Enabled",
            }
        },
        "export": {
            "deployment": {
                "resources": [
                    {
                        "urn": (
                            "urn:pulumi:test::example::"
                            "pulumi:pulumi:Stack::example-test"
                        )
                    }
                ],
                "secrets_providers": {
                    "type": "cloud",
                    "state": {
                        "url": provider,
                        "encryptedkey": base64.b64encode(
                            b"existing-ciphertext"
                        ).decode(),
                    },
                },
            }
        },
    }
    calls = []
    configurations = []

    def runner(argv, **kwargs):
        calls.append(argv)
        if argv[0] == "aws":
            payload = values[argv[1]]
        elif "export" in argv:
            payload = values["export"]
        else:
            if "--config-file" in argv:
                configurations.append(
                    yaml.safe_load(
                        Path(argv[argv.index("--config-file") + 1]).read_text()
                    )
                )
            if "--save-plan" in argv:
                Path(argv[argv.index("--save-plan") + 1]).write_text(
                    "encrypted-plan-fixture"
                )
                kwargs["stdout"].write("{}")
            return subprocess.CompletedProcess(argv, 0, "", "")
        return subprocess.CompletedProcess(argv, 0, json.dumps(payload), "")

    context = command.CommandContext(
        root_dir=tmp_path,
        env={
            "AWS_ACCOUNT_ID": "123456789012",
            "AWS_REGION": "eu-central-1",
            "PULUMI_COMMIT_SHA": "a" * 40,
        },
        pulumi_dir=project,
        policy_pack_dir=tmp_path / "policy",
        plan_dir=tmp_path / ".artifacts/pulumi-plan",
        preview_artifact_dir=tmp_path / ".artifacts/pulumi-preview",
        backend_url="s3://test-state/state/test",
        secrets_provider=provider,
        runner=runner,
    )
    return module, command, context, values, calls, configurations


def test_private_config_uses_existing_key_and_is_removed(setup):
    module, command, context, values, calls, _ = setup
    original = (context.pulumi_dir / "Pulumi.test.yaml").read_bytes()
    with module.prepared_stack_configuration(context, "test") as prepared:
        path = prepared.config_file
        assert path.stat().st_mode & 0o777 == 0o600
        assert path.parent.stat().st_mode & 0o777 == 0o700
        assert context.root_dir not in path.parents
        config = yaml.safe_load(path.read_text())
        assert (
            config["encryptedkey"]
            == values["export"]["deployment"]["secrets_providers"]["state"][
                "encryptedkey"
            ]
        )
        assert "encryptedkey" not in json.dumps(prepared.provider_identity)
        assert "--config-file" in command._pulumi_command(
            prepared, command.StackCommand("preview", "test")
        )
        module.verify_provider_identity(
            prepared, {"secretsProviderIdentity": prepared.provider_identity}
        )
    assert not path.exists()
    assert (context.pulumi_dir / "Pulumi.test.yaml").read_bytes() == original
    assert all("--show-secrets" not in c and "init" not in c for c in calls)
    assert all(
        "--expected-bucket-owner" in c for c in calls if c[0:2] == ["aws", "s3api"]
    )


def test_private_config_cleanup_on_operation_failure(setup):
    module, _, context, *_ = setup
    with pytest.raises(RuntimeError, match="operation failed"):
        with module.prepared_stack_configuration(context, "test") as prepared:
            path = prepared.config_file
            raise RuntimeError("operation failed")
    assert not path.exists()


def test_file_backend_preserves_local_convenience(setup):
    module, _, context, _, calls, _ = setup
    local = replace(context, backend_url="file:///tmp/local")
    with module.prepared_stack_configuration(local, "org/test") as prepared:
        assert prepared is local
        module.verify_provider_identity(prepared, {})
    assert not calls


@pytest.mark.parametrize(
    "backend",
    [
        "https://test-state",
        "s3://bad@bucket/path",
        "s3://test-state/path?region=other",
        "s3://test-state/path#fragment",
        "s3://test-state/a/../b",
        "s3://test-state/a//b",
        "s3://test-state//a",
        "s3://test-state/a/",
        "s3://test-state/state/%2e%2e/other",
        "s3://test-state/state%2Fother",
        "s3://test-state/state\\other",
        "s3://test-state/state\nother",
    ],
)
def test_rejects_ambiguous_backend(setup, backend):
    module, _, context, *_ = setup
    with pytest.raises(module.StackConfigError, match="exact S3"):
        with module.prepared_stack_configuration(
            replace(context, backend_url=backend), "test"
        ):
            pytest.fail("unexpected yield")


@pytest.mark.parametrize(
    "change",
    [
        {"AWS_ACCOUNT_ID": ""},
        {"AWS_ACCOUNT_ID": "123"},
        {"PULUMI_BACKEND_URL": "s3://other"},
        {"PULUMI_CLOUD_SECRET_OVERRIDE": "other"},
    ],
)
def test_rejects_missing_account_and_environment_redirects(setup, change):
    module, _, context, *_ = setup
    with pytest.raises(module.StackConfigError):
        with module.prepared_stack_configuration(
            replace(context, env={**context.env, **change}), "test"
        ):
            pytest.fail("unexpected yield")


@pytest.mark.parametrize(
    "name,stack",
    [(None, "test"), (42, "test"), ("bad/name", "test"), ("example", "../test")],
)
def test_rejects_project_or_stack_ambiguity(setup, name, stack):
    module, _, context, *_ = setup
    (context.pulumi_dir / "Pulumi.yaml").write_text(yaml.safe_dump({"name": name}))
    with pytest.raises(module.StackConfigError, match="Exact project"):
        with module.prepared_stack_configuration(context, stack):
            pytest.fail("unexpected yield")


@pytest.mark.parametrize("bad", [None, [], "[invalid", "missing", "symlink"])
def test_yaml_errors_are_sanitized(setup, bad):
    module, _, context, *_ = setup
    path = context.pulumi_dir / "Pulumi.yaml"
    if bad in ("missing", "symlink"):
        path.unlink()
        if bad == "symlink":
            path.symlink_to(context.pulumi_dir / "Pulumi.test.yaml")
    else:
        path.write_text(bad if isinstance(bad, str) else yaml.safe_dump(bad))
    with pytest.raises(module.StackConfigError, match="configuration"):
        with module.prepared_stack_configuration(context, "test"):
            pytest.fail("unexpected yield")


@pytest.mark.parametrize(
    "payload,code", [("bad-json PRIVATE DATA", 0), ("[]", 0), ("{}", 1)]
)
def test_metadata_errors_do_not_expose_payloads(setup, payload, code, capsys):
    module, _, context, *_ = setup
    ctx = replace(
        context,
        runner=lambda argv, **kwargs: subprocess.CompletedProcess(
            argv, code, payload, "PRIVATE DATA"
        ),
    )
    with pytest.raises(module.StackConfigError) as caught:
        with module.prepared_stack_configuration(ctx, "test"):
            pytest.fail("unexpected yield")
    assert "PRIVATE DATA" not in str(caught.value)
    assert "PRIVATE DATA" not in str(capsys.readouterr())


@pytest.mark.parametrize(
    "area,change",
    [
        ("sts", {"Account": "999999999999"}),
        ("s3api", {"VersionId": "null", "ETag": "etag"}),
        ("s3api", {"VersionId": "v", "ETag": None}),
        ("export", {"deployment": []}),
        ("export", {"deployment": {}}),
        ("export", {"deployment": {"resources": [None]}}),
        (
            "export",
            {"deployment": {"resources": [{"urn": "urn:pulumi:other::example::x::y"}]}},
        ),
    ],
)
@pytest.mark.parametrize("empty_inventory", [False, True])
def test_invalid_live_metadata_rejects_before_operation(
    setup, area, change, empty_inventory
):
    module, _, context, values, *_ = setup
    if empty_inventory:
        values["export"]["deployment"]["resources"] = []
    values[area] = change
    with pytest.raises(module.StackConfigError):
        with module.prepared_stack_configuration(context, "test"):
            pytest.fail("unexpected yield")


@pytest.mark.parametrize(
    "change",
    [
        {"pending_operations": [{}]},
        {"secrets_providers": []},
        {"secrets_providers": {"type": "passphrase", "state": {}}},
        {"secrets_providers": {"type": "cloud", "state": None}},
    ],
)
@pytest.mark.parametrize("empty_inventory", [False, True])
def test_pending_or_absent_existing_cloud_provider_rejects(
    setup, change, empty_inventory
):
    module, _, context, values, *_ = setup
    if empty_inventory:
        values["export"]["deployment"]["resources"] = []
    values["export"]["deployment"].update(change)
    with pytest.raises(module.StackConfigError):
        with module.prepared_stack_configuration(context, "test"):
            pytest.fail("unexpected yield")


@pytest.mark.parametrize(
    "change",
    [
        {"url": "awskms://alias/foreign?region=eu-central-1"},
        {"encryptedkey": ""},
        {"encryptedkey": None},
        {"encryptedkey": "%%%"},
    ],
)
@pytest.mark.parametrize("empty_inventory", [False, True])
def test_provider_mismatch_or_missing_encrypted_key_never_generates_key(
    setup, change, empty_inventory
):
    module, _, context, values, calls, _ = setup
    if empty_inventory:
        values["export"]["deployment"]["resources"] = []
    values["export"]["deployment"]["secrets_providers"]["state"].update(change)
    with pytest.raises(module.StackConfigError):
        with module.prepared_stack_configuration(context, "test"):
            pytest.fail("unexpected yield")
    assert not any("encrypt" in c or "generate-data-key" in c for c in calls)


@pytest.mark.parametrize(
    "metadata",
    [
        None,
        {"Arn": 42},
        {
            "Arn": "arn:aws:kms:eu-central-1:999999999999:key/wrong",
            "KeyState": "Enabled",
        },
        {"Arn": "arn:aws:kms:us-east-1:123456789012:key/wrong", "KeyState": "Enabled"},
        {
            "Arn": "arn:aws:kms:eu-central-1:123456789012:key/disabled",
            "KeyState": "Disabled",
        },
    ],
)
@pytest.mark.parametrize("empty_inventory", [False, True])
def test_kms_key_identity_rejects_foreign_account_region_or_disabled_key(
    setup, metadata, empty_inventory
):
    module, _, context, values, *_ = setup
    if empty_inventory:
        values["export"]["deployment"]["resources"] = []
    values["kms"] = {"KeyMetadata": metadata}
    with pytest.raises(module.StackConfigError, match="KMS key"):
        with module.prepared_stack_configuration(context, "test"):
            pytest.fail("unexpected yield")


@pytest.mark.parametrize(
    "provider",
    [
        "awskms://alias/example",
        "awskms://alias/example?region=other",
        "awskms://alias/example?region=eu-central-1#fragment",
        "awskms://?region=eu-central-1",
    ],
)
def test_requested_provider_uri_is_exact(setup, provider):
    module, _, context, values, *_ = setup
    values["export"]["deployment"]["secrets_providers"]["state"]["url"] = provider
    with pytest.raises(module.StackConfigError):
        with module.prepared_stack_configuration(
            replace(context, secrets_provider=provider), "test"
        ):
            pytest.fail("unexpected yield")


@pytest.mark.parametrize(
    "change",
    [
        {"encryptionsalt": "old"},
        {"encryptedkey": "another-key"},
        {"secretsprovider": "other"},
    ],
)
def test_tracked_configuration_provider_conflict_is_not_silently_rewritten(
    setup, change
):
    module, _, context, *_ = setup
    path = context.pulumi_dir / "Pulumi.test.yaml"
    current = yaml.safe_load(path.read_text())
    current.update(change)
    path.write_text(yaml.safe_dump(current))
    original = path.read_bytes()
    with pytest.raises(module.StackConfigError, match="Committed configuration"):
        with module.prepared_stack_configuration(context, "test"):
            pytest.fail("unexpected yield")
    assert path.read_bytes() == original


@pytest.mark.parametrize("empty_inventory", [False, True])
def test_checkpoint_change_during_export_is_rejected(setup, empty_inventory):
    module, _, context, values, *_ = setup
    if empty_inventory:
        values["export"]["deployment"]["resources"] = []
    original = context.runner
    count = 0

    def runner(argv, **kwargs):
        nonlocal count
        if argv[0:2] == ["aws", "s3api"]:
            count += 1
            values["s3api"]["VersionId"] = str(count)
        return original(argv, **kwargs)

    with pytest.raises(module.StackConfigError, match="Checkpoint changed"):
        with module.prepared_stack_configuration(
            replace(context, runner=runner), "test"
        ):
            pytest.fail("unexpected yield")


@pytest.mark.parametrize("empty_inventory", [False, True])
def test_separate_jobs_derive_same_existing_key_and_bind_replay(
    setup, monkeypatch, empty_inventory
):
    _, command, context, values, calls, configs = setup
    if empty_inventory:
        values["export"]["deployment"]["resources"] = []
    monkeypatch.setattr(
        command,
        "_write_preview_summary",
        lambda root, preview, summary, **kwargs: summary.write_text("safe summary"),
    )
    assert command._run_plan_command(context, ["test"]) == 0
    manifest = json.loads((context.plan_dir / "manifest.json").read_text())
    binding = manifest["stacks"][0]["secretsProviderIdentity"]
    assert binding["project"] == "example" and binding["accountId"] == "123456789012"
    assert command._run_up_plan_command(context, ["test"]) == 0
    assert len(configs) == 2 and configs[0] == configs[1]
    assert all(
        not Path(c[c.index("--config-file") + 1]).exists()
        for c in calls
        if "--config-file" in c
    )
    assert "encryptedkey" not in (context.plan_dir / "manifest.json").read_text()


@pytest.mark.parametrize(
    "change", ["missing-binding", "key", "version", "config", "retarget-key"]
)
@pytest.mark.parametrize("empty_inventory", [False, True])
def test_replay_rejects_stale_or_tampered_provider_before_up(
    setup, monkeypatch, change, empty_inventory
):
    module, command, context, values, calls, _ = setup
    if empty_inventory:
        values["export"]["deployment"]["resources"] = []
    monkeypatch.setattr(
        command,
        "_write_preview_summary",
        lambda root, preview, summary, **kwargs: summary.write_text("safe summary"),
    )
    assert command._run_plan_command(context, ["test"]) == 0
    if change == "missing-binding":
        path = context.plan_dir / "manifest.json"
        manifest = json.loads(path.read_text())
        manifest["stacks"][0].pop("secretsProviderIdentity")
        path.write_text(json.dumps(manifest))
    elif change == "key":
        values["export"]["deployment"]["secrets_providers"]["state"]["encryptedkey"] = (
            base64.b64encode(b"different-key").decode()
        )
    elif change == "version":
        values["s3api"]["VersionId"] = "other"
    elif change == "retarget-key":
        values["kms"]["KeyMetadata"]["Arn"] += "-retargeted"
    else:
        path = context.pulumi_dir / "Pulumi.test.yaml"
        config = yaml.safe_load(path.read_text())
        config["config"]["example:value"] = "tampered"
        path.write_text(yaml.safe_dump(config))
    with pytest.raises(module.StackConfigError, match="Saved-plan provider"):
        command._run_up_plan_command(context, ["test"])
    assert not any(c[0] == "pulumi" and c[3] == "up" for c in calls)


def test_existing_provider_default_region_and_root_backend(setup):
    module, _, context, values, *_ = setup
    config = copy.deepcopy(values["export"]["deployment"]["secrets_providers"]["state"])
    (context.pulumi_dir / "Pulumi.test.yaml").write_text(
        yaml.safe_dump({"encryptedkey": config["encryptedkey"]})
    )
    env = {**context.env, "AWS_DEFAULT_REGION": context.env["AWS_REGION"]}
    env.pop("AWS_REGION")
    with module.prepared_stack_configuration(
        replace(context, env=env, backend_url="s3://test-state"), "test"
    ) as prepared:
        assert prepared.provider_identity["backendUrl"] == "s3://test-state"


def test_main_reports_safe_configuration_failure(setup, monkeypatch, capsys):
    _, command, context, values, *_ = setup
    values["sts"]["Account"] = "000000000000"
    monkeypatch.setattr(command, "_context_from_environment", lambda: context)
    monkeypatch.setattr(command, "_login_and_prepare", lambda *args: None)
    assert command.main(["preview"]) == 1
    assert "AWS caller account differs" in capsys.readouterr().err


@pytest.mark.parametrize("omit_resources", [False, True])
def test_explicitly_initialized_empty_checkpoint_reuses_existing_key(
    setup, omit_resources
):
    module, _, context, values, calls, _ = setup
    deployment = values["export"]["deployment"]
    deployment["resources"] = []
    if omit_resources:
        deployment.pop("resources")
    original = (context.pulumi_dir / "Pulumi.test.yaml").read_bytes()
    with module.prepared_stack_configuration(context, "test") as prepared:
        config = yaml.safe_load(prepared.config_file.read_text())
        assert (
            config["encryptedkey"]
            == deployment["secrets_providers"]["state"]["encryptedkey"]
        )
        assert prepared.provider_identity["checkpointVersionId"] == "version-1"
        assert prepared.provider_identity["project"] == "example"
        assert prepared.provider_identity["stack"] == "test"
        assert prepared.provider_identity["accountId"] == "123456789012"
        assert prepared.provider_identity["backendUrl"] == context.backend_url
        assert prepared.config_file.stat().st_mode & 0o777 == 0o600
    assert (context.pulumi_dir / "Pulumi.test.yaml").read_bytes() == original
    assert not any(
        operation in call
        for call in calls
        for operation in ("init", "import", "up", "encrypt", "generate-data-key")
    )


@pytest.mark.parametrize(
    "resources",
    [
        None,
        {},
        False,
        "empty",
        [{"urn": "urn:pulumi:test::example::aws:s3/bucket:Bucket::child"}],
        [{"urn": "urn:pulumi:test::example::pulumi:pulumi:Stack::wrong-root"}],
        [
            {"urn": "urn:pulumi:test::example::pulumi:pulumi:Stack::example-test"},
            {"urn": "urn:pulumi:prod::example::aws:s3/bucket:Bucket::foreign"},
        ],
    ],
)
def test_nonempty_or_malformed_inventory_retains_identity_checks(setup, resources):
    module, _, context, values, *_ = setup
    values["export"]["deployment"]["resources"] = resources
    with pytest.raises(module.StackConfigError, match="Checkpoint project"):
        with module.prepared_stack_configuration(context, "test"):
            pytest.fail("unexpected yield")


def test_missing_checkpoint_never_becomes_empty_initialization_fallback(setup):
    module, _, context, _, calls, _ = setup
    original = context.runner

    def runner(argv, **kwargs):
        if argv[:2] == ["aws", "s3api"]:
            calls.append(argv)
            return subprocess.CompletedProcess(argv, 254, "", "NoSuchKey")
        return original(argv, **kwargs)

    with pytest.raises(module.StackConfigError):
        with module.prepared_stack_configuration(
            replace(context, runner=runner), "test"
        ):
            pytest.fail("unexpected yield")
    assert not any(call[0] == "pulumi" for call in calls)
    assert not any("encrypt" in call or "generate-data-key" in call for call in calls)
