"""Verify real process/network entry points cannot escape mutation isolation."""

import http.client
import os
import socket
import ssl
import subprocess
import sys
import urllib.request
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import run_pulumi_command as command  # noqa: E402

from tests import security_mutation_guard as guard  # noqa: E402

ORIGINAL_POPEN = subprocess.Popen


@pytest.fixture
def isolated(monkeypatch):
    """Install the real plugin fixture without requiring a mutation campaign."""
    guard.isolate_external_access.__wrapped__(monkeypatch)


@pytest.mark.parametrize("name", guard.PROCESS_APIS)
def test_every_subprocess_entry_point_is_denied(isolated, name):
    """Direct Popen and convenience helpers fail before any process creation."""
    with pytest.raises(AssertionError, match="prohibit unmocked external access"):
        getattr(subprocess, name)([sys.executable, "-c", "raise SystemExit(1)"])


@pytest.mark.parametrize("name", guard.OS_PROCESS_APIS)
def test_os_process_entry_points_are_denied(isolated, name):
    """Shell and direct child-creation entry points share the same default."""
    with pytest.raises(AssertionError, match="prohibit unmocked external access"):
        getattr(os, name)("this-command-must-never-run")


def test_target_default_runner_is_denied_before_actual_child_creation(monkeypatch):
    """The real saved-plan streaming path previously bypassed the run guard."""
    created = []

    def unexpected_child(*args, **kwargs):
        created.append(True)
        raise AssertionError("Reached actual child-creation boundary")

    # This sentinel keeps the regression safe even if Popen isolation regresses.
    monkeypatch.setattr(ORIGINAL_POPEN, "_execute_child", unexpected_child)
    guard.isolate_external_access.__wrapped__(monkeypatch)
    context = SimpleNamespace(env={}, runner=command.DEFAULT_RUNNER)
    with pytest.raises(AssertionError, match="prohibit unmocked external access"):
        command._run_with_observable_output(context, [sys.executable, "-c", "pass"])
    assert not created


@pytest.mark.parametrize("method", ["connect", "connect_ex", "sendto"])
def test_socket_entry_points_are_denied(isolated, method):
    """Both connected TCP and connectionless UDP writes are guarded."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        with pytest.raises(AssertionError, match="prohibit unmocked external access"):
            getattr(client, method)(b"blocked", ("127.0.0.1", 9))


@pytest.mark.parametrize("method", ["create_connection", "getaddrinfo"])
def test_socket_helpers_are_denied(isolated, method):
    """Resolution cannot leak a network operation before a connect denial."""
    with pytest.raises(AssertionError, match="prohibit unmocked external access"):
        getattr(socket, method)("invalid.example")


@pytest.mark.parametrize("method", ["connect", "connect_ex"])
def test_ssl_socket_overrides_are_denied(isolated, method):
    """SSL's socket overrides must not bypass the socket base-class patches."""
    with pytest.raises(AssertionError, match="prohibit unmocked external access"):
        getattr(ssl.SSLSocket, method)(object(), ("invalid.example", 443))


@pytest.mark.parametrize(
    "client_type", [http.client.HTTPConnection, http.client.HTTPSConnection]
)
@pytest.mark.parametrize("method", ["connect", "request"])
def test_http_client_entry_points_are_denied(isolated, client_type, method):
    """High-level HTTP calls fail without opening a network socket."""
    client = client_type("invalid.example")
    with pytest.raises(AssertionError, match="prohibit unmocked external access"):
        getattr(client, method)("GET", "/")


@pytest.mark.parametrize(
    "opener", [urllib.request.urlopen, urllib.request.build_opener]
)
def test_urllib_entry_points_are_denied(isolated, opener):
    """Cached convenience imports still terminate at the guarded opener."""
    # Parametrization captures urlopen before isolation; OpenerDirector.open is
    # independently patched so a previously imported alias is covered as well.
    with pytest.raises(AssertionError, match="prohibit unmocked external access"):
        if opener is urllib.request.build_opener:
            opener().open("https://invalid.example")
        else:
            opener("https://invalid.example")


def test_requests_uses_guarded_http_boundary(isolated):
    """Requests' cached socket helpers cannot reach external HTTP endpoints."""
    requests = pytest.importorskip("requests")
    with pytest.raises(AssertionError, match="prohibit unmocked external access"):
        requests.get("https://invalid.example", timeout=1)


def test_explicit_process_double_still_works(isolated, monkeypatch):
    """A deliberate Popen double can exercise the actual streaming helper."""
    calls = []

    def fake_process(args, **kwargs):
        calls.append(args)
        return SimpleNamespace(stdout=["reviewed fixture\n"], wait=lambda: 0)

    monkeypatch.setattr(subprocess, "Popen", fake_process)
    context = SimpleNamespace(env={}, runner=command.DEFAULT_RUNNER)
    result = command._run_with_observable_output(context, ["pulumi", "about"])
    assert result.returncode == 0 and result.stdout == "reviewed fixture\n"
    assert calls == [["pulumi", "about"]]


def test_explicit_runner_and_network_doubles_still_work(isolated, monkeypatch):
    """Tests opt into bounded doubles after installing the default guard."""
    response = subprocess.CompletedProcess(["fixture"], 0, stdout="", stderr="")
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: response)
    monkeypatch.setattr(urllib.request, "urlopen", lambda *args, **kwargs: "fixture")
    assert subprocess.run(["fixture"]) is response
    assert urllib.request.urlopen("https://invalid.example") == "fixture"
