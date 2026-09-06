"""Deny unmocked process and network entry points in semantic mutation tests."""

import http.client
import os
import socket
import ssl
import subprocess
import urllib.request

import pytest

PROCESS_APIS = (
    "run",
    "Popen",
    "call",
    "check_call",
    "check_output",
    "getoutput",
    "getstatusoutput",
)
OS_PROCESS_APIS = ("system", "popen", "fork", "forkpty", "posix_spawn", "posix_spawnp")


def denied(*args, **kwargs):
    """A missing boundary must never turn a mocked test into a real API write."""
    raise AssertionError("Security mutation tests prohibit unmocked external access")


@pytest.fixture(autouse=True)
def isolate_external_access(monkeypatch):
    """Tests may install explicit doubles after these fail-closed defaults."""
    for name in PROCESS_APIS:
        monkeypatch.setattr(subprocess, name, denied)
    for name in OS_PROCESS_APIS:
        monkeypatch.setattr(os, name, denied, raising=False)
    monkeypatch.setattr(socket.socket, "connect", denied)
    monkeypatch.setattr(socket.socket, "connect_ex", denied)
    monkeypatch.setattr(socket.socket, "sendto", denied)
    monkeypatch.setattr(socket, "create_connection", denied)
    monkeypatch.setattr(socket, "getaddrinfo", denied)
    monkeypatch.setattr(ssl.SSLSocket, "connect", denied)
    monkeypatch.setattr(ssl.SSLSocket, "connect_ex", denied)
    monkeypatch.setattr(http.client.HTTPConnection, "request", denied)
    monkeypatch.setattr(http.client.HTTPConnection, "connect", denied)
    monkeypatch.setattr(http.client.HTTPSConnection, "connect", denied)
    monkeypatch.setattr(urllib.request, "urlopen", denied)
    monkeypatch.setattr(urllib.request.OpenerDirector, "open", denied)
