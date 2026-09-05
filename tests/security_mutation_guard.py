"""Deny unmocked network or child-process access in the semantic mutation gate."""

import socket
import subprocess

import pytest


def denied(*args, **kwargs):
    """A missing boundary must never turn a mocked test into a real API write."""
    raise AssertionError("Security mutation tests prohibit unmocked external access")


@pytest.fixture(autouse=True)
def isolate_external_access(monkeypatch):
    """Tests may install explicit doubles after this fail-closed default."""
    monkeypatch.setattr(subprocess, "run", denied)
    monkeypatch.setattr(socket.socket, "connect", denied)
    monkeypatch.setattr(socket, "create_connection", denied)
