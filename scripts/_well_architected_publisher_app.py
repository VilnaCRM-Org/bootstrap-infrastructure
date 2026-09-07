"""Local bootstrap App token issuance; no private key or token is printed."""

from __future__ import annotations

import base64
import contextlib
import json
import os
import subprocess  # nosec B404
import time
import urllib.request
from pathlib import Path
from typing import cast

from _well_architected_publisher import APP_ID, APP_SLUG, REPOSITORY
from _well_architected_trusted_evidence import _json, _require


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def api(
    token: str, path: str, *, method: str = "GET", payload: dict | None = None
) -> dict:
    request = urllib.request.Request(
        "https://api.github.com/" + path,
        method=method,
        headers={
            "Authorization": "Bearer " + token,
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        data=None if payload is None else json.dumps(payload).encode(),
    )  # nosec B310
    with urllib.request.build_opener(NoRedirect).open(request, timeout=30) as response:
        data = response.read(2_000_001)
    return _json(data) if data else {}


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


@contextlib.contextmanager
def installation_token(key: Path, installation_id: int):
    """Authenticate the exact App, mint one repository-limited token, then revoke."""
    _require(
        type(installation_id) is int and installation_id > 0, "Invalid installation"
    )
    _require(
        key.is_file() and not key.is_symlink() and key.stat().st_mode & 0o077 == 0,
        "App key must be a private regular file",
    )
    now = int(time.time())
    signing = (
        b64(b'{"alg":"RS256","typ":"JWT"}')
        + "."
        + b64(json.dumps({"iat": now - 60, "exp": now + 300, "iss": APP_ID}).encode())
    )
    signature = subprocess.run(
        ["openssl", "dgst", "-sha256", "-sign", str(key)],
        input=signing.encode(),
        capture_output=True,
        check=False,
        timeout=30,
    )  # nosec B603 B607
    _require(signature.returncode == 0, "App signing failed")
    jwt = signing + "." + b64(signature.stdout)
    app = api(jwt, "app")
    _require(
        app.get("id") == APP_ID and app.get("slug") == APP_SLUG,
        "Signing identity is not the evidence App",
    )
    installation = api(jwt, f"app/installations/{installation_id}")
    _require(
        installation.get("app_id") == APP_ID
        and installation.get("account", {}).get("login") == "VilnaCRM-Org",
        "Foreign App installation",
    )
    result = api(
        jwt,
        f"app/installations/{installation_id}/access_tokens",
        method="POST",
        payload={
            "repositories": [REPOSITORY.split("/")[1]],
            "permissions": {
                "statuses": "write",
                "contents": "read",
                "actions": "read",
                "pull_requests": "read",
                "administration": "read",
                "vulnerability_alerts": "read",
            },
        },
    )
    token = result.get("token")
    _require(isinstance(token, str) and bool(token), "App token issuance failed")
    token = cast(str, token)
    previous = os.environ.get("GH_TOKEN")
    try:
        os.environ["GH_TOKEN"] = token
        yield
    finally:
        try:
            api(token, "installation/token", method="DELETE")
        finally:
            if previous is None:
                os.environ.pop("GH_TOKEN", None)
            else:
                os.environ["GH_TOKEN"] = previous
