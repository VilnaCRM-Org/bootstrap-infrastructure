"""Finite immutable GitHub artifact transport; never execute extracted content."""

from __future__ import annotations

import io
import os
import selectors
import stat
import subprocess  # nosec B404
import time
import zipfile
from pathlib import Path, PurePosixPath
from typing import BinaryIO, cast

from _well_architected_trusted_evidence import MAX_BUNDLE_BYTES, MAX_FILES, _require


def download(repository: str, artifact_id: int) -> bytes:
    """Bound stdout while gh performs authenticated artifact redirect handling."""
    process = subprocess.Popen(
        ["gh", "api", f"repos/{repository}/actions/artifacts/{artifact_id}/zip"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )  # nosec B603 B607
    data = bytearray()
    try:
        _require(process.stdout is not None, "Missing artifact stream")
        stdout = cast(BinaryIO, process.stdout)
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            deadline = time.monotonic() + 120
            while True:
                _require(time.monotonic() < deadline, "Artifact download timed out")
                if not selector.select(timeout=1):
                    continue
                chunk = os.read(stdout.fileno(), 65536)
                if not chunk:
                    break
                data.extend(chunk)
                _require(
                    len(data) <= MAX_BUNDLE_BYTES, "Compressed artifact exceeds bound"
                )
        _require(process.wait(timeout=10) == 0, "Artifact download failed")
        return bytes(data)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=10)
        if process.stdout is not None:
            process.stdout.close()


def extract(raw: bytes, destination: Path) -> None:
    """Extract a bounded, non-aliased regular-file archive into a fresh directory."""
    _require(len(raw) <= MAX_BUNDLE_BYTES, "Compressed artifact exceeds bound")
    _require(not destination.exists(), "Artifact staging must be fresh")
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        entries = archive.infolist()
        _require(
            0 < len(entries) <= MAX_FILES + 1, "Artifact entry count exceeds bound"
        )
        _require(
            sum(item.file_size for item in entries) <= MAX_BUNDLE_BYTES,
            "Expanded artifact exceeds bound",
        )
        names = set()
        for item in entries:
            path = PurePosixPath(item.filename)
            _require(
                not item.is_dir()
                and not path.is_absolute()
                and ".." not in path.parts
                and str(path) == item.filename
                and "\\" not in item.filename,
                "Unsafe artifact path",
            )
            _require(
                item.filename not in names
                and stat.S_IFMT(item.external_attr >> 16) in (0, stat.S_IFREG),
                "Artifact duplicate or special file",
            )
            names.add(item.filename)
        destination.mkdir(mode=0o700, parents=True)
        for item in entries:
            target = destination / item.filename
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with archive.open(item) as stream, target.open("xb") as output:
                data = stream.read(MAX_BUNDLE_BYTES + 1)
                _require(len(data) == item.file_size, "Artifact size differs")
                output.write(data)
            target.chmod(0o600)
