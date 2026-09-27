"""Decode complete GitHub REST pages from CLI versions without ``--slurp``."""

from __future__ import annotations

import json


def decode_array_pages(raw: str) -> list[list[object]]:
    """Preserve page boundaries from ``gh api --paginate`` JSON output."""
    decoder = json.JSONDecoder()
    pages: list[list[object]] = []
    offset = 0
    while offset < len(raw):
        while offset < len(raw) and raw[offset].isspace():
            offset += 1
        if offset == len(raw):
            break
        page, offset = decoder.raw_decode(raw, offset)
        if type(page) is not list:
            raise ValueError("GitHub paginated response must contain arrays")
        pages.append(page)
    return pages
