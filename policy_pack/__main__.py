"""Entrypoint for the bootstrap-infrastructure Pulumi Policy Pack."""

from __future__ import annotations

import sys
from importlib import import_module
from pathlib import Path

THIS_DIR = Path(__file__).resolve().parent
PARENT_DIR = THIS_DIR.parent
if str(PARENT_DIR) not in sys.path:
    sys.path.insert(0, str(PARENT_DIR))

create_policy_pack = import_module("policy_pack.guardrails").create_policy_pack

create_policy_pack()
