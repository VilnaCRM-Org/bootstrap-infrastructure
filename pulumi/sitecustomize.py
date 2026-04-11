"""Enable coverage collection in subprocesses when configured."""

import sys
from typing import Any

coverage_module: Any | None

try:
    import coverage as coverage_module
except Exception:
    coverage_module = None

if coverage_module is not None:
    try:
        coverage_module.process_startup()
    except Exception as exc:
        print(
            f"warning: coverage subprocess startup failed: {exc}",
            file=sys.stderr,
        )
