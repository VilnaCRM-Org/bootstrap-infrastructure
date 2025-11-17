#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cd "${ROOT_DIR}"

POETRY_BIN="${POETRY_BIN:-poetry}"
if ! command -v "${POETRY_BIN}" >/dev/null 2>&1; then
  POETRY_HOME="${POETRY_HOME:-/opt/poetry}"
  if [ -x "${POETRY_HOME}/bin/poetry" ]; then
    POETRY_BIN="${POETRY_HOME}/bin/poetry"
  fi
fi

if ! command -v "${POETRY_BIN}" >/dev/null 2>&1; then
  echo "Poetry executable not found. Set POETRY_BIN or install Poetry." >&2
  exit 127
fi

"${POETRY_BIN}" run mutmut run \
  --paths-to-mutate pulumi/pulumi_app \
  --runner "${POETRY_BIN} run pytest -q tests/unit tests/integration"
