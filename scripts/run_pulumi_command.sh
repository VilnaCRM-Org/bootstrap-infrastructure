#!/usr/bin/env bash

set -euo pipefail

command_name="${1:-}"
project_dir="${PULUMI_DIR:-pulumi}"
stack_name="${PULUMI_STACK:-}"
backend_url="${PULUMI_BACKEND_URL:-}"
secrets_provider="${PULUMI_SECRETS_PROVIDER:-}"
resolved_python=""

if [[ -z "${command_name}" ]]; then
  echo "usage: $0 <plan|up|drift>" >&2
  exit 1
fi

if [[ -z "${stack_name}" ]]; then
  echo "PULUMI_STACK is required." >&2
  exit 1
fi

if [[ -z "${backend_url}" ]]; then
  echo "PULUMI_BACKEND_URL is required." >&2
  exit 1
fi

if [[ -z "${secrets_provider}" ]]; then
  echo "PULUMI_SECRETS_PROVIDER is required." >&2
  exit 1
fi

export PULUMI_SKIP_UPDATE_CHECK="${PULUMI_SKIP_UPDATE_CHECK:-true}"

if [[ -x "/opt/uv-env/bin/python" ]]; then
  export PATH="/opt/pulumi:/opt/uv-env/bin:${PATH}"
  resolved_python="/opt/uv-env/bin/python"
elif [[ -x ".venv/bin/python" ]]; then
  resolved_python="$(pwd)/.venv/bin/python"
fi

if [[ -n "${resolved_python}" ]]; then
  export PULUMI_PYTHON_CMD="${PULUMI_PYTHON_CMD:-${resolved_python}}"
fi

pulumi login "${backend_url}"

if ! pulumi -C "${project_dir}" stack select "${stack_name}" --non-interactive; then
  pulumi -C "${project_dir}" stack init "${stack_name}" \
    --non-interactive \
    --secrets-provider "${secrets_provider}"
fi

pulumi -C "${project_dir}" stack change-secrets-provider \
  "${secrets_provider}" \
  --stack "${stack_name}" \
  --non-interactive

case "${command_name}" in
  plan)
    pulumi -C "${project_dir}" preview \
      --stack "${stack_name}" \
      --non-interactive \
      --diff
    ;;
  up)
    pulumi -C "${project_dir}" up \
      --stack "${stack_name}" \
      --yes \
      --skip-preview \
      --non-interactive
    ;;
  drift)
    pulumi -C "${project_dir}" preview \
      --stack "${stack_name}" \
      --non-interactive \
      --diff \
      --expect-no-changes
    ;;
  *)
    echo "unsupported command: ${command_name}" >&2
    exit 1
    ;;
esac
