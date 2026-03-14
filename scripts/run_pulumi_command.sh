#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
command_name="${1:-}"
project_dir="${PULUMI_DIR:-pulumi}"
stack_name="${PULUMI_STACK:-}"
backend_url="${PULUMI_BACKEND_URL:-}"
secrets_provider="${PULUMI_SECRETS_PROVIDER:-}"
policy_pack_dir="${PULUMI_POLICY_PACK_DIR:-${repo_root}/policy_pack}"
preview_json_path="${PULUMI_PREVIEW_JSON_PATH:-}"
require_existing_stack="${PULUMI_REQUIRE_EXISTING_STACK:-false}"
resolved_python=""
policy_args=()

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

if [[ -f "${policy_pack_dir}/PulumiPolicy.yaml" ]]; then
  policy_args=(--policy-pack "${policy_pack_dir}")
fi

pulumi login "${backend_url}"

if ! pulumi -C "${project_dir}" stack select "${stack_name}" --non-interactive; then
  if [[ "${require_existing_stack}" == "true" ]]; then
    echo "Pulumi stack '${stack_name}' does not exist in backend '${backend_url}'." >&2
    exit 1
  fi
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
    if [[ -n "${preview_json_path}" ]]; then
      mkdir -p "$(dirname "${preview_json_path}")"
      pulumi -C "${project_dir}" preview \
        "${policy_args[@]}" \
        --stack "${stack_name}" \
        --non-interactive \
        --json \
        --suppress-outputs | tee "${preview_json_path}"
    else
      pulumi -C "${project_dir}" preview \
        "${policy_args[@]}" \
        --stack "${stack_name}" \
        --non-interactive \
        --diff
    fi
    ;;
  up)
    pulumi -C "${project_dir}" up \
      "${policy_args[@]}" \
      --stack "${stack_name}" \
      --yes \
      --skip-preview \
      --non-interactive
    ;;
  drift)
    pulumi -C "${project_dir}" refresh \
      --stack "${stack_name}" \
      --non-interactive \
      --diff \
      --preview-only \
      --expect-no-changes
    ;;
  *)
    echo "unsupported command: ${command_name}" >&2
    exit 1
    ;;
esac
