#!/usr/bin/env bash

set -euo pipefail

aws_region="${AWS_REGION:-}"
image_source="${RUNNER_IMAGE_SOURCE:-}"
repository_name="${RUNNER_ECR_REPOSITORY:-}"
image_tag="${RUNNER_IMAGE_TAG:-}"
additional_tags="${RUNNER_IMAGE_ADDITIONAL_TAGS:-}"

if [[ -z "${aws_region}" ]]; then
  echo "AWS_REGION is required." >&2
  exit 1
fi

if [[ -z "${image_source}" ]]; then
  echo "RUNNER_IMAGE_SOURCE is required." >&2
  exit 1
fi

if [[ -z "${repository_name}" ]]; then
  echo "RUNNER_ECR_REPOSITORY is required." >&2
  exit 1
fi

if [[ -z "${image_tag}" ]]; then
  echo "RUNNER_IMAGE_TAG is required." >&2
  exit 1
fi

account_id="$(aws sts get-caller-identity --query Account --output text)"
registry="${account_id}.dkr.ecr.${aws_region}.amazonaws.com"
image_uri="${registry}/${repository_name}"

aws ecr describe-repositories \
  --region "${aws_region}" \
  --repository-names "${repository_name}" >/dev/null

aws ecr get-login-password --region "${aws_region}" \
  | docker login --username AWS --password-stdin "${registry}" >/dev/null

docker tag "${image_source}" "${image_uri}:${image_tag}"
docker push "${image_uri}:${image_tag}"

if [[ -n "${additional_tags}" ]]; then
  IFS=',' read -r -a extra_tags <<< "${additional_tags}"
  for extra_tag in "${extra_tags[@]}"; do
    trimmed_tag="${extra_tag// /}"
    if [[ -z "${trimmed_tag}" ]]; then
      continue
    fi
    docker tag "${image_source}" "${image_uri}:${trimmed_tag}"
    docker push "${image_uri}:${trimmed_tag}"
  done
fi

printf 'image_uri=%s\n' "${image_uri}"
