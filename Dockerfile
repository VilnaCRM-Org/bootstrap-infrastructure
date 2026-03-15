# syntax=docker/dockerfile:1.7-labs

# Keep a glibc-based slim image because AWS CLI v2 only guarantees support on
# glibc-based Linux distributions.
FROM python:3.11.9-slim-bookworm@sha256:8fb099199b9f2d70342674bd9dbccd3ed03a258f26bbd1d556822c6dfc60c317 AS tooling-builder

ARG TARGETARCH=amd64
ARG PULUMI_VERSION=3.138.0
ARG PULUMI_SHA256_AMD64=00245ee263285ee05ff33ec96c889aa4d1171e0c8eb0366a64205b45eafd6ed8
ARG PULUMI_SHA256_ARM64=905106b80be34963361737b6c4d471b45d77461c3455b137cefd66b2c470566c
ARG AWSCLI_VERSION=2.16.9
ARG AWSCLI_SHA256_AMD64=8c09f0aa7743fb04a28ac7a6f3c2822d6ffcc58bcace2beaf55258ee0f67c4cb
ARG AWSCLI_SHA256_ARM64=82636f7ec20c57beeed19a14f8684113e0edfb30e79f1a615809de2dfb482712
ARG CA_CERTIFICATES_VERSION=20230311
ARG UNZIP_VERSION=6.0-28
ARG CURL_VERSION=7.88.1-10+deb12u14
ARG UV_VERSION=0.9.21
ARG UV_SHA256_AMD64=0a1ab27383c28ef1c041f85cbbc609d8e3752dfb4b238d2ad97b208a52232baf
ARG UV_SHA256_ARM64=416984484783a357170c43f98e7d2d203f1fb595d6b3b95131513c53e50986ef
ARG TYPOS_VERSION=1.44.0
ARG TYPOS_SHA256_AMD64=1b788b7d764e2f20fe089487428a3944ed218d1fb6fcd8eac4230b5893a38779
ARG TYPOS_SHA256_ARM64=132c20fc5e3c9ba540ec55a0a468dcb9c1504625a405df1c237b10dd4f2ec433
ARG TAPLO_VERSION=0.10.0
ARG TAPLO_SHA256_AMD64=8fe196b894ccf9072f98d4e1013a180306e17d244830b03986ee5e8eabeb6156
ARG TAPLO_SHA256_ARM64=033681d01eec8376c3fd38fa3703c79316f5e14bb013d859943b60a07bccdcc3
ENV DEBIAN_FRONTEND=noninteractive
ENV UV_PROJECT_ENVIRONMENT=/opt/uv-env
ENV UV_LINK_MODE=copy
ENV UV_PYTHON_DOWNLOADS=never

RUN printf 'Acquire::Retries "5";\nAcquire::http::Timeout "30";\n' > /etc/apt/apt.conf.d/99retries \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates="${CA_CERTIFICATES_VERSION}" \
        curl="${CURL_VERSION}" \
        unzip="${UNZIP_VERSION}" \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /tmp

# Install Pulumi CLI, AWS CLI, and the repo-local Rust tooling in one builder
# step so the final image stays small and the quality gates see a single layer.
RUN bash -o pipefail <<'EOF'
set -euo pipefail

case "${TARGETARCH}" in
    amd64)
        pulumi_arch="x64"
        pulumi_sha256="${PULUMI_SHA256_AMD64}"
        awscli_arch="linux-x86_64"
        awscli_sha256="${AWSCLI_SHA256_AMD64}"
        uv_arch="x86_64-unknown-linux-gnu"
        uv_sha256="${UV_SHA256_AMD64}"
        typos_arch="x86_64-unknown-linux-musl"
        typos_sha256="${TYPOS_SHA256_AMD64}"
        taplo_arch="x86_64"
        taplo_sha256="${TAPLO_SHA256_AMD64}"
        ;;
    arm64)
        pulumi_arch="arm64"
        pulumi_sha256="${PULUMI_SHA256_ARM64}"
        awscli_arch="linux-aarch64"
        awscli_sha256="${AWSCLI_SHA256_ARM64}"
        uv_arch="aarch64-unknown-linux-gnu"
        uv_sha256="${UV_SHA256_ARM64}"
        typos_arch="aarch64-unknown-linux-musl"
        typos_sha256="${TYPOS_SHA256_ARM64}"
        taplo_arch="aarch64"
        taplo_sha256="${TAPLO_SHA256_ARM64}"
        ;;
    *)
        echo "Unsupported TARGETARCH: ${TARGETARCH}" >&2
        exit 1
        ;;
esac

# qlty-ignore(>radarlint-iac:docker:S7026): remote ADD cannot express the
# TARGETARCH-to-upstream-name mapping here without downloading both archives.
curl --fail --silent --show-error --location \
    --retry 5 --retry-delay 5 --retry-all-errors \
    "https://get.pulumi.com/releases/sdk/pulumi-v${PULUMI_VERSION}-linux-${pulumi_arch}.tar.gz" \
    --output /tmp/pulumi.tar.gz
echo "${pulumi_sha256}  /tmp/pulumi.tar.gz" | sha256sum -c -
mkdir -p /opt/pulumi
tar --extract --gzip --file /tmp/pulumi.tar.gz --strip-components=1 --directory /opt/pulumi
rm -f \
    /opt/pulumi/pulumi-language-dotnet \
    /opt/pulumi/pulumi-language-go \
    /opt/pulumi/pulumi-language-java \
    /opt/pulumi/pulumi-language-nodejs \
    /opt/pulumi/pulumi-language-yaml \
    /opt/pulumi/pulumi-resource-pulumi-nodejs \
    /opt/pulumi/pulumi-watch \
    /tmp/pulumi.tar.gz

curl --fail --silent --show-error --location \
    --retry 5 --retry-delay 5 --retry-all-errors \
    "https://awscli.amazonaws.com/awscli-exe-${awscli_arch}-${AWSCLI_VERSION}.zip" \
    --output /tmp/awscliv2.zip
echo "${awscli_sha256}  /tmp/awscliv2.zip" | sha256sum -c -
unzip /tmp/awscliv2.zip -d /tmp
/tmp/aws/install --bin-dir /usr/local/bin --install-dir /usr/local/aws-cli
rm -rf /usr/local/aws-cli/v2/current/dist/awscli/examples /tmp/aws /tmp/awscliv2.zip

curl --fail --silent --show-error --location \
    --retry 5 --retry-delay 5 --retry-all-errors \
    "https://github.com/astral-sh/uv/releases/download/${UV_VERSION}/uv-${uv_arch}.tar.gz" \
    --output /tmp/uv.tar.gz
echo "${uv_sha256}  /tmp/uv.tar.gz" | sha256sum -c -
tar --extract --gzip --file /tmp/uv.tar.gz --directory /tmp
install -m 0755 "/tmp/uv-${uv_arch}/uv" /usr/local/bin/uv
rm -rf /tmp/uv.tar.gz "/tmp/uv-${uv_arch}"

curl --fail --silent --show-error --location \
    --retry 5 --retry-delay 5 --retry-all-errors \
    "https://github.com/crate-ci/typos/releases/download/v${TYPOS_VERSION}/typos-v${TYPOS_VERSION}-${typos_arch}.tar.gz" \
    --output /tmp/typos.tar.gz
echo "${typos_sha256}  /tmp/typos.tar.gz" | sha256sum -c -
tar --extract --gzip --file /tmp/typos.tar.gz --directory /tmp
install -m 0755 /tmp/typos /usr/local/bin/typos
rm -rf /tmp/typos /tmp/typos.tar.gz

curl --fail --silent --show-error --location \
    --retry 5 --retry-delay 5 --retry-all-errors \
    "https://github.com/tamasfe/taplo/releases/download/${TAPLO_VERSION}/taplo-linux-${taplo_arch}.gz" \
    --output /tmp/taplo.gz
echo "${taplo_sha256}  /tmp/taplo.gz" | sha256sum -c -
python -c "import gzip, shutil; source = gzip.open('/tmp/taplo.gz', 'rb'); target = open('/tmp/taplo', 'wb'); shutil.copyfileobj(source, target); source.close(); target.close()"
install -m 0755 /tmp/taplo /usr/local/bin/taplo
rm -rf /tmp/taplo /tmp/taplo.gz
EOF

WORKDIR /workspace
COPY pyproject.toml uv.lock /workspace/

RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --all-groups --no-install-project --no-editable

FROM python:3.11.9-slim-bookworm@sha256:8fb099199b9f2d70342674bd9dbccd3ed03a258f26bbd1d556822c6dfc60c317 AS runtime

ARG USERNAME=dev
ARG UID=1000
ARG GID=1000
ARG GIT_VERSION=1:2.39.5-0+deb12u3
ENV UV_PROJECT_ENVIRONMENT=/opt/uv-env
ENV UV_LINK_MODE=copy
ENV UV_PYTHON_DOWNLOADS=never
ENV PATH="/opt/pulumi:${UV_PROJECT_ENVIRONMENT}/bin:/home/${USERNAME}/.local/bin:/home/${USERNAME}/.pulumi/bin:${PATH}"

RUN printf 'Acquire::Retries "5";\nAcquire::http::Timeout "30";\n' > /etc/apt/apt.conf.d/99retries \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        git="${GIT_VERSION}" \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid "${GID}" "${USERNAME}" \
    && useradd --uid "${UID}" --gid "${GID}" --create-home "${USERNAME}" \
    && install -d --owner "${UID}" --group "${GID}" "/home/${USERNAME}/tmp"

COPY --from=tooling-builder /opt/pulumi /opt/pulumi
COPY --from=tooling-builder /usr/local/aws-cli /usr/local/aws-cli
COPY --from=tooling-builder /usr/local/bin/uv /usr/local/bin/uv
COPY --from=tooling-builder /usr/local/bin/typos /usr/local/bin/typos
COPY --from=tooling-builder /usr/local/bin/taplo /usr/local/bin/taplo
COPY --from=tooling-builder /opt/uv-env /opt/uv-env

RUN ln -sf /opt/pulumi/pulumi /usr/local/bin/pulumi \
    && ln -sf /usr/local/aws-cli/v2/current/bin/aws /usr/local/bin/aws \
    && ln -sf /usr/local/aws-cli/v2/current/bin/aws_completer /usr/local/bin/aws_completer

WORKDIR /workspace
USER "${USERNAME}"

# Pulumi CLI caches a few files under the user's home directory
ENV HOME=/home/${USERNAME}
ENV TMPDIR=/home/${USERNAME}/tmp

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["python", "-V"]

CMD ["bash"]
