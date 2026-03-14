# syntax=docker/dockerfile:1.7-labs

# Keep a glibc-based slim image because AWS CLI v2 only guarantees support on
# glibc-based Linux distributions.
FROM python:3.11.9-slim-bookworm@sha256:8fb099199b9f2d70342674bd9dbccd3ed03a258f26bbd1d556822c6dfc60c317 AS tooling-builder

ARG PULUMI_VERSION=3.138.0
ARG AWSCLI_VERSION=2.16.9
ARG AWSCLI_ARCH=linux-x86_64
ARG CURL_VERSION=7.88.1-10+deb12u14
ARG GNUPG_VERSION=2.2.40-1.1+deb12u2
ARG UNZIP_VERSION=6.0-28
ARG UV_VERSION=0.9.21
ARG UV_SHA256=0a1ab27383c28ef1c041f85cbbc609d8e3752dfb4b238d2ad97b208a52232baf
ARG TYPOS_VERSION=1.44.0
ARG TYPOS_SHA256=1b788b7d764e2f20fe089487428a3944ed218d1fb6fcd8eac4230b5893a38779
ARG TAPLO_VERSION=0.10.0
ARG TAPLO_SHA256=8fe196b894ccf9072f98d4e1013a180306e17d244830b03986ee5e8eabeb6156
ENV DEBIAN_FRONTEND=noninteractive
ENV UV_PROJECT_ENVIRONMENT=/opt/uv-env
ENV UV_LINK_MODE=copy
ENV UV_PYTHON_DOWNLOADS=never

RUN printf 'Acquire::Retries "5";\nAcquire::http::Timeout "30";\n' > /etc/apt/apt.conf.d/99retries \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        curl="${CURL_VERSION}" \
        gnupg="${GNUPG_VERSION}" \
        unzip="${UNZIP_VERSION}" \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /tmp

# Install Pulumi CLI, AWS CLI v2, uv, and repository tooling in a throwaway
# stage so the final runtime image only carries the binaries and virtualenv.
RUN <<EOF
set -eu

download() {
  curl --fail --silent --show-error --location \
    --retry 5 --retry-delay 5 --retry-all-errors \
    "$1" --output "$2"
}

verify_sha256() {
  checksum_file=/tmp/asset.sha256
  printf '%s  %s\n' "$1" "$2" > "$checksum_file"
  sha256sum -c "$checksum_file"
  rm -f "$checksum_file"
}

download \
  "https://github.com/pulumi/pulumi/releases/download/v${PULUMI_VERSION}/pulumi-v${PULUMI_VERSION}-linux-x64.tar.gz" \
  "/tmp/pulumi-v${PULUMI_VERSION}-linux-x64.tar.gz"
download \
  "https://github.com/pulumi/pulumi/releases/download/v${PULUMI_VERSION}/pulumi-${PULUMI_VERSION}-checksums.txt" \
  /tmp/pulumi-checksums.txt
grep "pulumi-v${PULUMI_VERSION}-linux-x64.tar.gz" /tmp/pulumi-checksums.txt > /tmp/pulumi-checksums.sha256
sha256sum -c /tmp/pulumi-checksums.sha256
mkdir -p /opt/pulumi
tar --extract --gzip \
  --file "/tmp/pulumi-v${PULUMI_VERSION}-linux-x64.tar.gz" \
  --strip-components=1 \
  --directory /opt/pulumi

download \
  "https://awscli.amazonaws.com/awscli-exe-${AWSCLI_ARCH}-${AWSCLI_VERSION}.zip" \
  /tmp/awscliv2.zip
download \
  "https://awscli.amazonaws.com/awscli-exe-${AWSCLI_ARCH}-${AWSCLI_VERSION}.zip.sig" \
  /tmp/awscliv2.zip.sig
mkdir -p /tmp/aws-cli-keyring
cat > /tmp/aws-cli-keyring/awscli-public-key.asc <<'KEY'
-----BEGIN PGP PUBLIC KEY BLOCK-----

mQINBF2Cr7UBEADJZHcgusOJl7ENSyumXh85z0TRV0xJorM2B/JL0kHOyigQluUG
ZMLhENaG0bYatdrKP+3H91lvK050pXwnO/R7fB/FSTouki4ciIx5OuLlnJZIxSzx
PqGl0mkxImLNbGWoi6Lto0LYxqHN2iQtzlwTVmq9733zd3XfcXrZ3+LblHAgEt5G
TfNxEKJ8soPLyWmwDH6HWCnjZ/aIQRBTIQ05uVeEoYxSh6wOai7ss/KveoSNBbYz
gbdzoqI2Y8cgH2nbfgp3DSasaLZEdCSsIsK1u05CinE7k2qZ7KgKAUIcT/cR/grk
C6VwsnDU0OUCideXcQ8WeHutqvgZH1JgKDbznoIzeQHJD238GEu+eKhRHcz8/jeG
94zkcgJOz3KbZGYMiTh277Fvj9zzvZsbMBCedV1BTg3TqgvdX4bdkhf5cH+7NtWO
lrFj6UwAsGukBTAOxC0l/dnSmZhJ7Z1KmEWilro/gOrjtOxqRQutlIqG22TaqoPG
fYVN+en3Zwbt97kcgZDwqbuykNt64oZWc4XKCa3mprEGC3IbJTBFqglXmZ7l9ywG
EEUJYOlb2XrSuPWml39beWdKM8kzr1OjnlOm6+lpTRCBfo0wa9F8YZRhHPAkwKkX
XDeOGpWRj4ohOx0d2GWkyV5xyN14p2tQOCdOODmz80yUTgRpPVQUtOEhXQARAQAB
tCFBV1MgQ0xJIFRlYW0gPGF3cy1jbGlAYW1hem9uLmNvbT6JAlQEEwEIAD4CGwMF
CwkIBwIGFQoJCAsCBBYCAwECHgECF4AWIQT7Xbd/1cEYuAURraimMQrMRnJHXAUC
aGveYQUJDMpiLAAKCRCmMQrMRnJHXKBYD/9Ab0qQdGiO5hObchG8xh8Rpb4Mjyf6
0JrVo6m8GNjNj6BHkSc8fuTQJ/FaEhaQxj3pjZ3GXPrXjIIVChmICLlFuRXYzrXc
Pw0lniybypsZEVai5kO0tCNBCCFuMN9RsmmRG8mf7lC4FSTbUDmxG/QlYK+0IV/l
uJkzxWa+rySkdpm0JdqumjegNRgObdXHAQDWlubWQHWyZyIQ2B4U7AxqSpcdJp6I
S4Zds4wVLd1WE5pquYQ8vS2cNlDm4QNg8wTj58e3lKN47hXHMIb6CHxRnb947oJa
pg189LLPR5koh+EorNkA1wu5mAJtJvy5YMsppy2y/kIjp3lyY6AmPT1posgGk70Z
CmToEZ5rbd7ARExtlh76A0cabMDFlEHDIK8RNUOSRr7L64+KxOUegKBfQHb9dADY
qqiKqpCbKgvtWlds909Ms74JBgr2KwZCSY1HaOxnIr4CY43QRqAq5YHOay/mU+6w
hhmdF18vpyK0vfkvvGresWtSXbag7Hkt3XjaEw76BzxQH21EBDqU8WJVjHgU6ru+
DJTs+SxgJbaT3hb/vyjlw0lK+hFfhWKRwgOXH8vqducF95NRSUxtS4fpqxWVaw3Q
V2OWSjbne99A5EPEySzryFTKbMGwaTlAwMCwYevt4YT6eb7NmFhTx0Fis4TalUs+
j+c7Kg92pDx2uQ==
=OBAt
-----END PGP PUBLIC KEY BLOCK-----
KEY
GNUPGHOME=/tmp/aws-cli-keyring gpg --batch --import /tmp/aws-cli-keyring/awscli-public-key.asc
GNUPGHOME=/tmp/aws-cli-keyring gpg --batch --verify /tmp/awscliv2.zip.sig /tmp/awscliv2.zip
unzip /tmp/awscliv2.zip -d /tmp
/tmp/aws/install --bin-dir /usr/local/bin --install-dir /usr/local/aws-cli

download \
  "https://github.com/astral-sh/uv/releases/download/${UV_VERSION}/uv-x86_64-unknown-linux-gnu.tar.gz" \
  /tmp/uv.tar.gz
verify_sha256 "${UV_SHA256}" /tmp/uv.tar.gz
tar --extract --gzip --file /tmp/uv.tar.gz --directory /tmp
install -m 0755 /tmp/uv-x86_64-unknown-linux-gnu/uv /usr/local/bin/uv

download \
  "https://github.com/crate-ci/typos/releases/download/v${TYPOS_VERSION}/typos-v${TYPOS_VERSION}-x86_64-unknown-linux-musl.tar.gz" \
  /tmp/typos.tar.gz
verify_sha256 "${TYPOS_SHA256}" /tmp/typos.tar.gz
tar --extract --gzip --file /tmp/typos.tar.gz --directory /tmp
install -m 0755 /tmp/typos /usr/local/bin/typos

download \
  "https://github.com/tamasfe/taplo/releases/download/${TAPLO_VERSION}/taplo-linux-x86_64.gz" \
  /tmp/taplo.gz
verify_sha256 "${TAPLO_SHA256}" /tmp/taplo.gz
python - <<'PY'
import gzip
import shutil

with gzip.open("/tmp/taplo.gz", "rb") as source, open("/tmp/taplo", "wb") as target:
    shutil.copyfileobj(source, target)
PY
install -m 0755 /tmp/taplo /usr/local/bin/taplo

rm -rf \
  /tmp/aws \
  /tmp/aws-cli-keyring \
  /tmp/awscliv2.zip \
  /tmp/awscliv2.zip.sig \
  "/tmp/pulumi-v${PULUMI_VERSION}-linux-x64.tar.gz" \
  /tmp/pulumi-checksums.txt \
  /tmp/pulumi-checksums.sha256 \
  /tmp/taplo \
  /tmp/taplo.gz \
  /tmp/typos \
  /tmp/typos.tar.gz \
  /tmp/uv.tar.gz \
  /tmp/uv-x86_64-unknown-linux-gnu
EOF

WORKDIR /workspace
COPY pyproject.toml uv.lock /workspace/

RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --all-groups --no-install-project --no-editable

FROM python:3.11.9-slim-bookworm@sha256:8fb099199b9f2d70342674bd9dbccd3ed03a258f26bbd1d556822c6dfc60c317 AS runtime

ARG USERNAME=dev
ARG UID=1000
ARG GID=1000
ENV UV_PROJECT_ENVIRONMENT=/opt/uv-env
ENV UV_LINK_MODE=copy
ENV UV_PYTHON_DOWNLOADS=never
ENV PATH="/opt/pulumi:${UV_PROJECT_ENVIRONMENT}/bin:/home/${USERNAME}/.local/bin:/home/${USERNAME}/.pulumi/bin:${PATH}"

RUN groupadd --gid "${GID}" "${USERNAME}" \
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
