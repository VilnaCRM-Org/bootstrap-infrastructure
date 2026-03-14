# syntax=docker/dockerfile:1.7-labs

# Keep a glibc-based slim image because AWS CLI v2 only guarantees support on
# glibc-based Linux distributions.
FROM python:3.11.9-slim-bookworm@sha256:8fb099199b9f2d70342674bd9dbccd3ed03a258f26bbd1d556822c6dfc60c317 AS base

ARG USERNAME=dev
ARG UID=1000
ARG GID=1000
ARG PULUMI_VERSION=3.138.0
ARG AWSCLI_VERSION=2.16.9
ARG AWSCLI_ARCH=linux-x86_64
ARG CA_CERTIFICATES_VERSION=20230311
ARG UNZIP_VERSION=6.0-28
ARG CURL_VERSION=7.88.1-10+deb12u14
ARG GIT_VERSION=1:2.39.5-0+deb12u2
ARG GNUPG_VERSION=2.2.40-1.1+deb12u2
ARG PIP_VERSION=26.0.1
ARG UV_VERSION=0.9.21
ARG TYPOS_VERSION=1.44.0
ARG TAPLO_VERSION=0.10.0
ENV DEBIAN_FRONTEND=noninteractive

# Install OS dependencies required for Pulumi CLI, AWS CLI, and Python tooling
RUN printf 'Acquire::Retries "5";\nAcquire::http::Timeout "30";\n' > /etc/apt/apt.conf.d/99retries \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates="${CA_CERTIFICATES_VERSION}" \
        curl="${CURL_VERSION}" \
        git="${GIT_VERSION}" \
        gnupg="${GNUPG_VERSION}" \
        unzip="${UNZIP_VERSION}" \
    && groupadd --gid "${GID}" "${USERNAME}" \
    && useradd --uid "${UID}" --gid "${GID}" --create-home "${USERNAME}" \
    && install -d --owner "${UID}" --group "${GID}" "/home/${USERNAME}/tmp" \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /tmp

# Install Pulumi CLI once and expose it on the PATH for all users.
# Install AWS CLI v2 plus the Rust-native CLI quality tools used by local and
# CI guardrails, then remove the build-only packages used for downloads.
RUN <<EOF
set -e
curl --fail --silent --show-error --location \
  --retry 5 --retry-delay 5 --retry-all-errors \
  "https://github.com/pulumi/pulumi/releases/download/v${PULUMI_VERSION}/pulumi-v${PULUMI_VERSION}-linux-x64.tar.gz" \
  --output "/tmp/pulumi-v${PULUMI_VERSION}-linux-x64.tar.gz"
curl --fail --silent --show-error --location \
  --retry 5 --retry-delay 5 --retry-all-errors \
  "https://github.com/pulumi/pulumi/releases/download/v${PULUMI_VERSION}/pulumi-${PULUMI_VERSION}-checksums.txt" \
  --output "/tmp/pulumi-checksums.txt"
grep "pulumi-v${PULUMI_VERSION}-linux-x64.tar.gz" /tmp/pulumi-checksums.txt \
  > /tmp/pulumi-checksums.sha256
sha256sum -c /tmp/pulumi-checksums.sha256
mkdir -p /opt/pulumi
tar --extract --gzip \
  --file "/tmp/pulumi-v${PULUMI_VERSION}-linux-x64.tar.gz" \
  --strip-components=1 \
  --directory /opt/pulumi
ln -sf /opt/pulumi/pulumi /usr/local/bin/pulumi
rm -rf "/tmp/pulumi-v${PULUMI_VERSION}-linux-x64.tar.gz" /tmp/pulumi-checksums.txt /tmp/pulumi-checksums.sha256

curl --fail --silent --show-error --location \
  --retry 5 --retry-delay 5 --retry-all-errors \
  "https://awscli.amazonaws.com/awscli-exe-${AWSCLI_ARCH}-${AWSCLI_VERSION}.zip" \
  --output "/tmp/awscliv2.zip"
curl --fail --silent --show-error --location \
  --retry 5 --retry-delay 5 --retry-all-errors \
  "https://awscli.amazonaws.com/awscli-exe-${AWSCLI_ARCH}-${AWSCLI_VERSION}.zip.sig" \
  --output "/tmp/awscliv2.zip.sig"
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

curl --fail --silent --show-error --location \
  --retry 5 --retry-delay 5 --retry-all-errors \
  "https://github.com/crate-ci/typos/releases/download/v${TYPOS_VERSION}/typos-v${TYPOS_VERSION}-x86_64-unknown-linux-musl.tar.gz" \
  --output /tmp/typos.tar.gz
tar --extract --gzip --file /tmp/typos.tar.gz --directory /tmp
install -m 0755 /tmp/typos /usr/local/bin/typos

curl --fail --silent --show-error --location \
  --retry 5 --retry-delay 5 --retry-all-errors \
  "https://github.com/tamasfe/taplo/releases/download/${TAPLO_VERSION}/taplo-linux-x86_64.gz" \
  --output /tmp/taplo.gz
python - <<'PY'
import gzip
import shutil

with gzip.open("/tmp/taplo.gz", "rb") as source, open("/tmp/taplo", "wb") as target:
    shutil.copyfileobj(source, target)
PY
install -m 0755 /tmp/taplo /usr/local/bin/taplo

rm -rf \
  /tmp/aws \
  /tmp/awscliv2.zip \
  /tmp/awscliv2.zip.sig \
  /tmp/aws-cli-keyring \
  /tmp/taplo \
  /tmp/taplo.gz \
  /tmp/typos \
  /tmp/typos.tar.gz
apt-get purge -y --auto-remove curl gnupg unzip
rm -rf /var/lib/apt/lists/*
EOF

# Install uv for Python dependency and command management.
ENV UV_PROJECT_ENVIRONMENT=/opt/uv-env
ENV UV_LINK_MODE=copy
ENV UV_COMPILE_BYTECODE=1
ENV UV_PYTHON_DOWNLOADS=never
ENV PATH="/opt/pulumi:${UV_PROJECT_ENVIRONMENT}/bin:/home/${USERNAME}/.local/bin:/home/${USERNAME}/.pulumi/bin:${PATH}"
RUN python -m pip install --no-cache-dir --upgrade \
    "pip==${PIP_VERSION}" \
    "uv==${UV_VERSION}"

WORKDIR /workspace
COPY --chown=${USERNAME}:${GID} pyproject.toml uv.lock /workspace/

RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --all-groups --no-install-project --no-editable

USER "${USERNAME}"

# Pulumi CLI caches a few files under the user's home directory
ENV HOME=/home/${USERNAME}
ENV TMPDIR=/home/${USERNAME}/tmp

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["python", "-V"]

CMD ["bash"]
