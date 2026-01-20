# syntax=docker/dockerfile:1.7-labs

FROM python:3.11.9-slim-bookworm AS base

ARG USERNAME=dev
ARG UID=1000
ARG GID=1000
ARG PULUMI_VERSION=3.138.0
ARG AWSCLI_VERSION=2.16.9
ARG AWSCLI_ARCH=linux-x86_64
ARG CA_CERTIFICATES_VERSION=20230311
ARG UNZIP_VERSION=6.0-28
ARG GROFF_VERSION=1.22.4-10
ARG CURL_VERSION=7.88.1-10+deb12u14
ARG LESS_VERSION=590-2.1~deb12u2
ARG GIT_VERSION=1:2.39.5-0+deb12u2
ENV DEBIAN_FRONTEND=noninteractive

# Install OS dependencies required for Pulumi CLI, AWS CLI, and Python tooling
RUN printf 'Acquire::Retries "5";\nAcquire::http::Timeout "30";\n' > /etc/apt/apt.conf.d/99retries \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates="${CA_CERTIFICATES_VERSION}" \
        curl="${CURL_VERSION}" \
        unzip="${UNZIP_VERSION}" \
        groff="${GROFF_VERSION}" \
        less="${LESS_VERSION}" \
        gnupg \
        git="${GIT_VERSION}" \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user that mirrors the host developer UID/GID
RUN groupadd --gid "${GID}" "${USERNAME}" \
    && useradd --uid "${UID}" --gid "${GID}" --create-home "${USERNAME}"

# Install Pulumi CLI once and expose it on the PATH for all users
RUN curl --fail --silent --show-error --location \
        --retry 5 --retry-delay 5 --retry-all-errors \
        "https://get.pulumi.com/releases/sdk/pulumi-v${PULUMI_VERSION}-linux-x64.tar.gz" \
        --output /tmp/pulumi.tar.gz \
    && curl --fail --silent --show-error --location \
        --retry 5 --retry-delay 5 --retry-all-errors \
        "https://get.pulumi.com/releases/sdk/pulumi-v${PULUMI_VERSION}-linux-x64.tar.gz.sha256" \
        --output /tmp/pulumi.tar.gz.sha256 \
    && expected_sha="$(awk '{print $1}' /tmp/pulumi.tar.gz.sha256)" \
    && echo "${expected_sha}  /tmp/pulumi.tar.gz" | sha256sum -c - \
    && mkdir -p /opt/pulumi \
    && tar --extract --gzip --file /tmp/pulumi.tar.gz --strip-components=1 --directory /opt/pulumi \
    && ln -sf /opt/pulumi/pulumi /usr/local/bin/pulumi \
    && rm -rf /tmp/pulumi.tar.gz /tmp/pulumi.tar.gz.sha256

# Install AWS CLI v2
RUN <<EOF
set -e
curl --fail --silent --show-error --location     --retry 5 --retry-delay 5 --retry-all-errors     "https://awscli.amazonaws.com/awscli-exe-${AWSCLI_ARCH}-${AWSCLI_VERSION}.zip"     --output "/tmp/awscliv2.zip"
curl --fail --silent --show-error --location     --retry 5 --retry-delay 5 --retry-all-errors     "https://awscli.amazonaws.com/awscli-exe-${AWSCLI_ARCH}-${AWSCLI_VERSION}.zip.sig"     --output "/tmp/awscliv2.zip.sig"
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
rm -rf /tmp/aws /tmp/awscliv2.zip /tmp/awscliv2.zip.sig /tmp/aws-cli-keyring
EOF

# Install Poetry
ENV POETRY_HOME=/opt/poetry
ENV PATH="/opt/pulumi:${POETRY_HOME}/bin:/home/${USERNAME}/.local/bin:/home/${USERNAME}/.pulumi/bin:${PATH}"
ARG POETRY_VERSION=1.8.4
ARG POETRY_INSTALLER_SHA256=963d56703976ce9cdc6ff460c44a4f8fbad64c110dc447b86eeabb4a47ec2160
RUN curl --fail --silent --show-error --location \
        --retry 5 --retry-delay 5 --retry-all-errors \
        https://install.python-poetry.org \
        --output /tmp/poetry-installer.py \
    && echo "${POETRY_INSTALLER_SHA256}  /tmp/poetry-installer.py" | sha256sum -c - \
    && python /tmp/poetry-installer.py --version "${POETRY_VERSION}" \
    && rm -f /tmp/poetry-installer.py
ENV POETRY_VIRTUALENVS_CREATE=false
ENV POETRY_HTTP_TIMEOUT=60

COPY --chown=${USERNAME}:${GID} pyproject.toml poetry.lock /workspace/

RUN --mount=type=cache,target=/root/.cache/pip \
    --mount=type=cache,target=/root/.cache/pypoetry \
    cd /workspace \
    && poetry config installer.max-workers 4 \
    && poetry install --no-root --no-interaction --no-ansi --with dev

USER "${USERNAME}"
WORKDIR /workspace

# Pulumi CLI caches a few files under the user's home directory
ENV HOME=/home/${USERNAME}

CMD ["bash"]
