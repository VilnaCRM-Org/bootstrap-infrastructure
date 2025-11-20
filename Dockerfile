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
    && mkdir -p /opt/pulumi \
    && tar --extract --gzip --file /tmp/pulumi.tar.gz --strip-components=1 --directory /opt/pulumi \
    && ln -sf /opt/pulumi/pulumi /usr/local/bin/pulumi \
    && rm -rf /tmp/pulumi.tar.gz

# Install AWS CLI v2
RUN curl --fail --silent --show-error --location \
        --retry 5 --retry-delay 5 --retry-all-errors \
        "https://awscli.amazonaws.com/awscli-exe-${AWSCLI_ARCH}-${AWSCLI_VERSION}.zip" \
        --output "/tmp/awscliv2.zip" \
    && unzip /tmp/awscliv2.zip -d /tmp \
    && /tmp/aws/install --bin-dir /usr/local/bin --install-dir /usr/local/aws-cli \
    && rm -rf /tmp/aws /tmp/awscliv2.zip

# Install Poetry
ENV POETRY_HOME=/opt/poetry
ENV PATH="/opt/pulumi:${POETRY_HOME}/bin:/home/${USERNAME}/.local/bin:/home/${USERNAME}/.pulumi/bin:${PATH}"
ARG POETRY_VERSION=1.8.4
RUN bash -o pipefail -c 'curl --fail --silent --show-error --location \
        --retry 5 --retry-delay 5 --retry-all-errors \
        https://install.python-poetry.org \
        | python - --version "${POETRY_VERSION}"'
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
