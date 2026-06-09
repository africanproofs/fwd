# syntax=docker/dockerfile:1.7

# ---------- Build stage ----------
FROM python:3.12-slim-bookworm AS build

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    POETRY_VERSION=1.8.5 \
    POETRY_VIRTUALENVS_CREATE=false \
    POETRY_NO_INTERACTION=1 \
    POETRY_REQUESTS_TIMEOUT=300

# Network resilience for build-from-source on a variable/flaky provider link:
# POETRY_REQUESTS_TIMEOUT (default 15s) is raised so a slow PyPI-CDN wheel does
# not read-timeout the build; apt and poetry steps additionally RETRY (apt
# Acquire::Retries, poetry install up to 3x) so a transient unreachable/timeout
# on one package does not fail the whole image build. Build images SEQUENTIALLY
# (one at a time) — building fwd + clif in parallel can saturate a constrained
# link and cause spurious unreachable/timeout failures.

RUN apt-get -o Acquire::Retries=5 update && apt-get -o Acquire::Retries=5 install -y --no-install-recommends \
    build-essential \
    libffi-dev \
    libsecp256k1-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir --timeout 300 --retries 5 "poetry==${POETRY_VERSION}" \
 || (echo "poetry pip retry 1/2" && sleep 5  && pip install --no-cache-dir --timeout 300 --retries 5 "poetry==${POETRY_VERSION}") \
 || (echo "poetry pip retry 2/2" && sleep 15 && pip install --no-cache-dir --timeout 300 --retries 5 "poetry==${POETRY_VERSION}")

WORKDIR /build
COPY pyproject.toml poetry.lock ./
RUN poetry install --only main --no-root \
 || (echo "poetry install retry 1/2" && sleep 5  && poetry install --only main --no-root) \
 || (echo "poetry install retry 2/2" && sleep 15 && poetry install --only main --no-root)

COPY src/ ./src/
RUN poetry install --only main \
 || (echo "poetry install retry 1/2" && sleep 5  && poetry install --only main) \
 || (echo "poetry install retry 2/2" && sleep 15 && poetry install --only main)

# ---------- Runtime stage ----------
FROM python:3.12-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:${PATH}"

RUN apt-get -o Acquire::Retries=5 update && apt-get -o Acquire::Retries=5 install -y --no-install-recommends \
    libsecp256k1-dev \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 1000 fwd \
    && useradd --uid 1000 --gid fwd --shell /bin/bash --create-home fwd

COPY --from=build /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=build /usr/local/bin /usr/local/bin
COPY --from=build /build/src /app/src
COPY alembic.ini /app/alembic.ini
COPY alembic/ /app/alembic/
# The ABI registry (config/abis/) is read at lifespan startup by
# AbiRegistry.load(FWD_ABIS_DIR, default /app/config/abis). It MUST ship in
# the image or _startup_policy_load fail-fasts (D14). Copy ONLY config/abis/:
# policy.yaml, the sealed master, and any backups are operator-controlled and
# bind-mounted at runtime, NEVER baked into an image layer (Core invariant #12).
COPY config/abis/ /app/config/abis/
# networks.yaml is non-secret public Flare network constants, read ONLY by the
# `clifwd policy init` generator (not the daemon). Explicit single-file COPY
# (never broaden to `COPY config/` — Core invariant #12 / v1.1.0a28).
COPY config/networks.yaml /app/config/networks.yaml

# D16 promises `docker exec fwd clifwd audit verify` as the canonical
# walker invocation, but `poetry install --no-root` does not install the
# fwd package, so the pyproject `clifwd` console-script is never created.
# Ship a thin shim so the documented command resolves on PATH. `fwdctl` is an
# invocation alias (symlink) for the identical app — both resolve on PATH and
# exec the same `fwd.cli.main:app`.
RUN printf '#!/bin/sh\nexec python -c "from fwd.cli.main import app; app()" "$@"\n' \
        > /usr/local/bin/clifwd \
    && chmod 755 /usr/local/bin/clifwd \
    && ln -s clifwd /usr/local/bin/fwdctl

ENV PYTHONPATH=/app/src

RUN mkdir -p /data && chown fwd:fwd /data

WORKDIR /app
USER fwd

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8080/healthz || exit 1

CMD ["sh", "-c", "alembic upgrade head && exec uvicorn fwd.main:app --host 0.0.0.0 --port 8080"]
