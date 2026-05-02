# syntax=docker/dockerfile:1.7

# ---------- Build stage ----------
FROM python:3.12-slim-bookworm AS build

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    POETRY_VERSION=1.8.5 \
    POETRY_VIRTUALENVS_CREATE=false \
    POETRY_NO_INTERACTION=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libffi-dev \
    libsecp256k1-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir "poetry==${POETRY_VERSION}"

WORKDIR /build
COPY pyproject.toml poetry.lock ./
RUN poetry install --only main --no-root

COPY src/ ./src/
RUN poetry install --only main

# ---------- Runtime stage ----------
FROM python:3.12-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:${PATH}"

RUN apt-get update && apt-get install -y --no-install-recommends \
    libsecp256k1-dev \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 1000 fwd \
    && useradd --uid 1000 --gid fwd --shell /bin/bash --create-home fwd

COPY --from=build /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=build /usr/local/bin /usr/local/bin
COPY --from=build /build/src /app/src

ENV PYTHONPATH=/app/src

WORKDIR /app
USER fwd

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8080/healthz || exit 1

CMD ["uvicorn", "fwd.main:app", "--host", "0.0.0.0", "--port", "8080"]
