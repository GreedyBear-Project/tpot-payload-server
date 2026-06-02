# --------------------------------------------------------------------------
# tpot-payload-server — Production Dockerfile
# --------------------------------------------------------------------------
# Multi-stage build:
#   1. "builder" installs dependencies via uv into a virtual environment.
#   2. Final stage copies only the venv + app source for a slim runtime image.
# --------------------------------------------------------------------------

# ── Stage 1: Build dependencies ──────────────────────────────────────────
FROM python:3.14-slim AS builder

WORKDIR /build

# Install uv for fast, reproducible dependency resolution
COPY --from=ghcr.io/astral-sh/uv:0.11.18 /uv /usr/local/bin/uv

# Copy dependency manifests first for layer caching
COPY pyproject.toml uv.lock ./

# Install production dependencies into a virtual environment.
# We target /app/.venv so console-script shebangs match the final image path.
ENV UV_PROJECT_ENVIRONMENT=/app/.venv
RUN uv sync --locked --no-dev --no-install-project

# Copy the application source
COPY app/ ./app/


# ── Stage 2: Slim runtime ────────────────────────────────────────────────
FROM python:3.14-slim

LABEL maintainer="GreedyBear-Project"
LABEL description="Stateless FastAPI service to serve T-Pot honeypot payloads"

# libmagic1 is the runtime dependency for python-magic; curl is for health checking
RUN apt-get update \
    && apt-get install -y --no-install-recommends libmagic1 curl \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user
RUN groupadd --gid 1000 appuser \
    && useradd --uid 1000 --gid appuser --shell /bin/sh appuser

WORKDIR /app

# Copy the virtual environment and application from the builder stage
COPY --from=builder /app/.venv /app/.venv
COPY --from=builder /build/app /app/app

# Ensure the venv's Python and binaries are on PATH
ENV PATH="/app/.venv/bin:$PATH"
ENV VIRTUAL_ENV="/app/.venv"

# Application defaults (overridable at runtime)
ENV BASE_DATA_DIR="/data"
ENV HONEYPOT_DIRS="dionaea/binaries,cowrie/downloads,honeytrap/downloads,adbhoney/downloads"
ENV API_KEY=""

EXPOSE 8080

USER appuser

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
