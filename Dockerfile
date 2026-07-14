# Two stages so the runtime image carries only the locked *runtime* dependency
# set: no uv, no pip cache, and none of the `dev` dependency-group (pytest,
# respx, ruff, …). uv.lock is authoritative — `--frozen` consumes it as-is and
# never re-resolves, so an image build cannot silently pick up a newer FastAPI.
# uv is pulled as a named stage rather than a bare `COPY --from=ghcr.io/astral-sh/uv:…`
# because Dependabot's Docker parser reads `FROM` lines only — an image referenced
# straight from a COPY is invisible to it, so the pin would silently never be updated.
# Same layers, same image; do not "simplify" this back into the COPY form.
FROM ghcr.io/astral-sh/uv:0.11.23 AS uv

FROM python:3.14-slim AS builder

COPY --from=uv /uv /bin/uv

# The venv lives OUTSIDE /app on purpose: docker-compose.dev.yml bind-mounts the
# source tree over /app, which would shadow (or, with no host venv, erase) an
# in-tree /app/.venv and leave the container with no interpreter.
ENV UV_PROJECT_ENVIRONMENT=/opt/venv \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy

WORKDIR /app

# Manifests only, so the venv layer caches across source-only changes. Marvin is
# a virtual project (`[tool.uv] package = false`), so its dependencies resolve
# without the source tree being present yet.
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev


FROM python:3.14-slim

WORKDIR /app

RUN adduser --disabled-password --gecos '' appuser

COPY --from=builder --chown=appuser:appuser /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY --chown=appuser:appuser . .

# Build version is stamped in (the image has no .git for runtime resolution).
# Pass with: docker build --build-arg MARVIN_VERSION="build 142 · 8ebe5f8" .
ARG MARVIN_VERSION=""
ENV MARVIN_VERSION=$MARVIN_VERSION

USER appuser

CMD ["uvicorn", "app.main:app", \
     "--host", "0.0.0.0", "--port", "8000", \
     "--proxy-headers", "--forwarded-allow-ips=*"]
