# Two stages so the runtime image carries only the locked *runtime* dependency
# set: no uv, no pip cache, and none of the `dev` dependency-group (pytest,
# respx, ruff, …). uv.lock is authoritative — `--frozen` consumes it as-is and
# never re-resolves, so an image build cannot silently pick up a newer FastAPI.
# uv is pulled as a named stage rather than a bare `COPY --from=ghcr.io/astral-sh/uv:…`
# because Dependabot's Docker parser reads `FROM` lines only — an image referenced
# straight from a COPY is invisible to it, so the pin would silently never be updated.
# Same layers, same image; do not "simplify" this back into the COPY form.
FROM ghcr.io/astral-sh/uv:0.11.29 AS uv

FROM python:3.14-slim AS builder

COPY --from=uv /uv /bin/uv

# The venv lives OUTSIDE /app on purpose: docker-compose.dev.yml bind-mounts the
# source tree over /app, which would shadow (or, with no host venv, erase) an
# in-tree /app/.venv and leave the container with no interpreter.
ENV UV_PROJECT_ENVIRONMENT=/opt/venv \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy

WORKDIR /app

# Manifests only, so the venv layer caches across source-only changes. IcebergEBS is
# a virtual project (`[tool.uv] package = false`), so its dependencies resolve
# without the source tree being present yet.
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev


# Tailwind build stage (#85): compiles static/css/output.css (a gitignored build
# artifact) from static/css/input.css with the standalone CLI — no Node, and no
# pip either: the binary is downloaded straight from the tagged GitHub release and
# verified against its published sha256 before it ever runs, so rebuilding the same
# commit can only ever execute the same bytes (unlike a floating `pip install`,
# which could resolve a newer wrapper and fetch an unverified executable). Only the
# files the class scanner needs are copied in, which also keeps the @source scan
# surface identical to what input.css declares. The version must match the
# TAILWINDCSS_VERSION pin in the Makefile `css` target and the ci.yml lint job;
# bumping it means refreshing the checksums below from the release's sha256sums.txt.
FROM python:3.14-slim AS tailwind-builder

ARG TARGETARCH
RUN set -eux; \
    TAILWINDCSS_VERSION=v4.3.1; \
    case "${TARGETARCH}" in \
      amd64) asset=tailwindcss-linux-x64; sha256=2526d063ba03b71f9a3ea7d5cee14f0aec147f117f222d5adc97b1d736d45999 ;; \
      arm64) asset=tailwindcss-linux-arm64; sha256=3d662377a86d71c43b549dc06b90db4586b4acd412bf827a3268e951661e5adf ;; \
      *) echo "unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    python -c "import sys, urllib.request; urllib.request.urlretrieve(sys.argv[1], '/usr/local/bin/tailwindcss')" \
      "https://github.com/tailwindlabs/tailwindcss/releases/download/${TAILWINDCSS_VERSION}/${asset}"; \
    echo "${sha256}  /usr/local/bin/tailwindcss" | sha256sum -c -; \
    chmod +x /usr/local/bin/tailwindcss

WORKDIR /build
COPY static/ static/
COPY app/templates/ app/templates/

RUN tailwindcss -i static/css/input.css -o static/css/output.css --minify


FROM python:3.14-slim

WORKDIR /app

RUN adduser --disabled-password --gecos '' appuser

COPY --from=builder --chown=appuser:appuser /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY --chown=appuser:appuser . .
# The checkout has no output.css (gitignored); take the built one from the
# tailwind-builder stage.
COPY --from=tailwind-builder --chown=appuser:appuser /build/static/css/output.css static/css/output.css

# Build version is stamped in (the image has no .git for runtime resolution).
# Pass with: docker build --build-arg ICEBERG_EBS_VERSION="build 142 · 8ebe5f8" .
ARG ICEBERG_EBS_VERSION=""
ENV ICEBERG_EBS_VERSION=$ICEBERG_EBS_VERSION

USER appuser

CMD ["uvicorn", "app.main:app", \
     "--host", "0.0.0.0", "--port", "8000", \
     "--proxy-headers", "--forwarded-allow-ips=*"]
