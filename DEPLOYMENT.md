# IcebergEBS — Containerised Deployment (PostgreSQL + Nginx)

## Context

IcebergEBS runs on PostgreSQL (dev, test, and production — SQLite is not supported) behind nginx as a TLS-terminating reverse proxy following security hardening best practices. Everything is wired together with Docker Compose for a one-command production deployment.

---

## Database choice — use PostgreSQL for any SOC-scale deployment

**IcebergEBS runs on PostgreSQL everywhere — dev, test, and production** (set `ICEBERG_EBS_DATABASE_URL` to a `postgresql+asyncpg://…` URL; the Docker Compose, dev override, and Helm stacks all do this). SQLite is not supported.

**Why:** IcebergEBS has three concurrent write sources — the background scheduler refreshing the watchlist, interactive API/UI writes, and bulk ingestion. PostgreSQL's row-level locking and MVCC let these writers proceed concurrently, and it scales the history tables (`FetchLog`, `InstallCountHistory`, `AlertLog`) far better as the watchlist grows. (SQLite's single database-level write lock — which serialized all writes and surfaced as `database is locked` under contention — was the reason it was dropped.)

**App-side guarantees:**
- The schema is managed by Alembic; the test suite runs against a real Postgres (containerized), so CI exercises the same database as production.
- All writers are commit-isolated: the scheduler and the retention prune each use their own `AsyncSession` + commit, and alert firing (`fire_pending_alerts`) runs only **after** the caller commits — so a second session never runs inside an open write transaction.
- `app/database.py` gives the engine a tuned connection pool (`pool_size=5`, `max_overflow=10`, `pool_pre_ping`, `pool_recycle=1800`).

**A single uvicorn worker is mandatory** — APScheduler is per-process, so multiple workers produce duplicate watchlist refreshes and `AlertLog` rows. Scale read/write throughput with Postgres, not with extra app workers.

---

## Files to create

| Path | Purpose |
|------|---------|
| `Dockerfile` | App image |
| `docker-compose.yml` | Three-service stack (postgres, app, nginx) |
| `.dockerignore` | Exclude secrets, venvs, DB files |
| `.env.example` | Template for required env vars |
| `nginx/nginx.conf` | Full nginx config |
| `nginx/security_headers.conf` | Shared header include (avoids duplication across location blocks) |
| `nginx/generate-dev-cert.sh` | One-shot self-signed cert for local dev |
| `static/js/tailwind-config.js` | Move inline Tailwind config out of HTML (required for CSP) |

## Files to modify

| Path | Change |
|------|--------|
| `pyproject.toml` / `uv.lock` | `asyncpg` (async Postgres driver) in the locked runtime set |
| `app/database.py` | Postgres engine + tuned connection pool |
| `app/templates/base.html` | Replace inline `tailwind.config` script with `<script src="/static/js/tailwind-config.js">` |

---

## 1. Dependencies (`pyproject.toml` + `uv.lock`)

Dependencies are declared in `pyproject.toml` and pinned in the committed `uv.lock`; there is no `requirements.txt`. Runtime packages live in `[project.dependencies]`, test and static-analysis tooling in the `[dependency-groups] dev` group. Refresh the lock with `uv lock` after any change — CI's `uv sync --locked` rejects a stale one.

`asyncpg` is the async Postgres driver used at runtime. `psycopg2-binary` is in the `dev` group because it only backs the sync Alembic CLI / migration tests — production migrates via the async startup connection and does not need it. The image builds its venv with `uv sync --frozen --no-dev`, so nothing in the `dev` group (pytest, respx, ruff, …) is installed into the deployed container.

---

## 2. `app/database.py`

The engine is created with a tuned connection pool suited to production:

```python
engine: AsyncEngine = create_async_engine(
    settings.database_url,
    echo=False,
    pool_size=5,
    max_overflow=10,
    pool_pre_ping=True,
    pool_timeout=30,
    pool_recycle=1800,
)
```

`init_db()` runs Alembic migrations to head against a connection and commits the `alembic_version` row (the connection is not in autocommit). There is no SQLite WAL/pragma path.

---

## 3. `app/templates/base.html` + `static/js/tailwind-config.js`

The existing inline `tailwind.config = {...}` block (lines 16–25 of `base.html`) cannot be hash-allowed in a CSP without tracking the hash across every edit. Move it to a static file:

**`static/js/tailwind-config.js`**:
```js
tailwind.config = {
  theme: { extend: {
    fontFamily: {
      sans: ['"IBM Plex Sans"', 'system-ui', 'sans-serif'],
      mono: ['"IBM Plex Mono"', 'ui-monospace', 'monospace'],
    },
  } },
};
```

**`base.html`**: Replace the inline `<script>…tailwind.config…</script>` block with:
```html
<script src="/static/js/tailwind-config.js"></script>
```

The anti-flash inline script (line 7) cannot be moved — it must execute before first paint to prevent a theme flash. It is allowed in the CSP via a static SHA-256 hash computed during implementation:
```
sha256-<hash-of-exact-script-bytes>
```

---

## 4. `Dockerfile`

```dockerfile
# uv is pulled through a named stage (not a bare `COPY --from=ghcr.io/…`) because
# Dependabot's Docker parser reads FROM lines only — the version pin below is
# Dependabot-managed and may be newer than this snapshot.
FROM ghcr.io/astral-sh/uv:0.11.28 AS uv

FROM python:3.14-slim AS builder

COPY --from=uv /uv /bin/uv

ENV UV_PROJECT_ENVIRONMENT=/opt/venv \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy

WORKDIR /app

COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev


FROM python:3.14-slim

WORKDIR /app

RUN adduser --disabled-password --gecos '' appuser

COPY --from=builder --chown=appuser:appuser /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY --chown=appuser:appuser . .

USER appuser

CMD ["uvicorn", "app.main:app", \
     "--host", "0.0.0.0", "--port", "8000", \
     "--proxy-headers", "--forwarded-allow-ips=*"]
```

(The real `Dockerfile` also carries the `ICEBERG_EBS_VERSION` build-arg — see the Versioning section of `CLAUDE.md`.)

Notes:
- **Two stages on purpose.** The builder resolves the venv from `pyproject.toml` + `uv.lock` alone (IcebergEBS is a virtual project, so no source is needed), and the runtime stage copies only that venv — so `uv`, the pip cache, and the whole `dev` group are absent from the deployed image. `--frozen` consumes the lockfile as-is and never re-resolves, so a rebuild cannot silently pick up a newer FastAPI.
- **The venv lives at `/opt/venv`, not `/app/.venv`** (`UV_PROJECT_ENVIRONMENT`). `docker-compose.dev.yml` bind-mounts the source tree over `/app`, which would shadow an in-tree venv — and on a host with no `.venv/`, leave the container with no interpreter at all.
- Copying only the manifests before the source keeps the dependency layer cached across source-only changes.
- `--proxy-headers` makes uvicorn trust `X-Forwarded-For` / `X-Forwarded-Proto` from nginx
- **nginx must _overwrite_ `X-Forwarded-For` with `$remote_addr`, not append** (`$proxy_add_x_forwarded_for`). With `--forwarded-allow-ips=*` uvicorn trusts the last hop, so an appended chain lets a client spoof its IP via an inbound XFF header and evade the app-level login rate limiter (#77). See the `proxy_set_header` block below.
- Single worker only — APScheduler runs per-process; multiple workers would each schedule independent watchlist refreshes, causing duplicate fetches and duplicate `AlertLog` entries

---

## 5. `.dockerignore`

```
.env
*.db
venv/
.venv/
__pycache__/
.git/
tests/
*.pyc
nginx/certs/
DEPLOYMENT.md
```

`.venv/` matters: the image's venv lives at `/opt/venv` (see the Dockerfile notes), and a host `.venv/` swept in by `COPY . .` would bake a wrong (dev-including, host-platform) interpreter tree into the image.

---

## 6. `docker-compose.yml`

The stack is **four** services — `postgres`, `app`, `nginx`, and a `backup` service that takes
scheduled `pg_dump`s (#86, see the Backups section). Every service is hardened:
`no-new-privileges`, `cap_drop: [ALL]` where the image tolerates it, `read_only` root filesystem
with `tmpfs` for the paths that must be writable. The block below is a lightly-abridged snapshot —
the file in the repo root is authoritative (image pins are Dependabot-managed).

```yaml
name: iceberg-ebs   # pin the project name (container/volume names) to the app

services:
  postgres:
    image: postgres:16-alpine
    # Postgres' entrypoint needs its default caps to chown PGDATA and drop to the
    # postgres user, so caps are NOT dropped here; just block privilege escalation.
    security_opt:
      - no-new-privileges:true
    environment:
      POSTGRES_DB: ${POSTGRES_DB:-iceberg_ebs}
      POSTGRES_USER: ${POSTGRES_USER:-iceberg_ebs}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${POSTGRES_USER:-iceberg_ebs} -d ${POSTGRES_DB:-iceberg_ebs}"]
      interval: 5s
      timeout: 5s
      retries: 10
    restart: unless-stopped

  app:
    build: .
    # The app parses untrusted extension archives — tightest sandbox Compose offers.
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    read_only: true
    tmpfs:
      - /tmp
    environment:
      ICEBERG_EBS_DATABASE_URL: postgresql+asyncpg://${POSTGRES_USER:-iceberg_ebs}:${POSTGRES_PASSWORD}@postgres/${POSTGRES_DB:-iceberg_ebs}
      ICEBERG_EBS_ADMIN_USERNAME: ${ICEBERG_EBS_ADMIN_USERNAME}
      ICEBERG_EBS_ADMIN_PASSWORD: ${ICEBERG_EBS_ADMIN_PASSWORD}
      ICEBERG_EBS_SECRET_KEY: ${ICEBERG_EBS_SECRET_KEY}
      ICEBERG_EBS_APP_BASE_URL: ${ICEBERG_EBS_APP_BASE_URL:-}
      ICEBERG_EBS_SECURE_COOKIES: "true"
      ICEBERG_EBS_LOG_JSON: ${ICEBERG_EBS_LOG_JSON:-false}
      # Forwarded so an operator who sets these in .env actually gets them (#87):
      ICEBERG_EBS_RETENTION_DAYS: ${ICEBERG_EBS_RETENTION_DAYS:-0}
      ICEBERG_EBS_FETCH_INTERVAL_MINUTES: ${ICEBERG_EBS_FETCH_INTERVAL_MINUTES:-60}
      ICEBERG_EBS_SESSION_MAX_AGE: ${ICEBERG_EBS_SESSION_MAX_AGE:-86400}
      ICEBERG_EBS_HTTPX_TIMEOUT: ${ICEBERG_EBS_HTTPX_TIMEOUT:-15.0}
      # Don't attempt to write .pyc into the read-only /app tree.
      PYTHONDONTWRITEBYTECODE: "1"
    healthcheck:
      # python:3.14-slim has no curl/wget — probe /readyz via the stdlib.
      test: ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8000/readyz', timeout=5)"]
      interval: 15s
      timeout: 5s
      start_period: 30s
      retries: 5
    depends_on:
      postgres:
        condition: service_healthy
    # Time for the scheduler to drain an in-flight refresh before SIGKILL (#109);
    # keep above ICEBERG_EBS_SHUTDOWN_DRAIN_SECONDS (default 55).
    stop_grace_period: 60s
    restart: unless-stopped

  nginx:
    # Pinned to a minor: `nginx:alpine` floats, so the TLS-terminating proxy
    # would silently change version on every `docker compose pull`.
    image: nginx:1.29-alpine
    security_opt:
      - no-new-privileges:true
    # Drop everything, add back only what stock nginx needs under a read-only rootfs.
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
      - CHOWN
      - SETUID
      - SETGID
      - DAC_OVERRIDE
    read_only: true
    # pid + proxy temp files; do NOT tmpfs /var/log/nginx (it would shadow the
    # stdout/stderr log symlinks and swallow container logs).
    tmpfs:
      - /var/cache/nginx
      - /var/run
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./nginx/security_headers.conf:/etc/nginx/security_headers.conf:ro
      - ./nginx/certs:/etc/nginx/certs:ro
      - ./static:/app/static:ro
    healthcheck:
      # Plain-HTTP local liveness (the /nginx-health location in nginx.conf).
      test: ["CMD", "wget", "--quiet", "--tries=1", "--spider", "http://localhost:80/nginx-health"]
      interval: 15s
      timeout: 5s
      start_period: 10s
      retries: 5
    depends_on:
      app:
        condition: service_healthy
    restart: unless-stopped

  backup:
    # Scheduled pg_dump into ./backups (#86) — same pinned image as the server so
    # pg_dump's version always matches. Custom-format dumps (-Fc), written atomically
    # (.tmp then mv), pruned after BACKUP_RETENTION_DAYS. Full shell loop in the
    # repo file; behaviour documented in "Backups & disaster recovery" below.
    image: postgres:16-alpine
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    read_only: true
    tmpfs:
      - /tmp
    environment:
      POSTGRES_USER: ${POSTGRES_USER:-iceberg_ebs}
      POSTGRES_DB: ${POSTGRES_DB:-iceberg_ebs}
      PGPASSWORD: ${POSTGRES_PASSWORD}
      BACKUP_RETENTION_DAYS: ${BACKUP_RETENTION_DAYS:-7}
      BACKUP_INTERVAL_SECONDS: ${BACKUP_INTERVAL_SECONDS:-86400}
    command: [sh, -c, "…"]   # pg_dump loop — see docker-compose.yml
    volumes:
      - ./backups:/backups
    depends_on:
      postgres:
        condition: service_healthy
    restart: unless-stopped

volumes:
  postgres_data:
```

---

## 7. `.env.example`

```env
# PostgreSQL
POSTGRES_DB=iceberg_ebs
POSTGRES_USER=iceberg_ebs
POSTGRES_PASSWORD=<generate: openssl rand -hex 32>

# IcebergEBS app
ICEBERG_EBS_ADMIN_USERNAME=admin
ICEBERG_EBS_ADMIN_PASSWORD=<strong password>
ICEBERG_EBS_SECRET_KEY=<generate: python -c "import secrets; print(secrets.token_hex(32))">
ICEBERG_EBS_APP_BASE_URL=https://your-domain.example.com
```

### Supported environment variables

The deploy stacks forward the environment variables **listed below** into the app container. This
table is *not* the full set of `app/config.py` settings — **any other setting uses its default and
is not overridable** until you add it to both the Compose `app.environment` block and the Helm
ConfigMap (`.env` is excluded from the image by `.dockerignore`, so an unforwarded variable is
silently ignored — #87). All settings use the `ICEBERG_EBS_` prefix.

| Variable | Default | Purpose |
|---|---|---|
| `ICEBERG_EBS_DATABASE_URL` | local dev URL | Postgres DSN (`postgresql+asyncpg://…`) |
| `ICEBERG_EBS_ADMIN_USERNAME` | — (required) | Seeded admin username (first boot only) |
| `ICEBERG_EBS_ADMIN_PASSWORD` | — (required) | Seeded admin password (first boot only) |
| `ICEBERG_EBS_SECRET_KEY` | — (required) | Cookie/flash signing key; **≥ 32 chars** |
| `ICEBERG_EBS_APP_BASE_URL` | `""` | Base URL used in webhook payloads |
| `ICEBERG_EBS_SECURE_COOKIES` | `true` | `Secure` flag on the session cookie (HTTPS) |
| `ICEBERG_EBS_FETCH_INTERVAL_MINUTES` | `60` | Watchlist refresh interval |
| `ICEBERG_EBS_RETENTION_DAYS` | `0` | Prune history older than N days; `0` disables |
| `ICEBERG_EBS_SESSION_MAX_AGE` | `86400` | Session lifetime in seconds |
| `ICEBERG_EBS_HTTPX_TIMEOUT` | `15.0` | Outbound HTTP timeout in seconds |
| `ICEBERG_EBS_LOG_JSON` | `false` | Emit single-line JSON logs for a collector (#89) |

Settings **not** in this table (e.g. the login rate-limit tuning `ICEBERG_EBS_LOGIN_MAX_ATTEMPTS` /
`…_LOGIN_ATTEMPT_WINDOW_SECONDS` / `…_LOGIN_LOCKOUT_SECONDS`, `ICEBERG_EBS_API_KEY_LAST_USED_THROTTLE_SECONDS`,
`ICEBERG_EBS_SESSION_COOKIE_NAME`, `ICEBERG_EBS_TRUSTED_ORIGINS`, `ICEBERG_EBS_SHUTDOWN_DRAIN_SECONDS`,
the outbound-HTTP retry/pool tuning `ICEBERG_EBS_HTTPX_MAX_RETRIES` / `…_HTTPX_BACKOFF_BASE` /
`…_HTTPX_BACKOFF_CAP` / `…_HTTPX_MAX_CONNECTIONS` / `…_HTTPX_MAX_KEEPALIVE_CONNECTIONS`, and
`ICEBERG_EBS_STORE_CIRCUIT_FAILURE_THRESHOLD`) run at their `app/config.py` defaults; to make one tunable in
production, add it to the Compose `app.environment` block and the Helm ConfigMap (and a
`icebergEbs.*` value) the same way the rows above are wired.

---

## 8. `nginx/generate-dev-cert.sh`

```bash
#!/usr/bin/env bash
set -euo pipefail
mkdir -p "$(dirname "$0")/certs"
openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
  -keyout "$(dirname "$0")/certs/key.pem" \
  -out    "$(dirname "$0")/certs/cert.pem" \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
echo "Self-signed cert written to nginx/certs/. For production, replace with a real cert."
```

For production: mount a Let's Encrypt cert (e.g. via Certbot) or any CA-issued cert+key at `nginx/certs/cert.pem` and `nginx/certs/key.pem`.

---

## 9. `nginx/security_headers.conf`

Extracted so that every `location` block can `include` it without repetition. (Nginx drops parent-block `add_header` directives the moment a child location block defines any `add_header` of its own — the include pattern is the standard workaround.)

```nginx
# Compute the SHA-256 of the anti-flash inline script during implementation
# and substitute <HASH> below.
add_header Content-Security-Policy
  "default-src 'self'; \
   script-src 'self' 'sha256-<HASH>' https://cdn.tailwindcss.com https://cdn.jsdelivr.net; \
   style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; \
   font-src 'self' https://fonts.gstatic.com; \
   img-src 'self' data:; \
   connect-src 'self'; \
   frame-ancestors 'none'; \
   base-uri 'self'; \
   object-src 'none'; \
   form-action 'self'" always;
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
add_header Referrer-Policy "same-origin" always;
add_header Permissions-Policy
  "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()" always;
```

Note on `style-src 'unsafe-inline'`: Tailwind CDN injects styles at runtime via a `<style>` tag; this directive is unavoidable with the CDN build. To eliminate it entirely, switch to the Tailwind CLI build process (a future hardening step, not in scope here).

---

## 10. `nginx/nginx.conf`

```nginx
user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log warn;
pid /var/run/nginx.pid;

events {
    worker_connections 1024;
}

http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;

    server_tokens off;  # Don't expose nginx version in headers or error pages

    # Referer + User-Agent and timing (request time / upstream response time) are the
    # first things needed to debug a beta report or spot abuse (#89).
    log_format main '$remote_addr - [$time_local] "$request" $status $body_bytes_sent '
                    '"$http_referer" "$http_user_agent" rt=$request_time urt=$upstream_response_time';
    access_log /var/log/nginx/access.log main;

    sendfile        on;
    tcp_nopush      on;
    keepalive_timeout 65;

    gzip            on;
    gzip_vary       on;
    gzip_types      text/plain text/css application/json application/javascript text/javascript;

    client_max_body_size 2m;

    # Rate-limit zones
    limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;
    limit_req_zone $binary_remote_addr zone=api:10m   rate=60r/m;

    # HTTP -> HTTPS redirect
    server {
        listen 80;
        server_name _;
        # Plain-HTTP liveness for the container healthcheck — answered locally, not
        # redirected to HTTPS or proxied to the app.
        location = /nginx-health {
            access_log off;
            add_header Content-Type text/plain;
            return 200 "ok\n";
        }
        location / {
            return 301 https://$host$request_uri;
        }
    }

    server {
        listen 443 ssl;
        http2 on;
        server_name _;

        ssl_certificate     /etc/nginx/certs/cert.pem;
        ssl_certificate_key /etc/nginx/certs/key.pem;

        # Modern TLS: 1.2 minimum, 1.3 preferred
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256;
        ssl_prefer_server_ciphers off;

        ssl_session_cache   shared:SSL:10m;
        ssl_session_timeout 1d;
        ssl_session_tickets off;

        # Uncomment for production CA-issued certs only (not self-signed):
        # ssl_stapling on;
        # ssl_stapling_verify on;

        proxy_http_version 1.1;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        # Overwrite, don't append ($proxy_add_x_forwarded_for): a client-supplied
        # XFF header must not be trusted by the app (#77).
        proxy_set_header X-Forwarded-For   $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_connect_timeout 10s;
        proxy_send_timeout    10s;
        proxy_read_timeout    120s;

        # Static assets served directly by nginx
        location /static/ {
            alias /app/static/;
            expires 1y;
            include /etc/nginx/security_headers.conf;
            add_header Cache-Control "public, immutable" always;
        }

        # Login — tight rate limit
        location = /login {
            limit_req zone=login burst=5 nodelay;
            include /etc/nginx/security_headers.conf;
            proxy_pass http://app:8000;
        }

        # API — moderate rate limit
        location /api/ {
            limit_req zone=api burst=20 nodelay;
            include /etc/nginx/security_headers.conf;
            proxy_pass http://app:8000;
        }

        location / {
            include /etc/nginx/security_headers.conf;
            proxy_pass http://app:8000;
        }
    }
}
```

---

## Inline script hash

During implementation, compute the SHA-256 of the anti-flash script (the exact bytes between the `<script>` tags on line 7 of `base.html`):

```bash
printf '%s' "(function(){var t=localStorage.getItem('icebergebs-theme')||'light';document.documentElement.setAttribute('data-theme',t);})();" \
  | openssl dgst -sha256 -binary | openssl base64
```

Note the **trailing semicolon** — it is part of the script body and therefore part of the
hashed bytes. Omitting it yields a hash that does not match the script, and the CSP then
blocks the very script it was meant to allow.

Substitute the result as `'sha256-<base64>'` in `security_headers.conf`. This is the only inline script remaining after the `tailwind-config.js` extraction.

---

## Build order

1. `pyproject.toml` — add `asyncpg`, then `uv lock`
2. `app/database.py` — Postgres engine + pool settings
3. `static/js/tailwind-config.js` — new file
4. `app/templates/base.html` — replace inline script block with `<script src>` tag
5. `Dockerfile`, `.dockerignore`, `.env.example`
6. `docker-compose.yml`
7. `nginx/generate-dev-cert.sh`
8. Compute inline script SHA-256 hash
9. `nginx/security_headers.conf` — with computed hash
10. `nginx/nginx.conf`

---

## Verification

```bash
# Generate dev cert
bash nginx/generate-dev-cert.sh

# Copy and fill in env vars
cp .env.example .env && $EDITOR .env

# Build and start
docker compose up --build

# Check TLS and headers
curl -sko /dev/null -D - https://localhost/ | grep -E "HTTP|Content-Security|Strict-Transport|X-Frame|X-Content"

# HTTP -> HTTPS redirect
curl -sI http://localhost/ | head -3

# Static asset served by nginx (not proxied through Python)
curl -sI https://localhost/static/css/app.css | grep -E "Cache-Control|Server"

# Tests pass against a containerized Postgres (start one with `make db` first)
ICEBERG_EBS_TEST_DATABASE_URL=postgresql+asyncpg://iceberg_ebs:iceberg_ebs@localhost:5432/iceberg_ebs \
  uv run pytest tests/ -v

# The deployed image carries the runtime set only — this must fail
docker compose run --rm --no-deps app python -c "import pytest"
```

For production: replace `nginx/certs/` with a real certificate, uncomment OCSP stapling, and set `ICEBERG_EBS_APP_BASE_URL` to your public domain.

---

# Option B — Kubernetes (Helm chart)

Assumes the cluster already has:
- **nginx-ingress-controller** (`ingress-nginx`)
- **cert-manager** with a `ClusterIssuer` named `letsencrypt-prod`

PostgreSQL is deployed as a Bitnami subchart — no separate StatefulSet to maintain.

## Helm chart layout

```
helm/iceberg-ebs/
├── Chart.yaml
├── values.yaml
└── templates/
    ├── _helpers.tpl
    ├── deployment.yaml
    ├── service.yaml
    ├── ingress.yaml
    ├── configmap.yaml
    ├── secret.yaml
    ├── networkpolicy.yaml   # default-deny ingress + named hops (#103)
    └── pdb.yaml             # blocks voluntary eviction of the singleton pod (#104)
```

---

## `helm/iceberg-ebs/Chart.yaml`

```yaml
apiVersion: v2
name: iceberg-ebs
description: Extension risk monitor
type: application
version: 0.1.0
appVersion: "1.0.0"
dependencies:
  - name: postgresql
    version: "~15.x.x"
    repository: https://charts.bitnami.com/bitnami
```

---

## `helm/iceberg-ebs/values.yaml`

```yaml
image:
  repository: ghcr.io/yourorg/icebergebs   # or local registry
  tag: ""                                   # no default — pin an immutable release tag at
                                            # install/upgrade (--set image.tag=…); an empty
                                            # value fails the render, never deploys :latest (#88)
  pullPolicy: IfNotPresent

# Must stay at 1 — APScheduler runs per-process; multiple replicas would
# each independently refresh watchlisted extensions and write duplicate AlertLog rows.
replicaCount: 1

# Grace period for the scheduler to drain an in-flight watchlist refresh on shutdown
# before SIGKILL (#109); keep above ICEBERG_EBS_SHUTDOWN_DRAIN_SECONDS (default 55).
terminationGracePeriodSeconds: 60

# With replicaCount 1 the PDB uses maxUnavailable: 0 — blocks voluntary disruption
# (node drains) so an eviction can't take the singleton to 0 (#104).
podDisruptionBudget:
  enabled: true

icebergEbs:
  adminUsername: admin
  adminPassword: ""        # override with --set or existingSecret
  secretKey: ""            # override with --set or existingSecret
  appBaseUrl: ""           # e.g. https://icebergebs.example.com
  fetchIntervalMinutes: 60
  retentionDays: 0         # prune history older than N days; 0 disables (#22, #87)
  sessionMaxAge: 86400     # session lifetime in seconds
  httpxTimeout: 15.0       # outbound HTTP timeout in seconds
  secureCookies: true
  logJson: false           # emit single-line JSON logs for a collector (#89)

postgresql:
  auth:
    username: iceberg_ebs
    password: ""           # override with --set or existingSecret
    database: iceberg_ebs
  # Disable the Bitnami subchart's OWN NetworkPolicy (#103): policy ingress rules
  # union, so leaving it enabled would re-open Postgres past our app-only rule.
  networkPolicy:
    enabled: false

ingress:
  host: icebergebs.example.com
  className: nginx
  certManagerIssuer: letsencrypt-prod  # set "" to disable cert-manager annotation

networkPolicy:
  # Default-deny ingress + named hops (ingress→app:8000, app→postgres:5432).
  # Egress stays open (stores/webhooks). Needs an enforcing CNI (#103).
  enabled: true
  ingressController:
    namespaceSelector:
      matchLabels:
        kubernetes.io/metadata.name: ingress-nginx

resources:
  requests:
    cpu: 100m
    memory: 256Mi
  limits:
    cpu: 500m
    memory: 512Mi
```

**Never commit passwords in `values.yaml`.** Use `--set` for ad-hoc installs or a `SealedSecret` / ExternalSecret for GitOps.

---

## `helm/iceberg-ebs/templates/secret.yaml`

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: {{ include "iceberg-ebs.fullname" . }}
type: Opaque
stringData:
  admin-password: {{ .Values.icebergEbs.adminPassword | required "icebergEbs.adminPassword is required" | quote }}
  secret-key:     {{ .Values.icebergEbs.secretKey     | required "icebergEbs.secretKey is required"     | quote }}
```

---

## `helm/iceberg-ebs/templates/configmap.yaml`

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ include "iceberg-ebs.fullname" . }}
data:
  ICEBERG_EBS_ADMIN_USERNAME:        {{ .Values.icebergEbs.adminUsername | quote }}
  ICEBERG_EBS_APP_BASE_URL:          {{ .Values.icebergEbs.appBaseUrl | quote }}
  ICEBERG_EBS_FETCH_INTERVAL_MINUTES: {{ .Values.icebergEbs.fetchIntervalMinutes | quote }}
  ICEBERG_EBS_RETENTION_DAYS:        {{ .Values.icebergEbs.retentionDays | quote }}
  ICEBERG_EBS_SESSION_MAX_AGE:       {{ .Values.icebergEbs.sessionMaxAge | quote }}
  ICEBERG_EBS_HTTPX_TIMEOUT:         {{ .Values.icebergEbs.httpxTimeout | quote }}
  ICEBERG_EBS_SECURE_COOKIES:        {{ .Values.icebergEbs.secureCookies | quote }}
  ICEBERG_EBS_LOG_JSON:              {{ .Values.icebergEbs.logJson | quote }}
```

---

## `helm/iceberg-ebs/templates/deployment.yaml`

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ include "iceberg-ebs.fullname" . }}
spec:
  replicas: {{ .Values.replicaCount }}
  # Recreate (not RollingUpdate): a rolling update's maxSurge would briefly run a
  # second pod, and two APScheduler processes duplicate watchlist refreshes +
  # AlertLog rows. Recreate never opens a two-scheduler window (#104).
  strategy:
    type: Recreate
  selector:
    matchLabels:
      {{- include "iceberg-ebs.selectorLabels" . | nindent 6 }}
  template:
    metadata:
      labels:
        {{- include "iceberg-ebs.selectorLabels" . | nindent 8 }}
    spec:
      # Time for the scheduler to drain an in-flight refresh before SIGKILL (#109).
      terminationGracePeriodSeconds: {{ .Values.terminationGracePeriodSeconds }}
      # The app never talks to the Kubernetes API — don't mount a token an attacker
      # who compromised the untrusted-package parser could pivot with.
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
        seccompProfile:
          type: RuntimeDefault
      volumes:
        - name: tmp
          emptyDir: {}
      containers:
        - name: iceberg-ebs
          image: "{{ .Values.image.repository }}:{{ required "image.tag is required — pin an immutable release tag, e.g. --set image.tag=v0.1.0-beta.1 (never :latest); see DEPLOYMENT.md and docs/RELEASING.md (#88)" .Values.image.tag }}"
          imagePullPolicy: {{ .Values.image.pullPolicy }}
          ports:
            - containerPort: 8000
          envFrom:
            - configMapRef:
                name: {{ include "iceberg-ebs.fullname" . }}
          env:
            # POSTGRES_PASSWORD must be defined BEFORE the $(POSTGRES_PASSWORD)
            # reference below, or the interpolation doesn't resolve.
            - name: POSTGRES_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: {{ include "iceberg-ebs.fullname" . }}-postgresql
                  key: password
            - name: ICEBERG_EBS_DATABASE_URL
              value: "postgresql+asyncpg://{{ .Values.postgresql.auth.username }}:$(POSTGRES_PASSWORD)@{{ include \"iceberg-ebs.fullname\" . }}-postgresql/{{ .Values.postgresql.auth.database }}"
            - name: ICEBERG_EBS_ADMIN_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: {{ include "iceberg-ebs.fullname" . }}
                  key: admin-password
            - name: ICEBERG_EBS_SECRET_KEY
              valueFrom:
                secretKeyRef:
                  name: {{ include "iceberg-ebs.fullname" . }}
                  key: secret-key
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: [ALL]
          # Python/uvicorn still need a writable /tmp under the read-only rootfs.
          volumeMounts:
            - name: tmp
              mountPath: /tmp
          resources:
            {{- toYaml .Values.resources | nindent 12 }}
          readinessProbe:
            httpGet:
              path: /readyz
              port: 8000
            initialDelaySeconds: 5
            periodSeconds: 10
          livenessProbe:
            httpGet:
              path: /healthz
              port: 8000
            initialDelaySeconds: 15
            periodSeconds: 30
```

---

## `helm/iceberg-ebs/templates/service.yaml`

```yaml
apiVersion: v1
kind: Service
metadata:
  name: {{ include "iceberg-ebs.fullname" . }}
spec:
  type: ClusterIP
  ports:
    - port: 8000
      targetPort: 8000
  selector:
    app.kubernetes.io/name: {{ include "iceberg-ebs.name" . }}
```

---

## `helm/iceberg-ebs/templates/ingress.yaml`

Security headers are applied via the `configuration-snippet` annotation. This is the nginx-ingress equivalent of the `security_headers.conf` include in the Docker Compose setup.

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: {{ include "iceberg-ebs.fullname" . }}
  annotations:
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
    nginx.ingress.kubernetes.io/proxy-body-size: "2m"
    nginx.ingress.kubernetes.io/proxy-read-timeout: "120"
    nginx.ingress.kubernetes.io/limit-rps: "2"
    nginx.ingress.kubernetes.io/limit-connections: "20"
    nginx.ingress.kubernetes.io/configuration-snippet: |
      add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'sha256-<HASH>' https://cdn.tailwindcss.com https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'" always;
      add_header Permissions-Policy "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()" always;
    {{- if .Values.ingress.certManagerIssuer }}
    cert-manager.io/cluster-issuer: {{ .Values.ingress.certManagerIssuer | quote }}
    {{- end }}
spec:
  ingressClassName: {{ .Values.ingress.className }}
  tls:
    - hosts:
        - {{ .Values.ingress.host }}
      secretName: {{ include "iceberg-ebs.fullname" . }}-tls
  rules:
    - host: {{ .Values.ingress.host }}
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: {{ include "iceberg-ebs.fullname" . }}
                port:
                  number: 8000
```

`HSTS`, `X-Content-Type-Options`, `X-Frame-Options`, and `Referrer-Policy` are set automatically by nginx-ingress when `ssl-redirect` is enabled; the snippet adds the headers that ingress-nginx does not set by default (CSP and Permissions-Policy). Verify with `curl -sI https://your-host/ | grep -i -E "content-security|permissions"`.

---

## Installing

```bash
# Add Bitnami repo and update deps
helm repo add bitnami https://charts.bitnami.com/bitnami
helm dependency update helm/iceberg-ebs

# Install (generate strong values; never commit these)
helm upgrade --install icebergebs helm/iceberg-ebs \
  --namespace icebergebs --create-namespace \
  --set image.tag="v0.1.0-beta.1" \
  --set icebergEbs.adminPassword="$(openssl rand -hex 16)" \
  --set icebergEbs.secretKey="$(openssl rand -hex 32)" \
  --set postgresql.auth.password="$(openssl rand -hex 32)" \
  --set icebergEbs.appBaseUrl="https://icebergebs.example.com" \
  --set ingress.host="icebergebs.example.com"

# Watch rollout
kubectl rollout status deployment/icebergebs -n icebergebs
```

**`image.tag` is required — the chart has no default** (#88). Pin an immutable release tag
(`--set image.tag=v0.1.0-beta.1`) from a verified release; an empty tag fails the render rather than
silently deploying a mutable `:latest`, which with `pullPolicy: IfNotPresent` re-renders an identical
pod spec on `helm upgrade` (no rollout) and reuses the node's cached image — shipping stale code.
Do **not** deploy `:latest` or the `:edge` tag (`:edge` is the moving "latest `main`" dev image from
`build.yml`, not a release). See [docs/RELEASING.md → Verifying a release](docs/RELEASING.md), and
verify the image (`cosign verify` / `gh attestation verify`) before rolling it out.

> Pinning by **digest** is stronger still, but the chart's `deployment.yaml` renders
> `repository:tag`, so `--set image.tag=@sha256:…` would produce an invalid `repository:@sha256:…`
> reference. Chart-level digest support (a separate `image.digest` value) is a possible future
> enhancement; until then, pin the immutable SemVer tag above.

For GitOps (Flux / ArgoCD): use `SealedSecret` or an ExternalSecrets `ExternalSecret` object to inject passwords from your secrets store rather than `--set`, and pin the same immutable release tag there.

**NetworkPolicies (#103):** the chart ships default-deny ingress plus named hops (ingress-controller → app:8000, app → postgres:5432), gated behind `networkPolicy.enabled` (default `true`). They **require a CNI that enforces NetworkPolicy** (Calico, Cilium) — on a CNI that doesn't, they are a harmless no-op that gives no protection. Set `networkPolicy.ingressController.namespaceSelector` to match your ingress controller's namespace. **Egress is intentionally left open** (the app must reach the extension stores, webhook destinations, and TI feeds) — don't add an egress policy. A future backup CronJob (#86) will need its own rule to reach Postgres.

---

## Comparison: Docker Compose vs Kubernetes

| Concern | Docker Compose | Kubernetes (Helm) |
|---------|---------------|-------------------|
| Complexity | Low | Medium |
| TLS | Manual cert or self-signed | cert-manager + Let's Encrypt (automatic) |
| Scaling | Single host | Multi-node |
| Secret management | `.env` file | K8s Secret / ExternalSecret |
| PostgreSQL | Docker volume | Bitnami subchart (StatefulSet) |
| Upgrades | rebuild / repin image, `up` | `helm upgrade --set image.tag=<new release>` |
| Best for | Single-server / homelab | Cloud / team deployments |

---

## Backups & disaster recovery

All state lives in Postgres — the watchlist, users/API keys, alert **history**, and SOAR inventory.
The history tables (`FetchLog`, `InstallCountHistory`, `AlertLog`, `InstallObservation`) are exactly
the data that **cannot be regenerated**, so a lost volume or a botched Postgres major upgrade is the
single biggest data-loss risk for a real deployment (#86).

### Docker Compose — automatic dumps

The stack ships a `backup` service that runs `pg_dump -Fc` (custom format: compressed + selective
restore) into `./backups` on the host on a fixed cadence, keeping `BACKUP_RETENTION_DAYS` of dumps:

- **Cadence / retention** — `BACKUP_INTERVAL_SECONDS` (default `86400`, nightly) and
  `BACKUP_RETENTION_DAYS` (default `7`), both settable in `.env`.
- **RPO** — up to one interval of loss (nightly dumps ⇒ **≤ 24 h**). Shorten `BACKUP_INTERVAL_SECONDS`
  for a tighter RPO, or point at off-host storage (below) for durability.
- Dumps are written atomically (`.tmp` then `mv`) so a half-written file is never restored, and named
  `iceberg_ebs-<timestamp>.pgc`. `./backups` is git-ignored.
- **Off-host copies matter**: dumps on the same host don't survive a disk failure. Sync `./backups` to
  object storage / another host (e.g. a `cron` `rclone`/`aws s3 sync`), or bind-mount a remote volume.

**Restore (Compose):**

```bash
# 1. Stop the app AND the backup service so nothing writes (or dumps) mid-restore
#    (leave postgres up).
docker compose stop app backup

# 2. Restore a chosen dump into the existing database (--clean --if-exists drops objects first;
#    add --create to restore into a fresh DB instead). pg_restore reads the -Fc archive on the
#    container's stdin. The command runs in single quotes so $POSTGRES_USER/$POSTGRES_DB are
#    expanded by the *container's* shell (Compose reads .env but doesn't export it to your shell).
docker compose exec -T postgres \
  sh -c 'pg_restore -U "$POSTGRES_USER" -d "$POSTGRES_DB" --clean --if-exists' \
  < ./backups/iceberg_ebs-<timestamp>.pgc

# 3. Bring the app (and backup) back. Alembic runs at startup and no-ops if the schema matches.
docker compose start app backup
```

### Kubernetes (Helm)

The chart does not template a backup CronJob; choose one of:

- **Bitnami `postgresql` backup values** — the subchart supports a scheduled `pg_dump` CronJob
  (`postgresql.backup.enabled=true`, `postgresql.backup.cronjob.schedule`, storage size/retention).
  Enable it in your values and point it at a PVC or object-storage sidecar.
- **VolumeSnapshots** — if your CSI driver supports them, snapshot the Postgres PVC on a schedule
  (e.g. via an external-snapshotter policy). Fast, but crash-consistent, not a logical dump.
- **External managed Postgres** — run Postgres outside the cluster (RDS/Cloud SQL/etc.) and use the
  provider's automated backups + PITR; set `postgresql.enabled=false` and point `ICEBERG_EBS_DATABASE_URL`
  at it. Recommended for anything beyond a homelab.

Restore mirrors the Compose flow: scale the app to 0 (`kubectl scale deploy/icebergebs --replicas=0`),
`pg_restore` the dump into the database, then scale back to 1. Note the NetworkPolicy (#103) default-denies
ingress to Postgres, so a backup/restore Job needs either its own explicit rule or to carry the app pod's
labels (NetworkPolicy matches on pod/namespace selectors, so the existing allow-postgres-from-app rule
admits any pod with those labels) to reach `postgres:5432`.

### Before every upgrade

Take a fresh dump **before** a Postgres major-version bump or an app upgrade that carries an Alembic
migration — both rewrite data and are not trivially reversible:

```bash
# Single-quoted so $POSTGRES_USER/$POSTGRES_DB expand in the container (Compose reads .env
# but doesn't export it to your shell); the output redirect writes to a host file.
docker compose exec -T postgres \
  sh -c 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc' \
  > "./backups/pre-upgrade-$(date +%Y%m%d-%H%M%S).pgc"
```

---

## Monitoring & observability (#89)

- **Logs** — the app logs are timestamped; set `ICEBERG_EBS_LOG_JSON=true` to emit single-line JSON
  for a log collector. nginx's access log includes referer, user-agent, and request/upstream timing.
- **Liveness / readiness** — point orchestrator probes at `/healthz` (process up) and `/readyz`
  (DB reachable → 503 if not). Both are unauthenticated and cheap.
- **Scheduler freshness** — `/readyz`'s JSON body carries `last_scheduler_run` (ISO timestamp or
  `null`), an in-process signal recorded when the background scheduler completes a refresh cycle (no
  history-table scan on the probe path, and scheduler-only so an API-triggered fetch can't mask a
  stall). Add an **external uptime check** that alerts when it falls too far behind the configured
  `ICEBERG_EBS_FETCH_INTERVAL_MINUTES` — this catches "the app is up but the scheduler has stopped
  running its cycles", which a plain 200 on `/readyz` would miss. It is advisory only: a stale
  scheduler run does not make the pod unready (the app still serves).
- **Error tracking** — aggregating unhandled exceptions to a Sentry-style DSN is a documented
  follow-up; it needs a runtime dependency, so it isn't wired in yet.
