# IcebergEBS — Containerised Deployment (PostgreSQL + Caddy)

## Context

IcebergEBS runs on PostgreSQL (dev, test, and production — SQLite is not supported) behind [Caddy](https://caddyserver.com) as a TLS-terminating reverse proxy following security hardening best practices. Everything is wired together with Docker Compose for a one-command production deployment. (Caddy replaced nginx as the edge proxy in #188; the Kubernetes chart runs Caddy as an in-pod sidecar behind the cluster ingress.)

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
| `docker-compose.yml` | Three-service stack (postgres, app, caddy) |
| `.dockerignore` | Exclude secrets, venvs, DB files |
| `.env.example` | Template for required env vars |
| `caddy/Caddyfile` | Compose edge config (TLS termination, headers, proxy — /static included) |
| `caddy/Caddyfile.k8s` | In-pod sidecar config for Kubernetes (plain HTTP behind the ingress) |
| `caddy/headers.caddy` | Minimal set-if-absent fallback headers for Caddy-generated responses — the app owns the canonical set (`app/main.py:security_headers`) |
| `caddy/generate-dev-cert.sh` | One-shot self-signed cert for local dev |
| `static/css/input.css` | Tailwind v4 entry point — built to the gitignored `static/css/output.css` (#85) |
| `static/js/vendor/` | Vendored, version-pinned Alpine.js (no CDN at runtime, #85) |

## Files to modify

| Path | Change |
|------|--------|
| `pyproject.toml` / `uv.lock` | `asyncpg` (async Postgres driver) in the locked runtime set |
| `app/database.py` | Postgres engine + tuned connection pool |

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

## 3. Frontend assets — fully self-hosted (#85)

No third-party origin is contacted at runtime (`tests/test_no_third_party_origins.py` enforces it): the old Tailwind Play CDN, jsDelivr Alpine and Google Fonts dependencies are gone.

- **Tailwind v4** is compiled by the standalone CLI from `static/css/input.css` into `static/css/output.css`. `output.css` is a **gitignored build artifact**: images build it in the Dockerfile `tailwind-builder` stage, which downloads the CLI straight from the tagged GitHub release and **verifies its sha256** before running it (nothing floating executes in the image build); local checkouts build it with `make css` (via `pytailwindcss`, a locked `dev`-group dependency; `make dev` runs it automatically). **A bare source-checkout deploy (uvicorn straight from `git pull`) must run `make css` after every pull** or `/static/css/output.css` 404s. The CLI version is pinned via `TAILWINDCSS_VERSION` in the Makefile and ci.yml and by the checksum table in the Dockerfile — bump together.
- **Alpine.js** is vendored and version-pinned at `static/js/vendor/alpine-csp-3.15.12.min.js` (the `@alpinejs/csp` build — #106).
- **Fonts** (Archivo, JetBrains Mono, Spectral woff2 — the IcebergAI house set, #105) are served from `static/fonts/` via `static/css/fonts.css`.

There are **no inline scripts** (#106): the theme/anti-flash bootstrap is the external `static/js/theme-boot.js`, loaded synchronously at the top of `<head>` so it still runs before first paint, and Alpine is the `@alpinejs/csp` build with all components registered from same-origin files (`static/js/app.js` + `static/js/pages/`). `tests/test_csp_strict.py` fails CI if an inline `<script>` or `on*=` handler reappears.

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


# Builds the gitignored static/css/output.css (#85) — see section 3. The standalone
# CLI binary is fetched from the tagged GitHub release and sha256-verified before it
# runs (no pip, nothing floating executes in the image build); see the real
# Dockerfile for the per-arch checksum table.
FROM python:3.14-slim AS tailwind-builder

ARG TARGETARCH
RUN <download tailwindcss v4.3.1 for ${TARGETARCH}; verify sha256; chmod +x>

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
COPY --from=tailwind-builder --chown=appuser:appuser /build/static/css/output.css static/css/output.css

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
- `--proxy-headers` makes uvicorn trust `X-Forwarded-For` / `X-Forwarded-Proto` from Caddy
- **Caddy must set `X-Forwarded-For` to a single canonical client IP, not append a client-supplied chain.** The Caddyfiles use `header_up X-Forwarded-For {client_ip}`: at the Compose edge (no `trusted_proxies`) `{client_ip}` is the real peer and any inbound XFF is discarded; in K8s (`trusted_proxies static private_ranges`) it is the real external client the cluster ingress recorded. With `--forwarded-allow-ips=*` uvicorn trusts that value, so a forged inbound XFF cannot spoof a client IP and evade the app-level login/API rate limiters (#77). See the Caddyfile section below.
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
caddy/certs/
DEPLOYMENT.md
```

`.venv/` matters: the image's venv lives at `/opt/venv` (see the Dockerfile notes), and a host `.venv/` swept in by `COPY . .` would bake a wrong (dev-including, host-platform) interpreter tree into the image.

---

## 6. `docker-compose.yml`

The stack is **four** services — `postgres`, `app`, `caddy`, and a `backup` service that takes
scheduled `pg_dump`s (#86, see the Backups section). Every service is hardened:
`no-new-privileges`, `cap_drop: [ALL]` where the image tolerates it, `read_only` root filesystem
with `tmpfs` for the paths that must be writable. The block below is a lightly-abridged snapshot —
the file in the repo root is authoritative (image pins are Dependabot-managed).

```yaml
name: iceberg-ebs   # pin the project name (container/volume names) to the app

services:
  postgres:
    image: postgres:18-alpine
    # Postgres' entrypoint needs its default caps to chown PGDATA and drop to the
    # postgres user, so caps are NOT dropped here; just block privilege escalation.
    security_opt:
      - no-new-privileges:true
    environment:
      POSTGRES_DB: ${POSTGRES_DB:-iceberg_ebs}
      POSTGRES_USER: ${POSTGRES_USER:-iceberg_ebs}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    volumes:
      # Postgres 18+ wants the volume at /var/lib/postgresql (data lives in a
      # major-version subdirectory); the old .../data mount makes the 18 entrypoint error.
      - postgres_data:/var/lib/postgresql
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

  caddy:
    # Pinned to a minor: `caddy:alpine` floats, so the TLS-terminating edge proxy
    # would silently change version on every `docker compose pull`.
    image: caddy:2.11-alpine
    security_opt:
      - no-new-privileges:true
    # Fewer caps than nginx: NET_BIND_SERVICE to bind :80/:443, and DAC_OVERRIDE so root
    # can read the mounted key (OpenSSL 3.x writes key.pem 0600 owned by the host user).
    # No CHOWN/SETUID/SETGID — Caddy is a single process, no worker user-drop.
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
      - DAC_OVERRIDE
    read_only: true
    # Caddy's XDG data/config dirs (local CA/state) must be writable under a read-only
    # rootfs; no persistence is needed (TLS uses the mounted cert, not ACME).
    tmpfs:
      - /data
      - /config
      - /tmp
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./caddy/Caddyfile:/etc/caddy/Caddyfile:ro
      - ./caddy/headers.caddy:/etc/caddy/headers.caddy:ro
      - ./caddy/certs:/etc/caddy/certs:ro
      - ./static:/srv/static:ro
    healthcheck:
      # Plain-HTTP local liveness (the /caddy-health handler in the Caddyfile).
      test: ["CMD", "wget", "--quiet", "--tries=1", "--spider", "http://localhost:80/caddy-health"]
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
    image: postgres:18-alpine
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

Every credential above is referenced from `docker-compose.yml` as `${VAR:?message}`, so an unset
or empty value **aborts `docker compose up`** naming the variable. This is deliberate: Compose
resolves a bare `${VAR}` to the empty string behind a warning that scrolls past in `up` output,
and the stack then starts and fails later inside the app as an `asyncpg.InvalidPasswordError` —
which looks like a code or networking fault rather than a missing variable. `tests/test_compose_secrets.py`
fails if a credential reference loses its guard. The Helm equivalent is `| required` in
`templates/secret.yaml`.

Credentials live in `.env` and are referenced **only** from the base compose file.
`docker-compose.dev.yml` deliberately defines none — it previously hardcoded
`POSTGRES_PASSWORD: iceberg_ebs`, which meant `make dev` succeeded on a machine where a plain
`docker compose up` failed with the same `.env`, hiding the misconfiguration behind the dev path.

### Rotating the Postgres password

> **`POSTGRES_PASSWORD` is only read when the data volume is first created.** The image's
> entrypoint uses it to initialise the data directory; on an existing volume the value is
> ignored. Editing `.env` alone therefore does **not** change the password — Postgres keeps
> serving the old one, and you get an `InvalidPasswordError` while looking at a `.env` that
> appears correct.

Rotate the role itself, then update `.env` to match:

```bash
# 1. Change the stored password (non-destructive; preserves all data)
printf "ALTER USER iceberg_ebs WITH PASSWORD '<new>';\n" \
  | docker exec -i iceberg-ebs-postgres-1 psql -U iceberg_ebs -d iceberg_ebs -v ON_ERROR_STOP=1

# 2. Set POSTGRES_PASSWORD=<new> in .env, then recreate the app so it picks up the new URL
docker compose up -d
```

Piping the statement via stdin keeps the password out of the container's `ps` output. The
alternative — deleting the volume so the entrypoint re-initialises — **destroys all data**; use it
only on a throwaway dev database.

For host-side work (`uv run pytest`, `uv run alembic`) also set `ICEBERG_EBS_DATABASE_URL` in
`.env` to the rotated URL on `localhost:5432`. `tests/conftest.py` reads
`os.environ["ICEBERG_EBS_TEST_DATABASE_URL"]` and otherwise falls back to `settings.database_url`;
`.env` reaches `Settings` but **not** `os.environ`, so `ICEBERG_EBS_DATABASE_URL` is the key that
actually takes effect for a bare `pytest` run. Containers are unaffected — the app service sets its
own URL via `environment:`, and `.env` is excluded from the image by `.dockerignore`.

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
| `ICEBERG_EBS_API_RATE_LIMIT_ENABLED` | `true` (prod env) | App-side `/api/*` rate limiting (#188) |
| `ICEBERG_EBS_LOGIN_RATE_LIMIT_ENABLED` | `true` (prod env) | App-side `POST /login` rate limiting (#196) |
| `ICEBERG_EBS_API_RATE_LIMIT_PER_MINUTE` | `60` | Sustained `/api/*` requests/min per client IP (#202) |
| `ICEBERG_EBS_API_RATE_LIMIT_BURST` | `20` | `/api/*` back-to-back burst per client IP (#202) |
| `ICEBERG_EBS_LOGIN_RATE_LIMIT_PER_MINUTE` | `5` | Sustained `POST /login` requests/min per client IP (#202) |
| `ICEBERG_EBS_LOGIN_RATE_LIMIT_BURST` | `5` | `POST /login` back-to-back burst per client IP (#202) |
| `ICEBERG_EBS_TRUSTED_ORIGINS` | `""` | Extra origins the CSRF check trusts, comma-separated — for a proxy that rewrites `Host` (#107, #153) |
| `ICEBERG_EBS_PROXY_MODE` | `system` | Outbound proxy mode: `system` \| `none` \| `explicit` (#216) |
| `ICEBERG_EBS_PROXY_URL` | `""` | Forward proxy for `explicit` mode — no credentials in the URL |
| `ICEBERG_EBS_PROXY_NO_PROXY` | localhost + private ranges | Hosts/suffixes/IPs/CIDRs that bypass the explicit proxy |
| `ICEBERG_EBS_PROXY_USERNAME` | `""` | Proxy credentials — env-only secret (Helm: chart Secret, not ConfigMap) |
| `ICEBERG_EBS_PROXY_PASSWORD` | `""` | See above |
| `ICEBERG_EBS_AUTH_MODE` | `both` | Login paths: `local` \| `oidc` \| `both` (#32) |
| `ICEBERG_EBS_OIDC_REDIRECT_BASE_URL` | `""` | Public base URL for the IdP callback behind a rewriting proxy |
| `ICEBERG_EBS_OIDC_<PROVIDER>_*` | see `.env.example` | Per-provider OIDC config for `ENTRA`/`AUTHENTIK`/`AUTH0`/`OKTA` (#32) |
| `ICEBERG_EBS_OIDC_<PROVIDER>_CLIENT_SECRET` | `""` | OIDC client secret — env-only secret (Helm: chart Secret, not ConfigMap) |

Settings **not** in this table (e.g. the login rate-limit tuning `ICEBERG_EBS_LOGIN_MAX_ATTEMPTS` /
`…_LOGIN_ATTEMPT_WINDOW_SECONDS` / `…_LOGIN_LOCKOUT_SECONDS`, `ICEBERG_EBS_API_KEY_LAST_USED_THROTTLE_SECONDS`,
`ICEBERG_EBS_SESSION_COOKIE_NAME`, `ICEBERG_EBS_SHUTDOWN_DRAIN_SECONDS`,
the outbound-HTTP retry/pool tuning `ICEBERG_EBS_HTTPX_MAX_RETRIES` / `…_HTTPX_BACKOFF_BASE` /
`…_HTTPX_BACKOFF_CAP` / `…_HTTPX_MAX_CONNECTIONS` / `…_HTTPX_MAX_KEEPALIVE_CONNECTIONS`, and
`ICEBERG_EBS_STORE_CIRCUIT_FAILURE_THRESHOLD`) run at their `app/config.py` defaults; to make one tunable in
production, add it to the Compose `app.environment` block and the Helm ConfigMap (and a
`icebergEbs.*` value) the same way the rows above are wired.

### Outbound proxy (#216)

All egress — store metadata fetching, package downloads, **and** webhook alert delivery — routes
through the proxy layer. The `ICEBERG_EBS_PROXY_*` env vars **seed** an admin-editable routing
config (the `ProxySettings` DB singleton, edited live at `/admin/proxy` — changes apply from the
next outbound request, no restart). Credentials are the exception: they stay **env-only**
(`ICEBERG_EBS_PROXY_USERNAME` / `…_PASSWORD`), injected into the proxy URL at send time and never
persisted, returned by the API, or logged. In Helm they are chart-Secret keys
(`proxy-username`/`proxy-password`) wired as `secretKeyRef` env — never ConfigMap data
(`tests/test_deploy_env.py` enforces this split).

Operational notes:

- **Upgrade behaviour change:** before #216 the app ignored `HTTP(S)_PROXY` env vars entirely
  (httpx never applies them through a custom transport). The default mode `system` now honours
  them — a deployment that happens to export an ambient proxy var starts proxying after upgrade.
  Set `ICEBERG_EBS_PROXY_MODE=none` to force the old always-direct behaviour.
- **Webhooks keep their SSRF defence through the proxy.** Delivery still connects to the
  pre-validated public IP — through an HTTP proxy that is an IP-literal `CONNECT`. A proxy that
  denies IP-literal tunnels breaks webhook delivery; fix it with a proxy-side allowlist or a
  no-proxy **IP/CIDR** entry (domain entries can't match a pinned-IP URL). Never weaken the
  pinning to accommodate a proxy.
- **Local DNS must stay available**: webhook URL validation resolves the destination locally
  before dialling; a segment that blocks DNS egress fails validation before the proxy is
  consulted.
- Proxy schemes are `http`/`https` only (no SOCKS — it would add the `httpx[socks]` runtime
  dependency; widen `PROXY_URL_SCHEMES` in `app/proxy.py` + `pyproject.toml` if ever needed).
- The connectivity test at `/admin/proxy` dials only server-known egress targets (the five store
  origins + enabled webhook **origins**, never their capability paths) — by design it does not
  accept arbitrary URLs.

### Single sign-on (OIDC, #32)

OIDC sign-in (Authorization Code + PKCE via Authlib) against **Microsoft Entra ID, Authentik,
Auth0, or Okta**. The non-secret `ICEBERG_EBS_AUTH_MODE` / `ICEBERG_EBS_OIDC_*` env vars **seed**
an admin-editable config (the `OIDCSettings` DB singleton, edited live at `/admin/oidc` — after
the first boot **the DB row wins over the env** for everything except secrets). Client secrets
stay **env-only** (`ICEBERG_EBS_OIDC_<PROVIDER>_CLIENT_SECRET`) — never persisted, returned by
the API, or logged; in Helm they are chart-Secret keys wired as `secretKeyRef` env, never
ConfigMap data (`tests/test_deploy_env.py` enforces the split).

Setting up a provider:

1. Register IcebergEBS with the IdP as a **confidential web application** using the redirect URI
   `https://<your-host>/auth/oidc/<provider>/callback` (provider = `entra`/`authentik`/`auth0`/`okta`).
2. Set the provider's env vars (see `.env.example`) — client id + secret plus the
   provider-specific field(s): Entra **tenant ID** (a concrete GUID/verified domain, never
   `common` — issuer validation must pin one tenant), Authentik **base URL + application slug**,
   Auth0/Okta **domain** (Okta optionally an authorization-server id).
3. Behind Caddy/the ingress, set `ICEBERG_EBS_OIDC_REDIRECT_BASE_URL` to the public origin so the
   callback URL is built with the browser-visible host/scheme rather than the app-observed one.
4. To map IdP groups to admin, configure the provider's group claim (`…_ROLE_CLAIM`, e.g.
   `groups`) and an allowlist `…_ROLE_MAP` of `group=admin|user` pairs. Only groups mapped to
   `admin` grant admin; the default is a regular user (no self-elevation). The mapped flag is
   re-synced on every SSO login and revokes that user's older sessions when it changes.

Operational notes:

- **Break-glass:** keep `auth_mode=both` until SSO is proven, and keep at least one local admin
  (the seeded `ICEBERG_EBS_ADMIN_*` account). `auth_mode=oidc` disables password login entirely
  and is refused unless a complete provider is enabled — but a *misconfigured IdP* with
  `auth_mode=oidc` still locks the UI: recover by setting `ICEBERG_EBS_AUTH_MODE=both`… which the
  DB row overrides, so flip it back via the API/DB or temporarily restore the env secret and use
  SSO. Prefer switching to `oidc` only from the admin page, which validates the result.
- **Fail-closed startup:** the stored SSO config is validated during boot; a config that became
  invalid (typically the env client secret was removed while a provider is still enabled) aborts
  startup rather than silently starting without a working login path. Restore the env var (or
  correct the row) and restart.
- SSO-provisioned accounts have **no local password** (username = their email); password login
  refuses them, and a password reset is the IdP's job. Accounts are keyed on the immutable
  provider subject — a changed email never links to a different account; a collision with an
  existing account's email is denied ("account linking required") rather than auto-linked. A
  brand-new identity must present a **verified** email (the account name is derived from it), so
  configure your IdP to assert email verification.
- **The IdP is the access gate.** JIT provisioning means anyone your IdP authenticates for this
  application gets an account, so control access with **IdP-side app assignment** (assign the app
  to specific users/groups), not by deleting rows here: deleting an SSO user in `/admin/users` is
  **not a ban** — their next sign-in re-provisions a fresh account. Off-board at the IdP.
- **Logout ends the IdP session too (RP-initiated logout).** Logging out of an SSO account
  redirects to the provider's `end_session_endpoint` (from its discovery document) with the
  `id_token_hint`, so the IdP session is terminated, not just the local cookie. The IdP must have
  the app's post-logout redirect (`<base>/login`) registered. Providers without an
  `end_session_endpoint` fall back to a local-only logout.
- **IdP-side credential resets propagate within the SSO session window.** IcebergEBS can't be
  pushed an IdP password reset or account disable, so **SSO sessions use a shorter lifetime**
  (`ICEBERG_EBS_OIDC_SESSION_MAX_AGE`, default 1h) than local password sessions (`session_max_age`):
  once it lapses the browser must re-authenticate through the IdP, which fails for a disabled
  account — bounding how long a stale session or stolen cookie survives. Set it shorter for faster
  propagation. Continuous back-channel logout and API-key revocation on IdP change remain tracked
  follow-ups; for immediate revocation delete the user's API keys.
- All IdP traffic (discovery, JWKS, token, userinfo) routes through the **outbound proxy layer**
  above, like every other egress path.

---

## 8. `caddy/generate-dev-cert.sh`

```bash
#!/usr/bin/env bash
set -euo pipefail
mkdir -p "$(dirname "$0")/certs"
openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
  -keyout "$(dirname "$0")/certs/key.pem" \
  -out    "$(dirname "$0")/certs/cert.pem" \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
echo "Self-signed cert written to caddy/certs/."
```

For production: mount a Let's Encrypt cert (e.g. via Certbot) or any CA-issued cert+key at `caddy/certs/cert.pem` and `caddy/certs/key.pem`. (Caddy can also obtain and renew certs automatically via ACME; the Compose stack uses an explicit mounted cert so the same config works with a self-signed dev cert and behind a corporate CA.)

---

## 9. Security headers: the app is canonical, `caddy/headers.caddy` is fallback

The **app** is the single source of truth for security headers: `app/main.py:security_headers` (the outermost middleware) hard-sets the full canonical set on every response it generates — proxied or not, including error responses and static files:

```
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; style-src-elem 'self'; style-src-attr 'unsafe-inline'; font-src 'self'; img-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; object-src 'none'; form-action 'self'
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload   (only when ICEBERG_EBS_SECURE_COOKIES is on — the prod/HTTPS signal)
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: same-origin
Permissions-Policy: accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()
```

Owning the headers app-side means the strict CSP holds on **every** deployment path — behind Caddy, behind the Helm sidecar, or on a bare uvicorn checkout — instead of existing only at the proxy. `tests/test_security_headers.py` and `tests/test_csp_strict.py` assert this set on real responses.

`caddy/headers.caddy` (imported by both Caddyfiles via `import headers.caddy`) is now only a **minimal static fallback** for responses Caddy itself generates and the app never sees — Caddy's own 502 when the app is down, and the :80→HTTPS redirect. Every op in it uses Caddy's `?` (set-if-absent) prefix, so on a proxied response the app's canonical header already exists and the fallback stands down; its CSP is a tiny static deny-all (`default-src 'none'; frame-ancestors 'none'`) that never needs syncing with the app policy. A hard SET must never reappear there — it would clobber the app's canonical values (`tests/test_security_headers.py` enforces ?-only ops), and the block's `defer` is what makes `?` evaluate after the upstream headers are copied. (The Helm ConfigMap embeds a test-guarded mirror because Helm can't read files above the chart; `tests/test_helm_caddy.py` fails if the copies drift.)

Notes on the CSP: `style-src-attr 'unsafe-inline'` permits the templates' pervasive inline `style="…"` attributes (dynamic widths, token-var colours) — style injection is not a script-execution vector — while `style-src-elem 'self'` blocks injected `<style>` elements (no first-party code creates any); the plain `style-src 'self' 'unsafe-inline'` remains as the pre-CSP3 browser fallback. No directive references a third-party origin — every asset is self-hosted (#85) — and `img-src` carries no `data:` source (nothing uses data: URIs).

---

## 10. `caddy/Caddyfile` (Compose) and `caddy/Caddyfile.k8s` (Kubernetes)

The Compose Caddyfile terminates TLS on :443, imports the fallback headers, and proxies everything — including `/static`, which the app serves via StaticFiles — to the app (same topology as the K8s sidecar; since #85 the built `output.css` exists only inside the app image, so there is nothing on the host for Caddy to serve). A plain-HTTP :80 site answers the container healthcheck and redirects everything else to HTTPS. The repo files are authoritative — abbreviated here:

```caddy
{
	admin off
	auto_https disable_redirects  # explicit mounted cert below; no ACME
}

:80 {
	import headers.caddy      # fallback headers on the Caddy-generated redirects too

	handle /caddy-health {
		respond "ok" 200
	}
	handle {
		redir https://{host}{uri}
	}
}

:443 {
	tls /etc/caddy/certs/cert.pem /etc/caddy/certs/key.pem
	log                       # structured JSON access log (UA/Referer/duration) — #89
	encode gzip
	request_body {
		max_size 2MB           # == nginx client_max_body_size 2m
	}
	import headers.caddy      # set-if-absent fallback headers (section 9) — the app owns the canonical set

	handle {
		reverse_proxy app:8000 {
			# Single canonical client IP; a client-supplied XFF is discarded at the edge (#77).
			header_up X-Forwarded-For {client_ip}
			transport http {
				dial_timeout 10s
				read_timeout 120s
			}
		}
	}
}
```

**Rate limiting is not done in Caddy.** Stock Caddy has no `rate_limit` directive, so the nginx `login`/`api` `limit_req` zones both moved **app-side** (`app/ratelimit.py`): the API limiter over `/api/*` (enabled by `ICEBERG_EBS_API_RATE_LIMIT_ENABLED`) and a tighter per-IP token bucket over `POST /login` (enabled by `ICEBERG_EBS_LOGIN_RATE_LIMIT_ENABLED`, #196) — the login one exists because `POST /login` pays the bcrypt cost even for unknown users, so an unthrottled flood is a CPU-DoS and username-spray vector the failure-keyed lockout can't stop. Both default on in the Compose/Helm env; login has its own switch so disabling the API limiter can't silently drop login protection. In Kubernetes the cluster ingress also rate-limits at the true edge (`limit-rps`/`limit-connections`).

`caddy/Caddyfile.k8s` is the in-pod sidecar variant: it listens on plain HTTP :8080 (the ingress terminates TLS), sets `trusted_proxies static private_ranges` so `{client_ip}` resolves to the real external client the ingress recorded, imports the same `headers.caddy`, and proxies to `localhost:8000`. It is embedded as a mirror in the Helm `caddy` ConfigMap.

---

## Build order

1. `pyproject.toml` — add `asyncpg`, then `uv lock`
2. `app/database.py` — Postgres engine + pool settings
3. `static/css/input.css` + `make css` — Tailwind build (#85)
4. `app/templates/base.html` — self-hosted asset links (fonts.css, output.css, vendored Alpine)
5. `Dockerfile`, `.dockerignore`, `.env.example`
6. `docker-compose.yml`
7. `caddy/generate-dev-cert.sh`
8. `caddy/headers.caddy` — the set-if-absent fallback headers (the strict CSP lives in `app/main.py`)
9. `caddy/Caddyfile` and `caddy/Caddyfile.k8s`

---

## Verification

```bash
# Generate dev cert
bash caddy/generate-dev-cert.sh

# Copy and fill in env vars
cp .env.example .env && $EDITOR .env

# Build and start
docker compose up --build

# Check TLS and headers
curl -sko /dev/null -D - https://localhost/ | grep -E "HTTP|Content-Security|Strict-Transport|X-Frame|X-Content"

# HTTP -> HTTPS redirect
curl -sI http://localhost/ | head -3

# Static assets proxied to the app (which serves them via StaticFiles) — must be 200,
# including the image-built Tailwind artifact
curl -sko /dev/null -w "%{http_code}\n" https://localhost/static/css/output.css

# Tests pass against a containerized Postgres (start one with `make db` first)
ICEBERG_EBS_TEST_DATABASE_URL=postgresql+asyncpg://iceberg_ebs:iceberg_ebs@localhost:5432/iceberg_ebs \
  uv run pytest tests/ -v

# The deployed image carries the runtime set only — this must fail
docker compose run --rm --no-deps app python -c "import pytest"
```

For production: replace `caddy/certs/` with a real certificate (or let Caddy obtain one via ACME) and set `ICEBERG_EBS_APP_BASE_URL` to your public domain.

---

# Option B — Kubernetes (Helm chart)

Assumes the cluster already has:
- **nginx-ingress-controller** (`ingress-nginx`)
- **cert-manager** with a `ClusterIssuer` named `letsencrypt-prod`

PostgreSQL is deployed by the chart itself — a single-replica StatefulSet on
`docker.io/library/postgres`, the same image Compose and CI use (#276). It was previously the
Bitnami `postgresql` subchart, dropped when Broadcom's 2025 catalog migration moved every
versioned `bitnami/postgresql` tag to `bitnamilegacy` (so the pinned image stopped pulling) and
left the free catalog publishing `latest` only — a moving tag that could roll a running
deployment onto a new PostgreSQL major on a pod restart. Owning ~100 lines of StatefulSet buys
back an exact, testable version pin; `tests/test_helm_postgres.py` fails if it ever drifts from
the Compose image.

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
version: 0.2.0        # the CHART's version — bump on template changes
appVersion: "0.1.0b1" # the APP version it deploys — kept equal to pyproject.toml
# No dependencies — PostgreSQL is templates/postgres.yaml (#276)
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
  oidcSessionMaxAge: 3600  # SSO session cap in seconds (#221) — bounds IdP-disable propagation
  httpxTimeout: 15.0       # outbound HTTP timeout in seconds
  secureCookies: true
  logJson: false           # emit single-line JSON logs for a collector (#89)
  apiRateLimitEnabled: true   # app-side API rate limit (#188; Caddy has no rate_limit)
  loginRateLimitEnabled: true # app-side POST /login rate limit (#196)

# Caddy edge sidecar (#188): the cluster ingress forwards to it on :8080; it proxies to
# the app on localhost:8000 (the app owns the canonical security headers).
caddy:
  image:
    repository: caddy
    # Kept in lockstep with the Compose Caddy image by tests/test_helm_caddy.py (Dependabot
    # doesn't parse Helm values, so a Compose bump fails that test until this matches; #200).
    tag: "2.11-alpine"
    pullPolicy: IfNotPresent
  resources:
    requests: { cpu: 50m, memory: 64Mi }
    limits:   { cpu: 200m, memory: 128Mi }

postgresql:
  auth:
    username: iceberg_ebs
    password: ""           # override with --set or existingSecret
    database: iceberg_ebs
  image:
    repository: postgres   # docker.io/library/postgres, matching Compose + CI
    tag: "18-alpine"       # lockstep-tested against docker-compose.yml
  persistence:
    size: 10Gi
    storageClass: ""       # empty = cluster default

ingress:
  host: icebergebs.example.com
  className: nginx
  certManagerIssuer: letsencrypt-prod  # set "" to disable cert-manager annotation

networkPolicy:
  # Default-deny ingress + named hops (ingress→caddy:8080, app→postgres:5432; the
  # Caddy sidecar reaches the app on localhost, intra-pod). Egress stays open
  # (stores/webhooks). Needs an enforcing CNI (#103).
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
  ICEBERG_EBS_OIDC_SESSION_MAX_AGE:  {{ .Values.icebergEbs.oidcSessionMaxAge | quote }}
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
            {{- if .Values.postgresql.enabled }}
            # Bundled database. POSTGRES_PASSWORD must be defined BEFORE the
            # $(POSTGRES_PASSWORD) reference below, or the interpolation doesn't resolve.
            - name: POSTGRES_PASSWORD
              valueFrom:
                secretKeyRef:
                  # NOT iceberg-ebs.fullname + "-postgresql" — that named a Secret
                  # nothing creates, so the pod never started (#276).
                  name: {{ include "iceberg-ebs.postgresql.fullname" . }}
                  key: password
            - name: ICEBERG_EBS_DATABASE_URL
              value: "postgresql+asyncpg://{{ .Values.postgresql.auth.username }}:$(POSTGRES_PASSWORD)@{{ include \"iceberg-ebs.postgresql.fullname\" . }}/{{ .Values.postgresql.auth.database }}"
            {{- else }}
            # External database: the DSN carries a password, so it comes from a
            # Secret — never a ConfigMap, never a plaintext value here.
            - name: ICEBERG_EBS_DATABASE_URL
              valueFrom:
                secretKeyRef:
                  name: {{ .Values.externalDatabase.existingSecret | default (include "iceberg-ebs.fullname" .) }}
                  key: {{ .Values.externalDatabase.existingSecretKey | default "database-url" }}
            {{- end }}
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

The topology is **cluster ingress → in-pod Caddy sidecar (:8080) → app (localhost:8000)** (#188). The ingress still terminates TLS (cert-manager), redirects HTTP→HTTPS, sets body-size/read-timeout, and **rate-limits at the true cluster edge** (`limit-rps`/`limit-connections`). What it no longer does is set security headers: the app owns the canonical CSP/HSTS/etc. (`app/main.py:security_headers` — see section 9), the sidecar carries only the set-if-absent fallback, and the old `configuration-snippet` CSP (a second copy that had drifted from the Compose one) is gone.

> **HSTS (operator action, #201):** ingress-nginx's HSTS is a **controller-wide ConfigMap** setting (`hsts`, `hsts-max-age`, `hsts-preload`), **not** a per-Ingress annotation — there is no `nginx.ingress.kubernetes.io/hsts` annotation (an earlier version of this chart set one; it was silently ignored). On a **default** controller (`hsts: true`) the controller emits its own `Strict-Transport-Security` (`max-age=15724800; includeSubDomains`, no preload) which **overrides** the app's canonical one (`max-age=63072000; includeSubDomains; preload`). To make the app's the single copy, set `hsts: "false"` in the **ingress-nginx-controller ConfigMap** (cluster-wide, e.g. via the controller's own Helm values `controller.config.hsts: "false"`). Not a security regression either way — both values enforce HTTPS — but the app's stronger, preload-enabled policy only reaches clients once the controller stops setting its own.

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
    # Security headers are set by the app (app/main.py:security_headers), not here — no
    # configuration-snippet CSP, and NO per-ingress HSTS annotation (it doesn't exist; #201).
    # Disable the controller's own HSTS at its ConfigMap (`hsts: "false"`) so the app's is
    # the single copy — see the HSTS note above.
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
                  number: 8080   # the pod's Caddy sidecar (it proxies to the app on 8000)
```

`ingressClassName` and the `nginx.ingress.kubernetes.io/*` annotations refer to the **cluster nginx-ingress controller** (unchanged — it sits in front of Caddy). All response security headers come from the app; verify with `curl -sI https://your-host/ | grep -i -E "content-security|permissions|strict-transport"`.

---

## Installing

```bash
# No `helm repo add` / `helm dependency update` — the chart has no subcharts (#276).

# Install (generate strong values; never commit these)
helm upgrade --install icebergebs helm/iceberg-ebs \
  --namespace icebergebs --create-namespace \
  --set image.tag="v0.1.0-beta.1" \
  --set icebergEbs.adminPassword="$(openssl rand -hex 16)" \
  --set icebergEbs.secretKey="$(openssl rand -hex 32)" \
  --set postgresql.auth.password="$(openssl rand -hex 32)" \
  --set icebergEbs.appBaseUrl="https://icebergebs.example.com" \
  --set ingress.host="icebergebs.example.com"

# Watch rollout. The Deployment is named <release>-<chart>, so a release called
# "icebergebs" produces "icebergebs-iceberg-ebs" — not "icebergebs" (#276).
kubectl rollout status deployment/icebergebs-iceberg-ebs -n icebergebs
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

**NetworkPolicies (#103):** the chart ships default-deny ingress plus named hops (ingress-controller → caddy sidecar:8080, app → postgres:5432; the sidecar reaches the app on localhost intra-pod), gated behind `networkPolicy.enabled` (default `true`). They **require a CNI that enforces NetworkPolicy** (Calico, Cilium) — on a CNI that doesn't, they are a harmless no-op that gives no protection. Set `networkPolicy.ingressController.namespaceSelector` to match your ingress controller's namespace. **Egress is intentionally left open** (the app must reach the extension stores, webhook destinations, and TI feeds) — don't add an egress policy. A future backup CronJob (#86) will need its own rule to reach Postgres.

---

## Comparison: Docker Compose vs Kubernetes

| Concern | Docker Compose | Kubernetes (Helm) |
|---------|---------------|-------------------|
| Complexity | Low | Medium |
| TLS | Manual cert or self-signed | cert-manager + Let's Encrypt (automatic) |
| Scaling | Single host | Multi-node |
| Secret management | `.env` file | K8s Secret / ExternalSecret |
| PostgreSQL | Docker volume | In-chart StatefulSet + PVC |
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

### Major-version upgrade (Postgres 16 → 18)

A Postgres **major** bump changes the on-disk data-directory format: pointing an 18 image at a
`postgres_data` volume initialised by 16 fails to start (`database files are incompatible with
server`). The stack pins the same major across the **server**, the **`backup`** service (so
`pg_dump`'s version always matches the server's), and the **CI test** container — always bump them
together, never one in isolation. Note the 18 bump also **moves the volume mount** from
`/var/lib/postgresql/data` to `/var/lib/postgresql` (18+ stores data in a major-version subdirectory
and errors on the old mount) — this repo's `docker-compose.yml` already does that. A fresh install
(no existing volume) needs none of the below — 18 initialises cleanly. To migrate an existing
Compose deployment:

Run this as one block. Every **destructive** step (dropping the old volume, restoring) lives
inside the `if` and executes **only** when both the dump and its `pg_restore --list` integrity
check succeed — a failed or interrupted `pg_dump` leaves the `.tmp` behind and drops into the
`else`, so the data volume is never touched:

```bash
# Dump the OLD (16) database to a temp file and verify the archive is intact before trusting it.
if docker compose exec -T postgres sh -c 'pg_dump -Fc -U "$POSTGRES_USER" "$POSTGRES_DB"' > ./backups/pre-pg18.pgc.tmp \
   && docker compose exec -T postgres sh -c 'pg_restore --list' < ./backups/pre-pg18.pgc.tmp > /dev/null
then
  # The whole sequence is &&-chained, so each step must succeed before the next runs: a
  # failed `mv` never reaches the volume drop, and a failed `pg_restore` never reaches the
  # `up -d` that would start the app against a partial database.
  mv ./backups/pre-pg18.pgc.tmp ./backups/pre-pg18.pgc \
    && docker compose down \
    && docker volume rm iceberg-ebs_postgres_data \
    && docker compose up -d --wait --wait-timeout 120 postgres \
    && docker compose exec -T postgres sh -c 'pg_restore -U "$POSTGRES_USER" -d "$POSTGRES_DB" --clean --if-exists' < ./backups/pre-pg18.pgc \
    && docker compose up -d
else
  rm -f ./backups/pre-pg18.pgc.tmp
  echo "Dump/verify failed — data volume untouched; fix the error and re-run." >&2
fi
```

**Helm:** the chart runs the *same* image as Compose (`postgresql.image` in `values.yaml`), held in
lockstep by `tests/test_helm_postgres.py::test_helm_postgres_image_matches_compose_exactly` — so a
major bump is one PR touching both pins, and the two deployment paths cannot land on different
majors. The upgrade itself is the same dump/restore as above: the official image does **not**
run `pg_upgrade` for you, and pointing a new major at an old PGDATA fails to start. Scale the app
to 0, `pg_dump` from the old pod, bump both pins, delete the PVC, then restore into the new pod.

#### Migrating from the Bitnami subchart

**Applies only to releases installed before #276.** Fresh installs need none of this.

The chart used to deploy the Bitnami `postgresql` subchart; it now runs its own StatefulSet. The
two are **not** interchangeable in place, for two independent reasons:

- **Immutable fields.** The StatefulSet's `serviceName` and `selector` cannot be changed, so a
  plain `helm upgrade` is rejected by the API server.
- **Incompatible on-disk layout — the dangerous one.** Bitnami stores its cluster at
  `/bitnami/postgresql/data`; this chart uses `PGDATA=/var/lib/postgresql/data/pgdata`. Both
  declare a volumeClaimTemplate named `data`, so a *recreated* StatefulSet binds the **same PVC**,
  finds no `pgdata` directory, and `initdb` creates a brand-new **empty PostgreSQL 18 cluster**
  next to your untouched PostgreSQL 16 data. The app starts, Alembic builds a fresh schema, and
  every probe is green — while the application is empty. It looks exactly like a successful
  upgrade.

The chart therefore **refuses to render** against a release whose StatefulSet is still Bitnami's,
naming this section. Do not work around it; do this instead.

```bash
set -euo pipefail          # a failed pg_dump must NOT look like a successful one
NS=icebergebs
REL=icebergebs
# Two credentials, and the difference matters below: `password` is the application
# role, `postgres-password` is the superuser. The Bitnami chart creates the custom
# role WITHOUT the CREATEDB attribute, so the scratch database in step 3 has to be
# created by the superuser (verified: `createdb -U iceberg_ebs` fails with
# "permission denied to create database").
PGPW=$(kubectl -n "$NS" get secret "$REL"-postgresql -o jsonpath='{.data.password}' | base64 -d)
PGSUPERPW=$(kubectl -n "$NS" get secret "$REL"-postgresql -o jsonpath='{.data.postgres-password}' | base64 -d)

# 1. Stop writes. (The Deployment is <release>-<chart>.)
kubectl -n "$NS" scale deploy/"$REL"-iceberg-ebs --replicas=0
kubectl -n "$NS" rollout status deploy/"$REL"-iceberg-ebs --timeout=120s

# 2. Dump from the OLD (Bitnami) pod. `set -o pipefail` above is what makes a
#    mid-stream pg_dump failure fail this command instead of leaving a truncated
#    file that later steps treat as good.
kubectl -n "$NS" exec "$REL"-postgresql-0 -- \
  env PGPASSWORD="$PGPW" pg_dump -U iceberg_ebs -d iceberg_ebs -Fc \
  > icebergebs-premigration.pgc

# 3. VERIFY BY RESTORING, not by reading the header. `pg_restore --list` only
#    parses the table of contents, so an archive truncated after its TOC passes it
#    while missing every data block. Measured: a 65,751-byte dump truncated to 30%
#    still passed BOTH `pg_restore --list` and `test -s`, yet restored 0 of 5000
#    rows per table. Restore into a scratch database and compare counts instead.
kubectl -n "$NS" exec "$REL"-postgresql-0 -- \
  env PGPASSWORD="$PGSUPERPW" createdb -U postgres -O iceberg_ebs migration_verify
kubectl -n "$NS" exec -i "$REL"-postgresql-0 -- \
  env PGPASSWORD="$PGPW" pg_restore -U iceberg_ebs -d migration_verify \
  < icebergebs-premigration.pgc

# Compare a real row count between the live database and the restored copy.
for DB in iceberg_ebs migration_verify; do
  kubectl -n "$NS" exec "$REL"-postgresql-0 -- \
    env PGPASSWORD="$PGPW" psql -U iceberg_ebs -d "$DB" -tAc \
    'select (select count(*) from "user"), (select count(*) from extension);'
done
# The two lines MUST match. If they do not, STOP — nothing has been deleted yet.

kubectl -n "$NS" exec "$REL"-postgresql-0 -- \
  env PGPASSWORD="$PGSUPERPW" dropdb -U postgres migration_verify

# 4. Retain the underlying volume BEFORE deleting the PVC. Kubernetes cannot
#    rename a PVC, and the new StatefulSet's volumeClaimTemplate wants the same
#    name — so the old claim has to go. Flipping the PV to Retain means deleting
#    the claim releases the name without destroying the data: the PV survives,
#    and can be re-bound manually if the restore turns out wrong.
PV=$(kubectl -n "$NS" get pvc data-"$REL"-postgresql-0 -o jsonpath='{.spec.volumeName}')
kubectl patch pv "$PV" -p '{"spec":{"persistentVolumeReclaimPolicy":"Retain"}}'
kubectl get pv "$PV" -o jsonpath='{.spec.persistentVolumeReclaimPolicy}'   # must print: Retain

# 5. Delete the Bitnami database resources.
kubectl -n "$NS" delete statefulset "$REL"-postgresql
kubectl -n "$NS" delete svc "$REL"-postgresql "$REL"-postgresql-hl --ignore-not-found
kubectl -n "$NS" delete pvc data-"$REL"-postgresql-0

# 6. Upgrade. The guard now passes and the chart's own StatefulSet is created.
helm upgrade "$REL" helm/iceberg-ebs -n "$NS" --set image.tag=... --set postgresql.auth.password=...
kubectl -n "$NS" rollout status statefulset/"$REL"-postgresql --timeout=300s

# 7. Restore, then bring the app back.
kubectl -n "$NS" exec -i "$REL"-postgresql-0 -- \
  env PGPASSWORD='<postgresql.auth.password>' \
  pg_restore -U iceberg_ebs -d iceberg_ebs --clean --if-exists \
  < icebergebs-premigration.pgc
kubectl -n "$NS" scale deploy/"$REL"-iceberg-ebs --replicas=1
```

**Do not clean up until the new deployment is validated.** Keep both the dump file and the retained
PV until you have confirmed the restored application looks right — extension count, users, alert
destinations, and a successful scheduler run. Only then `kubectl delete pv "$PV"`.

Rolling back means `helm rollback`, then re-creating a PVC bound to the retained PV (clear its
`claimRef` first, so it can bind again) — which is the reason step 4 exists.

If you would rather not migrate data at all, `postgresql.enabled=false` with `externalDatabase.*`
pointed at a managed Postgres is a clean alternative: restore the dump there instead, and the
in-cluster database stops being your problem.

### Kubernetes (Helm)

The chart does not template a backup CronJob; choose one of:

- **Your own `CronJob`** — a scheduled `pg_dump -Fc` into a PVC or object storage, mirroring the
  Compose `backup` service. The chart no longer bundles one: the Bitnami subchart's backup values
  went away with the subchart (#276). Give the Job the app pod's labels or its own NetworkPolicy
  rule, per the note below.
- **VolumeSnapshots** — if your CSI driver supports them, snapshot the Postgres PVC on a schedule
  (e.g. via an external-snapshotter policy). Fast, but crash-consistent, not a logical dump.
- **External managed Postgres** — run Postgres outside the cluster (RDS/Cloud SQL/etc.) and use the
  provider's automated backups + PITR. Recommended for anything beyond a homelab. Set
  `postgresql.enabled=false` — since #276 there is no subchart at all, so this simply skips the
  chart's own `templates/postgres.yaml` — and supply the DSN one of two ways:

  ```bash
  # (a) chart-managed Secret — simplest
  --set postgresql.enabled=false \
  --set externalDatabase.url="postgresql+asyncpg://user:pass@db.example.com:5432/iceberg_ebs"

  # (b) bring your own Secret — keeps the credential out of your values file and
  #     out of `helm get values`
  --set postgresql.enabled=false \
  --set externalDatabase.existingSecret=icebergebs-db \
  --set externalDatabase.existingSecretKey=dsn
  ```

  The DSN carries a password, so the chart only ever reads it from a Secret — never a ConfigMap and
  never a plaintext `value:` in the pod spec. Setting neither fails the render with a message naming
  the missing value, rather than deploying a pod that cannot reach a database.

Restore mirrors the Compose flow: scale the app to 0 (`kubectl scale deploy/icebergebs-iceberg-ebs --replicas=0`),
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
  for a log collector. Caddy's structured (JSON) access log — enabled by the `log` directive — carries
  the request User-Agent/Referer and `duration` (Cookie/Authorization are redacted).
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
