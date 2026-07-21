---
title: Deployment
icon: material/rocket-launch
---

<p class="eyebrow">Operations</p>

# Deployment

IcebergEBS ships two supported deployment paths: **Docker Compose** for a single
host, and a **Helm chart** for Kubernetes. Both front the app with **Caddy**, which
owns the TLS termination and the security headers; the difference is only where TLS
is terminated and what sits in front of Caddy.

This page is the operator overview. The long-form runbook — every environment
variable, upgrade procedure, restore drill, and failure mode — lives in
[`DEPLOYMENT.md`](https://github.com/IcebergAI/IcebergEBS/blob/main/DEPLOYMENT.md) in
the repository.

!!! danger "Single worker, single replica — mandatory"
    IcebergEBS must run as **one application process**. The scheduler (APScheduler)
    and the rate limiters are **per-process**, so a second worker or replica would
    independently refresh every watchlisted extension — duplicating fetches, writing
    duplicate alert-log rows, and multiplying the effective login-throttle limit by
    the process count.

    This is enforced in both stacks: the container's uvicorn command carries no
    `--workers`, the chart pins `replicaCount: 1`, and the Deployment uses
    `strategy: Recreate` rather than the default rolling update — a `maxSurge` would
    briefly run two pods and open a two-scheduler window. A PodDisruptionBudget with
    `maxUnavailable: 0` stops a voluntary eviction taking the singleton to zero.

    Scale throughput with Postgres, not with extra app workers.

## Docker Compose

Four services: **postgres** (`postgres:18-alpine`), the **app**, **caddy**, and a
**backup** sidecar that runs `pg_dump` on a loop.

```bash
bash caddy/generate-dev-cert.sh      # self-signed cert into caddy/certs/
cp .env.example .env && $EDITOR .env # fill in the credentials — see below
docker compose up --build
```

Caddy publishes `:80` (redirect to HTTPS, plus a local health endpoint) and `:443`,
and reverse-proxies **everything** to the app — including `/static`, because the
built Tailwind stylesheet exists only inside the app image. It sets
`X-Forwarded-For` to a single canonical `{client_ip}`, discarding any
client-supplied value at the edge; the app-side rate limiters depend on that.

Stock Caddy has no rate-limiting directive, so throttling is done in the
application rather than at the edge.

### The credential contract

Every credential lives in `.env` and is referenced **only** from
`docker-compose.yml`, always as `${VAR:?message}` — never as a bare `${VAR}`.

!!! warning "Why the `:?` matters"
    Compose resolves a bare `${VAR}` to an **empty string** behind a warning that
    scrolls past the `up` output. The stack then starts and fails much later, deep
    in the app, as an `asyncpg.InvalidPasswordError` that reads exactly like a code
    bug. Worse, only `ICEBERG_EBS_SECRET_KEY` has an app-side validator — an empty
    `ICEBERG_EBS_ADMIN_PASSWORD` would otherwise silently seed a passwordless admin.

    `docker-compose.dev.yml` defines **no** credentials, and Compose interpolates
    each file before merging, so the base file's guards fire through any override —
    dev and prod cannot disagree about where a secret comes from. A test
    (`tests/test_compose_secrets.py`) fails the build if a bare `${VAR}` appears.

    Diagnose interpolation with `docker compose config`, which prints the resolved
    values and every "not set" warning.

Guarded variables: `POSTGRES_PASSWORD`, `ICEBERG_EBS_ADMIN_USERNAME`,
`ICEBERG_EBS_ADMIN_PASSWORD`, `ICEBERG_EBS_SECRET_KEY`.

### Development stack

```bash
make dev    # docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build postgres app
make db     # just Postgres, published on localhost:5432
make test   # pytest against the dev Postgres
```

The dev overlay sets `ICEBERG_EBS_SECURE_COOKIES=false`, enables `--reload`, and
does not start Caddy. It still needs a populated `.env` for the guarded credentials.

## Kubernetes (Helm)

The chart is at
[`helm/iceberg-ebs/`](https://github.com/IcebergAI/IcebergEBS/tree/main/helm/iceberg-ebs).

**Topology:** cluster ingress-nginx (TLS via cert-manager, edge rate limiting) →
**in-pod Caddy sidecar** on `:8080` → app on `localhost:8000`. The app owns the
canonical security headers; the sidecar carries a minimal set-if-absent fallback,
mirrored into a ConfigMap from the same `caddy/` files the Compose stack mounts —
a test fails the build if the two drift.

```bash
helm upgrade --install icebergebs helm/iceberg-ebs \
  --namespace icebergebs --create-namespace \
  --set image.repository="ghcr.io/icebergai/icebergebs" \
  --set image.tag="0.1.0-beta.1" \
  --set icebergEbs.adminPassword="$(openssl rand -hex 16)" \
  --set icebergEbs.secretKey="$(openssl rand -hex 32)" \
  --set postgresql.auth.password="$(openssl rand -hex 32)" \
  --set icebergEbs.appBaseUrl="https://icebergebs.example.com" \
  --set ingress.host="icebergebs.example.com"
```

For GitOps, use a SealedSecret or ExternalSecret rather than `--set`.

!!! note "`image.tag` has no default, on purpose"
    The chart **fails to render** without an explicit tag rather than defaulting to
    a mutable `:latest`. With `IfNotPresent`, a moving tag re-renders an identical
    pod spec and quietly reuses whatever image the node already cached — so a
    "deploy" ships stale code. Pin an immutable release tag.

    `image.repository` also defaults to a placeholder and must be overridden.

**Database.** `postgresql.enabled: true` (the default) deploys an in-chart
StatefulSet on the official `postgres` image, held in lockstep with the Compose pin
by a test. Set it to `false` and supply `externalDatabase.url`, or
`externalDatabase.existingSecret`, to use managed Postgres — recommended for
anything beyond a homelab, since the bundled instance is a single replica with no
failover and no in-cluster backup job.

**Hardening defaults.** `automountServiceAccountToken: false`, non-root with
`seccompProfile: RuntimeDefault`, `readOnlyRootFilesystem: true` and
`capabilities.drop: [ALL]` on both containers, and a default-deny NetworkPolicy with
named hops (ingress controller → sidecar, app → Postgres). Egress is deliberately
open — the app must reach the extension stores and your webhook destinations.

!!! info "HSTS is a controller-wide setting"
    There is deliberately **no HSTS ingress annotation** — `nginx.ingress.kubernetes.io/hsts`
    does not exist and is silently ignored. ingress-nginx sets HSTS from its own
    ConfigMap (`hsts`, `hsts-max-age`, `hsts-preload`), and on a default controller
    that value **overrides** the stronger one Caddy sets. To make Caddy's the single
    copy, set `hsts: "false"` in the controller ConfigMap.

## Configuration

Settings are read from the environment with the `ICEBERG_EBS_` prefix.

!!! warning "Both stacks forward an explicit allowlist"
    A setting that exists in the application config but is **not** listed in the
    Compose `app.environment` block *and* the Helm ConfigMap is silently ignored in
    a container deployment — `.env` is excluded from the image build context. If a
    variable appears to have no effect, check that it is forwarded before assuming
    the value is wrong.

**Required.** `ICEBERG_EBS_SECRET_KEY` (≥32 characters, validated at startup),
`ICEBERG_EBS_ADMIN_USERNAME` and `ICEBERG_EBS_ADMIN_PASSWORD` (the seeded admin, used
on first boot only), the database credentials, and — on Helm — `image.tag`.

**Commonly tuned:**

| Group | Variables |
|---|---|
| **Session** | `SECURE_COOKIES` (`true`), `SESSION_MAX_AGE` (`86400`), `APP_BASE_URL`, `TRUSTED_ORIGINS` |
| **Scheduler** | `FETCH_INTERVAL_MINUTES` (`60`) |
| **Retention** | `RETENTION_DAYS` (`0` = off; 90 is a sensible start for a real watchlist) |
| **Rate limiting** | `API_RATE_LIMIT_ENABLED`, `LOGIN_RATE_LIMIT_ENABLED` (both **on** in the shipped production stacks), plus per-minute and burst values |
| **SSO** | `AUTH_MODE` (`both`/`local`/`oidc`), `OIDC_REDIRECT_BASE_URL`, and per-provider `OIDC_<PROVIDER>_*` |
| **Outbound proxy** | `PROXY_MODE` (`system`/`none`/`explicit`), `PROXY_URL`, `PROXY_NO_PROXY`, `PROXY_USERNAME`, `PROXY_PASSWORD` |
| **Observability** | `LOG_JSON` (`false`), `HTTPX_TIMEOUT` (`15.0`) |

OIDC client secrets and outbound-proxy credentials are **environment-only** — they
are never written to the database, returned from the API, rendered in the UI, or
logged. See [Security](security.md).

`TRUSTED_ORIGINS` is only needed behind a proxy that rewrites `Host`; a wrong value
rejects every browser POST, including login.

## Database and migrations

**PostgreSQL only** — development, test, and production. SQLite is not supported.

**Migrations run automatically at startup.** The app runs Alembic to head against
its own connection and no-ops when the schema already matches, so a normal upgrade
is just a redeploy — there is no init container or Helm hook to sequence. The
startup path explicitly handles the awkward states (an unstamped database whose
schema already matches head, a stamped database with an empty schema, and so on)
rather than guessing.

**Backups.** The Compose stack runs a `backup` service that writes compressed
`pg_dump` archives on an interval (`BACKUP_INTERVAL_SECONDS`, default daily) and
prunes them after `BACKUP_RETENTION_DAYS` (default 7). Recovery point is therefore
one interval. **Copy the dumps off-host** — a same-host archive does not survive the
disk failure it exists for. There is no in-cluster equivalent in the chart; use your
platform's Postgres backup mechanism.

!!! warning "Two traps that look like bugs"
    - **`POSTGRES_PASSWORD` is only read when the data volume is first created.**
      Editing `.env` against an existing volume silently keeps the old password.
      Rotate the role with `ALTER USER` instead; deleting the volume destroys the
      database.
    - **A Postgres major upgrade is not in-place.** The official image does not run
      `pg_upgrade`, so pointing a new major at the old data directory simply fails
      to start. Dump, verify the archive, remove the volume, then restore.

Take a fresh dump before any upgrade that carries a migration.

## Which image to deploy

| | Built by | Tags | Deployable |
|---|---|---|---|
| **Release** | `release.yml`, on a `v*` tag | Immutable SemVer | ✅ |
| **Dev** | `build.yml`, on every push to `main` | `:edge`, `:<sha>` | ❌ |

Release images are the only verifiable artefact: the workflow checks the tag matches
the project version, refuses to publish a commit that is not an ancestor of `main`,
emits an SBOM and SLSA provenance, attests it, and signs the image keylessly with
cosign. Verify before rollout:

```bash
IMAGE=ghcr.io/icebergai/icebergebs
gh attestation verify "oci://${IMAGE}:0.1.0-beta.1" --repo IcebergAI/IcebergEBS
cosign verify "${IMAGE}:0.1.0-beta.1" \
  --certificate-identity-regexp "^https://github.com/IcebergAI/IcebergEBS/\.github/workflows/release\.yml@refs/tags/v" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

The full release procedure is in
[`docs/RELEASING.md`](https://github.com/IcebergAI/IcebergEBS/blob/main/docs/RELEASING.md).

## Verify a deployment

```bash
# Security headers present, TLS serving
curl -sko /dev/null -D - https://localhost/ | grep -E "HTTP|Content-Security|Strict-Transport|X-Frame|X-Content"

# Plain HTTP redirects
curl -sI http://localhost/ | head -3

# Static assets served through the proxy
curl -sko /dev/null -w "%{http_code}\n" https://localhost/static/css/output.css

# The runtime image carries no dev dependencies — this MUST fail
docker compose run --rm --no-deps app python -c "import pytest"
```

[:octicons-arrow-right-24: Security posture](security.md)
