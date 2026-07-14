# IcebergEBS

[![CI](https://github.com/IcebergAI/IcebergEBS/actions/workflows/ci.yml/badge.svg)](https://github.com/IcebergAI/IcebergEBS/actions/workflows/ci.yml)
[![build](https://github.com/IcebergAI/IcebergEBS/actions/workflows/build.yml/badge.svg)](https://github.com/IcebergAI/IcebergEBS/actions/workflows/build.yml)

Extension-watch tool for Chrome, Edge, and VS Code. Tracks browser and editor extensions, downloads the actual packages, inspects the code, and produces a 0–100 risk score across six signals: permissions, popularity, publisher identity, staleness, code behaviour (eval/obfuscation/remote fetches), and external domains.

Multi-user. Each user maintains an independent list of monitored extensions. A background scheduler re-fetches watchlisted extensions on a configurable interval and fires webhook alerts when something changes.

## Requirements

- Python 3.14+
- [uv](https://docs.astral.sh/uv/) — dependencies are declared in `pyproject.toml` and pinned in the committed `uv.lock`. `uv sync` (or `make sync`) installs the locked set into `.venv/`.

## Quick start (local dev, containers)

IcebergEBS runs on PostgreSQL — dev included. The dev stack runs the app with live
reload against a containerized Postgres (no nginx):

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build postgres app
# or: make dev
```

Open `http://localhost:8000` and log in (default dev credentials `admin` / `admin`).
The admin account is seeded automatically on first startup.

To run a host-side uvicorn instead, start just Postgres and point the app at it:

```bash
make db   # docker compose ... up -d postgres  (published on localhost:5432)
ICEBERG_EBS_DATABASE_URL=postgresql+asyncpg://iceberg_ebs:iceberg_ebs@localhost:5432/iceberg_ebs \
  ICEBERG_EBS_ADMIN_USERNAME=admin ICEBERG_EBS_ADMIN_PASSWORD=admin \
  ICEBERG_EBS_SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))") \
  ICEBERG_EBS_SECURE_COOKIES=false uv run uvicorn app.main:app --reload
```

### Tests

The suite runs against a real Postgres (the dev stack above provides one):

```bash
make test
# or: ICEBERG_EBS_TEST_DATABASE_URL=postgresql+asyncpg://iceberg_ebs:iceberg_ebs@localhost:5432/iceberg_ebs uv run pytest tests/ -v
```

## Production deployment (Docker + PostgreSQL + nginx)

See **[DEPLOYMENT.md](DEPLOYMENT.md)** for full instructions. The short version:

```bash
bash nginx/generate-dev-cert.sh   # self-signed cert for local testing
cp .env.example .env
$EDITOR .env                      # fill in passwords and secret key
docker compose up --build
```

This starts three containers: PostgreSQL, the IcebergEBS app, and nginx as a TLS-terminating reverse proxy. For production, replace `nginx/certs/` with a real certificate (Let's Encrypt via Certbot or similar) and set `ICEBERG_EBS_APP_BASE_URL` to your public domain.

> **Database:** IcebergEBS runs on **PostgreSQL only** — in development, test, and production. The Compose and Helm stacks provision it for you. See [DEPLOYMENT.md → Database choice](DEPLOYMENT.md#database-choice--use-postgresql-for-any-soc-scale-deployment).

A Kubernetes/Helm chart is also provided under `helm/iceberg-ebs/` — see DEPLOYMENT.md for details.

## Configuration

All settings use the `ICEBERG_EBS_` prefix and can be set via `.env` or environment variables.

| Variable | Default | Description |
|---|---|---|
| `ICEBERG_EBS_ADMIN_USERNAME` | — | **required** — seeded admin username |
| `ICEBERG_EBS_ADMIN_PASSWORD` | — | **required** — seeded admin password |
| `ICEBERG_EBS_SECRET_KEY` | — | **required** — signs session cookies |
| `ICEBERG_EBS_DATABASE_URL` | `postgresql+asyncpg://iceberg_ebs:iceberg_ebs@localhost:5432/iceberg_ebs` | SQLAlchemy async Postgres URL |
| `ICEBERG_EBS_SESSION_MAX_AGE` | `86400` | Session lifetime in seconds |
| `ICEBERG_EBS_FETCH_INTERVAL_MINUTES` | `60` | Background watchlist refresh cadence |
| `ICEBERG_EBS_RETENTION_DAYS` | `0` | Prune `FetchLog`/`InstallCountHistory`/`AlertLog` rows older than N days (`0` = disabled) |
| `ICEBERG_EBS_APP_BASE_URL` | — | Public URL of your instance; included as `iceberg_ebs_url` in webhook payloads |
| `ICEBERG_EBS_HTTPX_TIMEOUT` | `15.0` | Outbound HTTP timeout in seconds |
| `ICEBERG_EBS_SECURE_COOKIES` | `true` | Set `Secure` flag on session cookies — set to `false` for plain HTTP dev |

## Supported stores

| Store | ID format | Example |
|---|---|---|
| Chrome Web Store | 32-char alphanumeric | `cjpalhdlnbpafiamejdnhcphjbkeiagm` |
| VS Code Marketplace | `publisher.extensionName` | `ms-python.python` |
| Microsoft Edge Add-ons | GUID-like string | `jmjflgjpcpepeafmmgdpfkogkghcpiha` |

Paste a full store URL or a bare ID on the Add extension page — the store is auto-detected from URLs.

## Alerts & webhooks

Configure destinations (webhook URLs) and alert rules under **Account → Alerts & webhooks**. Rules fire on four event types: `risk_level_change`, `publisher_change`, `permission_change`, `new_version`. Each rule can be scoped to all extensions or a specific one and toggled independently.

Example payload:

```json
{
  "text": "IcebergEBS: uBlock Origin risk level changed medium → high",
  "event": "risk_level_change",
  "extension": {
    "id": 42,
    "name": "uBlock Origin",
    "store": "chrome",
    "store_url": "https://chromewebstore.google.com/detail/...",
    "iceberg_ebs_url": "https://your-instance/extensions/42"
  },
  "change": { "old": "medium", "new": "high" },
  "risk_score": 55
}
```

`iceberg_ebs_url` is only included when `ICEBERG_EBS_APP_BASE_URL` is set.

## Tests & CI

```bash
uv run pytest tests/ -v
```

CI ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) runs four blocking gates on every PR and push to `main`: **pytest**, **Ruff** (`ruff check` + `ruff format --check`), **mypy** (type-checks the pure logic/contract modules; ORM-query modules are excluded — see `pyproject.toml`), and **security** (**Bandit** + **pip-audit**). Every job installs with `uv sync --locked`, which fails if `uv.lock` has drifted from `pyproject.toml` — so a dependency change without a lock refresh cannot merge. Run the same checks locally with:

```bash
uv sync
uv run ruff check app tests && uv run ruff format --check app tests alembic
uv run mypy app
uv run bandit -c pyproject.toml -r app
# pip-audit runs against the exact runtime set the production image installs:
# the lockfile exported without the dev group.
uv export --frozen --no-dev --no-hashes --format requirements-txt -o /tmp/requirements-prod.txt
uv run pip-audit -r /tmp/requirements-prod.txt
```

### Dependencies

`pyproject.toml` is the only dependency manifest: runtime packages in `[project.dependencies]`, test and static-analysis tooling in the `[dependency-groups] dev` group. After changing either, run **`uv lock`** and commit the updated `uv.lock`. The production image builds its venv with `uv sync --frozen --no-dev`, so the `dev` group physically cannot reach it — anything a runtime import needs must be a real runtime dependency.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup, the CI gates a PR must pass, and the conventions for dependency and schema changes. Participation is governed by our [Code of Conduct](CODE_OF_CONDUCT.md).

## Security

Please **do not** report vulnerabilities in a public issue — see [SECURITY.md](SECURITY.md) for the private reporting path and for the **scope** of what counts as a vulnerability (IcebergEBS documents its trust boundaries explicitly, including the things that are shared by design).

## License

[Apache License 2.0](LICENSE) — Copyright 2026 IcebergAI.
