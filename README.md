# Marvin

[![CI](https://github.com/TheSlopBucket/marvin/actions/workflows/ci.yml/badge.svg)](https://github.com/TheSlopBucket/marvin/actions/workflows/ci.yml)
[![build](https://github.com/TheSlopBucket/marvin/actions/workflows/build.yml/badge.svg)](https://github.com/TheSlopBucket/marvin/actions/workflows/build.yml)

Extension-watch tool for Chrome, Edge, and VS Code. Tracks browser and editor extensions, downloads the actual packages, inspects the code, and produces a 0–100 risk score across six signals: permissions, popularity, publisher identity, staleness, code behaviour (eval/obfuscation/remote fetches), and external domains.

Multi-user. Each user maintains an independent list of monitored extensions. A background scheduler re-fetches watchlisted extensions on a configurable interval and fires webhook alerts when something changes.

## Requirements

- Python 3.14+

## Quick start (local dev, SQLite)

```bash
python -m venv venv
venv/bin/pip install -r requirements.txt
```

Create a `.env` file (or export environment variables):

```env
MARVIN_ADMIN_USERNAME=admin
MARVIN_ADMIN_PASSWORD=changeme
MARVIN_SECRET_KEY=<run: python -c "import secrets; print(secrets.token_hex(32))">
```

```bash
venv/bin/uvicorn app.main:app --reload
```

The admin account is seeded automatically on first startup using the credentials in your environment. Open `http://localhost:8000` and log in.

## Production deployment (Docker + PostgreSQL + nginx)

See **[DEPLOYMENT.md](DEPLOYMENT.md)** for full instructions. The short version:

```bash
bash nginx/generate-dev-cert.sh   # self-signed cert for local testing
cp .env.example .env
$EDITOR .env                      # fill in passwords and secret key
docker compose up --build
```

This starts three containers: PostgreSQL, the Marvin app, and nginx as a TLS-terminating reverse proxy. For production, replace `nginx/certs/` with a real certificate (Let's Encrypt via Certbot or similar) and set `MARVIN_APP_BASE_URL` to your public domain.

> **Database:** SQLite is for local development only. **Run PostgreSQL for production and any SOC-scale deployment** — SQLite's single database-level write lock becomes a ceiling once the scheduler, interactive writes, and bulk ingestion contend for it. The Compose and Helm stacks default to Postgres. See [DEPLOYMENT.md → Database choice](DEPLOYMENT.md#database-choice--use-postgresql-for-any-soc-scale-deployment).

A Kubernetes/Helm chart is also provided under `helm/marvin/` — see DEPLOYMENT.md for details.

## Configuration

All settings use the `MARVIN_` prefix and can be set via `.env` or environment variables.

| Variable | Default | Description |
|---|---|---|
| `MARVIN_ADMIN_USERNAME` | — | **required** — seeded admin username |
| `MARVIN_ADMIN_PASSWORD` | — | **required** — seeded admin password |
| `MARVIN_SECRET_KEY` | — | **required** — signs session cookies |
| `MARVIN_DATABASE_URL` | `sqlite+aiosqlite:///./marvin.db` | SQLAlchemy async database URL |
| `MARVIN_SESSION_MAX_AGE` | `86400` | Session lifetime in seconds |
| `MARVIN_FETCH_INTERVAL_MINUTES` | `60` | Background watchlist refresh cadence |
| `MARVIN_RETENTION_DAYS` | `0` | Prune `FetchLog`/`InstallCountHistory`/`AlertLog` rows older than N days (`0` = disabled) |
| `MARVIN_APP_BASE_URL` | — | Public URL of your instance; included as `marvin_url` in webhook payloads |
| `MARVIN_HTTPX_TIMEOUT` | `15.0` | Outbound HTTP timeout in seconds |
| `MARVIN_SECURE_COOKIES` | `true` | Set `Secure` flag on session cookies — set to `false` for plain HTTP dev |

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
  "text": "Marvin: uBlock Origin risk level changed medium → high",
  "event": "risk_level_change",
  "extension": {
    "id": 42,
    "name": "uBlock Origin",
    "store": "chrome",
    "store_url": "https://chromewebstore.google.com/detail/...",
    "marvin_url": "https://your-instance/extensions/42"
  },
  "change": { "old": "medium", "new": "high" },
  "risk_score": 55
}
```

`marvin_url` is only included when `MARVIN_APP_BASE_URL` is set.

## Tests & CI

```bash
venv/bin/python -m pytest tests/ -v
```

CI ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) runs four blocking gates on every PR and push to `main`: **pytest**, **Ruff** (`ruff check` + `ruff format --check`), **mypy** (type-checks the pure logic/contract modules; ORM-query modules are excluded — see `pyproject.toml`), and **security** (**Bandit** + **pip-audit**). Install the tooling and run the same checks locally with:

```bash
venv/bin/pip install -r requirements-dev.txt
venv/bin/ruff check app tests && venv/bin/ruff format --check app tests alembic
venv/bin/mypy app
venv/bin/bandit -c pyproject.toml -r app && venv/bin/pip-audit -r requirements.txt
```
