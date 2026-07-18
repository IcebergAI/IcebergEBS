---
description: Configuration and startup contract — where credentials live, the fail-fast Compose guards, the single dev/prod config path, and the two traps (volume-init password, .env vs os.environ) that make a misconfiguration look like a code bug
paths:
  - "docker-compose*.yml"
  - "Dockerfile"
  - "Makefile"
  - ".env*"
  - "helm/**"
---

# Configuration & startup

Moved from the repo CLAUDE.md (budget): the credentials contract. The one-line summary stays
there; everything below auto-loads when editing the compose stack, Dockerfile, Makefile,
`.env*`, or the Helm chart.

The app is only ever executed as a container (Docker Compose or Helm). Host-side Python is for
the test suite and Alembic only — that split is what makes the `.env` wiring below subtle.

## One credential source, fail-fast

All credentials live in `.env` and are referenced **only** from `docker-compose.yml`, always as
`${VAR:?message}` — never a bare `${VAR}`.

- A bare `${VAR}` interpolates to the **empty string** behind a warning that scrolls past in
  `up` output. The stack then starts and fails later *inside the app* as an
  `asyncpg.InvalidPasswordError`, which reads like a code or networking fault. Only
  `SECRET_KEY` has an app-side validator (`config.py` enforces >= 32 chars), so an empty
  `ICEBERG_EBS_ADMIN_PASSWORD` would otherwise seed a passwordless admin silently.
- `docker-compose.dev.yml` defines **no** credentials. It used to hardcode
  `POSTGRES_PASSWORD: iceberg_ebs` plus a full `ICEBERG_EBS_DATABASE_URL`, so `make dev`
  succeeded on a machine where a plain `docker compose up` failed with the same `.env` — the
  dev path silently masked the misconfiguration. It now overrides only the genuine dev
  difference (`ICEBERG_EBS_SECURE_COOKIES: "false"`) plus ports/reload/bind-mount.
  Consequence: `make dev` requires a populated `.env`.
- Compose interpolates each file **before** merging, so the base file's guards fire regardless
  of what an override sets — the dev overlay cannot mask a missing variable.
- `tests/test_compose_secrets.py` enforces both rules (guarded references; no dev-side
  literals). The Helm equivalent is `| required` in `templates/secret.yaml`.
- Diagnose interpolation with `docker compose config` — it prints every resolved value and each
  "variable is not set" warning, which is the fastest reproduction of a credential problem.

## Trap 1 — the Postgres password is only read at volume creation

`POSTGRES_PASSWORD` is consumed by the image entrypoint when it initialises the data directory.
On an **existing** volume the value is ignored, so editing `.env` alone does not change the
password: Postgres keeps serving the old one and you get `InvalidPasswordError` while looking
at a `.env` that appears correct. Rotate the role instead, then update `.env` to match:

```bash
printf "ALTER USER iceberg_ebs WITH PASSWORD '<new>';\n" \
  | docker exec -i iceberg-ebs-postgres-1 psql -U iceberg_ebs -d iceberg_ebs -v ON_ERROR_STOP=1
```

Piping via stdin keeps the password out of the container's `ps`. Deleting the volume also works
but **destroys all data** — dev throwaway databases only. Full procedure lives in
`DEPLOYMENT.md → Rotating the Postgres password`.

## Trap 2 — host-side tests need `ICEBERG_EBS_DATABASE_URL`, not `..._TEST_DATABASE_URL`

`tests/conftest.py` reads `os.environ["ICEBERG_EBS_TEST_DATABASE_URL"]` and otherwise falls back
to `settings.database_url`. **`.env` reaches `Settings` but never `os.environ`** (pydantic-settings
does not export), so putting `ICEBERG_EBS_TEST_DATABASE_URL` in `.env` is inert for a bare
`uv run pytest` — it is `ICEBERG_EBS_DATABASE_URL` that actually takes effect, pointed at the dev
Postgres on `localhost:5432`. `make test` works either way because the Makefile passes the URL as
an env prefix, deriving it from the `.env` `POSTGRES_*` values via `-include .env` — so `make test`
follows a rotation automatically.

Containers are unaffected by that host-side key: the app service sets its own
`ICEBERG_EBS_DATABASE_URL` via `environment:` (pointing at the `postgres` service, not localhost),
and `.env` is excluded from the image by `.dockerignore`. A setting not forwarded in the Compose
`app.environment` block **or** the Helm ConfigMap is silently ignored in-container (#87).
