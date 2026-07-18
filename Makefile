# Developer convenience targets. Dev runs against containerized Postgres
# (see docker-compose.dev.yml); SQLite is no longer supported.

COMPOSE := docker compose -f docker-compose.yml -f docker-compose.dev.yml

# Pull the Postgres credentials out of .env so host-side pytest talks to the dev
# container with the SAME creds Compose gave it. Previously this line hardcoded
# iceberg_ebs:iceberg_ebs, which silently broke the moment the password was rotated.
# `-include` (leading dash) so a missing .env is not a hard error — the defaults below
# still let `make` parse; the compose guards are what enforce a real password.
-include .env
POSTGRES_USER ?= iceberg_ebs
POSTGRES_DB ?= iceberg_ebs
TEST_DATABASE_URL ?= postgresql+asyncpg://$(POSTGRES_USER):$(POSTGRES_PASSWORD)@localhost:5432/$(POSTGRES_DB)
PYTHON ?= uv run python
# Tailwind standalone-CLI pin (#85) — keep in lockstep with the Dockerfile
# tailwind-builder stage and the ci.yml lint job.
TAILWINDCSS_VERSION ?= v4.3.1

.PHONY: db dev sync test test-up down logs css

# Install the locked dependency set (runtime + the `dev` group) into .venv/.
sync:
	uv sync

# Start just Postgres (published on localhost:5432) for host-side tests / uvicorn.
db:
	$(COMPOSE) up -d postgres

# Build static/css/output.css from static/css/input.css (gitignored artifact, #85).
# Rerun after editing input.css, app.css or any template/JS that adds utility classes.
css:
	TAILWINDCSS_VERSION=$(TAILWINDCSS_VERSION) uv run tailwindcss -i static/css/input.css -o static/css/output.css --minify

# Full dev stack with live reload (Postgres + app, no edge proxy) on http://localhost:8000.
# Depends on `css`: docker-compose.dev.yml bind-mounts the source tree over /app, so
# the container serves the HOST's output.css, not the image-built one.
dev: css
	$(COMPOSE) up --build postgres app

# Run the test suite against the dev Postgres. Brings Postgres up first.
test: db
	ICEBERG_EBS_TEST_DATABASE_URL=$(TEST_DATABASE_URL) $(PYTHON) -m pytest tests/ -v

down:
	$(COMPOSE) down

logs:
	$(COMPOSE) logs -f
