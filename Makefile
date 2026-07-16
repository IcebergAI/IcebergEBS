# Developer convenience targets. Dev runs against containerized Postgres
# (see docker-compose.dev.yml); SQLite is no longer supported.

COMPOSE := docker compose -f docker-compose.yml -f docker-compose.dev.yml
TEST_DATABASE_URL ?= postgresql+asyncpg://iceberg_ebs:iceberg_ebs@localhost:5432/iceberg_ebs
PYTHON ?= uv run python

.PHONY: db dev sync test test-up down logs

# Install the locked dependency set (runtime + the `dev` group) into .venv/.
sync:
	uv sync

# Start just Postgres (published on localhost:5432) for host-side tests / uvicorn.
db:
	$(COMPOSE) up -d postgres

# Full dev stack with live reload (Postgres + app, no edge proxy) on http://localhost:8000.
dev:
	$(COMPOSE) up --build postgres app

# Run the test suite against the dev Postgres. Brings Postgres up first.
test: db
	ICEBERG_EBS_TEST_DATABASE_URL=$(TEST_DATABASE_URL) $(PYTHON) -m pytest tests/ -v

down:
	$(COMPOSE) down

logs:
	$(COMPOSE) logs -f
