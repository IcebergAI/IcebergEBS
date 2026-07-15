# Contributing to IcebergEBS

Thanks for your interest in contributing! IcebergEBS tracks browser and editor extensions
(Chrome, Edge, VS Code), inspects the packages, and produces a risk score. This guide
covers the essentials; the deeper architecture notes live in [CLAUDE.md](CLAUDE.md).

## Code of Conduct

This project adheres to a [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you
are expected to uphold it. Please report unacceptable behaviour as described there.

## Reporting bugs & requesting features

- **Bugs** and **feature requests** — open an
  [issue](https://github.com/IcebergAI/IcebergEBS/issues).
- **Security vulnerabilities** — do **not** open a public issue. Follow
  [SECURITY.md](SECURITY.md) and use GitHub's private vulnerability reporting.

## Development setup

IcebergEBS targets **Python 3.14+**, FastAPI (fully async), and **PostgreSQL** via
`asyncpg` — SQLite is not supported, in dev or anywhere else. Dependencies are managed
with [uv](https://docs.astral.sh/uv/) against the committed `uv.lock`.

```bash
uv sync          # create .venv from the lockfile (runtime + dev tooling)
make db          # start the dev Postgres (docker compose), published on :5432
make dev         # full dev stack with live reload on http://localhost:8000
```

Log in with the seeded dev credentials (`admin` / `admin`). Full deployment
instructions are in [DEPLOYMENT.md](DEPLOYMENT.md).

**The test suite needs a real Postgres** — there is no SQLite fallback and no
in-memory mode. `make test` brings one up via docker compose and runs against it:

```bash
make test
# or: ICEBERG_EBS_TEST_DATABASE_URL=postgresql+asyncpg://iceberg_ebs:iceberg_ebs@localhost:5432/iceberg_ebs uv run pytest tests/ -v
```

## Before you open a pull request

Run the same core gates CI does, and make sure they pass:

```bash
uv run ruff check app tests e2e
uv run ruff format --check app tests alembic e2e
uvx vulture@2.16                                 # dead-code gate (part of CI's lint job)
uv run mypy app
uv run bandit -c pyproject.toml -r app
uv run pytest                                    # needs Postgres (see above)

# pip-audit runs against the locked runtime set — what the production image installs
uv export --frozen --no-dev --no-emit-project --no-hashes --format requirements-txt -o /tmp/requirements-prod.txt
uv run pip-audit -r /tmp/requirements-prod.txt
```

(CI additionally runs `uv lock --check`, a workflow linter (`lint-workflows`), and a
Playwright browser smoke (`ui`) that boots the full Compose stack — the commands above
cover everything you can quickly run locally.)

Then, depending on what you changed:

- **New behaviour or a bug fix** — **add tests**. Regression tests are expected for
  anything that fixes a bug. Fixtures live in `tests/conftest.py`; `asyncio_mode` is
  `auto`, so async tests need no decoration.
- **Dependencies** — edit `pyproject.toml` (`[project.dependencies]` for runtime, the
  `[dependency-groups] dev` group for tooling), then run **`uv lock`** and commit the
  updated `uv.lock`. CI runs `uv lock --check` and will fail on a stale lock. The
  production image installs with `--no-dev`, so anything a runtime import needs must
  be a real runtime dependency. Routine version bumps you can leave alone —
  **Dependabot** opens weekly grouped PRs for Python packages, GitHub Actions, and
  container images.
- **Schema** — edit the models in `app/models.py`, then generate a migration with
  `alembic revision --autogenerate -m "describe change"` and commit the file under
  `alembic/versions/`.
- **Docs** — keep [CLAUDE.md](CLAUDE.md) in step when you change structure or
  architecture, and update the in-app help page (`app/templates/help.html`) when you
  change user-facing behaviour.
- **Anything an operator would notice** — add an entry to [CHANGELOG.md](CHANGELOG.md)
  under the current unreleased section (Added / Changed / Fixed / Security). Releases and
  the PEP 440 ↔ SemVer tag mapping are documented in [docs/RELEASING.md](docs/RELEASING.md).

## Pull request expectations

- Branch off `main` and keep each PR to a single concern.
- Write a clear description of **what** changed and **why**, with test evidence.
- Reference the issue you're addressing with a closing keyword — one **`Closes #123`**
  per issue (prose like "closes #1–#3" does not auto-close anything).
- CI (test, lint, types, security, lint-workflows, ui) must be green before review.

By contributing, you agree that your contributions are licensed under the project's
[Apache License 2.0](LICENSE).
