"""Alembic environment for Marvin.

Reads the database URL from ``app.config.settings`` so dev SQLite and prod
Postgres share one config. Supports three callers:

* the ``alembic`` CLI (offline ``--sql`` or online), building its own sync engine;
* application startup, which hands in an existing (sync) connection via
  ``config.attributes["connection"]`` — see ``app.database.init_db``.
"""

from logging.config import fileConfig

from alembic import context
from sqlalchemy import create_engine, pool
from sqlmodel import SQLModel

import app.models  # noqa: F401 — registers every table on SQLModel.metadata
from app.config import settings

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = SQLModel.metadata


def _sync_url() -> str:
    """Translate the app's async URL to a sync driver for CLI engine creation."""
    return settings.database_url.replace("+aiosqlite", "").replace("+asyncpg", "+psycopg2")


def _configure(**kwargs) -> None:
    context.configure(
        target_metadata=target_metadata,
        render_as_batch=True,  # batch mode so future SQLite ALTERs work
        compare_type=True,
        **kwargs,
    )


def run_migrations_offline() -> None:
    _configure(url=_sync_url(), literal_binds=True, dialect_opts={"paramstyle": "named"})
    with context.begin_transaction():
        context.run_migrations()


def _run(connection) -> None:
    _configure(connection=connection)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    # Application startup passes a live connection; reuse it.
    connection = config.attributes.get("connection")
    if connection is not None:
        _run(connection)
        return
    # Standalone CLI: build a throwaway sync engine.
    engine = create_engine(_sync_url(), poolclass=pool.NullPool)
    with engine.connect() as conn:
        _run(conn)
    engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
