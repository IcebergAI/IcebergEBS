"""Tests for Alembic-driven schema management in app.database (D1 / #11).

The hand-rolled `_migrate_sqlite`/`_migrate_postgres` functions were replaced by
Alembic. `_run_migrations` either upgrades a fresh/empty database to head or, for
a database created the old way (tables present, no alembic_version), stamps it at
the baseline revision its schema matches and upgrades to head, without recreating
anything (#143).

Each test runs against a freshly CREATEd Postgres database on the configured test
server (dropped afterwards), so migrations always start from a clean target.
"""

import os
import uuid
from datetime import datetime, timezone

import pytest
from alembic.autogenerate import compare_metadata
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, inspect, make_url, text
from sqlalchemy.ext.asyncio import create_async_engine
from sqlmodel import SQLModel

import app.models  # noqa: F401 — register tables on SQLModel.metadata
from alembic import command
from app.config import settings
from app.database import _PRE_ALEMBIC_BASELINE, _alembic_config, _run_migrations

TEST_DATABASE_URL = os.environ.get("ICEBERG_EBS_TEST_DATABASE_URL", settings.database_url)


def _async_url(db_name: str) -> str:
    """asyncpg URL pointing at ``db_name`` on the test server."""
    return make_url(TEST_DATABASE_URL).set(database=db_name).render_as_string(hide_password=False)


def _sync_url(db_name: str) -> str:
    """psycopg2 (sync) URL pointing at ``db_name`` on the test server."""
    url = make_url(TEST_DATABASE_URL).set(database=db_name, drivername="postgresql+psycopg2")
    return url.render_as_string(hide_password=False)


def _admin_engine():
    """Sync engine on the maintenance ``postgres`` DB for CREATE/DROP DATABASE.

    AUTOCOMMIT because CREATE/DROP DATABASE cannot run inside a transaction.
    """
    url = make_url(TEST_DATABASE_URL).set(database="postgres", drivername="postgresql+psycopg2")
    return create_engine(url.render_as_string(hide_password=False), isolation_level="AUTOCOMMIT")


@pytest.fixture
def temp_db():
    """Create a uniquely-named throwaway Postgres database; drop it afterwards."""
    name = f"iceberg_ebs_test_{uuid.uuid4().hex}"
    admin = _admin_engine()
    with admin.connect() as conn:
        conn.execute(text(f'CREATE DATABASE "{name}"'))
    admin.dispose()
    try:
        yield name
    finally:
        admin = _admin_engine()
        with admin.connect() as conn:
            conn.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        admin.dispose()


async def _migrate(db_name: str) -> None:
    engine = create_async_engine(_async_url(db_name))
    async with engine.connect() as conn:
        await conn.run_sync(_run_migrations)
        await conn.commit()
    await engine.dispose()


def _tables(db_name: str) -> set[str]:
    engine = create_engine(_sync_url(db_name))
    try:
        with engine.connect() as conn:
            return set(inspect(conn).get_table_names())
    finally:
        engine.dispose()


def _columns(db_name: str, table: str) -> set[str]:
    engine = create_engine(_sync_url(db_name))
    try:
        with engine.connect() as conn:
            return {col["name"] for col in inspect(conn).get_columns(table)}
    finally:
        engine.dispose()


def _version(db_name: str):
    engine = create_engine(_sync_url(db_name))
    try:
        with engine.connect() as conn:
            return conn.execute(text("SELECT version_num FROM alembic_version")).fetchone()
    finally:
        engine.dispose()


async def test_fresh_db_upgrades_to_head(temp_db):
    await _migrate(temp_db)
    tables = _tables(temp_db)
    assert {"user", "extension", "alertlog", "apikey", "alembic_version"} <= tables
    assert _version(temp_db) is not None  # stamped at head


async def test_fresh_db_has_all_current_columns(temp_db):
    """Baseline must include the columns added by the hand-rolled migrations."""
    await _migrate(temp_db)
    assert "password_changed_at" in _columns(temp_db, "user")  # M1
    assert {"user_id", "destination_id"} <= _columns(temp_db, "alertlog")
    assert {"key_prefix", "key_suffix"} <= _columns(temp_db, "apikey")
    assert "install_footprint" in _columns(temp_db, "extension")  # #29
    assert "installobservation" in _tables(temp_db)  # #29
    assert {"extension_id", "asset_id", "first_seen", "last_seen"} <= _columns(temp_db, "installobservation")


async def test_migration_is_idempotent(temp_db):
    await _migrate(temp_db)
    first = _version(temp_db)
    await _migrate(temp_db)  # second run must not error or change the revision
    assert _version(temp_db) == first


async def test_existing_pre_alembic_db_is_adopted_and_upgraded(temp_db):
    """A database built the old way is stamped at the BASELINE and upgraded to head.

    A genuinely pre-Alembic database has the baseline-era schema — stamping it at
    head would silently skip every post-baseline migration with no recovery path
    (#143). The fixture must therefore build the real baseline schema (not
    ``create_all`` from current models, which already contains the migrations'
    end state and would mask exactly that bug).
    """
    # Build the baseline-era schema, then remove alembic_version to simulate a
    # database created by the retired create_all/_migrate_* path.
    sync = create_engine(_sync_url(temp_db))
    with sync.connect() as conn:
        cfg = _alembic_config()
        cfg.attributes["connection"] = conn
        command.upgrade(cfg, _PRE_ALEMBIC_BASELINE)
        conn.commit()
    with sync.begin() as conn:
        conn.execute(text("DROP TABLE alembic_version"))
        # Seed a row so we can prove the tables were not dropped/recreated.
        conn.execute(
            text('INSERT INTO "user"(username, password_hash, is_admin, created_at) VALUES (:u, :p, :a, :t)'),
            {"u": "bob", "p": "h", "a": False, "t": datetime(2024, 1, 1, tzinfo=timezone.utc)},
        )
    sync.dispose()

    await _migrate(temp_db)

    # Adopted at head — not just stamped: the post-baseline schema must exist.
    head = ScriptDirectory.from_config(_alembic_config()).get_current_head()
    assert _version(temp_db) == (head,)
    assert "installobservation" in _tables(temp_db)  # inventory migration
    assert "store_outage" in _columns(temp_db, "fetchlog")  # store-outage migration
    assert "pending_alert_events" in _columns(temp_db, "extension")  # pending-alerts migration
    sync = create_engine(_sync_url(temp_db))
    try:
        with sync.connect() as conn:
            # Data survived adoption (nothing was dropped/recreated) …
            assert conn.execute(text('SELECT username FROM "user"')).fetchone() == ("bob",)
            # … and the adopted schema fully matches the models.
            ctx = MigrationContext.configure(conn, opts={"compare_type": True})
            assert compare_metadata(ctx, SQLModel.metadata) == []
    finally:
        sync.dispose()


def test_head_matches_models(temp_db):
    """Autogenerate finds no diff between the migrations head and the models.

    Guards against the baseline drifting out of sync with app/models.py — the
    exact failure mode (two sources of truth) that motivated adopting Alembic.
    """
    engine = create_engine(_sync_url(temp_db))
    with engine.connect() as conn:
        _run_migrations(conn)
        conn.commit()
        ctx = MigrationContext.configure(conn, opts={"compare_type": True})
        diffs = compare_metadata(ctx, SQLModel.metadata)
    engine.dispose()
    assert diffs == [], f"Models drifted from migrations head: {diffs}"
