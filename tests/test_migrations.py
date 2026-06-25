"""Tests for Alembic-driven schema management in app.database (D1 / #11).

The hand-rolled `_migrate_sqlite`/`_migrate_postgres` functions were replaced by
Alembic. `_run_migrations` either upgrades a fresh/empty database to head or, for
a database created the old way (tables present, no alembic_version), stamps it to
head without recreating anything.
"""
import sqlite3

import pytest
from alembic.autogenerate import compare_metadata
from alembic.runtime.migration import MigrationContext
from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import create_async_engine
from sqlmodel import SQLModel

import app.models  # noqa: F401 — register tables on SQLModel.metadata
from app.database import _run_migrations


async def _migrate(db_path) -> None:
    engine = create_async_engine(f"sqlite+aiosqlite:///{db_path}")
    async with engine.connect() as conn:
        await conn.run_sync(_run_migrations)
        await conn.commit()
    await engine.dispose()


def _tables(db_path) -> set[str]:
    c = sqlite3.connect(db_path)
    try:
        return {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    finally:
        c.close()


def _version(db_path):
    c = sqlite3.connect(db_path)
    try:
        return c.execute("SELECT version_num FROM alembic_version").fetchone()
    finally:
        c.close()


async def test_fresh_db_upgrades_to_head(tmp_path):
    db = tmp_path / "fresh.db"
    await _migrate(db)
    tables = _tables(db)
    assert {"user", "extension", "alertlog", "apikey", "alembic_version"} <= tables
    assert _version(db) is not None  # stamped at head


async def test_fresh_db_has_all_current_columns(tmp_path):
    """Baseline must include the columns added by the hand-rolled migrations."""
    db = tmp_path / "cols.db"
    await _migrate(db)
    c = sqlite3.connect(db)
    try:
        user_cols = {r[1] for r in c.execute('PRAGMA table_info("user")')}
        alertlog_cols = {r[1] for r in c.execute("PRAGMA table_info(alertlog)")}
        apikey_cols = {r[1] for r in c.execute("PRAGMA table_info(apikey)")}
    finally:
        c.close()
    assert "password_changed_at" in user_cols          # M1
    assert {"user_id", "destination_id"} <= alertlog_cols
    assert {"key_prefix", "key_suffix"} <= apikey_cols


async def test_migration_is_idempotent(tmp_path):
    db = tmp_path / "idem.db"
    await _migrate(db)
    first = _version(db)
    await _migrate(db)  # second run must not error or change the revision
    assert _version(db) == first


async def test_existing_pre_alembic_db_is_stamped_not_recreated(tmp_path):
    """A database built the old way (create_all, no alembic_version) is adopted."""
    db = tmp_path / "old.db"
    engine = create_async_engine(f"sqlite+aiosqlite:///{db}")
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    await engine.dispose()

    # Seed a row so we can prove the tables were not dropped/recreated.
    c = sqlite3.connect(db)
    c.execute(
        'INSERT INTO "user"(username, password_hash, is_admin, created_at) '
        "VALUES (?, ?, ?, ?)", ("bob", "h", 0, "2024-01-01"),
    )
    c.commit()
    c.close()

    await _migrate(db)

    assert _version(db) is not None
    c = sqlite3.connect(db)
    try:
        assert c.execute('SELECT username FROM "user"').fetchone() == ("bob",)
    finally:
        c.close()


def test_head_matches_models(tmp_path):
    """Autogenerate finds no diff between the migrations head and the models.

    Guards against the baseline drifting out of sync with app/models.py — the
    exact failure mode (two sources of truth) that motivated adopting Alembic.
    """
    db = tmp_path / "cmp.db"
    engine = create_engine(f"sqlite:///{db}")
    with engine.connect() as conn:
        _run_migrations(conn)
        conn.commit()
        ctx = MigrationContext.configure(
            conn, opts={"compare_type": True, "render_as_batch": True}
        )
        diffs = compare_metadata(ctx, SQLModel.metadata)
    engine.dispose()
    assert diffs == [], f"Models drifted from migrations head: {diffs}"
