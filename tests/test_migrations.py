"""Tests for the incremental database migration logic in app.database._migrate."""
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from app.database import _migrate


_OLD_SCHEMA = """
    CREATE TABLE IF NOT EXISTS "user" (
        id INTEGER PRIMARY KEY,
        username TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        email TEXT,
        is_admin INTEGER NOT NULL DEFAULT 0,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS extension (
        id INTEGER PRIMARY KEY,
        user_id INTEGER REFERENCES "user"(id),
        store TEXT NOT NULL,
        extension_id TEXT NOT NULL,
        name TEXT NOT NULL,
        publisher TEXT NOT NULL,
        version TEXT NOT NULL,
        store_url TEXT NOT NULL,
        permissions TEXT NOT NULL DEFAULT '[]',
        added_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        watchlist INTEGER NOT NULL DEFAULT 1,
        risk_score INTEGER
    );
    CREATE TABLE IF NOT EXISTS alertdestination (
        id INTEGER PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES "user"(id),
        label TEXT NOT NULL,
        target TEXT NOT NULL,
        enabled INTEGER NOT NULL DEFAULT 1,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS alertrule (
        id INTEGER PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES "user"(id),
        destination_id INTEGER NOT NULL REFERENCES alertdestination(id),
        extension_id INTEGER REFERENCES extension(id),
        event_type TEXT NOT NULL,
        enabled INTEGER NOT NULL DEFAULT 1,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS alertlog (
        id INTEGER PRIMARY KEY NOT NULL,
        rule_id INTEGER NOT NULL REFERENCES alertrule(id),
        extension_id INTEGER NOT NULL REFERENCES extension(id),
        event_type TEXT NOT NULL,
        detail TEXT NOT NULL,
        sent_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        success INTEGER NOT NULL,
        error TEXT
    );
"""


async def _column_names(conn, table: str) -> set[str]:
    result = await conn.execute(text(f"PRAGMA table_info({table})"))
    return {row[1] for row in result.fetchall()}


async def _index_names(conn) -> set[str]:
    result = await conn.execute(text("SELECT name FROM sqlite_master WHERE type='index'"))
    return {row[0] for row in result.fetchall()}


@pytest.mark.asyncio
async def test_migrate_adds_new_columns_to_old_alertlog():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)

    async with engine.begin() as conn:
        for stmt in _OLD_SCHEMA.strip().split(";"):
            stmt = stmt.strip()
            if stmt:
                await conn.execute(text(stmt))

        cols_before = await _column_names(conn, "alertlog")
        assert "user_id" not in cols_before
        assert "destination_id" not in cols_before

        await _migrate(conn)

        cols_after = await _column_names(conn, "alertlog")
        assert "user_id" in cols_after
        assert "destination_id" in cols_after

    await engine.dispose()


@pytest.mark.asyncio
async def test_migrate_preserves_existing_rows():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)

    async with engine.begin() as conn:
        for stmt in _OLD_SCHEMA.strip().split(";"):
            stmt = stmt.strip()
            if stmt:
                await conn.execute(text(stmt))

        await conn.execute(text("""
            INSERT INTO alertlog (id, rule_id, extension_id, event_type, detail, sent_at, success)
            VALUES (1, 42, 99, 'risk_level_change', '{"old":"low","new":"high"}', '2024-01-01', 1),
                   (2, 42, 99, 'new_version', '{"old":"1.0","new":"2.0"}', '2024-01-02', 0)
        """))

        await _migrate(conn)

        result = await conn.execute(text(
            "SELECT id, rule_id, extension_id, event_type, success FROM alertlog ORDER BY id"
        ))
        rows = result.fetchall()

    assert len(rows) == 2
    assert rows[0] == (1, 42, 99, "risk_level_change", 1)
    assert rows[1] == (2, 42, 99, "new_version", 0)

    await engine.dispose()


@pytest.mark.asyncio
async def test_migrate_creates_expected_indexes():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)

    async with engine.begin() as conn:
        for stmt in _OLD_SCHEMA.strip().split(";"):
            stmt = stmt.strip()
            if stmt:
                await conn.execute(text(stmt))

        await _migrate(conn)

        indexes = await _index_names(conn)

    assert "ix_alertlog_rule_id" in indexes
    assert "ix_alertlog_extension_id" in indexes
    assert "ix_alertlog_user_id" in indexes
    assert "ix_alertrule_destination_id" in indexes

    await engine.dispose()


@pytest.mark.asyncio
async def test_migrate_is_idempotent_on_current_schema():
    """Running _migrate on an already-migrated schema should not raise."""
    from sqlmodel import SQLModel
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)

    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
        # Should not raise even though columns already exist and indexes are present
        await _migrate(conn)
        await _migrate(conn)

        cols = await _column_names(conn, "alertlog")
        assert "user_id" in cols
        assert "destination_id" in cols

    await engine.dispose()
