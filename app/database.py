import logging
from collections.abc import AsyncGenerator

from sqlmodel import SQLModel
from sqlmodel.ext.asyncio.session import AsyncSession
from sqlalchemy.ext.asyncio import create_async_engine, AsyncEngine
from sqlalchemy import text

from app.config import settings

logger = logging.getLogger(__name__)

_is_sqlite = settings.database_url.startswith("sqlite")
_pool_kwargs = {} if _is_sqlite else {
    "pool_size": 5,
    "max_overflow": 10,
    "pool_pre_ping": True,
    "pool_timeout": 30,
    "pool_recycle": 1800,  # Recycle connections every 30 min to avoid server-side idle timeouts
}

# SQLite allows a single writer at a time. Set a busy timeout so a connection
# waits (up to 30s) for the write lock instead of immediately raising
# "database is locked" when another connection (e.g. the scheduler vs. an API
# request) is mid-write. Defense-in-depth alongside firing alerts only after the
# caller commits (see app/services.py).
_connect_args = {"timeout": 30} if _is_sqlite else {}

engine: AsyncEngine = create_async_engine(
    settings.database_url, echo=False, connect_args=_connect_args, **_pool_kwargs
)


async def init_db() -> None:
    async with engine.begin() as conn:
        if _is_sqlite:
            await conn.execute(text("PRAGMA journal_mode=WAL"))
        await conn.run_sync(SQLModel.metadata.create_all)
        if _is_sqlite:
            # SQLite has no transactional-DDL poisoning concern and the alertlog
            # rebuild below must be atomic, so it shares init_db's transaction.
            await _migrate_sqlite(conn)
    if not _is_sqlite:
        # Postgres: run each statement in its OWN transaction (below) — must be
        # outside the create_all transaction above.
        await _migrate_postgres()


async def _migrate_sqlite(conn) -> None:
    """Incremental schema changes that create_all cannot apply to existing tables."""
    # apikey: add display prefix/suffix columns (only if table already exists)
    result = await conn.execute(text("PRAGMA table_info(apikey)"))
    existing_apikey_cols = {row[1] for row in result.fetchall()}
    if existing_apikey_cols and "key_prefix" not in existing_apikey_cols:
        await conn.execute(text("ALTER TABLE apikey ADD COLUMN key_prefix TEXT NOT NULL DEFAULT ''"))
        await conn.execute(text("ALTER TABLE apikey ADD COLUMN key_suffix TEXT NOT NULL DEFAULT ''"))
    # user: add password-change marker for session/API-key revocation (M1 / #6)
    result = await conn.execute(text('PRAGMA table_info("user")'))
    existing_user_cols = {row[1] for row in result.fetchall()}
    if existing_user_cols and "password_changed_at" not in existing_user_cols:
        await conn.execute(text('ALTER TABLE "user" ADD COLUMN password_changed_at TIMESTAMP'))
    result = await conn.execute(text("PRAGMA table_info(alertlog)"))
    existing_cols = {row[1] for row in result.fetchall()}
    if "user_id" not in existing_cols:
        # Recreate alertlog with nullable rule_id and new snapshot columns.
        await conn.execute(text("""
            CREATE TABLE alertlog_new (
                id       INTEGER PRIMARY KEY NOT NULL,
                rule_id  INTEGER REFERENCES alertrule(id),
                destination_id INTEGER REFERENCES alertdestination(id),
                extension_id INTEGER NOT NULL REFERENCES extension(id),
                user_id  INTEGER REFERENCES "user"(id),
                event_type TEXT NOT NULL,
                detail   TEXT NOT NULL,
                sent_at  TIMESTAMP NOT NULL,
                success  INTEGER NOT NULL,
                error    TEXT
            )
        """))
        await conn.execute(text("""
            INSERT INTO alertlog_new
                (id, rule_id, extension_id, event_type, detail, sent_at, success, error)
            SELECT id, rule_id, extension_id, event_type, detail, sent_at, success, error
            FROM alertlog
        """))
        await conn.execute(text("DROP TABLE alertlog"))
        await conn.execute(text("ALTER TABLE alertlog_new RENAME TO alertlog"))
    for stmt in [
        "CREATE INDEX IF NOT EXISTS ix_alertlog_rule_id ON alertlog(rule_id)",
        "CREATE INDEX IF NOT EXISTS ix_alertlog_extension_id ON alertlog(extension_id)",
        "CREATE INDEX IF NOT EXISTS ix_alertlog_user_id ON alertlog(user_id)",
        "CREATE INDEX IF NOT EXISTS ix_alertrule_destination_id ON alertrule(destination_id)",
    ]:
        await conn.execute(text(stmt))


async def _migrate_postgres() -> None:
    """Incremental Postgres schema changes, each in its OWN transaction.

    Critically, every statement gets its own ``engine.begin()`` block. On Postgres
    a single failing statement aborts its whole transaction, after which every
    later statement on that same connection fails with "current transaction is
    aborted". If all statements shared one transaction, an early failure would
    silently skip the ADD COLUMN statements below — leaving alertlog without the
    user_id/destination_id columns, so every AlertLog insert would then fail
    (and be swallowed) while webhooks still fire. Per-statement isolation keeps
    one idempotent no-op from taking the rest of the migration down with it.
    """
    for stmt in [
        "ALTER TABLE alertlog ALTER COLUMN rule_id DROP NOT NULL",
        'ALTER TABLE alertlog ADD COLUMN IF NOT EXISTS destination_id INTEGER REFERENCES alertdestination(id)',
        'ALTER TABLE alertlog ADD COLUMN IF NOT EXISTS user_id INTEGER REFERENCES "user"(id)',
        "CREATE INDEX IF NOT EXISTS ix_alertlog_rule_id ON alertlog(rule_id)",
        "CREATE INDEX IF NOT EXISTS ix_alertlog_extension_id ON alertlog(extension_id)",
        "CREATE INDEX IF NOT EXISTS ix_alertlog_user_id ON alertlog(user_id)",
        "CREATE INDEX IF NOT EXISTS ix_alertrule_destination_id ON alertrule(destination_id)",
        "ALTER TABLE apikey ADD COLUMN IF NOT EXISTS key_prefix TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE apikey ADD COLUMN IF NOT EXISTS key_suffix TEXT NOT NULL DEFAULT ''",
        'ALTER TABLE "user" ADD COLUMN IF NOT EXISTS password_changed_at TIMESTAMP',
    ]:
        try:
            async with engine.begin() as conn:
                await conn.execute(text(stmt))
        except Exception as exc:
            # Most of these statements are idempotent (IF NOT EXISTS / DROP NOT
            # NULL on an already-nullable column) and won't raise. Log anything
            # that does so a genuine migration failure is visible instead of
            # being silently swallowed.
            logger.warning("Migration step failed (may already be applied): %s — %s", stmt, exc)


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSession(engine) as session:
        yield session
