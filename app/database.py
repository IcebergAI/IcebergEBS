from collections.abc import AsyncGenerator

from sqlmodel import SQLModel
from sqlmodel.ext.asyncio.session import AsyncSession
from sqlalchemy.ext.asyncio import create_async_engine, AsyncEngine
from sqlalchemy import text

from app.config import settings

_is_sqlite = settings.database_url.startswith("sqlite")
_pool_kwargs = {} if _is_sqlite else {
    "pool_size": 5,
    "max_overflow": 10,
    "pool_pre_ping": True,
    "pool_timeout": 30,
    "pool_recycle": 1800,  # Recycle connections every 30 min to avoid server-side idle timeouts
}

engine: AsyncEngine = create_async_engine(settings.database_url, echo=False, **_pool_kwargs)


async def init_db() -> None:
    async with engine.begin() as conn:
        if _is_sqlite:
            await conn.execute(text("PRAGMA journal_mode=WAL"))
        await conn.run_sync(SQLModel.metadata.create_all)
        await _migrate(conn)


async def _migrate(conn) -> None:
    """Incremental schema changes that create_all cannot apply to existing tables."""
    if _is_sqlite:
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
    else:
        for stmt in [
            "ALTER TABLE alertlog ALTER COLUMN rule_id DROP NOT NULL",
            'ALTER TABLE alertlog ADD COLUMN IF NOT EXISTS destination_id INTEGER REFERENCES alertdestination(id)',
            'ALTER TABLE alertlog ADD COLUMN IF NOT EXISTS user_id INTEGER REFERENCES "user"(id)',
            "CREATE INDEX IF NOT EXISTS ix_alertlog_rule_id ON alertlog(rule_id)",
            "CREATE INDEX IF NOT EXISTS ix_alertlog_extension_id ON alertlog(extension_id)",
            "CREATE INDEX IF NOT EXISTS ix_alertlog_user_id ON alertlog(user_id)",
            "CREATE INDEX IF NOT EXISTS ix_alertrule_destination_id ON alertrule(destination_id)",
        ]:
            try:
                await conn.execute(text(stmt))
            except Exception:
                pass  # already applied


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSession(engine) as session:
        yield session
