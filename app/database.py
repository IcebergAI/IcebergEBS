import logging
from collections.abc import AsyncGenerator
from pathlib import Path

from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from sqlalchemy import inspect
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine
from sqlmodel.ext.asyncio.session import AsyncSession

from alembic import command
from app.config import settings

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parent.parent

engine: AsyncEngine = create_async_engine(
    settings.database_url,
    echo=False,
    pool_size=5,
    max_overflow=10,
    pool_pre_ping=True,
    pool_timeout=30,
    pool_recycle=1800,  # Recycle connections every 30 min to avoid server-side idle timeouts
)


def _alembic_config() -> Config:
    """Programmatic Alembic config.

    Built without the .ini file so env.py's ``fileConfig`` (logging override) is
    skipped — the ini is only for the ``alembic`` CLI. script_location is set
    explicitly so the config works regardless of the process cwd.
    """
    cfg = Config()
    cfg.set_main_option("script_location", str(_PROJECT_ROOT / "alembic"))
    return cfg


def _run_migrations(sync_conn) -> None:
    """Bring the database to head, adopting pre-Alembic databases by stamping.

    Runs on a sync connection handed in by ``run_sync``. Three cases:
    - alembic_version present  → ``upgrade head`` applies any new revisions.
    - no alembic_version, core tables already exist (a database created by the
      old create_all/_migrate_* path) → ``stamp head`` adopts it WITHOUT trying to
      recreate the tables.
    - empty database → ``upgrade head`` creates everything from the baseline.
    """
    cfg = _alembic_config()
    cfg.attributes["connection"] = sync_conn

    current = MigrationContext.configure(sync_conn).get_current_revision()
    if current is None and "user" in inspect(sync_conn).get_table_names():
        logger.info("Adopting existing pre-Alembic database — stamping to head")
        command.stamp(cfg, "head")
    else:
        command.upgrade(cfg, "head")


async def init_db() -> None:
    async with engine.connect() as conn:
        await conn.run_sync(_run_migrations)
        # Persist the alembic_version row: the connection is not in autocommit, so
        # the version INSERT (DML) would otherwise be rolled back when it closes.
        await conn.commit()


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSession(engine) as session:
        yield session
