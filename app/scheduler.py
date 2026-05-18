import logging

import httpx
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.config import settings
from app.database import engine
from app.fetchers.base import FetchError
from app.models import Extension, FetchLog
from app.services import fetch_and_store

logger = logging.getLogger(__name__)


async def _refresh_one(ext_id: int, client: httpx.AsyncClient) -> None:
    """Refresh a single extension in its own session+commit so failures are isolated."""
    async with AsyncSession(engine) as session:
        ext = await session.get(Extension, ext_id)
        if not ext or not ext.watchlist:
            return
        score_before = ext.risk_score
        try:
            await fetch_and_store(ext, session, client, engine)
            await session.commit()
        except FetchError as exc:
            logger.warning("Fetch failed for %s/%s: %s", ext.store, ext.extension_id, exc)
            session.add(FetchLog(
                extension_id=ext.id,
                success=False,
                error_message=str(exc),
                risk_score_before=score_before,
            ))
            await session.commit()
        except Exception:
            logger.exception("Unexpected error refreshing ext_id=%d", ext_id)
            await session.rollback()


async def refresh_watchlist(client: httpx.AsyncClient) -> None:
    logger.info("Starting watchlist refresh")
    async with AsyncSession(engine) as session:
        ext_ids = (await session.exec(
            select(Extension.id).where(Extension.watchlist == True)  # noqa: E712
        )).all()

    for ext_id in ext_ids:
        await _refresh_one(ext_id, client)

    logger.info("Watchlist refresh complete (%d extensions)", len(ext_ids))


def create_scheduler(client: httpx.AsyncClient) -> AsyncIOScheduler:
    scheduler = AsyncIOScheduler()
    scheduler.add_job(
        refresh_watchlist,
        trigger="interval",
        minutes=settings.fetch_interval_minutes,
        args=[client],
        id="watchlist_refresh",
        replace_existing=True,
    )
    return scheduler
