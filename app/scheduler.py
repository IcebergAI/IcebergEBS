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


async def _refresh_one(ext: Extension, session: AsyncSession, client: httpx.AsyncClient) -> None:
    score_before = ext.risk_score
    try:
        await fetch_and_store(ext, session, client)
    except FetchError as exc:
        logger.warning("Fetch failed for %s/%s: %s", ext.store, ext.extension_id, exc)
        session.add(FetchLog(
            extension_id=ext.id,
            success=False,
            error_message=str(exc),
            risk_score_before=score_before,
        ))


async def refresh_watchlist(client: httpx.AsyncClient) -> None:
    logger.info("Starting watchlist refresh")
    async with AsyncSession(engine) as session:
        watchlist = (await session.exec(
            select(Extension).where(Extension.watchlist == True)
        )).all()

        for ext in watchlist:
            try:
                await _refresh_one(ext, session, client)
            except Exception as exc:
                logger.error("Unexpected error refreshing %s: %s", ext.extension_id, exc)

        await session.commit()
    logger.info("Watchlist refresh complete (%d extensions)", len(watchlist))


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
