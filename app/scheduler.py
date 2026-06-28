import logging

import httpx
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.config import settings
from app.database import engine
from app.fetchers.base import FetchError
from app.models import Extension, FetchLog
from app.retention import run_retention_prune
from app.services import fetch_and_store, fire_pending_alerts

logger = logging.getLogger(__name__)


async def _refresh_one(ext_id: int, client: httpx.AsyncClient) -> None:
    """Refresh a single extension in its own session+commit so failures are isolated."""
    async with AsyncSession(engine) as session:
        ext = await session.get(Extension, ext_id)
        if not ext or not ext.watchlist:
            return
        score_before = ext.risk_score
        try:
            ext, events = await fetch_and_store(ext, session, client)
            await session.commit()
        except FetchError as exc:
            logger.warning("Fetch failed for %s/%s: %s", ext.store, ext.extension_id, exc)
            session.add(
                FetchLog(
                    extension_id=ext.id,
                    success=False,
                    error_message=str(exc),
                    risk_score_before=score_before,
                )
            )
            await session.commit()
            return
        except Exception:
            logger.exception("Unexpected error refreshing ext_id=%d", ext_id)
            await session.rollback()
            return
        # Fire alerts only after committing above, so fire_alerts' own session (which
        # writes AlertLog) does not run inside this session's open write transaction.
        await session.refresh(ext)
        await fire_pending_alerts(events, ext, engine, client)


async def refresh_watchlist(client: httpx.AsyncClient) -> None:
    logger.info("Starting watchlist refresh")
    async with AsyncSession(engine) as session:
        ext_ids = (
            await session.exec(
                select(Extension.id).where(Extension.watchlist == True)  # noqa: E712
            )
        ).all()

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
    # Daily data-retention prune, only when MARVIN_RETENTION_DAYS is configured.
    # run_retention_prune is itself a no-op when disabled, but skipping the job
    # entirely avoids a pointless daily wakeup on the default (disabled) config.
    if settings.retention_days > 0:
        scheduler.add_job(
            run_retention_prune,
            trigger="interval",
            hours=24,
            id="retention_prune",
            replace_existing=True,
        )
    return scheduler
