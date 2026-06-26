"""Data retention / pruning for unbounded history tables.

`FetchLog`, `InstallCountHistory` and `AlertLog` grow on every refresh and every
alert. A real watchlist would bloat the DB indefinitely, so the scheduler runs a
daily prune (when `MARVIN_RETENTION_DAYS` is set) that deletes rows older than the
window. The `Extension` rows themselves are never touched — only their history."""

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete as sa_delete
from sqlmodel.ext.asyncio.session import AsyncSession

from app.config import settings
from app.database import engine
from app.models import AlertLog, FetchLog, InstallCountHistory

logger = logging.getLogger(__name__)

# (model, timestamp column) pairs pruned by the retention job.
_RETENTION_TARGETS = (
    (FetchLog, FetchLog.fetched_at),
    (InstallCountHistory, InstallCountHistory.recorded_at),
    (AlertLog, AlertLog.sent_at),
)


async def prune_expired(
    session: AsyncSession,
    *,
    retention_days: int,
    now: datetime | None = None,
) -> dict[str, int]:
    """Delete history rows older than the retention window.

    Returns per-table delete counts keyed by model name. ``retention_days <= 0``
    disables pruning (returns zero counts without touching the database). The
    caller is responsible for committing.
    """
    if retention_days <= 0:
        return {model.__name__: 0 for model, _ in _RETENTION_TARGETS}

    cutoff = (now or datetime.now(timezone.utc)) - timedelta(days=retention_days)
    counts: dict[str, int] = {}
    for model, ts_col in _RETENTION_TARGETS:
        result = await session.execute(sa_delete(model).where(ts_col < cutoff))
        counts[model.__name__] = result.rowcount or 0
    return counts


async def run_retention_prune() -> dict[str, int]:
    """Scheduler entry point: prune in a dedicated session + commit.

    No-op when retention is disabled. Like the watchlist refresh, this owns its
    own session and commit so it stays isolated from other writers."""
    retention_days = settings.retention_days
    if retention_days <= 0:
        return {}
    async with AsyncSession(engine) as session:
        counts = await prune_expired(session, retention_days=retention_days)
        await session.commit()
    total = sum(counts.values())
    if total:
        logger.info("Retention prune removed %d rows older than %d days (%s)", total, retention_days, counts)
    return counts
