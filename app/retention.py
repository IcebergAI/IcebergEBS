"""Data retention / pruning for unbounded history tables, and install-footprint decay.

`FetchLog`, `InstallCountHistory`, `AlertLog` and `InstallObservation` grow on every
refresh, alert, and SOAR push. A real watchlist would bloat the DB indefinitely, so the
scheduler runs a daily prune (when `ICEBERG_EBS_RETENTION_DAYS` is set) that deletes rows
older than the window. The `Extension` rows themselves are never touched — only their
history.

This module is also the home of **install-footprint decay** (#287): `InstallObservation.
last_seen` is bumped on every SOAR re-push, and an observation not re-seen within
`ICEBERG_EBS_INVENTORY_FRESHNESS_DAYS` stops counting toward `install_footprint` — so an
extension removed from every endpoint stops inflating exposure and the "Top exposure"
ranking. `freshness_cutoff()` is the single home of the window; the inventory API's
per-batch recompute and the daily `run_footprint_refresh` job both apply it."""

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete as sa_delete
from sqlalchemy import func, or_, select
from sqlalchemy import update as sa_update
from sqlmodel.ext.asyncio.session import AsyncSession

from app.config import settings
from app.database import engine
from app.models import AlertLog, Extension, FetchLog, InstallCountHistory, InstallObservation

logger = logging.getLogger(__name__)

# (model, timestamp column) pairs pruned by the retention job. InstallObservation
# prunes on last_seen (#287): a row a SOAR re-push keeps refreshing never expires,
# while one whose (extension, asset) pair stopped being reported eventually does.
_RETENTION_TARGETS = (
    (FetchLog, FetchLog.fetched_at),
    (InstallCountHistory, InstallCountHistory.recorded_at),
    (AlertLog, AlertLog.sent_at),
    (InstallObservation, InstallObservation.last_seen),
)


def freshness_cutoff(now: datetime | None = None) -> datetime | None:
    """The ``last_seen`` cutoff for a "fresh" install observation (#287).

    Returns None when decay is disabled (`inventory_freshness_days <= 0`), meaning
    every observation ever counts — the pre-#287 behaviour.
    """
    days = settings.inventory_freshness_days
    if days <= 0:
        return None
    return (now or datetime.now(timezone.utc)) - timedelta(days=days)


async def refresh_install_footprints(
    session: AsyncSession,
    *,
    now: datetime | None = None,
) -> int:
    """Recompute every cached ``install_footprint`` over FRESH observations only.

    One bulk UPDATE with a correlated distinct-asset count, covering every extension
    that has observations or a previously-set footprint — so an extension whose SOAR
    pushes stopped entirely (the #287 failure case: it never appears in a batch's
    "touched" set again) decays to zero instead of staying inflated forever. The
    caller commits. Returns the number of extensions updated.
    """
    cutoff = freshness_cutoff(now)
    fresh_count = select(func.count(func.distinct(InstallObservation.asset_id))).where(
        InstallObservation.extension_id == Extension.id
    )
    if cutoff is not None:
        fresh_count = fresh_count.where(InstallObservation.last_seen >= cutoff)
    stmt = (
        sa_update(Extension)
        .where(
            or_(
                Extension.install_footprint.is_not(None),
                Extension.id.in_(select(InstallObservation.extension_id)),
            )
        )
        .values(install_footprint=fresh_count.scalar_subquery())
    )
    result = await session.execute(stmt)
    return result.rowcount or 0


async def run_footprint_refresh() -> int:
    """Scheduler entry point (#287): daily footprint decay in its own session + commit.

    No-op when decay is disabled. Separate from the retention prune because decay must
    run even on deployments that keep retention off (the default)."""
    if settings.inventory_freshness_days <= 0:
        return 0
    async with AsyncSession(engine) as session:
        updated = await refresh_install_footprints(session)
        await session.commit()
    logger.info("Footprint refresh: recomputed install_footprint for %d extension(s)", updated)
    return updated


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
