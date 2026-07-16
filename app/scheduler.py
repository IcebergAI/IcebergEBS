import asyncio
import enum
import logging
from datetime import datetime, timezone

import httpx
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.config import settings
from app.database import engine
from app.fetchers.base import FetchError
from app.models import Extension, FetchLog
from app.retention import run_retention_prune
from app.scheduler_state import mark_scheduler_run
from app.services import fetch_and_store, fire_pending_alerts, recover_pending_alerts

logger = logging.getLogger(__name__)

# Tasks for in-flight refresh cycles, so a graceful shutdown can await them (#109). APScheduler
# 3.x's AsyncIOExecutor.shutdown(wait=True) does NOT await running asyncio jobs — it cancels
# their futures — so `wait=True` alone can abandon a refresh mid-cycle. We track the running
# task ourselves and drain it explicitly in drain_inflight().
_inflight: set[asyncio.Task] = set()


async def drain_inflight(timeout: float) -> None:
    """Await any in-flight refresh job (bounded by ``timeout``) so a graceful shutdown lets it
    finish committing + firing instead of being cancelled. The durable pending-alert marker
    (#109) is the backstop if the timeout is exceeded (SIGKILL): recovery re-fires on restart."""
    tasks = [t for t in _inflight if not t.done()]
    if not tasks:
        return
    logger.info("Draining %d in-flight refresh job(s) before shutdown", len(tasks))
    await asyncio.wait(tasks, timeout=timeout)


class _Outcome(enum.Enum):
    """Result of refreshing one extension, used to drive the circuit breaker."""

    SUCCESS = "success"
    FAILED = "failed"  # a store/network failure (FetchError or httpx.TransportError) — counts
    # toward the breaker. TransportError covers a fetch whose retries were all exhausted.
    GONE = "gone"  # extension removed / no longer watchlisted — not a store signal
    ERROR = "error"  # an unexpected *internal* error (inspector/scoring/DB/bug) — NOT a
    # store signal, so it must not open the circuit; it stays loudly logged instead.


class _StoreCircuitBreaker:
    """Per-cycle, per-store consecutive-failure tracker (#108).

    Counts consecutive failures per store; any success resets that store's counter.
    Once a store reaches ``threshold`` consecutive failures its circuit opens and the
    remaining extensions of that store are skipped for the rest of the cycle. Because a
    single success resets the count, an isolated broken extension (e.g. a 404 delisting)
    never trips the breaker — its store-neighbours succeed in between — so an open
    circuit genuinely means *the store* is failing, not N unrelated extensions.
    """

    def __init__(self, threshold: int) -> None:
        self._threshold = threshold
        self._consecutive: dict[str, int] = {}
        self._open: set[str] = set()

    def is_open(self, store: str) -> bool:
        return store in self._open

    def record(self, store: str, outcome: _Outcome) -> None:
        # Only a real store/network FAILED counts; SUCCESS resets; GONE and ERROR
        # (internal errors) are neutral — they neither open nor reset the circuit.
        if outcome is _Outcome.SUCCESS:
            self._consecutive[store] = 0
        elif outcome is _Outcome.FAILED:
            n = self._consecutive.get(store, 0) + 1
            self._consecutive[store] = n
            if self._threshold > 0 and n >= self._threshold:
                self._open.add(store)


async def _refresh_one(ext_id: int, client: httpx.AsyncClient) -> _Outcome:
    """Refresh a single extension in its own session+commit so failures are isolated."""
    async with AsyncSession(engine) as session:
        ext = await session.get(Extension, ext_id)
        if not ext or not ext.watchlist:
            return _Outcome.GONE
        score_before = ext.risk_score
        try:
            ext, events = await fetch_and_store(ext, session, client)
            await session.commit()
        except (FetchError, httpx.TransportError) as exc:
            # A store/network failure: either the fetcher raised FetchError, or a raw
            # httpx.TransportError propagated after RetryTransport exhausted its retries
            # (connect refused, timeout, read/write error). Both are evidence the *store*
            # is unreachable, so they count toward the circuit breaker.
            logger.warning("Fetch failed for %s/%s: %s", ext.store, ext.extension_id, exc)
            await session.rollback()
            session.add(
                FetchLog(
                    extension_id=ext_id,
                    success=False,
                    error_message=str(exc),
                    risk_score_before=score_before,
                )
            )
            await session.commit()
            return _Outcome.FAILED
        except Exception:
            # An unexpected internal error (inspector/scoring/DB/programming bug) is NOT
            # evidence the store is down, so it must not count toward the circuit breaker
            # (that would skip healthy extensions and mislabel them as a store outage).
            # Return the neutral ERROR outcome; the exception is loudly logged above.
            logger.exception("Unexpected error refreshing ext_id=%d", ext_id)
            await session.rollback()
            return _Outcome.ERROR
        # Fire alerts only after committing above, so fire_alerts' own session (which
        # writes AlertLog) does not run inside this session's open write transaction.
        await session.refresh(ext)
        await fire_pending_alerts(events, ext, engine, client)
        return _Outcome.SUCCESS


async def _record_store_outage(ext_id: int, store: str) -> None:
    """Log a store-outage FetchLog for an extension skipped by an open circuit (#108).

    Written as ``success=False, store_outage=True`` so the Fetch-health tile can tell a
    store outage apart from a broken extension and not blame the extension for it.
    """
    async with AsyncSession(engine) as session:
        ext = await session.get(Extension, ext_id)
        if not ext or not ext.watchlist:
            return
        session.add(
            FetchLog(
                extension_id=ext_id,
                success=False,
                store_outage=True,
                error_message=f"Skipped: {store} appears unavailable (store circuit open this cycle)",
                risk_score_before=ext.risk_score,
            )
        )
        await session.commit()


async def refresh_watchlist(client: httpx.AsyncClient) -> None:
    # Register this cycle so drain_inflight() can await it on a graceful shutdown (#109).
    task = asyncio.current_task()
    if task is not None:
        _inflight.add(task)
    try:
        logger.info("Starting watchlist refresh")
        # Re-fire any alerts persisted-but-not-delivered before a prior shutdown/crash (#109),
        # before the new cycle overwrites the state they describe.
        await recover_pending_alerts(engine, client)
        async with AsyncSession(engine) as session:
            rows = (
                await session.exec(
                    select(Extension.id, Extension.store).where(Extension.watchlist == True)  # noqa: E712
                )
            ).all()

        breaker = _StoreCircuitBreaker(settings.store_circuit_failure_threshold)
        skipped = 0
        for ext_id, store in rows:
            if breaker.is_open(store):
                await _record_store_outage(ext_id, store)
                skipped += 1
                continue
            outcome = await _refresh_one(ext_id, client)
            breaker.record(store, outcome)

        # Record that the scheduler completed a cycle, so /readyz can surface freshness
        # without scanning the history table on every probe (#89).
        mark_scheduler_run()
        if skipped:
            logger.warning(
                "Watchlist refresh complete (%d extensions, %d skipped due to store outage)",
                len(rows),
                skipped,
            )
        else:
            logger.info("Watchlist refresh complete (%d extensions)", len(rows))
    finally:
        if task is not None:
            _inflight.discard(task)


def create_scheduler(client: httpx.AsyncClient) -> AsyncIOScheduler:
    scheduler = AsyncIOScheduler()
    scheduler.add_job(
        refresh_watchlist,
        trigger="interval",
        minutes=settings.fetch_interval_minutes,
        args=[client],
        id="watchlist_refresh",
        replace_existing=True,
        # APScheduler's default misfire_grace_time is 1s: if the single-worker event loop is
        # busy (a long refresh, GC, a CPU-starved container) when a fire is due, the run is
        # silently dropped as a misfire rather than run late. None removes that limit so a
        # missed refresh runs when the loop frees up; coalesce (default True) collapses a
        # backlog to one run (#198).
        misfire_grace_time=None,
    )
    # Daily data-retention prune, only when ICEBERG_EBS_RETENTION_DAYS is configured.
    # run_retention_prune is itself a no-op when disabled, but skipping the job
    # entirely avoids a pointless daily wakeup on the default (disabled) config.
    if settings.retention_days > 0:
        scheduler.add_job(
            run_retention_prune,
            trigger="interval",
            hours=24,
            id="retention_prune",
            replace_existing=True,
            # Run once at startup, then daily. An interval trigger's first fire is otherwise
            # start+24h with no next_run_time, so a deployment that restarts more often than
            # daily (crash / OOM / redeploy) would never prune despite retention being enabled
            # (#145). This fires on the scheduler executor after startup, so it does not block
            # the server from binding / answering probes (cf. #155).
            next_run_time=datetime.now(timezone.utc),
            # Without this the startup fire is subject to APScheduler's 1s default
            # misfire_grace_time: a >1s gap between create_scheduler() stamping next_run_time
            # and the executor picking the job up (exactly the CPU-starved restart #145
            # targets) drops the startup prune as a misfire, and no prune runs until +24h.
            # None removes the limit so the prune always runs, however late the loop is (#198).
            misfire_grace_time=None,
        )
    return scheduler
