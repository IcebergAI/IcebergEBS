"""Per-store circuit breaker + store-outage FetchLog (#108).

A store that fails N times consecutively in one refresh cycle has its remaining
extensions skipped and recorded as a *store outage*, not blamed as broken — so a
store being down doesn't spike every one of its extensions in the Fetch-health tile.
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import httpx
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app import scheduler
from app.fetchers.base import FetchError
from app.models import Extension, FetchLog
from app.scheduler import _Outcome, _StoreCircuitBreaker

# ---- pure breaker logic ---------------------------------------------------


def test_breaker_opens_after_threshold():
    b = _StoreCircuitBreaker(3)
    b.record("chrome", _Outcome.FAILED)
    b.record("chrome", _Outcome.FAILED)
    assert not b.is_open("chrome")
    b.record("chrome", _Outcome.FAILED)
    assert b.is_open("chrome")


def test_success_resets_consecutive_count():
    b = _StoreCircuitBreaker(3)
    b.record("chrome", _Outcome.FAILED)
    b.record("chrome", _Outcome.FAILED)
    b.record("chrome", _Outcome.SUCCESS)  # a healthy neighbour resets the run
    b.record("chrome", _Outcome.FAILED)
    b.record("chrome", _Outcome.FAILED)
    assert not b.is_open("chrome")  # only 2 consecutive since the reset


def test_gone_outcome_is_not_a_store_signal():
    b = _StoreCircuitBreaker(2)
    b.record("chrome", _Outcome.GONE)
    b.record("chrome", _Outcome.GONE)
    assert not b.is_open("chrome")


def test_threshold_zero_disables_breaker():
    b = _StoreCircuitBreaker(0)
    for _ in range(10):
        b.record("chrome", _Outcome.FAILED)
    assert not b.is_open("chrome")


def test_stores_are_tracked_independently():
    b = _StoreCircuitBreaker(2)
    b.record("chrome", _Outcome.FAILED)
    b.record("chrome", _Outcome.FAILED)
    b.record("edge", _Outcome.FAILED)
    assert b.is_open("chrome")
    assert not b.is_open("edge")


def test_internal_error_outcome_is_neutral():
    # Unexpected internal errors (inspector/scoring/DB/bug) are not a store signal, so
    # they must never open the circuit — otherwise a bug would mask itself as a store outage.
    b = _StoreCircuitBreaker(2)
    for _ in range(5):
        b.record("chrome", _Outcome.ERROR)
    assert not b.is_open("chrome")


# ---- integration: refresh_watchlist records store outages ------------------


async def test_refresh_watchlist_records_store_outage(test_db, admin_user, monkeypatch):
    monkeypatch.setattr(scheduler, "engine", test_db)
    monkeypatch.setattr(scheduler.settings, "store_circuit_failure_threshold", 2)

    async with AsyncSession(test_db) as s:
        for i in range(4):
            s.add(
                Extension(
                    user_id=admin_user.id,
                    store="vscode",
                    extension_id=f"pub.ext{i}",
                    name=f"Ext {i}",
                    publisher="pub",
                    version="1.0",
                    store_url="https://example.com",
                    risk_score=10,
                    watchlist=True,
                )
            )
        await s.commit()

    with patch("app.fetchers.VSCodeFetcher") as MockFetcher:
        MockFetcher.return_value.fetch = AsyncMock(side_effect=FetchError("store down"))
        async with httpx.AsyncClient() as http:
            await scheduler.refresh_watchlist(http)

    async with AsyncSession(test_db) as s:
        logs = (await s.exec(select(FetchLog))).all()

    real_failures = [lg for lg in logs if not lg.success and not lg.store_outage]
    outages = [lg for lg in logs if lg.store_outage]
    # First 2 consecutive failures trip the breaker; the remaining 2 are skipped as outages.
    assert len(real_failures) == 2
    assert len(outages) == 2
    assert all(lg.success is False for lg in outages)


async def test_transport_error_opens_circuit(test_db, admin_user, monkeypatch):
    # A raw httpx.TransportError (e.g. connection refused after RetryTransport exhausted its
    # retries) is a genuine store outage, not an internal bug: it must be classified FAILED so
    # the circuit opens and the store's remaining extensions are skipped as outages — the same
    # behaviour as a FetchError, and unlike the neutral RuntimeError case below.
    monkeypatch.setattr(scheduler, "engine", test_db)
    monkeypatch.setattr(scheduler.settings, "store_circuit_failure_threshold", 2)

    async with AsyncSession(test_db) as s:
        for i in range(4):
            s.add(
                Extension(
                    user_id=admin_user.id,
                    store="vscode",
                    extension_id=f"pub.net{i}",
                    name=f"Net {i}",
                    publisher="pub",
                    version="1.0",
                    store_url="https://example.com",
                    risk_score=10,
                    watchlist=True,
                )
            )
        await s.commit()

    with patch("app.fetchers.VSCodeFetcher") as MockFetcher:
        MockFetcher.return_value.fetch = AsyncMock(side_effect=httpx.ConnectError("connection refused"))
        async with httpx.AsyncClient() as http:
            await scheduler.refresh_watchlist(http)

    async with AsyncSession(test_db) as s:
        logs = (await s.exec(select(FetchLog))).all()

    real_failures = [lg for lg in logs if not lg.success and not lg.store_outage]
    outages = [lg for lg in logs if lg.store_outage]
    # First 2 consecutive transport failures trip the breaker; the remaining 2 are outages.
    assert len(real_failures) == 2
    assert len(outages) == 2


async def test_unexpected_errors_do_not_open_circuit(test_db, admin_user, monkeypatch):
    # A non-FetchError bug is a neutral ERROR outcome, so the circuit never opens and every
    # extension is still attempted (no bogus store_outage rows).
    monkeypatch.setattr(scheduler, "engine", test_db)
    monkeypatch.setattr(scheduler.settings, "store_circuit_failure_threshold", 2)

    async with AsyncSession(test_db) as s:
        for i in range(4):
            s.add(
                Extension(
                    user_id=admin_user.id,
                    store="vscode",
                    extension_id=f"pub.bug{i}",
                    name=f"Bug {i}",
                    publisher="pub",
                    version="1.0",
                    store_url="https://example.com",
                    risk_score=10,
                    watchlist=True,
                )
            )
        await s.commit()

    with patch("app.fetchers.VSCodeFetcher") as MockFetcher:
        MockFetcher.return_value.fetch = AsyncMock(side_effect=RuntimeError("internal bug"))
        async with httpx.AsyncClient() as http:
            await scheduler.refresh_watchlist(http)
        # All four were attempted — the circuit never opened despite repeated errors.
        assert MockFetcher.return_value.fetch.await_count == 4

    async with AsyncSession(test_db) as s:
        logs = (await s.exec(select(FetchLog))).all()
    assert [lg for lg in logs if lg.store_outage] == []


# ---- dashboard: a store outage doesn't count against Fetch health ----------


async def test_store_outage_not_counted_as_failing(client, test_db, admin_user):
    now = datetime.now(timezone.utc)
    async with AsyncSession(test_db) as s:
        ext = Extension(
            user_id=admin_user.id,
            store="vscode",
            extension_id="pub.outage",
            name="Outage Ext",
            publisher="pub",
            version="1.0",
            store_url="https://example.com",
            risk_score=10,
            watchlist=True,
            last_fetched_at=now,  # recent, so not stale
        )
        s.add(ext)
        await s.commit()
        await s.refresh(ext)
        s.add(
            FetchLog(
                extension_id=ext.id,
                success=False,
                store_outage=True,
                error_message="Skipped: vscode appears unavailable",
                fetched_at=now,
            )
        )
        await s.commit()

    r = await client.get("/")
    assert r.status_code == 200
    # A store outage is not the extension's fault, so Fetch health stays clean.
    assert "all healthy" in r.text


async def test_plain_failure_is_counted_as_failing(client, test_db, admin_user):
    now = datetime.now(timezone.utc)
    async with AsyncSession(test_db) as s:
        ext = Extension(
            user_id=admin_user.id,
            store="vscode",
            extension_id="pub.broken",
            name="Broken Ext",
            publisher="pub",
            version="1.0",
            store_url="https://example.com",
            risk_score=10,
            watchlist=True,
            last_fetched_at=now - timedelta(minutes=1),
        )
        s.add(ext)
        await s.commit()
        await s.refresh(ext)
        s.add(FetchLog(extension_id=ext.id, success=False, error_message="404 not found", fetched_at=now))
        await s.commit()

    r = await client.get("/")
    assert r.status_code == 200
    assert "stale or failing" in r.text
