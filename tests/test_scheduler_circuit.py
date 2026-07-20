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


async def test_fetch_failure_error_message_is_scrubbed(test_db, admin_user, monkeypatch):
    # FetchLog.error_message is rendered to non-admin owners on the dashboard and
    # detail pages; a proxy-layer failure can echo the credential-injected proxy URL
    # in the exception text, so it must pass proxy.scrub before persisting (#228).
    monkeypatch.setattr(scheduler, "engine", test_db)

    async with AsyncSession(test_db) as s:
        s.add(
            Extension(
                user_id=admin_user.id,
                store="vscode",
                extension_id="pub.scrubme",
                name="Scrub Me",
                publisher="pub",
                version="1.0",
                store_url="https://example.com",
                risk_score=10,
                watchlist=True,
            )
        )
        await s.commit()

    leaky = FetchError("CONNECT via http://bob:hunter2@proxy.corp:3128 failed")
    with patch("app.fetchers.VSCodeFetcher") as MockFetcher:
        MockFetcher.return_value.fetch = AsyncMock(side_effect=leaky)
        async with httpx.AsyncClient() as http:
            await scheduler.refresh_watchlist(http)

    async with AsyncSession(test_db) as s:
        logs = (await s.exec(select(FetchLog))).all()
    assert len(logs) == 1
    assert logs[0].success is False
    assert "hunter2" not in logs[0].error_message
    assert "bob" not in logs[0].error_message
    assert "proxy.corp" in logs[0].error_message  # only the userinfo is redacted


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


# ---- per-extension isolation: one failure cannot abort the cycle (#282) ----


async def test_mid_cycle_delete_does_not_abort_remaining_extensions(test_db, admin_user, monkeypatch):
    # A DELETE racing the scheduler mid-fetch makes the failure-FetchLog FK insert
    # raise IntegrityError from inside the FetchError handler — where the sibling
    # `except Exception` can't catch it. Previously that aborted the whole cycle,
    # starving every remaining extension (#282).
    monkeypatch.setattr(scheduler, "engine", test_db)
    # Disable the breaker: all three fetches fail by design, and this test is about
    # cycle isolation, not the circuit (which would otherwise skip the third).
    monkeypatch.setattr(scheduler.settings, "store_circuit_failure_threshold", 0)

    ids = {}
    async with AsyncSession(test_db) as s:
        for i in range(3):
            ext = Extension(
                user_id=admin_user.id,
                store="vscode",
                extension_id=f"pub.iso{i}",
                name=f"Iso {i}",
                publisher="pub",
                version="1.0",
                store_url="https://example.com",
                risk_score=10,
                watchlist=True,
            )
            s.add(ext)
            await s.commit()
            await s.refresh(ext)
            ids[f"pub.iso{i}"] = ext.id

    fetched: list[str] = []

    async def fetch_side_effect(extension_id):
        fetched.append(extension_id)
        if extension_id == "pub.iso1":
            # Simulate the user deleting this extension while its fetch is in flight,
            # then the fetch failing — the failure-log insert now hits a dead FK.
            async with AsyncSession(test_db) as s:
                row = await s.get(Extension, ids["pub.iso1"])
                await s.delete(row)
                await s.commit()
            raise FetchError("store hiccup")
        raise FetchError("store hiccup")

    with patch("app.fetchers.VSCodeFetcher") as MockFetcher:
        MockFetcher.return_value.fetch = AsyncMock(side_effect=fetch_side_effect)
        async with httpx.AsyncClient() as http:
            # Must not raise, and must reach every extension.
            await scheduler.refresh_watchlist(http)

    assert fetched == ["pub.iso0", "pub.iso1", "pub.iso2"]
    async with AsyncSession(test_db) as s:
        logs = (await s.exec(select(FetchLog))).all()
    # The two surviving extensions recorded their failure logs; the deleted one's
    # failure-log write failed quietly (its row is gone).
    assert {lg.extension_id for lg in logs} == {ids["pub.iso0"], ids["pub.iso2"]}


async def test_escaped_refresh_error_is_breaker_neutral_and_cycle_continues(test_db, admin_user, monkeypatch):
    # The loop-level backstop (#282): anything escaping _refresh_one records the
    # neutral ERROR outcome — the cycle continues and the circuit never opens.
    monkeypatch.setattr(scheduler, "engine", test_db)
    monkeypatch.setattr(scheduler.settings, "store_circuit_failure_threshold", 2)

    async with AsyncSession(test_db) as s:
        for i in range(4):
            s.add(
                Extension(
                    user_id=admin_user.id,
                    store="vscode",
                    extension_id=f"pub.esc{i}",
                    name=f"Esc {i}",
                    publisher="pub",
                    version="1.0",
                    store_url="https://example.com",
                    risk_score=10,
                    watchlist=True,
                )
            )
        await s.commit()

    calls = []

    async def exploding_refresh(ext_id, client):
        calls.append(ext_id)
        raise RuntimeError("escaped _refresh_one")

    monkeypatch.setattr(scheduler, "_refresh_one", exploding_refresh)
    async with httpx.AsyncClient() as http:
        await scheduler.refresh_watchlist(http)  # must not raise

    assert len(calls) == 4  # every extension attempted; nothing skipped as outage
    async with AsyncSession(test_db) as s:
        logs = (await s.exec(select(FetchLog))).all()
    assert [lg for lg in logs if lg.store_outage] == []


# ---- recovery isolation: a failed recovery can't abort the cycle (#282 review) ----


async def test_recovery_failure_does_not_abort_remaining_recovery(test_db, admin_user, monkeypatch):
    # recover_pending_alerts runs at the head of the cycle, before the guarded refresh
    # loop. Without its own per-extension isolation, one extension's recovery failure (a
    # concurrent delete between get/refresh, a delivery error) escaped and aborted the
    # whole cycle — the exact failure #282 targets, in the recovery path (#282 review).
    import json

    from app import services

    monkeypatch.setattr(scheduler, "engine", test_db)

    ids = []
    async with AsyncSession(test_db) as s:
        for i in range(2):
            ext = Extension(
                user_id=admin_user.id,
                store="vscode",
                extension_id=f"pub.rec{i}",
                name=f"Rec {i}",
                publisher="pub",
                version="1.0",
                store_url="https://example.com",
                risk_score=10,
                watchlist=True,
                pending_alert_events=json.dumps(
                    [{"event_type": "new_version", "old_value": "1.0", "new_value": "2.0"}]
                ),
            )
            s.add(ext)
            await s.commit()
            await s.refresh(ext)
            ids.append(ext.id)

    fired: list[int] = []

    async def fire_side_effect(events, ext, engine, client, expected_marker=None):
        fired.append(ext.id)
        if ext.id == ids[0]:
            raise RuntimeError("delivery blew up")

    monkeypatch.setattr(services, "fire_pending_alerts", fire_side_effect)
    async with httpx.AsyncClient() as http:
        await services.recover_pending_alerts(test_db, http)  # must not raise

    # Both extensions were attempted — the first's failure did not abort recovery of the second.
    assert fired == ids


async def test_recovery_error_does_not_abort_refresh_cycle(test_db, admin_user, monkeypatch):
    # Cycle-level backstop (#282 review): even if recover_pending_alerts raises entirely
    # (e.g. its initial scan query errors), the refresh loop must still run and the
    # /readyz scheduler heartbeat must still be marked.
    monkeypatch.setattr(scheduler, "engine", test_db)

    async with AsyncSession(test_db) as s:
        s.add(
            Extension(
                user_id=admin_user.id,
                store="vscode",
                extension_id="pub.after",
                name="After",
                publisher="pub",
                version="1.0",
                store_url="https://example.com",
                risk_score=10,
                watchlist=True,
            )
        )
        await s.commit()

    async def boom(engine, client):
        raise RuntimeError("recovery exploded")

    heartbeat: list[bool] = []
    monkeypatch.setattr(scheduler, "recover_pending_alerts", boom)
    monkeypatch.setattr(scheduler, "mark_scheduler_run", lambda: heartbeat.append(True))

    with patch("app.fetchers.VSCodeFetcher") as MockFetcher:
        MockFetcher.return_value.fetch = AsyncMock(side_effect=FetchError("store down"))
        async with httpx.AsyncClient() as http:
            await scheduler.refresh_watchlist(http)  # must not raise
        # The refresh loop still ran the extension despite recovery blowing up.
        assert MockFetcher.return_value.fetch.await_count == 1
    assert heartbeat == [True]  # heartbeat still marked
